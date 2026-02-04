# src/deduplication_manager.py
import logging
from typing import List, Tuple, Dict, Optional, Any
from collections import defaultdict
from src.models import Vulnerability

logger = logging.getLogger(__name__)

class DeduplicationManager:
    """
    Gestisce la deduplicazione intelligente delle vulnerabilità.
    Se la stessa CVE arriva da più fonti, mantiene quella con più informazioni.
    """
    
    @staticmethod
    def deduplicate(vulnerabilities: List[Tuple[Vulnerability, Optional[Dict[str, Any]]]]) -> List[Tuple[Vulnerability, Optional[Dict[str, Any]]]]:
        """
        Deduplica vulnerabilità mantenendo la versione migliore di ogni CVE.
        
        Regole di priorità:
        1. Quella con CVSS score (se altre non l'hanno)
        2. Quella con CVSS vector (se altre non l'hanno)
        3. Quella con descrizione più lunga
        4. Quella da fonte più autorevole (CISA > NVD > RSS)
        """
        
        # Raggruppa per ID
        grouped = defaultdict(list)
        for vuln, metadata in vulnerabilities:
            grouped[vuln.id].append((vuln, metadata))
        
        deduplicated = []
        duplicates_removed = 0
        
        for cve_id, versions in grouped.items():
            if len(versions) == 1:
                # Nessun duplicato
                deduplicated.append(versions[0])
            else:
                # Scegli la versione migliore
                best = DeduplicationManager._select_best_version(versions)
                deduplicated.append(best)
                duplicates_removed += len(versions) - 1
                
                # Log delle fonti duplicate
                sources = [v[0].source for v in versions]
                logger.info(f"🔄 Deduplicato {cve_id}: {len(versions)} fonti ({', '.join(sources)}) → usata migliore")
        
        if duplicates_removed > 0:
            logger.info(f"✅ Rimosse {duplicates_removed} duplicazioni, mantenute {len(deduplicated)} vulnerabilità uniche")
        
        return deduplicated
    
    @staticmethod
    def _select_best_version(versions: List[Tuple[Vulnerability, Optional[Dict[str, Any]]]]) -> Tuple[Vulnerability, Optional[Dict[str, Any]]]:
        """Seleziona la versione migliore tra i duplicati"""
        
        # Sistema di scoring
        def score_vuln(vuln: Vulnerability) -> int:
            score = 0
            
            # +100 se ha CVSS score
            if vuln.cvss_score is not None:
                score += 100
            
            # +50 se ha CVSS vector
            if vuln.cvss_vector:
                score += 50
            
            # +1 per ogni 10 caratteri di descrizione (max 50)
            if vuln.description:
                score += min(len(vuln.description) // 10, 50)
            
            # +200 se ha exploit pubblico
            if vuln.has_public_exploit:
                score += 200
            
            # Priorità fonte (CISA > NVD > CERT > RSS)
            source_priority = {
                "CISA KEV": 150,
                "NVD": 120,
                "CERT-EU": 80,
                "US-CERT": 80,
                "GitHub": 60
            }
            for key, priority in source_priority.items():
                if key.lower() in vuln.source.lower():
                    score += priority
                    break
            else:
                score += 30  # RSS generico
            
            return score
        
        # Trova la versione con score più alto
        best = max(versions, key=lambda v: score_vuln(v[0]))
        
        # Se la migliore non ha CVSS ma un'altra sì, fai merge
        best_vuln, best_meta = best
        if best_vuln.cvss_score is None:
            for vuln, meta in versions:
                if vuln.cvss_score is not None:
                    # Crea versione merged
                    from dataclasses import replace
                    merged = replace(
                        best_vuln,
                        cvss_score=vuln.cvss_score,
                        cvss_vector=vuln.cvss_vector or best_vuln.cvss_vector
                    )
                    logger.debug(f"📊 Merged CVSS data da {vuln.source} in {best_vuln.source}")
                    return (merged, best_meta)
        
        return best


# Esempio di integrazione in main.py:
"""
from src.deduplication_manager import DeduplicationManager

# Dopo aver raccolto tutte le vulnerabilità:
all_vulnerabilities = []
for source in sources:
    vulns = source.fetch()
    all_vulnerabilities.extend(vulns)

# Deduplica PRIMA di filtrare con state_manager
deduplicated = DeduplicationManager.deduplicate(all_vulnerabilities)

# Poi procedi con state check e invio
for vuln, metadata in deduplicated:
    if not state_manager.is_processed(vuln.id):
        # ... invia messaggio
"""