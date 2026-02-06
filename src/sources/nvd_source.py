# src/sources/nvd_source.py
"""
NVD (National Vulnerability Database) Source
Versione 2.0 - Estrae anche CWE ID, attack vector components, e patch URL
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Tuple, Dict, Optional, Any
from .base_source import BaseSource
from ..models import Vulnerability
from ..rate_limiter import get_rate_limiter

logger = logging.getLogger(__name__)


class NvdSource(BaseSource):
    """
    Gestisce la raccolta di vulnerabilità dal NVD API 2.0

    NUOVI CAMPI ESTRATTI in v2.0:
    - CWE IDs: Lista di CWE associati
    - Attack Vector Components: AV, AC, PR, UI, S, C, I, A
    - Patch URL: Primo riferimento con tag "Patch"
    """

    def fetch(self) -> List[Tuple[Vulnerability, Optional[Dict[str, Any]]]]:
        api_key = self.credentials.get("nvd_api_key")

        # Ottieni rate limiter
        rate_limiter = get_rate_limiter()

        # NVD 2.0 richiede il formato ISO 8601 ESTESO: YYYY-MM-DDTHH:mm:ss.SSS
        now = datetime.now(timezone.utc)

        # Sicurezza: NVD non accetta intervalli superiori a 120 giorni
        limit_date = now - timedelta(days=90)
        start_date = self.fetch_since if self.fetch_since > limit_date else limit_date

        start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        end_str = now.strftime('%Y-%m-%dT%H:%M:%S.000')

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        full_url = f"{url}?lastModStartDate={start_str}&lastModEndDate={end_str}&resultsPerPage=50"

        headers = {"apiKey": api_key} if api_key else {}
        vulnerabilities = []

        try:
            # Aspetta se necessario prima della richiesta
            rate_limiter.wait_if_needed("nvd")

            # Usa _make_request della classe base
            response = self._make_request(full_url, headers=headers)
            data = response.json()

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue

                # === ESTRAZIONE CVSS ===
                metrics = cve.get("metrics", {})
                cvss_score, cvss_vector = None, None
                v31 = metrics.get("cvssMetricV31", [])
                v30 = metrics.get("cvssMetricV30", [])

                if v31:
                    cvss_score = v31[0]["cvssData"].get("baseScore")
                    cvss_vector = v31[0]["cvssData"].get("vectorString")
                elif v30:
                    cvss_score = v30[0]["cvssData"].get("baseScore")
                    cvss_vector = v30[0]["cvssData"].get("vectorString")

                # === ESTRAZIONE DESCRIZIONE ===
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                    "No description."
                )

                # === ESTRAZIONE CWE (NUOVO) ===
                cwe_ids = []
                for weakness in cve.get("weaknesses", []):
                    for weak_desc in weakness.get("description", []):
                        value = weak_desc.get("value", "")
                        if value.startswith("CWE-"):
                            cwe_ids.append(value)

                cwe_id = cwe_ids[0] if cwe_ids else None

                # === ESTRAZIONE PATCH URL (NUOVO) ===
                patch_url = None
                references = cve.get("references", [])

                # Priorità: Patch > Vendor Advisory > Mitigation
                for priority_tag in ["Patch", "Vendor Advisory", "Mitigation"]:
                    for ref in references:
                        tags = ref.get("tags", [])
                        if priority_tag in tags:
                            patch_url = ref.get("url")
                            break
                    if patch_url:
                        break

                # === ESTRAZIONE ATTACK TYPE DA CWE ===
                attack_type = self._map_cwe_to_attack_type(cwe_id)

                # Parsing data pubblicazione
                published_str = cve.get("published", "")
                try:
                    published_date = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                except (ValueError, AttributeError):
                    published_date = datetime.now(timezone.utc)

                vuln = Vulnerability(
                    id=cve_id,
                    source=self.name,
                    title=f"{cve_id} - {desc[:80]}...",
                    link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published_date=published_date,
                    description=desc,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    cwe_id=cwe_id,
                    attack_type=attack_type,
                    patch_url=patch_url
                )

                # Passa il raw item completo per elaborazione successiva
                # Include tutte le info per impact_analyzer
                enriched_raw = {
                    **item,
                    "_extracted": {
                        "cwe_ids": cwe_ids,
                        "patch_url": patch_url,
                        "attack_type": attack_type,
                        "references_count": len(references)
                    },
                    "_source": "nvd"
                }

                vulnerabilities.append((vuln, enriched_raw))

            logger.info(f"[{self.name}] Connessione riuscita. Scaricate {len(vulnerabilities)} voci.")

        except Exception as e:
            logger.error(f"[{self.name}] Errore critico. URL inviato: {full_url}")
            logger.error(f"[{self.name}] Dettaglio: {e}", exc_info=True)

        return vulnerabilities

    def _map_cwe_to_attack_type(self, cwe_id: Optional[str]) -> Optional[str]:
        """
        Mappa CWE ID a tipo di attacco leggibile.
        Versione semplificata - la mappa completa è in impact_analyzer.py
        """
        if not cwe_id:
            return None

        # Mappa principale
        cwe_map = {
            # RCE
            "CWE-94": "RCE",
            "CWE-78": "RCE",
            "CWE-77": "RCE",
            "CWE-502": "RCE",
            "CWE-434": "RCE",

            # Injection
            "CWE-89": "SQLi",
            "CWE-79": "XSS",
            "CWE-611": "XXE",

            # Auth
            "CWE-287": "Auth Bypass",
            "CWE-306": "Missing Auth",
            "CWE-269": "Privilege Escalation",

            # Memory
            "CWE-119": "Buffer Overflow",
            "CWE-120": "Buffer Overflow",
            "CWE-416": "Use After Free",
            "CWE-787": "OOB Write",

            # Path
            "CWE-22": "Path Traversal",

            # DoS
            "CWE-400": "DoS",

            # SSRF
            "CWE-918": "SSRF",
        }

        return cwe_map.get(cwe_id)
