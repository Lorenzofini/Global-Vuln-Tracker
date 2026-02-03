# src/sources/nvd_source.py
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Tuple, Dict, Optional, Any
from .base_source import BaseSource
from ..models import Vulnerability

logger = logging.getLogger(__name__)

class NvdSource(BaseSource):
    def fetch(self) -> List[Tuple[Vulnerability, Optional[Dict[str, Any]]]]:
        api_key = self.credentials.get("nvd_api_key")
        
        # NVD 2.0 richiede il formato ISO 8601 ESTESO: YYYY-MM-DDTHH:mm:ss.SSS
        # Fondamentale: non deve esserci la 'Z' e i millisecondi sono caldamente consigliati.
        now = datetime.now(timezone.utc)
        
        # Sicurezza: NVD non accetta intervalli superiori a 120 giorni.
        # Se fetch_since è troppo vecchio, lo limitiamo a 90 giorni fa.
        limit_date = now - timedelta(days=90)
        start_date = self.fetch_since if self.fetch_since > limit_date else limit_date

        start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
        end_str = now.strftime('%Y-%m-%dT%H:%M:%S.000')
        
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Costruiamo i parametri. Nota: Non usiamo params di requests per le date 
        # perché a volte la codifica dei caratteri : manda in tilt NVD.
        # Costruiamo l'URL manualmente per sicurezza assoluta.
        full_url = f"{url}?lastModStartDate={start_str}&lastModEndDate={end_str}&resultsPerPage=50"
        
        headers = {"apiKey": api_key} if api_key else {}
        vulnerabilities = []

        try:
            # Usiamo _make_request della classe base
            response = self._make_request(full_url, headers=headers)
            data = response.json()
            
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id: continue

                # Estrazione CVSS
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

                desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "No description.")

                vuln = Vulnerability(
                    id=cve_id,
                    source=self.name,
                    title=f"{cve_id} - {desc[:80]}...",
                    link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published_date=datetime.fromisoformat(cve.get("published").replace('Z', '+00:00')),
                    description=desc,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector
                )
                vulnerabilities.append((vuln, item))
            
            logger.info(f"[{self.name}] Connessione riuscita. Scaricate {len(vulnerabilities)} voci.")

        except Exception as e:
            logger.error(f"[{self.name}] Errore critico. URL inviato: {full_url}")
            logger.error(f"[{self.name}] Dettaglio: {e}")

        return vulnerabilities