# src/sources/cisa_kev_source.py
import logging
import requests
from datetime import datetime, timezone
from typing import List
from .base_source import BaseSource
from ..models import Vulnerability

logger = logging.getLogger(__name__)


class CisaKevSource(BaseSource):
    """
    Gestisce la raccolta di vulnerabilità dal catalogo CISA KEV
    (Known Exploited Vulnerabilities).
    """

    def fetch(self) -> List[Vulnerability]:
        url = self.config.get("url")
        if not url:
            logger.error(f"[{self.name}] URL non specificato per CISA KEV.")
            return []

        logger.info(f"[{self.name}] Sto recuperando dati da: {url}")
        try:
            response = self._make_request(url)
            data = response.json()
        except (ConnectionError, requests.exceptions.JSONDecodeError) as e:
            logger.error(f"[{self.name}] Errore nel recuperare o parsare il JSON di CISA KEV: {e}")
            return []

        vulnerabilities = []
        for entry in data.get("vulnerabilities", []):
            try:
                cve_id = entry.get("cveID")
                if not cve_id:
                    continue

                date_added_str = entry.get("dateAdded")
                # Converte la data stringa 'YYYY-MM-DD' in un oggetto datetime con timezone UTC
                published_date = datetime.strptime(date_added_str, "%Y-%m-%d")

                # Il link alla vulnerabilità su NVD è più informativo
                link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                vuln = Vulnerability(
                    id=cve_id,  # Usiamo il CVE ID come identificatore unico
                    source=self.name,
                    title=f"{cve_id}: {entry.get('vulnerabilityName', 'N/A')}",
                    link=link,
                    published_date=published_date,
                    description=entry.get('shortDescription', '')
                )
                vulnerabilities.append((vuln, entry))
            except (KeyError, TypeError, ValueError) as e:
                logger.error(f"[{self.name}] Errore nel processare una voce di CISA KEV: {e}", exc_info=True)

        logger.info(f"[{self.name}] Trovate {len(vulnerabilities)} voci dal catalogo CISA KEV.")
        return vulnerabilities