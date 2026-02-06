# src/sources/cisa_kev_source.py
"""
CISA KEV (Known Exploited Vulnerabilities) Source
Versione 2.0 - Estrae anche knownRansomwareCampaignUse e requiredAction
"""
import logging
import requests
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional
from .base_source import BaseSource
from ..models import Vulnerability

logger = logging.getLogger(__name__)


class CisaKevSource(BaseSource):
    """
    Gestisce la raccolta di vulnerabilità dal catalogo CISA KEV
    (Known Exploited Vulnerabilities).

    NUOVI CAMPI ESTRATTI in v2.0:
    - knownRansomwareCampaignUse: "Known" se usato in campagne ransomware
    - requiredAction: Azione raccomandata da CISA
    - vendorProject: Vendor del prodotto vulnerabile
    - product: Nome del prodotto
    """

    def fetch(self) -> List[Tuple[Vulnerability, Optional[Dict[str, Any]]]]:
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
        ransomware_count = 0

        for entry in data.get("vulnerabilities", []):
            try:
                cve_id = entry.get("cveID")
                if not cve_id:
                    continue

                date_added_str = entry.get("dateAdded")
                # Converte la data stringa 'YYYY-MM-DD' in un oggetto datetime con timezone UTC
                published_date = datetime.strptime(date_added_str, "%Y-%m-%d")

                # Estrai vendor e prodotto per titolo più descrittivo
                vendor = entry.get("vendorProject", "Unknown")
                product = entry.get("product", "Unknown")
                vuln_name = entry.get("vulnerabilityName", "N/A")

                # Costruisci titolo più informativo
                if vendor != "Unknown" and product != "Unknown":
                    title = f"{cve_id}: {vendor} {product} - {vuln_name}"
                else:
                    title = f"{cve_id}: {vuln_name}"

                # Il link alla vulnerabilità su NVD è più informativo
                link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                # === NUOVI CAMPI v2.0 ===
                # Ransomware flag
                known_ransomware = entry.get("knownRansomwareCampaignUse") == "Known"
                if known_ransomware:
                    ransomware_count += 1

                # Required action da CISA
                required_action = entry.get("requiredAction", "")

                # CISA KEV = sempre exploit attivo (è il punto del catalogo)
                has_exploit = True

                vuln = Vulnerability(
                    id=cve_id,
                    source=self.name,
                    title=title,
                    link=link,
                    published_date=published_date,
                    description=entry.get('shortDescription', ''),
                    has_public_exploit=has_exploit,
                    known_ransomware=known_ransomware,
                    required_action=required_action
                )

                # Passa TUTTI i dati originali per elaborazione successiva
                # Questo permette a impact_analyzer di estrarre knownRansomwareCampaignUse
                raw_data = {
                    "cveID": cve_id,
                    "vendorProject": vendor,
                    "product": product,
                    "vulnerabilityName": vuln_name,
                    "dateAdded": date_added_str,
                    "shortDescription": entry.get('shortDescription', ''),
                    "requiredAction": required_action,
                    "dueDate": entry.get("dueDate"),
                    "knownRansomwareCampaignUse": entry.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": entry.get("notes", ""),
                    # Flag per identificare la fonte
                    "_source": "cisa_kev"
                }

                vulnerabilities.append((vuln, raw_data))

            except (KeyError, TypeError, ValueError) as e:
                logger.error(f"[{self.name}] Errore nel processare una voce di CISA KEV: {e}", exc_info=True)

        logger.info(
            f"[{self.name}] Trovate {len(vulnerabilities)} voci dal catalogo CISA KEV "
            f"({ransomware_count} con ransomware conosciuto)"
        )
        return vulnerabilities
