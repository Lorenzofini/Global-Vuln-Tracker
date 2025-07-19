# src/sources/nvd_source.py
import re
import logging
import requests
import time
from datetime import datetime, timedelta, timezone
from typing import List
from .base_source import BaseSource
from ..models import Vulnerability
logger = logging.getLogger(__name__)


class NvdSource(BaseSource):
    """
    Gestisce la raccolta di vulnerabilità dalla API 2.0 di NVD.
    Recupera le CVE modificate di recente per rimanere aggiornato.
    """
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch(self) -> List[Vulnerability]:
        api_key = self.config.get('credentials', {}).get('nvd_api_key')
        headers = {'apiKey': api_key} if api_key else {}

        # Per evitare di scaricare l'intero database, cerchiamo le CVE modificate
        # nell'ultimo giorno. Questo è un buon compromesso per un check periodico.
        # L'API NVD ha un ritardo di pubblicazione, quindi un intervallo più ampio è più sicuro.
        fetch_since = self.config.get('fetch_since')
        # L'API NVD funziona meglio con un intervallo, non solo una data di inizio.
        # Cerchiamo dall'ultima data di esecuzione fino ad ora.
        start_date = fetch_since
        end_date = datetime.now(timezone.utc)

        start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%S.000Z')

        params = {
            'lastModStartDate': start_date_str,
            'lastModEndDate': end_date_str,
            'resultsPerPage': 2000
        }
        # logger.info(f"[{self.name}] Sto recuperando CVE modificate tra {start_date_str} e {end_date_str}")

        try:
            response = self._make_request(self.BASE_URL, headers=headers, params=params)
            data = response.json()
        except (ConnectionError, requests.exceptions.JSONDecodeError) as e:
            logger.error(f"[{self.name}] Errore nella richiesta all'API NVD: {e}")
            return []

        vulnerabilities = []
        for cve_item in data.get("vulnerabilities", []):
            try:
                cve = cve_item.get('cve')
                if not cve:
                    continue

                cve_id = cve.get("id")

                # metrics = cve.get('metrics', {})
                # logger.debug(f"[NVD DEBUG] CVE: {cve_id} | Dati metrici ricevuti: {metrics}")

                # Prendiamo la prima descrizione in inglese
                description = next((desc['value'] for desc in cve.get('descriptions', []) if desc['lang'] == 'en'),
                                   "No description available.")

                cvss_score = None
                cvss_vector = None

                # NVD fornisce i dati metrici, cerchiamo CVSS v3.1, altrimenti v3.0
                metrics = cve.get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString')
                elif 'cvssMetricV30' in metrics:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString')

                first_sentence = description.strip()

                match = re.search(r'\.\s|\.$', description)

                if match:
                    # Se troviamo una corrispondenza, tagliamo la stringa in quel punto.
                    # match.start() ci dà l'indice di inizio della corrispondenza (cioè dove si trova il '.')
                    first_sentence = description[:match.start() + 1]
                else:
                    # Se non troviamo un punto "di fine frase", usiamo il fallback della lunghezza.
                    first_sentence = (description[:120] + '...') if len(description) > 120 else description

                # Pulisci ulteriormente il risultato
                first_sentence = first_sentence.strip()

                # Costruisci il titolo finale
                title = f"{cve_id}: {first_sentence}"

                # Estraiamo il titolo dalla CVE, se non disponibile usiamo l'ID
                # Spesso non c'è un titolo formale, quindi usiamo l'ID come standard
                # title = f"{cve_id}"

                published_date_str = cve.get("published")
                published_date = datetime.fromisoformat(published_date_str)

                vuln = Vulnerability(
                    id=cve_id,
                    source=self.name,
                    title=title,
                    link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    published_date=published_date,
                    description=description,
                    cvss_score = cvss_score,
                    cvss_vector = cvss_vector,
                )
                vulnerabilities.append(vuln)
            except (KeyError, TypeError, ValueError) as e:
                logger.error(f"[{self.name}] Errore nel processare una CVE da NVD: {cve_id if 'cve_id' in locals() else 'ID sconosciuto'} - {e}", exc_info=True)

        # Pausa per rispettare il rate-limit, specialmente senza API key
        sleep_time = 0.6 if api_key else 6
        time.sleep(sleep_time)

        logger.info(f"[{self.name}] Trovate {len(vulnerabilities)} voci da NVD.")
        return vulnerabilities