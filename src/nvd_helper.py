# src/nvd_helper.py
import logging
import requests
import time
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve_details(cve_id: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Recupera i dettagli di un singolo CVE dall'API di NVD.
    Restituisce un dizionario con score e vector, o None se non trovato.
    """
    logger.debug(f"Richiesta di arricchimento per {cve_id} a NVD...")

    headers = {'apiKey': api_key} if api_key else {}
    params = {'cveId': cve_id}

    try:
        response = requests.get(BASE_URL, headers=headers, params=params, timeout=15)
        # Pausa per rispettare il rate limit, anche per le singole richieste
        sleep_time = 0.6 if api_key else 6
        time.sleep(sleep_time)

        if not response.ok:
            logger.warning(f"Arricchimento NVD fallito per {cve_id}. Status: {response.status_code}")
            return None

        data = response.json()
        if not data.get("vulnerabilities"):
            logger.warning(f"Nessun dato trovato su NVD per {cve_id}.")
            return None

        cve = data['vulnerabilities'][0]['cve']

        cvss_score = None
        cvss_vector = None
        metrics = cve.get('metrics', {})

        if 'cvssMetricV31' in metrics:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')
        elif 'cvssMetricV30' in metrics:
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            cvss_score = cvss_data.get('baseScore')
            cvss_vector = cvss_data.get('vectorString')

        if cvss_score is not None:
            logger.info(f"Arricchimento per {cve_id} riuscito. Score: {cvss_score}")
            return {"cvss_score": cvss_score, "cvss_vector": cvss_vector}

    except requests.exceptions.RequestException as e:
        logger.error(f"Errore di rete durante l'arricchimento per {cve_id}: {e}")

    return None