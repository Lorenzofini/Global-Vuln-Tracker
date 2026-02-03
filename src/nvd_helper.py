# src/nvd_helper.py
import logging
import httpx
import asyncio
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def fetch_cve_details_async(cve_id: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Recupera i dettagli di un CVE in modo asincrono."""
    headers = {'apiKey': api_key} if api_key else {}
    params = {'cveId': cve_id}

    # Definiamo il tempo di attesa per rispettare il rate limit
    # Con API Key possiamo essere molto più aggressivi
    delay = 0.6 if api_key else 6.0

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.get(BASE_URL, headers=headers, params=params)
            
            # Rispettiamo il rate limit prima di restituire il risultato
            await asyncio.sleep(delay)

            if response.status_code != 200:
                return None

            data = response.json()
            if not data.get("vulnerabilities"):
                return None

            cve = data['vulnerabilities'][0]['cve']
            metrics = cve.get('metrics', {})

            cvss_score = None
            cvss_vector = None

            if 'cvssMetricV31' in metrics:
                m = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score, cvss_vector = m.get('baseScore'), m.get('vectorString')
            elif 'cvssMetricV30' in metrics:
                m = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score, cvss_vector = m.get('baseScore'), m.get('vectorString')

            if cvss_score is not None:
                logger.info(f"🚀 Arricchimento rapido per {cve_id}: {cvss_score}")
                return {"cvss_score": cvss_score, "cvss_vector": cvss_vector}

        except Exception as e:
            logger.error(f"Errore asincrono su {cve_id}: {e}")
    
    return None