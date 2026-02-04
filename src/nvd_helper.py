# src/nvd_helper.py
import logging
import httpx
import asyncio
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def fetch_cve_details_async(cve_id: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Recupera i dettagli di un CVE in modo asincrono.
    
    IMPORTANTE: Il rate limiting è ora gestito dal RateLimiter globale in main.py,
    quindi questa funzione NON include più delay interni.
    """
    headers = {'apiKey': api_key} if api_key else {}
    params = {'cveId': cve_id}

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            response = await client.get(BASE_URL, headers=headers, params=params)
            
            if response.status_code != 200:
                logger.debug(f"NVD API returned {response.status_code} for {cve_id}")
                return None

            data = response.json()
            if not data.get("vulnerabilities"):
                logger.debug(f"No vulnerability data found for {cve_id}")
                return None

            cve = data['vulnerabilities'][0]['cve']
            metrics = cve.get('metrics', {})

            cvss_score = None
            cvss_vector = None

            # Priorità: CVSS v3.1 > v3.0 > v2.0
            if 'cvssMetricV31' in metrics:
                m = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score, cvss_vector = m.get('baseScore'), m.get('vectorString')
            elif 'cvssMetricV30' in metrics:
                m = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score, cvss_vector = m.get('baseScore'), m.get('vectorString')
            elif 'cvssMetricV2' in metrics:
                m = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = m.get('baseScore')
                cvss_vector = m.get('vectorString')

            if cvss_score is not None:
                logger.info(f"🚀 Arricchimento rapido per {cve_id}: {cvss_score}")
                return {"cvss_score": cvss_score, "cvss_vector": cvss_vector}
            else:
                logger.debug(f"No CVSS score available for {cve_id}")

        except httpx.TimeoutException:
            logger.warning(f"⏱️ Timeout per {cve_id}")
        except Exception as e:
            logger.error(f"❌ Errore asincrono su {cve_id}: {e}")
    
    return None