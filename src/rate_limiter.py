# src/rate_limiter.py
import time
import logging
from collections import deque
from typing import Dict, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class RateLimiter:
    """
    Rate limiter intelligente per API esterne.
    Supporta limiti per finestra temporale (es: 50 req/30sec per NVD).
    """
    
    def __init__(self):
        # Storage delle richieste per API
        self._request_history: Dict[str, deque] = {}
        
        # Configurazione limiti per API
        self._limits = {
            "nvd": {"max_requests": 50, "window_seconds": 30},
            "github": {"max_requests": 100, "window_seconds": 60},
            "default": {"max_requests": 60, "window_seconds": 60}
        }
    
    def wait_if_needed(self, api_name: str) -> None:
        """
        Blocca l'esecuzione se necessario per rispettare i rate limits.
        
        Args:
            api_name: Nome dell'API (es: 'nvd', 'github')
        """
        api_name = api_name.lower()
        
        # Inizializza history se non esiste
        if api_name not in self._request_history:
            self._request_history[api_name] = deque()
        
        # Ottieni configurazione limiti
        config = self._limits.get(api_name, self._limits["default"])
        max_requests = config["max_requests"]
        window_seconds = config["window_seconds"]
        
        history = self._request_history[api_name]
        now = time.time()
        
        # Rimuovi richieste fuori dalla finestra temporale
        cutoff = now - window_seconds
        while history and history[0] < cutoff:
            history.popleft()
        
        # Se abbiamo raggiunto il limite, aspetta
        if len(history) >= max_requests:
            # Calcola quanto aspettare
            oldest_request = history[0]
            wait_time = window_seconds - (now - oldest_request) + 0.1  # +0.1 di buffer
            
            if wait_time > 0:
                logger.warning(
                    f"⏱️ Rate limit {api_name.upper()}: {len(history)}/{max_requests} richieste in {window_seconds}s. "
                    f"Attendo {wait_time:.1f}s..."
                )
                time.sleep(wait_time)
                
                # Ripulisci dopo l'attesa
                now = time.time()
                cutoff = now - window_seconds
                while history and history[0] < cutoff:
                    history.popleft()
        
        # Registra questa richiesta
        history.append(now)
    
    def get_stats(self, api_name: str) -> Dict:
        """Ritorna statistiche sull'uso dell'API"""
        api_name = api_name.lower()
        
        if api_name not in self._request_history:
            return {"requests": 0, "limit": self._limits.get(api_name, self._limits["default"])["max_requests"]}
        
        config = self._limits.get(api_name, self._limits["default"])
        history = self._request_history[api_name]
        now = time.time()
        cutoff = now - config["window_seconds"]
        
        # Conta richieste nella finestra attuale
        active_requests = sum(1 for t in history if t > cutoff)
        
        return {
            "requests": active_requests,
            "limit": config["max_requests"],
            "window_seconds": config["window_seconds"],
            "usage_percent": (active_requests / config["max_requests"]) * 100
        }


# Singleton globale
_rate_limiter = RateLimiter()

def get_rate_limiter() -> RateLimiter:
    """Ottieni l'istanza globale del rate limiter"""
    return _rate_limiter


# Esempio di integrazione in nvd_helper.py:
"""
from src.rate_limiter import get_rate_limiter

def enrich_from_nvd(cve_id: str) -> dict:
    rate_limiter = get_rate_limiter()
    
    # Aspetta se necessario prima della chiamata
    rate_limiter.wait_if_needed("nvd")
    
    # Ora fai la richiesta
    response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
    # ...
"""

# Esempio di integrazione in main.py per statistiche:
"""
from src.rate_limiter import get_rate_limiter

# Alla fine di ogni ciclo
rate_limiter = get_rate_limiter()
for api in ["nvd", "github"]:
    stats = rate_limiter.get_stats(api)
    logger.info(f"📊 {api.upper()}: {stats['requests']}/{stats['limit']} richieste ({stats['usage_percent']:.1f}%)")
"""