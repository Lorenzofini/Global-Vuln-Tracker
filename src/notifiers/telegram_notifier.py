# src/notifiers/telegram_notifier.py
import logging
import time  # Importa il modulo time
import requests
from .base_notifier import BaseNotifier
from ..models import Vulnerability

logger = logging.getLogger(__name__)


class TelegramNotifier(BaseNotifier):
    """Implementazione del notificatore per Telegram."""

    def __init__(self, token: str, chat_id: str):
        if not token or not chat_id:
            raise ValueError("Token e Chat ID di Telegram non possono essere vuoti.")
        self.api_url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id

    def send(self, vulnerability: Vulnerability) -> bool:
        """Invia una vulnerabilità a un canale/chat Telegram con gestione del rate limiting."""
        message = vulnerability.to_telegram_message()
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': 'HTML',
            'disable_web_page_preview': False
        }

        try:
            response = requests.post(self.api_url, data=payload, timeout=10)

            # Se la richiesta fallisce, controlliamo se è per rate limiting
            if not response.ok:
                # Errore 429: Too Many Requests
                if response.status_code == 429:
                    error_data = response.json()
                    retry_after = error_data.get('parameters', {}).get('retry_after',
                                                                       5)  # Default a 5 sec se non specificato
                    logger.warning(f"Rate limit di Telegram raggiunto. Attendo per {retry_after} secondi...")
                    time.sleep(retry_after + 1)  # Aggiungo 1 secondo di margine

                    # Riprovo la richiesta una sola volta
                    logger.info("Riprovo l'invio della notifica...")
                    response = requests.post(self.api_url, data=payload, timeout=10)

            response.raise_for_status()  # Solleva un'eccezione per status code 4xx/5xx finali
            logger.info(f"Notifica per '{vulnerability.id}' inviata con successo a Telegram.")
            return True

        except requests.exceptions.RequestException as e:
            logger.error(f"Errore durante l'invio della notifica a Telegram per '{vulnerability.id}': {e}")
            if e.response is not None:
                logger.error(f"Dettagli errore Telegram: {e.response.text}")
            return False