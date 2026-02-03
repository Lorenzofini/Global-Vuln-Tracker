# src/notifiers/telegram_notifier.py
import logging
import time
import requests
from typing import Optional
from .base_notifier import BaseNotifier
from ..models import Vulnerability

logger = logging.getLogger(__name__)

class TelegramNotifier(BaseNotifier):
    """Implementazione del notificatore per Telegram, con supporto per i Topics."""

    def __init__(self, token: str, chat_id: str, message_thread_id: Optional[int] = None):
        if not token or not chat_id:
            raise ValueError("Token e Chat ID di Telegram non possono essere vuoti.")
        self.api_url = f"https://api.telegram.org/bot{token}/sendMessage"
        self.chat_id = chat_id
        self.message_thread_id = message_thread_id

    def send(self, vulnerability: Vulnerability) -> bool:
        """Invia una vulnerabilità a un canale/chat/topic Telegram."""
        message = vulnerability.to_telegram_message()
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': 'HTML',
            'disable_web_page_preview': False
        }
        if self.message_thread_id is not None:
            payload['message_thread_id'] = self.message_thread_id

        try:
            # ... (la logica di retry rimane identica a prima)
            response = requests.post(self.api_url, data=payload, timeout=15)
            if not response.ok and response.status_code == 429:
                # ...
                response = requests.post(self.api_url, data=payload, timeout=15)

            response.raise_for_status()
            logger.info(f"Notifica per '{vulnerability.id}' inviata con successo (Chat: {self.chat_id}, Topic: {self.message_thread_id}).")
            return True

        except requests.exceptions.RequestException as e:
            logger.error(f"Errore nell'invio a (Chat: {self.chat_id}, Topic: {self.message_thread_id}): {e}")
            if e.response is not None:
                logger.error(f"Dettagli errore Telegram: {e.response.text}")
            return False