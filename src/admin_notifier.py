# src/admin_notifier.py
import os
import requests
import logging
import html

logger = logging.getLogger(__name__)


def send_admin_alert(message: str, critical: bool = False):
    admin_chat_id = os.getenv("ADMIN_CHAT_ID")
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")

    # logger.info(f"Tentativo di invio alert all'admin. CHAT_ID: {admin_chat_id}, TOKEN trovato: {'Sì' if bot_token else 'No'}")

    if not admin_chat_id or not bot_token:
        logger.warning("ADMIN_CHAT_ID non impostato. Impossibile inviare alert all'admin.")
        return

    prefix = "🚨 ERRORE CRITICO 🚨\n" if critical else "ℹ️ INFO BOT ℹ️\n"

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": admin_chat_id,
        "text": prefix + message,
        "parse_mode": "HTML"
    }

    try:
        response = requests.post(url, data=payload, timeout=10)
        if not response.ok:
            logger.error(f"Fallito l'invio dell'alert all'admin: {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Eccezione durante l'invio dell'alert all'admin: {e}")