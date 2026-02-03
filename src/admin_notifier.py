# src/admin_notifier.py
import os
import requests
import logging
import html

logger = logging.getLogger(__name__)

def send_admin_alert(message: str, critical: bool = False):
    admin_chat_id = os.getenv("ADMIN_CHAT_ID")
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")

    if not admin_chat_id or not bot_token:
        logger.warning("ADMIN_CHAT_ID o TOKEN non impostati. Alert saltato.")
        return

    prefix = "🚨 <b>ERRORE CRITICO</b> 🚨\n" if critical else "ℹ️ <b>INFO BOT</b>\n"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": admin_chat_id,
        "text": prefix + message,
        "parse_mode": "HTML"
    }

    try:
        # Timeout ridotto per non bloccare lo spegnimento
        response = requests.post(url, data=payload, timeout=5)
        if not response.ok:
            logger.error(f"Invio alert fallito: {response.text}")
    except Exception as e:
        # In fase di chiusura (KeyboardInterrupt), requests potrebbe fallire
        logger.debug(f"Impossibile inviare alert admin durante la chiusura: {e}")