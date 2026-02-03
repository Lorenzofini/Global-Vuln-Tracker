# test_topics_now.py
import asyncio
import logging
from datetime import datetime, timezone
from telegram.ext import ExtBot

from src.config import load_environment_variables, load_configuration
from src.models import Vulnerability
from src.topic_dispatcher import dispatch_to_topics

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def run_test():
    print("🚀 Avvio test forzato dei Topic...")
    
    # 1. Carica configurazioni
    try:
        env = load_environment_variables()
        config = load_configuration()
        topics_config = config['settings']['topics']
        bot = ExtBot(token=env["TELEGRAM_BOT_TOKEN"])
    except Exception as e:
        print(f"❌ Errore caricamento config: {e}")
        return

    # 2. Crea una vulnerabilità finta (simuliamo una critica Microsoft)
    test_vuln = Vulnerability(
        id="CVE-2026-TEST-999",
        source="Test-System",
        title="CVE-2026-TEST-999: Vulnerabilità di test per verifica Topics",
        link="https://example.com",
        published_date=datetime.now(timezone.utc),
        description="Questa è una vulnerabilità di test generata per verificare la creazione dei topic.",
        cvss_score=9.8,  # Questo dovrebbe mandarlo nel topic "Critiche"
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        has_public_exploit=True
    )

    # 3. Dati grezzi per il vendor extractor (simuliamo NVD)
    raw_data = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{"criteria": "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"}]
            }]
        }]
    }

    print(f"📡 Invio messaggio di test al gruppo: {topics_config['main_chat_id']}")
    
    try:
        await dispatch_to_topics(
            vulnerability=test_vuln,
            raw_data=raw_data,
            bot=bot,
            config=topics_config
        )
        print("✅ Test completato! Controlla il tuo gruppo Telegram.")
        print("Dovresti vedere il topic 'Generale', 'Microsoft & Windows' e '🔥 CVE Critiche'.")
    except Exception as e:
        print(f"❌ Errore durante il dispatch: {e}")

if __name__ == "__main__":
    asyncio.run(run_test())