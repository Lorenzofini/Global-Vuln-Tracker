# src/topic_dispatcher.py
import logging
import asyncio
from typing import Dict, Optional, Any, Set
from dataclasses import replace
from telegram.ext import ExtBot
from telegram.error import RetryAfter
from .models import Vulnerability
from .vendor_extractor import extract_smart_category
from .topic_manager import get_or_create_topic_id

logger = logging.getLogger(__name__)

async def dispatch_to_topics(vulnerability: Vulnerability, raw_data: Optional[Dict[str, Any]], bot: ExtBot, config: Dict[str, Any]):
    main_chat_id = config.get("main_chat_id")
    if not main_chat_id: return

    target_topic_names: Set[str] = set()
    
    # 1. LOGICA EXPLOIT (Priorità Massima)
    # Se la fonte è ExploitDB o se il flag exploit è attivo, va nel canale dedicato
    is_exploit = vulnerability.has_public_exploit or vulnerability.source.lower() == "exploitdb"
    
    if is_exploit:
        target_topic_names.add("🚨 EXPLOIT DISPONIBILI")

    # 2. Categorie Standard
    tags = extract_smart_category(vulnerability, raw_data)
    vendor_map = config.get("vendor_to_topic_name_map", {})
    for tag in tags:
        if tag in vendor_map:
            target_topic_names.add(vendor_map[tag])
        elif tag in ["Web Servers & CMS", "Browsers", "Databases", "Networking", "Virtualization & Cloud"]:
            target_topic_names.add(f"📂 {tag}")

    # 3. Gravità (Solo se non è già andato in Exploit, o per ridondanza se critico)
    score = vulnerability.cvss_score
    severity_map = config.get("severity_to_topic_name_map", {})
    if score and score >= 7.0:
        if score >= 9.0 and "critical" in severity_map:
            target_topic_names.add(severity_map["critical"])
        elif "high" in severity_map:
            target_topic_names.add(severity_map["high"])

    # Fallback se non ha categorie
    if not target_topic_names:
        target_topic_names.add(config.get("general_topic_name", "Generale"))

    # 4. Preparazione Messaggio
    v_tagged = replace(vulnerability, detected_tags=tags, has_public_exploit=is_exploit)
    message_text, reply_markup = v_tagged.get_ui_elements()

    # 5. Invio
    for topic_name in target_topic_names:
        thread_id = await get_or_create_topic_id(bot, main_chat_id, topic_name)
        # Notifica sonora solo se è un exploit o critico
        is_silent = not (is_exploit or (score and score >= 9.0))
        
        try:
            await bot.send_message(
                chat_id=main_chat_id,
                text=message_text,
                message_thread_id=thread_id,
                reply_markup=reply_markup,
                parse_mode='HTML',
                disable_notification=is_silent
            )
            await asyncio.sleep(0.5)
        except RetryAfter as e:
            await asyncio.sleep(e.retry_after + 1)
        except Exception as e:
            logger.error(f"Errore invio a {topic_name}: {e}")