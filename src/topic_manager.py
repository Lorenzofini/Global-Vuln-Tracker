# src/topic_manager.py
import logging
import json
import os
import asyncio
from typing import Dict, Optional
from telegram.ext import ExtBot
from telegram.error import RetryAfter, TelegramError

logger = logging.getLogger(__name__)

CACHE_FILE = "topic_cache.json"
# Lock globale per impedire creazioni simultanee dello stesso topic
creation_lock = asyncio.Lock()

def load_cache() -> Dict[str, int]:
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Errore lettura cache topic: {e}")
            return {}
    return {}

def save_cache(cache: Dict[str, int]):
    try:
        with open(CACHE_FILE, "w", encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        logger.error(f"Errore salvataggio cache topic: {e}")

async def get_or_create_topic_id(bot: ExtBot, chat_id: str, topic_name: str) -> Optional[int]:
    """
    Recupera l'ID del topic usando un Lock per evitare duplicati in caso di invio massiccio.
    """
    if not topic_name:
        return None

    # 1. Controllo rapido fuori dal lock
    cache = load_cache()
    if topic_name in cache:
        return cache[topic_name]

    # 2. Se non è in cache, acquisiamo il Lock per creare il topic in modo atomico
    async with creation_lock:
        # Ricontrolliamo la cache dentro il lock (magari un altro task lo ha creato mentre aspettavamo)
        cache = load_cache()
        if topic_name in cache:
            return cache[topic_name]

        logger.info(f"🆕 Creazione del topic unico: '{topic_name}'...")
        
        for attempt in range(3):
            try:
                forum_topic = await bot.create_forum_topic(chat_id=chat_id, name=topic_name)
                topic_id = forum_topic.message_thread_id
                
                cache[topic_name] = topic_id
                save_cache(cache)
                
                logger.info(f"✅ Topic '{topic_name}' registrato con ID {topic_id}")
                return topic_id

            except RetryAfter as e:
                wait_time = e.retry_after + 1
                logger.warning(f"Flood limit! Attesa {wait_time}s per creare '{topic_name}'...")
                await asyncio.sleep(wait_time)
                
            except TelegramError as e:
                logger.error(f"Errore API Telegram per '{topic_name}': {e}")
                return None
            
    return None