# src/main.py
import logging
from logging.handlers import RotatingFileHandler
import re
import asyncio
import datetime as dt
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import replace
from dotenv import load_dotenv

from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

from .config import load_configuration, load_environment_variables
from .models import Vulnerability
from .state_manager import StateManager
from .nvd_helper import fetch_cve_details_async
from .topic_dispatcher import dispatch_to_topics
from .deduplication_manager import DeduplicationManager  # NUOVO
from .rate_limiter import get_rate_limiter  # NUOVO

# --- LOGGING ---
log_handler = RotatingFileHandler("bot.log", maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[log_handler, logging.StreamHandler()])
logger = logging.getLogger(__name__)

BOT_STATS = {
    "start_time": datetime.now(), 
    "total_processed": 0, 
    "duplicates_removed": 0,  # NUOVO
    "last_check": None, 
    "errors": []
}
SEARCH_INDEX: List[Vulnerability] = []

from .sources import rss_source, cisa_kev_source, nvd_source, github_source, osv_source
SOURCE_HANDLERS = {
    "rss": rss_source.RssSource, 
    "cisa_kev": cisa_kev_source.CisaKevSource, 
    "nvd": nvd_source.NvdSource, 
    "github": github_source.GithubSource, 
    "osv": osv_source.OsvSource
}

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uptime = str(datetime.now() - BOT_STATS["start_time"]).split('.')[0]
    
    # NUOVO: Statistiche rate limiter
    rate_limiter = get_rate_limiter()
    nvd_stats = rate_limiter.get_stats("nvd")
    
    msg = (
        f"🤖 <b>STATUS DASHBOARD</b>\n━━━━━━━━━━━━━━━\n"
        f"🩺 <b>Health:</b> {'✅ OK' if not BOT_STATS['errors'] else '⚠️ Errore API'}\n"
        f"⏱ <b>Uptime:</b> {uptime}\n"
        f"📊 <b>Inviate:</b> {BOT_STATS['total_processed']}\n"
        f"🔄 <b>Duplicate Rimosse:</b> {BOT_STATS['duplicates_removed']}\n"  # NUOVO
        f"🗂 <b>Indice:</b> {len(SEARCH_INDEX)} voci\n"
        f"📡 <b>NVD API:</b> {nvd_stats['requests']}/{nvd_stats['limit']} ({nvd_stats['usage_percent']:.1f}%)\n"  # NUOVO
        f"━━━━━━━━━━━━━━━"
    )
    await update.message.reply_text(msg, parse_mode='HTML')

async def scanner_loop(application):
    env = load_environment_variables()
    config = load_configuration()
    state_manager = StateManager()
    
    while True:
        try:
            start_date = datetime.strptime(config['settings']['start_date'], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            fetch_since = state_manager.last_successful_run or start_date
            
            # === FASE 1: RACCOLTA DA TUTTE LE FONTI ===
            logger.info("🔍 Inizio raccolta da tutte le fonti...")
            all_collected = []
            
            for s_cfg in config.get('sources', []):
                if not s_cfg.get('enabled'): 
                    continue
                
                handler_cls = SOURCE_HANDLERS.get(s_cfg['type'])
                if handler_cls:
                    src = handler_cls(
                        name=s_cfg['name'],
                        type=s_cfg['type'],
                        enabled=s_cfg.get('enabled', True),
                        fetch_since=fetch_since,
                        credentials={
                            'nvd_api_key': env.get('NVD_API_KEY'),
                            'github_token': env.get('GITHUB_TOKEN')
                        },
                        **{k: v for k, v in s_cfg.items() if k not in ['name', 'type', 'enabled']}
                    )
                    all_collected.extend(src.fetch())
            
            logger.info(f"📦 Raccolte {len(all_collected)} vulnerabilità totali da tutte le fonti")
            
            # === FASE 2: DEDUPLICAZIONE ===
            logger.info("🔄 Avvio deduplicazione intelligente...")
            deduplicated = DeduplicationManager.deduplicate(all_collected)
            duplicates_count = len(all_collected) - len(deduplicated)
            BOT_STATS["duplicates_removed"] += duplicates_count
            
            if duplicates_count > 0:
                logger.info(f"✅ Rimosse {duplicates_count} duplicazioni, mantenute {len(deduplicated)} uniche")
            
            # === FASE 3: FILTRO STATE (solo le nuove) ===
            to_process = [item for item in deduplicated if not state_manager.is_processed(item[0].id)]
            logger.info(f"🆕 {len(to_process)} vulnerabilità nuove da processare")

            if to_process:
                # === FASE 4: ARRICCHIMENTO CON RATE LIMITING ===
                logger.info("🚀 Inizio arricchimento con rate limiting NVD...")
                
                for i in range(0, len(to_process), 5):
                    chunk = to_process[i:i+5]
                    results = await asyncio.gather(*[enrich_task(item, env.get('NVD_API_KEY')) for item in chunk])
                    
                    # === FASE 5: INVIO MESSAGGI ===
                    for v_en, r_raw in results:
                        await dispatch_to_topics(v_en, r_raw, application.bot, config['settings']['topics'])
                        state_manager.add_processed(v_en.id)
                        if v_en not in SEARCH_INDEX: 
                            SEARCH_INDEX.append(v_en)
                        BOT_STATS["total_processed"] += 1
                    
                    state_manager.save()
                
                logger.info(f"✅ Processate e inviate {len(to_process)} nuove vulnerabilità")
            else:
                logger.info("ℹ️ Nessuna nuova vulnerabilità da processare")

            # === FASE 6: STATISTICHE FINALI ===
            rate_limiter = get_rate_limiter()
            for api_name in ["nvd"]:
                stats = rate_limiter.get_stats(api_name)
                logger.info(
                    f"📊 {api_name.upper()}: {stats['requests']}/{stats['limit']} richieste "
                    f"({stats['usage_percent']:.1f}% utilizzo)"
                )
            
            state_manager.update_last_run_time(datetime.now(timezone.utc))
            
        except Exception as e:
            logger.error(f"❌ Errore scanner: {e}", exc_info=True)
            BOT_STATS["errors"].append(str(e))
        
        # Attendi prima del prossimo ciclo
        interval = config['settings']['polling_interval_minutes'] * 60
        logger.info(f"⏸️ Attesa {config['settings']['polling_interval_minutes']} minuti prima del prossimo ciclo...")
        await asyncio.sleep(interval)

async def enrich_task(item, key):
    """Arricchisce una vulnerabilità con dati NVD usando rate limiting"""
    v, r = item
    if v.cvss_score: 
        return v, r
    
    # Cerca CVE ID nel titolo o ID
    cve = re.search(r'CVE-\d{4}-\d+', (v.id + v.title).upper())
    if cve:
        # NUOVO: Usa rate limiter prima di chiamare NVD
        rate_limiter = get_rate_limiter()
        rate_limiter.wait_if_needed("nvd")
        
        details = await fetch_cve_details_async(cve.group(0), key)
        if details: 
            return replace(
                v, 
                cvss_score=details['cvss_score'], 
                cvss_vector=details['cvss_vector']
            ), r
    
    return v, r

async def post_init(application):
    """Avvia lo scanner dopo che l'app è pronta."""
    asyncio.create_task(scanner_loop(application))

if __name__ == "__main__":
    load_dotenv()
    env = load_environment_variables()
    app = ApplicationBuilder().token(env["TELEGRAM_BOT_TOKEN"]).post_init(post_init).build()
    app.add_handler(CommandHandler("status", status_command))
    logger.info("🚀 Sistema avviato. Monitoraggio in corso...")
    app.run_polling()