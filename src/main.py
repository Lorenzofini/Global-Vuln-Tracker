# src/main.py
"""
Global-Vuln-Tracker 2.0 - Security Intelligence Hub
Main entry point with action-based topic routing
"""
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
from .topic_dispatcher import dispatch_to_topics, get_topic_stats, determine_action_topic
from .deduplication_manager import DeduplicationManager
from .rate_limiter import get_rate_limiter
from .digest_manager import get_digest_manager

# --- LOGGING ---
log_handler = RotatingFileHandler("bot.log", maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[log_handler, logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

BOT_STATS = {
    "start_time": datetime.now(),
    "total_processed": 0,
    "duplicates_removed": 0,
    "last_check": None,
    "errors": [],
    # Nuove statistiche v2.0
    "by_action_topic": {
        "patch_now": 0,
        "plan_week": 0,
        "monitor": 0,
        "intel": 0,
        "digest_queue": 0
    }
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
    """Comando /status - Mostra statistiche del bot"""
    uptime = str(datetime.now() - BOT_STATS["start_time"]).split('.')[0]

    # Statistiche rate limiter
    rate_limiter = get_rate_limiter()
    nvd_stats = rate_limiter.get_stats("nvd")

    # Statistiche digest
    digest_mgr = get_digest_manager()
    digest_queue = digest_mgr.get_queue_count()

    # Statistiche per action topic
    action_stats = BOT_STATS["by_action_topic"]

    msg = (
        f"🤖 <b>STATUS DASHBOARD v2.0</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🩺 <b>Health:</b> {'✅ OK' if not BOT_STATS['errors'] else '⚠️ Errore'}\n"
        f"⏱ <b>Uptime:</b> {uptime}\n"
        f"\n📊 <b>STATISTICHE INVIO</b>\n"
        f"  📨 Totali: {BOT_STATS['total_processed']}\n"
        f"  🔄 Duplicati rimossi: {BOT_STATS['duplicates_removed']}\n"
        f"\n🎯 <b>PER ACTION TOPIC</b>\n"
        f"  🔴 PATCH NOW: {action_stats['patch_now']}\n"
        f"  🟠 PLAN WEEK: {action_stats['plan_week']}\n"
        f"  🟡 MONITOR: {action_stats['monitor']}\n"
        f"  📰 INTEL: {action_stats['intel']}\n"
        f"  📊 In Digest Queue: {digest_queue}\n"
        f"\n📡 <b>API USAGE</b>\n"
        f"  NVD: {nvd_stats['requests']}/{nvd_stats['limit']} ({nvd_stats['usage_percent']:.1f}%)\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    await update.message.reply_text(msg, parse_mode='HTML')


async def digest_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Comando /digest - Forza l'invio del weekly digest"""
    config = load_configuration()
    digest_mgr = get_digest_manager()

    await update.message.reply_text("📊 Generazione digest in corso...")

    # Usa il bot dal context
    bot = context.application.bot
    success = await digest_mgr.send_weekly_digest(bot, config['settings']['topics'])

    if success:
        await update.message.reply_text("✅ Weekly Digest inviato con successo!")
    else:
        await update.message.reply_text("❌ Errore nell'invio del digest. Controlla i log.")


async def topics_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Comando /topics - Mostra info sui topic action-based"""
    msg = (
        "🎯 <b>ACTION-BASED TOPICS</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🔴 <b>PATCH NOW</b>\n"
        "   Azione immediata richiesta\n"
        "   • Exploit attivi\n"
        "   • Ransomware\n"
        "   • CVSS 9+ con network attack\n\n"
        "🟠 <b>PLAN THIS WEEK</b>\n"
        "   Da pianificare questa settimana\n"
        "   • CVSS 7-8.9\n"
        "   • Vulnerabilità importanti\n\n"
        "🟡 <b>MONITOR</b>\n"
        "   Tieni d'occhio\n"
        "   • CVSS 4-6.9\n"
        "   • Rischio moderato\n\n"
        "📰 <b>INTEL BRIEFING</b>\n"
        "   News e articoli\n"
        "   • Senza CVE specifico\n"
        "   • Trend e campagne\n\n"
        "📊 <b>WEEKLY DIGEST</b>\n"
        "   Riepilogo settimanale\n"
        "   • Ogni domenica\n"
        "   • Include low-priority\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    await update.message.reply_text(msg, parse_mode='HTML')


async def scanner_loop(application):
    """
    Main scanner loop - Raccoglie, deduplica, arricchisce e invia vulnerabilità.

    Pipeline v2.0:
    1. Raccolta da tutte le fonti
    2. Deduplicazione intelligente
    3. Filtro state (skip già processate)
    4. Arricchimento NVD con rate limiting
    5. Dispatch action-based (una CVE → un topic)
    6. Weekly digest check
    7. Statistiche
    """
    env = load_environment_variables()
    config = load_configuration()
    state_manager = StateManager()
    digest_mgr = get_digest_manager()

    # Coda per vulnerabilità low-priority (vanno nel digest)
    digest_queue: List[Tuple[Vulnerability, Optional[Dict]]] = []

    while True:
        try:
            start_date = datetime.strptime(
                config['settings']['start_date'], "%Y-%m-%d"
            ).replace(tzinfo=timezone.utc)
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

            logger.info(f"📦 Raccolte {len(all_collected)} vulnerabilità totali")

            # === FASE 2: DEDUPLICAZIONE ===
            logger.info("🔄 Avvio deduplicazione intelligente...")
            deduplicated = DeduplicationManager.deduplicate(all_collected)
            duplicates_count = len(all_collected) - len(deduplicated)
            BOT_STATS["duplicates_removed"] += duplicates_count

            if duplicates_count > 0:
                logger.info(f"✅ Rimosse {duplicates_count} duplicazioni")

            # === FASE 3: FILTRO STATE ===
            to_process = [
                item for item in deduplicated
                if not state_manager.is_processed(item[0].id)
            ]
            logger.info(f"🆕 {len(to_process)} vulnerabilità nuove")

            if to_process:
                # Log statistiche topic prima dell'invio
                topic_stats = get_topic_stats(to_process, config['settings']['topics'])
                logger.info(
                    f"📊 Distribuzione: PATCH_NOW={topic_stats['patch_now']}, "
                    f"PLAN_WEEK={topic_stats['plan_week']}, MONITOR={topic_stats['monitor']}, "
                    f"INTEL={topic_stats['intel']}, DIGEST={topic_stats['digest_queue']}"
                )

                # === FASE 4: ARRICCHIMENTO CON RATE LIMITING ===
                logger.info("🚀 Inizio arricchimento e invio...")

                for i in range(0, len(to_process), 5):
                    chunk = to_process[i:i+5]
                    results = await asyncio.gather(*[
                        enrich_task(item, env.get('NVD_API_KEY'))
                        for item in chunk
                    ])

                    # === FASE 5: DISPATCH ACTION-BASED ===
                    for v_en, r_raw in results:
                        await dispatch_to_topics(
                            v_en, r_raw,
                            application.bot,
                            config['settings']['topics'],
                            digest_queue=digest_queue
                        )

                        # Aggiorna state
                        state_manager.add_processed(v_en.id)

                        # Aggiorna statistiche digest (anche per inviate normalmente)
                        digest_mgr.update_stats_for_sent(v_en, r_raw)

                        # Aggiorna search index
                        if v_en not in SEARCH_INDEX:
                            SEARCH_INDEX.append(v_en)

                        BOT_STATS["total_processed"] += 1

                        # Aggiorna stats per action topic
                        action = determine_action_topic(v_en, r_raw)
                        if action in BOT_STATS["by_action_topic"]:
                            BOT_STATS["by_action_topic"][action] += 1

                    state_manager.save()

                # Processa coda digest (aggiungi a digest manager)
                for v, r in digest_queue:
                    digest_mgr.add_to_queue(v, r)
                digest_queue.clear()

                logger.info(f"✅ Processate {len(to_process)} vulnerabilità")
            else:
                logger.info("ℹ️ Nessuna nuova vulnerabilità")

            # === FASE 6: CHECK WEEKLY DIGEST ===
            if digest_mgr.should_send_digest(config['settings']):
                logger.info("📊 È ora del Weekly Digest!")
                await digest_mgr.send_weekly_digest(
                    application.bot,
                    config['settings']['topics']
                )

            # === FASE 7: STATISTICHE FINALI ===
            rate_limiter = get_rate_limiter()
            for api_name in ["nvd"]:
                stats = rate_limiter.get_stats(api_name)
                logger.info(
                    f"📊 {api_name.upper()}: {stats['requests']}/{stats['limit']} "
                    f"({stats['usage_percent']:.1f}%)"
                )

            state_manager.update_last_run_time(datetime.now(timezone.utc))
            BOT_STATS["last_check"] = datetime.now()

        except Exception as e:
            logger.error(f"❌ Errore scanner: {e}", exc_info=True)
            BOT_STATS["errors"].append(str(e))
            # Mantieni solo ultimi 10 errori
            BOT_STATS["errors"] = BOT_STATS["errors"][-10:]

        # Attendi prima del prossimo ciclo
        interval = config['settings']['polling_interval_minutes'] * 60
        logger.info(
            f"⏸️ Attesa {config['settings']['polling_interval_minutes']} minuti..."
        )
        await asyncio.sleep(interval)


async def enrich_task(item, key):
    """Arricchisce una vulnerabilità con dati NVD usando rate limiting"""
    v, r = item
    if v.cvss_score:
        return v, r

    # Cerca CVE ID nel titolo o ID
    cve = re.search(r'CVE-\d{4}-\d+', (v.id + v.title).upper())
    if cve:
        # Usa rate limiter prima di chiamare NVD
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

    # Comandi
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("digest", digest_command))
    app.add_handler(CommandHandler("topics", topics_command))

    logger.info("🚀 Global-Vuln-Tracker 2.0 avviato. Action-Based Topics attivi.")
    app.run_polling()
