# src/topic_dispatcher.py
"""
Topic Dispatcher 2.0 - Action-Based Routing
Sostituisce il multi-topic routing con un sistema basato su AZIONE richiesta.
Una CVE → Un topic.
"""
import logging
import asyncio
from typing import Dict, Optional, Any
from dataclasses import replace
from telegram.ext import ExtBot
from telegram.error import RetryAfter
from .models import Vulnerability
from .impact_analyzer import analyze_impact, get_action_topic_name, extract_patch_url, extract_cwe_ids
from .topic_manager import get_or_create_topic_id
from .card_generator import generate_card_for_vuln

logger = logging.getLogger(__name__)


def determine_action_topic(
    vulnerability: Vulnerability,
    raw_data: Optional[Dict[str, Any]]
) -> str:
    """
    Determina il topic di destinazione basato su URGENZA e AZIONE richiesta.

    LOGICA DI ROUTING:
    1. PATCH NOW (🔴): Exploit attivi, ransomware, CVSS 9+ con network attack
    2. PLAN THIS WEEK (🟠): CVSS 7-8.9, vulnerabilità importanti
    3. MONITOR (🟡): CVSS 4-6.9, rischio moderato
    4. INTEL BRIEFING (📰): News senza CVE
    5. DIGEST_QUEUE: Low priority, va nel digest settimanale

    Returns:
        String key per il topic (patch_now, plan_week, monitor, intel, digest_queue)
    """
    # Usa impact_analyzer per analisi completa
    analysis = analyze_impact(vulnerability, raw_data)
    return analysis.action_topic


def enrich_vulnerability_with_impact(
    vulnerability: Vulnerability,
    raw_data: Optional[Dict[str, Any]]
) -> Vulnerability:
    """
    Arricchisce la vulnerabilità con dati di impatto estratti da raw_data.
    Usato prima dell'invio del messaggio.
    """
    analysis = analyze_impact(vulnerability, raw_data)

    # Estrai dati aggiuntivi
    patch_url = extract_patch_url(raw_data)
    cwe_ids = extract_cwe_ids(raw_data)
    cwe_id = cwe_ids[0] if cwe_ids else None

    # Check ransomware flag
    known_ransomware = False
    required_action = None
    if raw_data:
        known_ransomware = raw_data.get("knownRansomwareCampaignUse") == "Known"
        required_action = raw_data.get("requiredAction")

    # Crea nuova vulnerabilità arricchita
    return replace(
        vulnerability,
        impact_tags=analysis.impact_tags,
        attack_type=analysis.attack_type,
        cwe_id=cwe_id,
        patch_url=patch_url,
        known_ransomware=known_ransomware,
        required_action=required_action,
        # Mantieni has_public_exploit se già presente, altrimenti verifica da analysis
        has_public_exploit=vulnerability.has_public_exploit or analysis.is_critical
    )


async def dispatch_to_topics(
    vulnerability: Vulnerability,
    raw_data: Optional[Dict[str, Any]],
    bot: ExtBot,
    config: Dict[str, Any],
    digest_queue: Optional[list] = None
):
    """
    Dispatcher principale - Invia la vulnerabilità al topic appropriato.

    NUOVO SISTEMA (action_based=true):
    - Una CVE va in UN solo topic basato su azione
    - Niente più duplicati in topic multipli

    LEGACY SYSTEM (action_based=false):
    - Mantiene la vecchia logica vendor-based per retrocompatibilità

    Args:
        vulnerability: La vulnerabilità da inviare
        raw_data: Dati grezzi dalla fonte (per estrazione CWE, patch URL, etc.)
        bot: Bot Telegram
        config: Configurazione topics
        digest_queue: Lista opzionale per accodare vulnerabilità low-priority
    """
    main_chat_id = config.get("main_chat_id")
    if not main_chat_id:
        logger.warning("main_chat_id non configurato, impossibile inviare messaggi")
        return

    # Check se usare nuovo sistema action-based
    use_action_based = config.get("action_based", True)

    if use_action_based:
        await _dispatch_action_based(vulnerability, raw_data, bot, config, main_chat_id, digest_queue)
    else:
        await _dispatch_legacy(vulnerability, raw_data, bot, config, main_chat_id)


async def _dispatch_action_based(
    vulnerability: Vulnerability,
    raw_data: Optional[Dict[str, Any]],
    bot: ExtBot,
    config: Dict[str, Any],
    main_chat_id: str,
    digest_queue: Optional[list] = None
):
    """
    NUOVO: Dispatch action-based (una CVE → un topic)
    Supporta invio con immagine banner se configurato.
    """
    # 1. Determina il topic di destinazione
    action_topic = determine_action_topic(vulnerability, raw_data)

    # 2. Se è low-priority, accoda per digest invece di inviare
    if action_topic == "digest_queue":
        if digest_queue is not None:
            digest_queue.append((vulnerability, raw_data))
            logger.debug(f"[{vulnerability.id}] Accodato per digest (low priority)")
        else:
            action_topic = "monitor"

    # 3. Skip se accodato per digest
    if action_topic == "digest_queue":
        return

    # 4. Arricchisci la vulnerabilità con dati di impatto
    enriched_vuln = enrich_vulnerability_with_impact(vulnerability, raw_data)

    # 5. Ottieni nome topic Telegram
    topic_name = get_action_topic_name(action_topic, config)

    # 6. Genera messaggio con la card appropriata
    message_text, reply_markup = enriched_vuln.get_ui_elements()

    # 7. Ottieni o crea il topic
    thread_id = await get_or_create_topic_id(bot, main_chat_id, topic_name)

    # 8. Determina se inviare notifica sonora
    is_silent = action_topic not in ["patch_now"]

    # 9. Genera immagine per CVE, testo per articoli
    is_cve = enriched_vuln.id.startswith("CVE-")

    # 10. Invia il messaggio
    try:
        if is_cve:
            # CVE → Genera immagine card
            try:
                card_image = generate_card_for_vuln(enriched_vuln)
                if card_image:
                    await bot.send_photo(
                        chat_id=main_chat_id,
                        photo=card_image,
                        message_thread_id=thread_id,
                        reply_markup=reply_markup,
                        disable_notification=is_silent
                    )
                else:
                    raise Exception("Card generation returned None")
            except Exception as img_err:
                # Fallback a testo se immagine fallisce
                logger.warning(f"Immagine fallita per {vulnerability.id}: {img_err}, uso testo")
                await bot.send_message(
                    chat_id=main_chat_id,
                    text=message_text,
                    message_thread_id=thread_id,
                    reply_markup=reply_markup,
                    parse_mode='HTML',
                    disable_notification=is_silent
                )
        else:
            # Articoli → Testo normale
            await bot.send_message(
                chat_id=main_chat_id,
                text=message_text,
                message_thread_id=thread_id,
                reply_markup=reply_markup,
                parse_mode='HTML',
                disable_notification=is_silent
            )

        logger.info(f"[{vulnerability.id}] → {topic_name}")
        await asyncio.sleep(0.3)

    except RetryAfter as e:
        logger.warning(f"Rate limit Telegram, attendo {e.retry_after}s")
        await asyncio.sleep(e.retry_after + 1)
        try:
            await bot.send_message(
                chat_id=main_chat_id,
                text=message_text,
                message_thread_id=thread_id,
                reply_markup=reply_markup,
                parse_mode='HTML',
                disable_notification=is_silent
            )
        except Exception as retry_err:
            logger.error(f"Errore retry invio {vulnerability.id}: {retry_err}")

    except Exception as e:
        logger.error(f"Errore invio {vulnerability.id} a {topic_name}: {e}")


async def _dispatch_legacy(
    vulnerability: Vulnerability,
    raw_data: Optional[Dict[str, Any]],
    bot: ExtBot,
    config: Dict[str, Any],
    main_chat_id: str
):
    """
    LEGACY: Dispatch vendor-based (manteniamo per retrocompatibilità)
    Una CVE può andare in multipli topic.
    """
    from .vendor_extractor import extract_smart_category

    target_topic_names = set()

    # 1. Logica exploit
    is_exploit = vulnerability.has_public_exploit or vulnerability.source.lower() == "exploitdb"
    if is_exploit:
        target_topic_names.add("🚨 EXPLOIT DISPONIBILI")

    # 2. Categorie vendor
    tags = extract_smart_category(vulnerability, raw_data)
    vendor_map = config.get("vendor_to_topic_name_map", {})
    for tag in tags:
        if tag in vendor_map:
            target_topic_names.add(vendor_map[tag])

    # 3. Gravità
    score = vulnerability.cvss_score
    severity_map = config.get("severity_to_topic_name_map", {})
    if score and score >= 7.0:
        if score >= 9.0 and "critical" in severity_map:
            target_topic_names.add(severity_map["critical"])
        elif "high" in severity_map:
            target_topic_names.add(severity_map["high"])

    # 4. Fallback
    if not target_topic_names:
        target_topic_names.add(config.get("general_topic_name", "Generale"))

    # 5. Prepara messaggio
    v_tagged = replace(vulnerability, detected_tags=tags, has_public_exploit=is_exploit)
    message_text, reply_markup = v_tagged.get_ui_elements()

    # 6. Invia a tutti i topic
    for topic_name in target_topic_names:
        thread_id = await get_or_create_topic_id(bot, main_chat_id, topic_name)
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


# === UTILITY FUNCTIONS ===

def get_topic_stats(vulnerabilities: list, config: Dict[str, Any]) -> Dict[str, int]:
    """
    Restituisce statistiche sui topic di destinazione per una lista di vulnerabilità.
    Utile per logging e debug.
    """
    stats = {
        "patch_now": 0,
        "plan_week": 0,
        "monitor": 0,
        "intel": 0,
        "digest_queue": 0
    }

    for vuln, raw_data in vulnerabilities:
        action = determine_action_topic(vuln, raw_data)
        if action in stats:
            stats[action] += 1

    return stats
