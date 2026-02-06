# src/digest_manager.py
"""
Digest Manager - Gestisce il Weekly Digest e le vulnerabilità low-priority
"""
import json
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from collections import Counter
from dataclasses import dataclass, asdict
from telegram.ext import ExtBot

from .models import Vulnerability, create_digest_card
from .topic_manager import get_or_create_topic_id
from .impact_analyzer import analyze_impact, extract_smart_category

logger = logging.getLogger(__name__)

# File per persistere la coda digest
DIGEST_QUEUE_FILE = Path("digest_queue.json")
DIGEST_STATS_FILE = Path("digest_stats.json")


@dataclass
class WeeklyStats:
    """Statistiche settimanali per il digest"""
    week_number: int
    year: int
    start_date: str
    end_date: str
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    exploit_count: int = 0
    ransomware_count: int = 0
    vendor_counts: Dict[str, int] = None
    highlights: List[Dict[str, str]] = None

    def __post_init__(self):
        if self.vendor_counts is None:
            self.vendor_counts = {}
        if self.highlights is None:
            self.highlights = []


class DigestManager:
    """
    Gestisce la coda delle vulnerabilità low-priority e genera il digest settimanale.

    Funzionalità:
    - Accoda vulnerabilità low-priority invece di inviarle subito
    - Traccia statistiche per il digest
    - Genera il Weekly Digest ogni domenica
    - Persiste la coda su disco
    """

    def __init__(self):
        self.queue: List[Tuple[Dict, Dict]] = []  # (vuln_dict, raw_data)
        self.current_stats: Optional[WeeklyStats] = None
        self._load_queue()
        self._load_or_create_stats()

    def _load_queue(self):
        """Carica la coda dal file"""
        if DIGEST_QUEUE_FILE.exists():
            try:
                with open(DIGEST_QUEUE_FILE, 'r', encoding='utf-8') as f:
                    self.queue = json.load(f)
                logger.info(f"[DigestManager] Caricati {len(self.queue)} elementi dalla coda")
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"[DigestManager] Errore caricamento coda: {e}")
                self.queue = []
        else:
            self.queue = []

    def _save_queue(self):
        """Salva la coda su file"""
        try:
            with open(DIGEST_QUEUE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.queue, f, ensure_ascii=False, indent=2, default=str)
        except IOError as e:
            logger.error(f"[DigestManager] Errore salvataggio coda: {e}")

    def _load_or_create_stats(self):
        """Carica o crea statistiche per la settimana corrente"""
        now = datetime.now(timezone.utc)
        week_num = now.isocalendar()[1]
        year = now.year

        if DIGEST_STATS_FILE.exists():
            try:
                with open(DIGEST_STATS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if data.get("week_number") == week_num and data.get("year") == year:
                        self.current_stats = WeeklyStats(**data)
                        return
            except (json.JSONDecodeError, IOError, TypeError):
                pass

        # Crea nuove statistiche per questa settimana
        week_start = now - timedelta(days=now.weekday())
        week_end = week_start + timedelta(days=6)

        self.current_stats = WeeklyStats(
            week_number=week_num,
            year=year,
            start_date=week_start.strftime("%b %d"),
            end_date=week_end.strftime("%b %d")
        )

    def _save_stats(self):
        """Salva le statistiche su file"""
        if self.current_stats:
            try:
                with open(DIGEST_STATS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(asdict(self.current_stats), f, ensure_ascii=False, indent=2)
            except IOError as e:
                logger.error(f"[DigestManager] Errore salvataggio stats: {e}")

    def add_to_queue(self, vulnerability: Vulnerability, raw_data: Optional[Dict] = None):
        """
        Aggiunge una vulnerabilità alla coda del digest.
        Usato per vulnerabilità low-priority che non meritano un messaggio immediato.
        """
        # Serializza la vulnerabilità (dataclass frozen non è direttamente serializzabile)
        vuln_dict = {
            "id": vulnerability.id,
            "source": vulnerability.source,
            "title": vulnerability.title,
            "link": vulnerability.link,
            "published_date": vulnerability.published_date.isoformat(),
            "description": vulnerability.description,
            "cvss_score": vulnerability.cvss_score,
            "cvss_vector": vulnerability.cvss_vector,
            "has_public_exploit": vulnerability.has_public_exploit,
            "cwe_id": vulnerability.cwe_id,
            "attack_type": vulnerability.attack_type,
            "known_ransomware": vulnerability.known_ransomware,
        }

        self.queue.append((vuln_dict, raw_data or {}))
        self._save_queue()

        # Aggiorna statistiche
        self._update_stats(vulnerability, raw_data)

    def _update_stats(self, vulnerability: Vulnerability, raw_data: Optional[Dict]):
        """Aggiorna le statistiche settimanali"""
        if not self.current_stats:
            self._load_or_create_stats()

        self.current_stats.total_vulns += 1

        # Conta per severità
        score = vulnerability.cvss_score or 0
        if score >= 9.0:
            self.current_stats.critical_count += 1
        elif score >= 7.0:
            self.current_stats.high_count += 1
        elif score >= 4.0:
            self.current_stats.medium_count += 1
        else:
            self.current_stats.low_count += 1

        # Conta exploit e ransomware
        if vulnerability.has_public_exploit:
            self.current_stats.exploit_count += 1
        if vulnerability.known_ransomware:
            self.current_stats.ransomware_count += 1

        # Estrai vendor per statistiche
        categories = extract_smart_category(vulnerability, raw_data)
        for cat in categories:
            cat_lower = cat.lower()
            if cat_lower in ["microsoft", "google", "apple", "linux", "cisco", "vmware", "apache"]:
                self.current_stats.vendor_counts[cat.capitalize()] = \
                    self.current_stats.vendor_counts.get(cat.capitalize(), 0) + 1

        # Aggiungi a highlights se è critico
        if score >= 9.0 or vulnerability.has_public_exploit:
            desc = vulnerability.description[:60] if vulnerability.description else vulnerability.title[:60]
            self.current_stats.highlights.append({
                "cve_id": vulnerability.id,
                "description": desc
            })
            # Mantieni solo i top 5
            self.current_stats.highlights = self.current_stats.highlights[:5]

        self._save_stats()

    def update_stats_for_sent(self, vulnerability: Vulnerability, raw_data: Optional[Dict]):
        """
        Aggiorna le statistiche anche per vulnerabilità inviate normalmente (non in coda).
        Chiamato dal main loop dopo ogni invio.
        """
        self._update_stats(vulnerability, raw_data)

    def get_queue_count(self) -> int:
        """Ritorna il numero di elementi in coda"""
        return len(self.queue)

    def clear_queue(self):
        """Svuota la coda dopo l'invio del digest"""
        self.queue = []
        self._save_queue()

    def reset_stats(self):
        """Reset delle statistiche per nuova settimana"""
        now = datetime.now(timezone.utc)
        week_num = now.isocalendar()[1]
        year = now.year
        week_start = now - timedelta(days=now.weekday())
        week_end = week_start + timedelta(days=6)

        self.current_stats = WeeklyStats(
            week_number=week_num,
            year=year,
            start_date=week_start.strftime("%b %d"),
            end_date=week_end.strftime("%b %d")
        )
        self._save_stats()

    async def send_weekly_digest(
        self,
        bot: ExtBot,
        config: Dict[str, Any]
    ) -> bool:
        """
        Genera e invia il Weekly Digest.

        Args:
            bot: Bot Telegram
            config: Configurazione topics

        Returns:
            True se inviato con successo, False altrimenti
        """
        if not self.current_stats:
            logger.warning("[DigestManager] Nessuna statistica disponibile per il digest")
            return False

        main_chat_id = config.get("main_chat_id")
        if not main_chat_id:
            logger.error("[DigestManager] main_chat_id non configurato")
            return False

        # Prepara dati per la card
        stats = self.current_stats

        # Top vendors ordinati
        top_vendors = sorted(
            stats.vendor_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:4]

        # Se non ci sono vendor, usa placeholder
        if not top_vendors:
            top_vendors = [("Various", stats.total_vulns)]

        # Highlights
        highlights = [
            (h["cve_id"], h["description"])
            for h in stats.highlights[:3]
        ]

        # Se non ci sono highlights, usa messaggio default
        if not highlights:
            highlights = [("N/A", "No critical vulnerabilities this week")]

        # Genera la card
        message_text, reply_markup = create_digest_card(
            week_number=stats.week_number,
            year=stats.year,
            date_range=f"{stats.start_date} - {stats.end_date}",
            total_vulns=stats.total_vulns,
            critical_count=stats.critical_count,
            high_count=stats.high_count,
            medium_count=stats.medium_count,
            low_count=stats.low_count,
            exploit_count=stats.exploit_count,
            ransomware_count=stats.ransomware_count,
            top_vendors=top_vendors,
            highlights=highlights
        )

        # Ottieni topic per digest
        action_topics = config.get("action_topics", {})
        digest_topic_name = action_topics.get("digest", "📊 Weekly Digest")

        try:
            thread_id = await get_or_create_topic_id(bot, main_chat_id, digest_topic_name)

            await bot.send_message(
                chat_id=main_chat_id,
                text=message_text,
                message_thread_id=thread_id,
                reply_markup=reply_markup,
                parse_mode='HTML',
                disable_notification=False  # Notifica per il digest
            )

            logger.info(
                f"[DigestManager] Weekly Digest inviato: "
                f"{stats.total_vulns} vulns, {stats.exploit_count} exploits"
            )

            # Svuota coda e resetta stats per prossima settimana
            self.clear_queue()
            self.reset_stats()

            return True

        except Exception as e:
            logger.error(f"[DigestManager] Errore invio digest: {e}")
            return False

    def should_send_digest(self, config: Dict[str, Any]) -> bool:
        """
        Verifica se è il momento di inviare il digest.
        Basato sulla configurazione in config.yaml.
        """
        digest_config = config.get("digest", {})
        if not digest_config.get("enabled", True):
            return False

        now = datetime.now(timezone.utc)

        # Default: domenica alle 10:00
        target_day = digest_config.get("day_of_week", 6)  # 0=Mon, 6=Sun
        target_hour = digest_config.get("hour", 10)
        target_minute = digest_config.get("minute", 0)

        if now.weekday() != target_day:
            return False

        if now.hour != target_hour:
            return False

        # Check minuti (con tolleranza di 5 minuti)
        if abs(now.minute - target_minute) > 5:
            return False

        return True


# Singleton per accesso globale
_digest_manager: Optional[DigestManager] = None


def get_digest_manager() -> DigestManager:
    """Ritorna l'istanza singleton del DigestManager"""
    global _digest_manager
    if _digest_manager is None:
        _digest_manager = DigestManager()
    return _digest_manager
