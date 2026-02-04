import html
import re
import datetime
from datetime import timezone
from dataclasses import dataclass, field
from typing import List, Tuple
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

@dataclass(frozen=True, eq=True)
class Vulnerability:
    id: str
    source: str
    title: str
    link: str
    published_date: datetime.datetime
    description: str = ""
    cvss_score: float = None
    cvss_vector: str = None
    has_public_exploit: bool = False
    detected_tags: List[str] = field(default_factory=list)

    def _get_urgency_config(self) -> dict:
        """Strategia di urgenza basata su psicologia + data"""
        score = self.cvss_score or 0.0
        
        if self.has_public_exploit:
            return {
                "emoji": "🔴",
                "badge": "ACTIVE EXPLOIT",
                "action_verb": "VAI ALLA FONTE"
            }
        elif score >= 9.0:
            return {
                "emoji": "🔴",
                "badge": "CRITICAL SEVERITY",
                "action_verb": "VAI ALLA FONTE"
            }
        elif score >= 7.0:
            return {
                "emoji": "🟠",
                "badge": "HIGH SEVERITY",
                "action_verb": "VAI ALLA FONTE"
            }
        elif score >= 4.0:
            return {
                "emoji": "🟡",
                "badge": "MEDIUM SEVERITY",
                "action_verb": "VAI ALLA FONTE"
            }
        else:
            return {
                "emoji": "🔵",
                "badge": "LOW SEVERITY",
                "action_verb": "VAI ALLA FONTE"
            }

    def _format_score_visual(self) -> str:
        """Score visivo IMMEDIATO"""
        if not self.cvss_score:
            return "Non valutato"
        
        score = self.cvss_score
        filled = int(score)
        bar = "█" * filled + "░" * (10 - filled)
        return f"{bar} {score}/10"

    def _clean_source_name(self) -> str:
        """Nome fonte leggibile"""
        if "CISA" in self.source.upper():
            return "🏛️ CISA KEV"
        elif "NVD" in self.source.upper():
            return "🗂️ NVD"
        else:
            return f"📰 {self.source[:15]}"

    def _time_ago(self) -> str:
        """Human-readable time"""
        now = datetime.datetime.now(timezone.utc)
        
        pub_date = self.published_date
        if pub_date.tzinfo is None:
            pub_date = pub_date.replace(tzinfo=timezone.utc)
        
        diff = now - pub_date
        
        if diff.days == 0:
            hours = diff.seconds // 3600
            if hours == 0:
                return "🔥 APPENA PUBBLICATA"
            return f"🕐 {hours}h fa"
        elif diff.days == 1:
            return "📅 Ieri"
        elif diff.days < 7:
            return f"📅 {diff.days} giorni fa"
        else:
            return pub_date.strftime("%d/%m/%Y")

    def _clean_html_description(self, text: str) -> str:
        """Pulisce HTML dalla descrizione e formatta per Telegram"""
        if not text:
            return "Nessuna descrizione disponibile."
        
        # Rimuovi tutti i tag HTML
        text = re.sub(r'<[^>]+>', ' ', text)
        
        # Decodifica entità HTML (&nbsp; → spazio, ecc.)
        text = html.unescape(text)
        
        # Rimuovi spazi multipli
        text = re.sub(r'\s+', ' ', text)
        
        # Rimuovi spazi all'inizio/fine
        text = text.strip()
        
        return text

    def get_ui_elements(self) -> Tuple[str, InlineKeyboardMarkup]:
        urg = self._get_urgency_config()
        
        # HEADER: Solo emoji + badge
        header = (
            f"{urg['emoji']} <b>{urg['badge']}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━"
        )
        
        # CVE ID + Score
        hero = (
            f"\n<b>🆔 {self.id}</b>\n"
            f"📊 {self._format_score_visual()}\n"
        )
        
        # CVSS Vector (se presente)
        vector_line = ""
        if self.cvss_vector:
            vector_line = f"🧬 <code>{self.cvss_vector}</code>\n"
        
        # Titolo vulnerabilità (pulito da HTML)
        clean_title = self._clean_html_description(self.title)
        vuln_title = html.escape(clean_title[:120])
        if len(clean_title) > 120:
            vuln_title += "..."
        
        # Descrizione (pulita da HTML)
        clean_desc = self._clean_html_description(self.description)
        desc = html.escape(clean_desc[:300])
        if len(clean_desc) > 300:
            desc += "..."
        
        # Footer compatto
        footer = (
            f"\n━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📡 {self._clean_source_name()}  •  {self._time_ago()}"
        )
        
        # MESSAGGIO FINALE
        message = (
            f"{header}"
            f"{hero}"
            f"{vector_line}"
            f"\n💬 <b>{vuln_title}</b>\n\n"
            f"<i>{desc}</i>"
            f"{footer}"
        )
        
        # BOTTONI DIFFERENZIATI
        buttons = []

        search_query = self.id if self.id.startswith("CVE-") else f"{self.title[:50]}"
        
        # Prima riga: Fonte originale + Ricerca exploit
        row1 = [
            InlineKeyboardButton(
                f"📄 {urg['action_verb']}", 
                url=self.link
            ),
            InlineKeyboardButton(
                "🔍 Cerca Info",
                url=f"https://www.google.com/search?q={search_query}+vulnerability"
            )
        ]
        buttons.append(row1)

        if self.id.startswith("CVE-"):
            row2 = [
                InlineKeyboardButton(
                    "📚 NVD Database",
                    url=f"https://nvd.nist.gov/vuln/detail/{self.id}"
                ),
                InlineKeyboardButton(
                    "🔬 MITRE Info",
                    url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={self.id}"
                )
            ]
            buttons.append(row2)
        
        # Terza riga condizionale: se exploit pubblico
        if self.has_public_exploit:
            row3 = [
                InlineKeyboardButton(
                    "⚠️ Condividi Urgenza",
                    switch_inline_query=f"🚨 {self.id} - EXPLOIT PUBBLICO ATTIVO"
                )
            ]
            buttons.append(row3)
        
        return message, InlineKeyboardMarkup(buttons)