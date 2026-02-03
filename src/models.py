# src/models.py
import html
import datetime
import re
import urllib.parse
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

    def get_ui_elements(self) -> Tuple[str, InlineKeyboardMarkup]:
        """Restituisce il messaggio e i pulsanti (sempre presenti)."""
        
        tags_prefix = "".join([f"[{t.upper()}] " for t in self.detected_tags[:2]])
        
        # Colori e Icone
        if self.cvss_score and self.cvss_score >= 9.0:
            status_icon, label = "🔴", "CRITICA"
        elif self.cvss_score and self.cvss_score >= 7.0:
            status_icon, label = "🟠", "ALTA"
        elif self.cvss_score and self.cvss_score >= 4.0:
            status_icon, label = "🟡", "MEDIA"
        else:
            status_icon, label = "⚪️", "BASSA/INFO"

        exploit_header = "🔥 <b>EXPLOIT PUBBLICO DISPONIBILE</b>\n" if self.has_public_exploit else ""
        
        clean_desc = html.escape(self.description or "Nessuna descrizione fornita.")
        if len(clean_desc) > 300:
            clean_desc = clean_desc[:297] + "..."

        message = (
            f"{exploit_header}"
            f"{status_icon} <b>LIVELLO {label}: {self.cvss_score or 'N/A'}</b>\n"
            f"<code>━━━━━━━━━━━━━━━</code>\n\n"
            f"📜 <b>{tags_prefix}{html.escape(self.title)}</b>\n\n"
            f"🆔 <b>ID:</b> <code>{html.escape(self.id[:30])}</code>\n"
            f"📖 <b>DESC:</b> <i>{clean_desc}</i>\n\n"
            f"🗓 {self.published_date.strftime('%d/%m/%Y')} | 📡 {html.escape(self.source)}"
        )

        # Costruzione dinamica della tastiera
        row1 = [InlineKeyboardButton("🌐 Fonte", url=self.link)]
        
        # 1. Prova a estrarre CVE da Titolo, ID o Descrizione
        full_text = f"{self.id} {self.title} {self.description}".upper()
        cve_match = re.search(r'CVE-\d{4}-\d+', full_text)
        
        if cve_match:
            cve_id = cve_match.group(0)
            row1.append(InlineKeyboardButton("🔍 Analizza NVD", url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"))
        else:
            # 2. Se non c'è il CVE, offriamo una ricerca rapida su Google
            search_query = urllib.parse.quote(self.title)
            row1.append(InlineKeyboardButton("🔎 Cerca Info", url=f"https://www.google.com/search?q={search_query}"))

        keyboard = InlineKeyboardMarkup([row1])
        
        return message, keyboard