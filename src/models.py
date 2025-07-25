# src/models.py
import html
import datetime
from dataclasses import dataclass


@dataclass(frozen=True, eq=True)
class Vulnerability:
    """
    Rappresenta una singola vulnerabilità in modo standardizzato,
    indipendentemente dalla fonte.
    'frozen=True' la rende immutabile e quindi utilizzabile in un set.
    """
    id: str
    source: str
    title: str
    link: str
    published_date: datetime.datetime
    description: str = ""
    cvss_score: float = None
    cvss_vector: str = None
    has_public_exploit: bool = False

    def __str__(self):
        return f"[{self.source}] {self.title}"

    def to_telegram_message(self) -> str:
        """Formatta la vulnerabilità come messaggio finale per Telegram in HTML."""

        # 1. Definisci etichette e emoji in base alla gravità
        header_text = "🚨 AVVISO DI SICUREZZA"

        if self.cvss_score is not None:
            if self.cvss_score >= 9.0:
                header_text = f"🔥 VULNERABILITÀ CRITICA ({self.cvss_score})"
            elif self.cvss_score >= 7.0:
                header_text = f"🔶 VULNERABILITÀ ALTA ({self.cvss_score})"
            elif self.cvss_score >= 4.0:
                header_text = f"🟡 VULNERABILITÀ MEDIA ({self.cvss_score})"
            else:
                header_text = f"⚪️ VULNERABILITÀ BASSA ({self.cvss_score})"

        exploit_warning = ""
        if self.has_public_exploit:
            exploit_warning = "<b>❗️ EXPLOIT PUBBLICO DISPONIBILE ❗️</b>\n\n"

        # 2. Prepara la riga del titolo, facendo l'escape di eventuali caratteri HTML
        clean_title = html.escape(self.title)

        # Se il titolo è nella forma "CVE-XXXX: Descrizione", lo separiamo
        if ":" in clean_title and clean_title.upper().startswith("CVE-"):
            parts = clean_title.split(':', 1)
            cve_id_part = parts[0].strip()
            title_part = parts[1].strip()
            title_line = f"🆔 <code>{cve_id_part}</code>\n📜 <b>{title_part}</b>"
        else:
            # Fallback per fonti che non hanno un ID nel titolo (es. news)
            title_line = f"📜 <b>{clean_title}</b>"

        # 3. Prepara la riga del vettore CVSS
        vector_line = f"📊 <code>{html.escape(self.cvss_vector)}</code>\n" if self.cvss_vector else ""

        # 4. Assembla il messaggio finale
        message = (
            f"{exploit_warning}\n"
            f"{header_text}\n\n"
            f"{title_line}\n\n"
            f"{vector_line}"
            f"🗓️ {self.published_date.strftime('%d-%m-%Y')}\n"
            f"📰 Fonte: {self.source}\n"
            f"🔗 <a href='{self.link}'>Dettagli completi</a>"
        )

        return message