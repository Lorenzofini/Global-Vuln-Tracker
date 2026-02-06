# src/models.py
"""
Models for Global-Vuln-Tracker 2.0
Clean, readable card design
"""
import html
import re
import datetime
from datetime import timezone
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
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
    cwe_id: Optional[str] = None
    attack_type: Optional[str] = None
    known_ransomware: bool = False
    patch_url: Optional[str] = None
    required_action: Optional[str] = None
    impact_tags: List[str] = field(default_factory=list)
    due_date: Optional[str] = None
    image_url: Optional[str] = None  # Immagine dall'articolo originale

    # Banner images per severity level
    # Questi sono placeholder - configura i tuoi URL in config.yaml
    # oppure modifica direttamente qui
    THREAT_BANNERS = {
        "CRITICAL": None,  # Configura in config.yaml → topics.banners.critical
        "HIGH": None,
        "MEDIUM": None,
        "LOW": None,
        "INTEL": None,
    }

    def _get_threat_config(self) -> dict:
        score = self.cvss_score or 0.0

        if self.has_public_exploit or self.known_ransomware or score >= 9.0:
            return {
                "header": "🚨 CRITICAL ALERT",
                "action": "PATCH NOW",
                "level": "CRITICAL",
                "is_critical": True,
                "banner": self.THREAT_BANNERS.get("CRITICAL")
            }
        elif score >= 7.0:
            return {
                "header": "🟠 HIGH PRIORITY",
                "action": "PLAN THIS WEEK",
                "level": "HIGH",
                "is_critical": False,
                "banner": self.THREAT_BANNERS.get("HIGH")
            }
        elif score >= 4.0:
            return {
                "header": "🟡 MODERATE RISK",
                "action": "MONITOR",
                "level": "MEDIUM",
                "is_critical": False,
                "banner": self.THREAT_BANNERS.get("MEDIUM")
            }
        else:
            return {
                "header": "🔵 LOW PRIORITY",
                "action": "REVIEW",
                "level": "LOW",
                "is_critical": False,
                "banner": self.THREAT_BANNERS.get("LOW")
            }

    def _format_cvss(self) -> str:
        if not self.cvss_score:
            return "N/A"

        score = self.cvss_score
        if score >= 9.0:
            return f"🔴 {score:.1f} CRITICAL"
        elif score >= 7.0:
            return f"🟠 {score:.1f} HIGH"
        elif score >= 4.0:
            return f"🟡 {score:.1f} MEDIUM"
        else:
            return f"🔵 {score:.1f} LOW"

    def _get_vendor(self) -> str:
        title_lower = self.title.lower()
        vendors = {
            "microsoft": "Microsoft", "windows": "Microsoft", "exchange": "Microsoft",
            "apple": "Apple", "ios": "Apple", "macos": "Apple",
            "google": "Google", "chrome": "Google", "android": "Google",
            "cisco": "Cisco", "vmware": "VMware", "fortinet": "Fortinet",
            "apache": "Apache", "linux": "Linux", "oracle": "Oracle",
            "adobe": "Adobe", "citrix": "Citrix", "juniper": "Juniper",
        }
        for key, val in vendors.items():
            if key in title_lower:
                return val
        return ""

    def _time_ago(self) -> str:
        now = datetime.datetime.now(timezone.utc)
        pub = self.published_date
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=timezone.utc)

        diff = now - pub
        if diff.days == 0:
            h = diff.seconds // 3600
            if h == 0:
                m = diff.seconds // 60
                return f"{m}m" if m > 0 else "now"
            return f"{h}h"
        elif diff.days < 7:
            return f"{diff.days}d"
        return pub.strftime("%d/%m")

    def _source_name(self) -> str:
        s = self.source.upper()
        if "CISA" in s: return "CISA"
        if "NVD" in s: return "NVD"
        if "GITHUB" in s: return "GitHub"
        return self.source[:10]

    def _clean(self, text: str) -> str:
        if not text: return ""
        text = re.sub(r'<[^>]+>', ' ', text)
        text = html.unescape(text)
        return re.sub(r'\s+', ' ', text).strip()

    def get_banner_url(self) -> Optional[str]:
        """Ritorna l'URL del banner per questa vulnerabilità"""
        if not self.id.startswith("CVE-"):
            return self.THREAT_BANNERS.get("INTEL")
        cfg = self._get_threat_config()
        return cfg.get("banner")

    def get_vuln_card(self) -> Tuple[str, InlineKeyboardMarkup]:
        cfg = self._get_threat_config()
        vendor = self._get_vendor()
        score = self.cvss_score or 0

        # Severity config
        if score >= 9.0:
            sev_emoji = "🔴"
            sev_label = "CRITICAL"
        elif score >= 7.0:
            sev_emoji = "🟠"
            sev_label = "HIGH"
        elif score >= 4.0:
            sev_emoji = "🟡"
            sev_label = "MEDIUM"
        else:
            sev_emoji = "🔵"
            sev_label = "LOW"

        # ═══ HEADER ═══
        msg = "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n"
        msg += f"  {sev_emoji}  <b>{sev_label}</b>"
        if score:
            msg += f"                        <b>{score:.1f}</b><i>/10</i>"
        msg += "\n"
        msg += "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n\n"

        # ═══ CVE ID (grande, grassetto) ═══
        msg += f"  <b>{self.id}</b>\n"

        # ═══ CVSS VECTOR (monospace, piccolo) ═══
        if self.cvss_vector:
            msg += f"  <code>{self.cvss_vector}</code>\n"

        msg += "\n"

        # ═══ VENDOR (grassetto) + TITLE (normale) ═══
        title = self._clean(self.title)
        title = re.sub(r'^CVE-\d{4}-\d+\s*[-:]\s*', '', title)
        if len(title) > 65:
            title = title[:62] + "..."

        if vendor:
            msg += f"  <b>{vendor}</b>\n"
        msg += f"  <i>{html.escape(title)}</i>\n\n"

        # ═══ TAGS (grassetto) ═══
        tags = []
        if self.has_public_exploit:
            tags.append("<b>⚡ EXPLOIT</b>")
        if self.known_ransomware:
            tags.append("<b>🦠 RANSOMWARE</b>")
        if self.cvss_vector:
            if "AV:N" in self.cvss_vector:
                tags.append("🌐 REMOTE")
            if "PR:N" in self.cvss_vector:
                tags.append("🔓 NO AUTH")
            if "UI:N" in self.cvss_vector:
                tags.append("👆 0-CLICK")
        if self.attack_type:
            tags.append(f"💢 {self.attack_type.upper()}")

        if tags:
            msg += "  " + "  ·  ".join(tags) + "\n\n"

        # ═══ ACTION BAR ═══
        msg += "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬\n"
        msg += f"  ▸  <b>{cfg['action']}</b>"
        if self.due_date:
            msg += f"        📅 <i>{self.due_date}</i>"
        msg += "\n"
        msg += f"  <i>{self._source_name()}  ·  {self._time_ago()}</i>\n"
        msg += "▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬"

        # Buttons - belli e utili
        buttons = []

        # Row 1: Azioni principali
        row1 = []
        if self.patch_url:
            row1.append(InlineKeyboardButton("🔧 PATCH", url=self.patch_url))
        row1.append(InlineKeyboardButton("📄 NVD", url=f"https://nvd.nist.gov/vuln/detail/{self.id}"))
        row1.append(InlineKeyboardButton("🔍 EXPLOIT", url=f"https://www.google.com/search?q={self.id}+exploit+PoC"))
        buttons.append(row1)

        # Row 2: Info aggiuntive
        buttons.append([
            InlineKeyboardButton("📚 MITRE", url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={self.id}"),
            InlineKeyboardButton("🌐 Google", url=f"https://www.google.com/search?q={self.id}"),
        ])

        return msg, InlineKeyboardMarkup(buttons)

    def get_intel_card(self) -> Tuple[str, InlineKeyboardMarkup]:
        msg = "<b>📰 INTEL BRIEFING</b>\n\n"

        title = self._clean(self.title)
        if len(title) > 80:
            title = title[:77] + "..."
        msg += f"<b>{html.escape(title)}</b>\n\n"

        desc = self._clean(self.description)
        if desc:
            if len(desc) > 250:
                desc = desc[:247] + "..."
            msg += f"{html.escape(desc)}\n\n"

        # Related CVEs
        cves = re.findall(r'CVE-\d{4}-\d+', f"{self.title} {self.description}")
        if cves:
            unique = list(dict.fromkeys(cves))[:3]
            msg += "🔗 " + " ".join(f"<code>{c}</code>" for c in unique) + "\n\n"

        msg += f"<i>{self._source_name()} • {self._time_ago()}</i>"

        buttons = [[InlineKeyboardButton("📖 Read More", url=self.link)]]
        if cves:
            buttons.append([InlineKeyboardButton(f"🔍 {cves[0]}", url=f"https://nvd.nist.gov/vuln/detail/{cves[0]}")])

        return msg, InlineKeyboardMarkup(buttons)

    def get_ui_elements(self) -> Tuple[str, InlineKeyboardMarkup]:
        if not self.id.startswith("CVE-"):
            return self.get_intel_card()
        return self.get_vuln_card()

    # Legacy
    def _get_action_config(self) -> dict:
        cfg = self._get_threat_config()
        return {"emoji": "🔴" if cfg['is_critical'] else "🟡", "label": cfg['action'], "is_critical": cfg['is_critical']}

    def _get_urgency_config(self) -> dict:
        return self._get_action_config()


def create_digest_card(
    week_number: int,
    year: int,
    date_range: str,
    total_vulns: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    exploit_count: int,
    ransomware_count: int,
    top_vendors: List[Tuple[str, int]],
    highlights: List[Tuple[str, str]]
) -> Tuple[str, InlineKeyboardMarkup]:

    msg = f"<b>📊 WEEKLY DIGEST</b>\n"
    msg += f"Week {week_number}, {year}\n\n"

    msg += f"<b>📈 This Week</b>\n"
    msg += f"Total: <b>{total_vulns}</b>\n"
    msg += f"🔴 {critical_count} Critical • 🟠 {high_count} High\n"
    msg += f"🟡 {medium_count} Medium • 🔵 {low_count} Low\n\n"

    if exploit_count or ransomware_count:
        msg += f"<b>⚠️ Threats</b>\n"
        if exploit_count:
            msg += f"⚡ {exploit_count} Active Exploits\n"
        if ransomware_count:
            msg += f"🦠 {ransomware_count} Ransomware\n"
        msg += "\n"

    if top_vendors:
        msg += "<b>🎯 Top Affected</b>\n"
        for vendor, count in top_vendors[:4]:
            bar = "█" * min(count, 8)
            msg += f"{vendor}: {bar} {count}\n"
        msg += "\n"

    if highlights:
        msg += "<b>🔥 Highlights</b>\n"
        for cve, desc in highlights[:3]:
            short = desc[:40] + "..." if len(desc) > 40 else desc
            msg += f"• <code>{cve}</code> {short}\n"
        msg += "\n"

    msg += f"<i>{date_range}</i>"

    buttons = [[
        InlineKeyboardButton("📋 Full Report", callback_data="digest_full"),
        InlineKeyboardButton("⚙️ Settings", callback_data="digest_settings")
    ]]

    return msg, InlineKeyboardMarkup(buttons)
