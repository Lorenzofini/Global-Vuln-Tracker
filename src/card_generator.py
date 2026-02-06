# src/card_generator.py
"""
Generatore di card grafiche per vulnerabilità
"""
import io
import logging
from typing import Optional, Tuple
from PIL import Image, ImageDraw, ImageFont

logger = logging.getLogger(__name__)

# Colori per severity
COLORS = {
    "critical": {"bg": "#DC2626", "accent": "#FEE2E2", "text": "#FFFFFF"},
    "high": {"bg": "#EA580C", "accent": "#FFEDD5", "text": "#FFFFFF"},
    "medium": {"bg": "#CA8A04", "accent": "#FEF9C3", "text": "#FFFFFF"},
    "low": {"bg": "#2563EB", "accent": "#DBEAFE", "text": "#FFFFFF"},
}


def hex_to_rgb(hex_color: str) -> Tuple[int, int, int]:
    """Converte colore hex in RGB"""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))


def get_fonts():
    """Carica i font, con fallback"""
    try:
        return {
            "title": ImageFont.truetype("arialbd.ttf", 38),
            "big": ImageFont.truetype("arialbd.ttf", 32),
            "normal": ImageFont.truetype("arial.ttf", 24),
            "small": ImageFont.truetype("arial.ttf", 20),
            "mono": ImageFont.truetype("consola.ttf", 18),
        }
    except:
        default = ImageFont.load_default()
        return {
            "title": default,
            "big": default,
            "normal": default,
            "small": default,
            "mono": default,
        }


def generate_vuln_card(
    cve_id: str,
    score: float,
    vendor: str,
    title: str,
    cvss_vector: str = None,
    tags: list = None,
    action: str = "PATCH NOW",
    source: str = "CISA",
    time_ago: str = "2h ago",
) -> io.BytesIO:
    """
    Genera un'immagine card per la vulnerabilità.
    Ritorna un BytesIO pronto per essere inviato a Telegram.
    """
    tags = tags or []

    # Determina severity
    if score >= 9.0:
        severity = "critical"
        sev_label = "CRITICAL"
    elif score >= 7.0:
        severity = "high"
        sev_label = "HIGH"
    elif score >= 4.0:
        severity = "medium"
        sev_label = "MEDIUM"
    else:
        severity = "low"
        sev_label = "LOW"

    colors = COLORS[severity]
    bg_color = hex_to_rgb(colors["bg"])
    accent_color = hex_to_rgb(colors["accent"])
    text_color = hex_to_rgb(colors["text"])

    # Dimensioni
    width = 700
    height = 380
    pad = 25

    # Crea immagine
    img = Image.new('RGB', (width, height), bg_color)
    draw = ImageDraw.Draw(img)
    fonts = get_fonts()

    y = pad

    # ═══ HEADER: Badge + Score ═══
    # Badge
    draw.rounded_rectangle([pad, y, pad + 160, y + 42], radius=8, fill=accent_color)
    draw.text((pad + 12, y + 6), sev_label, font=fonts["big"], fill=bg_color)

    # Score
    score_text = f"{score:.1f}"
    draw.text((width - pad - 90, y - 5), score_text, font=fonts["title"], fill=text_color)
    draw.text((width - pad - 30, y + 12), "/10", font=fonts["small"], fill=accent_color)

    y += 60

    # ═══ CVE ID ═══
    draw.text((pad, y), cve_id, font=fonts["title"], fill=text_color)
    y += 48

    # ═══ CVSS Vector ═══
    if cvss_vector:
        draw.text((pad, y), cvss_vector, font=fonts["mono"], fill=accent_color)
        y += 28

    y += 15

    # ═══ Vendor ═══
    if vendor:
        draw.text((pad, y), vendor, font=fonts["big"], fill=text_color)
        y += 38

    # ═══ Title ═══
    if len(title) > 45:
        title = title[:42] + "..."
    draw.text((pad, y), title, font=fonts["normal"], fill=accent_color)
    y += 35

    # ═══ Tags ═══
    if tags:
        tag_x = pad
        y += 10
        for tag in tags[:4]:
            # Misura tag
            bbox = draw.textbbox((0, 0), tag, font=fonts["small"])
            tag_w = bbox[2] - bbox[0] + 20

            # Pill
            draw.rounded_rectangle([tag_x, y, tag_x + tag_w, y + 28], radius=14, fill=accent_color)
            draw.text((tag_x + 10, y + 3), tag, font=fonts["small"], fill=bg_color)
            tag_x += tag_w + 8

            if tag_x > width - 100:
                break

    # ═══ Footer bar ═══
    footer_y = height - 55
    draw.rectangle([0, footer_y, width, height], fill=(0, 0, 0, 80))

    # Action
    draw.text((pad, footer_y + 12), f"▸ {action}", font=fonts["big"], fill=text_color)

    # Source + time
    footer_text = f"{source} · {time_ago}"
    bbox = draw.textbbox((0, 0), footer_text, font=fonts["small"])
    footer_w = bbox[2] - bbox[0]
    draw.text((width - pad - footer_w, footer_y + 18), footer_text, font=fonts["small"], fill=accent_color)

    # Salva in BytesIO
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)

    return buffer


def generate_card_for_vuln(vuln) -> Optional[io.BytesIO]:
    """
    Genera una card per un oggetto Vulnerability.
    Ritorna None se non è una CVE.
    """
    if not vuln.id.startswith("CVE-"):
        return None

    # Estrai vendor
    title_lower = vuln.title.lower()
    vendor = ""
    vendors_map = {
        "microsoft": "Microsoft", "windows": "Microsoft", "exchange": "Microsoft",
        "apple": "Apple", "google": "Google", "chrome": "Google",
        "cisco": "Cisco", "vmware": "VMware", "fortinet": "Fortinet",
        "apache": "Apache", "linux": "Linux", "adobe": "Adobe",
    }
    for key, val in vendors_map.items():
        if key in title_lower:
            vendor = val
            break

    # Pulisci titolo
    import re
    title = re.sub(r'^CVE-\d{4}-\d+\s*[-:]\s*', '', vuln.title)
    title = re.sub(r'<[^>]+>', '', title)  # Rimuovi HTML

    # Tags
    tags = []
    if vuln.has_public_exploit:
        tags.append("EXPLOIT")
    if vuln.known_ransomware:
        tags.append("RANSOMWARE")
    if vuln.cvss_vector:
        if "AV:N" in vuln.cvss_vector:
            tags.append("REMOTE")
        if "PR:N" in vuln.cvss_vector:
            tags.append("NO AUTH")
    if vuln.attack_type:
        tags.append(vuln.attack_type.upper())

    # Action
    score = vuln.cvss_score or 0
    if vuln.has_public_exploit or vuln.known_ransomware or score >= 9.0:
        action = "PATCH NOW"
    elif score >= 7.0:
        action = "PLAN THIS WEEK"
    elif score >= 4.0:
        action = "MONITOR"
    else:
        action = "REVIEW"

    # Source
    source = vuln.source.upper()
    if "CISA" in source:
        source = "CISA"
    elif "NVD" in source:
        source = "NVD"
    else:
        source = vuln.source[:10]

    # Time ago
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    pub = vuln.published_date
    if pub.tzinfo is None:
        pub = pub.replace(tzinfo=timezone.utc)
    diff = now - pub
    if diff.days == 0:
        h = diff.seconds // 3600
        time_ago = f"{h}h ago" if h > 0 else "now"
    elif diff.days < 7:
        time_ago = f"{diff.days}d ago"
    else:
        time_ago = pub.strftime("%d/%m")

    return generate_vuln_card(
        cve_id=vuln.id,
        score=vuln.cvss_score or 0,
        vendor=vendor,
        title=title,
        cvss_vector=vuln.cvss_vector,
        tags=tags,
        action=action,
        source=source,
        time_ago=time_ago,
    )
