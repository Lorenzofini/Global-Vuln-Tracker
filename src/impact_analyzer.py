# src/impact_analyzer.py
"""
Impact Analyzer - Analizza vulnerabilità e genera tag visuali per urgenza
Sostituisce vendor_extractor.py con focus su IMPATTO e AZIONE richiesta
"""
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# Mappa CWE ID -> Tipo di attacco leggibile
CWE_TO_ATTACK_TYPE = {
    # Remote Code Execution
    "CWE-94": ("RCE", "Remote Code Execution"),
    "CWE-78": ("RCE", "OS Command Injection"),
    "CWE-77": ("RCE", "Command Injection"),
    "CWE-502": ("RCE", "Deserialization"),
    "CWE-434": ("RCE", "Unrestricted File Upload"),

    # Injection
    "CWE-89": ("SQLi", "SQL Injection"),
    "CWE-79": ("XSS", "Cross-Site Scripting"),
    "CWE-91": ("XMLi", "XML Injection"),
    "CWE-611": ("XXE", "XML External Entity"),
    "CWE-917": ("EL Injection", "Expression Language Injection"),

    # Authentication/Authorization
    "CWE-287": ("Auth Bypass", "Authentication Bypass"),
    "CWE-306": ("Missing Auth", "Missing Authentication"),
    "CWE-862": ("Missing Authz", "Missing Authorization"),
    "CWE-863": ("Incorrect Authz", "Incorrect Authorization"),
    "CWE-269": ("Privilege Escalation", "Improper Privilege Management"),

    # Memory Corruption
    "CWE-119": ("Memory Corruption", "Buffer Overflow"),
    "CWE-120": ("Buffer Overflow", "Classic Buffer Overflow"),
    "CWE-122": ("Heap Overflow", "Heap-based Buffer Overflow"),
    "CWE-121": ("Stack Overflow", "Stack-based Buffer Overflow"),
    "CWE-416": ("UAF", "Use After Free"),
    "CWE-787": ("OOB Write", "Out-of-bounds Write"),
    "CWE-125": ("OOB Read", "Out-of-bounds Read"),

    # Information Disclosure
    "CWE-200": ("Info Leak", "Information Exposure"),
    "CWE-209": ("Error Info Leak", "Error Message Information Leak"),
    "CWE-532": ("Log Info Leak", "Log File Information Leak"),

    # Path Traversal
    "CWE-22": ("Path Traversal", "Path Traversal"),
    "CWE-23": ("Path Traversal", "Relative Path Traversal"),

    # Denial of Service
    "CWE-400": ("DoS", "Resource Exhaustion"),
    "CWE-770": ("DoS", "Allocation without Limits"),
    "CWE-835": ("DoS", "Infinite Loop"),

    # SSRF
    "CWE-918": ("SSRF", "Server-Side Request Forgery"),

    # CSRF
    "CWE-352": ("CSRF", "Cross-Site Request Forgery"),
}


# Emoji per tipo di attacco
ATTACK_TYPE_EMOJI = {
    "RCE": "💥",
    "SQLi": "💉",
    "XSS": "💉",
    "XMLi": "💉",
    "XXE": "💉",
    "EL Injection": "💉",
    "Auth Bypass": "🔑",
    "Missing Auth": "🔑",
    "Missing Authz": "🔑",
    "Incorrect Authz": "🔑",
    "Privilege Escalation": "⬆️",
    "Memory Corruption": "🧠",
    "Buffer Overflow": "🧠",
    "Heap Overflow": "🧠",
    "Stack Overflow": "🧠",
    "UAF": "🧠",
    "OOB Write": "🧠",
    "OOB Read": "🧠",
    "Info Leak": "👁️",
    "Error Info Leak": "👁️",
    "Log Info Leak": "👁️",
    "Path Traversal": "📂",
    "DoS": "💀",
    "SSRF": "🌐",
    "CSRF": "🎭",
}


@dataclass
class ImpactAnalysis:
    """Risultato dell'analisi di impatto"""
    action_topic: str  # Topic di destinazione (PATCH NOW, PLAN THIS WEEK, etc.)
    impact_tags: List[str]  # Tag visuali (es. ["⚡ Exploit attivo", "🌐 Remote"])
    attack_type: Optional[str]  # Tipo attacco (RCE, SQLi, etc.)
    attack_type_full: Optional[str]  # Nome completo
    is_critical: bool  # Richiede azione immediata
    is_news: bool  # È una news, non una CVE
    urgency_level: int  # 1-4 (4=più urgente)


def extract_cwe_ids(raw_data: Optional[Dict[str, Any]]) -> List[str]:
    """Estrae tutti i CWE ID dai dati grezzi NVD"""
    cwe_ids = []
    if not raw_data:
        return cwe_ids

    # Struttura NVD: cve -> weaknesses -> [description -> value]
    cve_data = raw_data.get("cve", raw_data)
    weaknesses = cve_data.get("weaknesses", [])

    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwe_ids.append(value)

    return cwe_ids


def extract_attack_vector(cvss_vector: Optional[str]) -> Dict[str, str]:
    """Estrae componenti dal CVSS vector string"""
    result = {
        "attack_vector": None,  # N=Network, A=Adjacent, L=Local, P=Physical
        "privileges_required": None,  # N=None, L=Low, H=High
        "user_interaction": None,  # N=None, R=Required
        "scope": None,  # U=Unchanged, C=Changed
    }

    if not cvss_vector:
        return result

    # Parse CVSS 3.x vector (es: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
    patterns = {
        "attack_vector": r"AV:([NALP])",
        "privileges_required": r"PR:([NLH])",
        "user_interaction": r"UI:([NR])",
        "scope": r"S:([UC])",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, cvss_vector)
        if match:
            result[key] = match.group(1)

    return result


def extract_patch_url(raw_data: Optional[Dict[str, Any]]) -> Optional[str]:
    """Estrae l'URL della patch dai riferimenti NVD"""
    if not raw_data:
        return None

    cve_data = raw_data.get("cve", raw_data)
    references = cve_data.get("references", [])

    # Priorità: Patch > Vendor Advisory > Mitigation
    priority_tags = ["Patch", "Vendor Advisory", "Mitigation"]

    for priority_tag in priority_tags:
        for ref in references:
            tags = ref.get("tags", [])
            if priority_tag in tags:
                return ref.get("url")

    # Fallback: primo riferimento
    if references:
        return references[0].get("url")

    return None


def analyze_impact(
    vulnerability,
    raw_data: Optional[Dict[str, Any]] = None
) -> ImpactAnalysis:
    """
    Analizza una vulnerabilità e determina:
    - Topic di destinazione basato su azione
    - Tag visuali di impatto
    - Urgenza e tipo di attacco
    """
    impact_tags = []
    attack_type = None
    attack_type_full = None
    urgency_level = 1

    # Estrai info dal vulnerability object
    cvss_score = vulnerability.cvss_score or 0.0
    cvss_vector = vulnerability.cvss_vector
    has_exploit = vulnerability.has_public_exploit
    vuln_id = vulnerability.id

    # Estrai info da raw_data
    cwe_ids = extract_cwe_ids(raw_data)
    vector_components = extract_attack_vector(cvss_vector)

    # Check ransomware (da CISA KEV)
    known_ransomware = False
    if raw_data:
        known_ransomware = raw_data.get("knownRansomwareCampaignUse") == "Known"

    # === GENERA IMPACT TAGS ===

    # 1. Exploit status
    if has_exploit:
        impact_tags.append("⚡ Exploit attivo")
        urgency_level = max(urgency_level, 4)

    # 2. Ransomware
    if known_ransomware:
        impact_tags.append("🦠 Ransomware")
        urgency_level = max(urgency_level, 4)

    # 3. Attack vector
    av = vector_components.get("attack_vector")
    if av == "N":
        impact_tags.append("🌐 Remote")
        urgency_level = max(urgency_level, 3)
    elif av == "A":
        impact_tags.append("📡 Adjacent Network")
    elif av == "L":
        impact_tags.append("💻 Local")

    # 4. Auth required
    pr = vector_components.get("privileges_required")
    if pr == "N":
        impact_tags.append("🔓 No Auth")
        urgency_level = max(urgency_level, 3)
    elif pr == "L":
        impact_tags.append("🔐 Low Priv")

    # 5. Attack type from CWE
    for cwe_id in cwe_ids:
        if cwe_id in CWE_TO_ATTACK_TYPE:
            at_short, at_full = CWE_TO_ATTACK_TYPE[cwe_id]
            attack_type = at_short
            attack_type_full = at_full
            emoji = ATTACK_TYPE_EMOJI.get(at_short, "⚠️")
            impact_tags.append(f"{emoji} {at_short}")

            # RCE aumenta urgency
            if at_short == "RCE":
                urgency_level = max(urgency_level, 4)
            break  # Prendi solo il primo

    # === DETERMINA ACTION TOPIC ===
    is_news = not vuln_id.startswith("CVE-")
    is_critical = False

    if is_news:
        # News senza CVE -> Intel Briefing
        action_topic = "intel"
    elif any([
        has_exploit,
        known_ransomware,
        (cvss_score >= 9.0 and av == "N"),
        (attack_type == "RCE" and av == "N" and pr == "N")
    ]):
        # Azione immediata
        action_topic = "patch_now"
        is_critical = True
        urgency_level = 4
    elif any([
        cvss_score >= 7.0,
        (av == "N" and cvss_score >= 5.0),
        attack_type in ["RCE", "SQLi", "Auth Bypass"]
    ]):
        # Pianifica questa settimana
        action_topic = "plan_week"
        urgency_level = max(urgency_level, 3)
    elif cvss_score >= 4.0:
        # Monitor
        action_topic = "monitor"
        urgency_level = 2
    else:
        # Low priority -> va nel digest
        action_topic = "digest_queue"
        urgency_level = 1

    return ImpactAnalysis(
        action_topic=action_topic,
        impact_tags=impact_tags[:4],  # Max 4 tags
        attack_type=attack_type,
        attack_type_full=attack_type_full,
        is_critical=is_critical,
        is_news=is_news,
        urgency_level=urgency_level
    )


def get_action_topic_name(action_topic: str, config: Dict[str, Any]) -> str:
    """Converte l'action topic interno nel nome del topic Telegram"""
    action_topics = config.get("action_topics", {})

    mapping = {
        "patch_now": action_topics.get("patch_now", "🔴 PATCH NOW"),
        "plan_week": action_topics.get("plan_week", "🟠 PLAN THIS WEEK"),
        "monitor": action_topics.get("monitor", "🟡 MONITOR"),
        "intel": action_topics.get("intel", "📰 INTEL BRIEFING"),
        "digest": action_topics.get("digest", "📊 Weekly Digest"),
        "threat_intel": action_topics.get("threat_intel", "🎯 Threat Intel"),
        "digest_queue": None,  # Non viene inviato subito
    }

    return mapping.get(action_topic, config.get("general_topic_name", "Generale"))


# === LEGACY SUPPORT (retrocompatibilità con vendor_extractor) ===

# Manteniamo le vecchie strutture per retrocompatibilità
MACRO_CATEGORIES = {
    "Web Servers & CMS": ["apache", "nginx", "wordpress", "joomla", "drupal", "php", "iis", "tomcat"],
    "Browsers": ["chrome", "firefox", "safari", "edge", "opera", "webkit", "chromium"],
    "Databases": ["mysql", "postgresql", "oracle", "mongodb", "redis", "sql server", "mariadb", "sqlite"],
    "Networking": ["cisco", "fortinet", "juniper", "palo alto", "vpn", "router", "switch", "firewall"],
    "Virtualization & Cloud": ["vmware", "proxmox", "docker", "kubernetes", "aws", "azure", "google cloud", "esxi"],
    "Operating Systems": ["linux", "windows", "macos", "android", "ios", "ubuntu", "debian", "redhat"]
}

VENDOR_KEYWORDS = {
    "microsoft": ["microsoft", "windows", "win11", "win10", "outlook", "exchange", "office365"],
    "apple": ["apple", "ios", "macos", "iphone", "ipad"],
    "google": ["google", "chrome", "android"],
    "linux": ["linux", "kernel", "ubuntu", "debian", "redhat"]
}


def extract_smart_category(vulnerability, raw_data: Optional[Dict[str, Any]]) -> List[str]:
    """
    LEGACY: Manteniamo per retrocompatibilità.
    Analizza la vulnerabilità e restituisce una lista di categorie/vendor.
    """
    found_categories = set()
    text_to_scan = f"{vulnerability.title} {vulnerability.description}".lower()

    # 1. Cerca Vendor specifici
    for vendor, keywords in VENDOR_KEYWORDS.items():
        if any(kw in text_to_scan for kw in keywords):
            found_categories.add(vendor)

    # 2. Cerca Macro-Categorie
    for macro, keywords in MACRO_CATEGORIES.items():
        if any(kw in text_to_scan for kw in keywords):
            found_categories.add(macro)

    # 3. Analisi dati tecnici (CPE)
    if raw_data and "configurations" in raw_data:
        for config in raw_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe_uri = cpe_match.get("criteria", "").lower()
                    parts = cpe_uri.split(":")
                    if len(parts) > 4:
                        found_categories.add(parts[3])

    return list(found_categories)
