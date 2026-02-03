# src/vendor_extractor.py
import logging
import re
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Mappa Parole Chiave -> Macro-Categoria
MACRO_CATEGORIES = {
    "Web Servers & CMS": ["apache", "nginx", "wordpress", "joomla", "drupal", "php", "iis", "tomcat"],
    "Browsers": ["chrome", "firefox", "safari", "edge", "opera", "webkit", "chromium"],
    "Databases": ["mysql", "postgresql", "oracle", "mongodb", "redis", "sql server", "mariadb", "sqlite"],
    "Networking": ["cisco", "fortinet", "juniper", "palo alto", "vpn", "router", "switch", "firewall"],
    "Virtualization & Cloud": ["vmware", "proxmox", "docker", "kubernetes", "aws", "azure", "google cloud", "esxi"],
    "Operating Systems": ["linux", "windows", "macos", "android", "ios", "ubuntu", "debian", "redhat"]
}

# Mappa specifica Vendor -> Topic Name (per coerenza con config.yaml)
VENDOR_KEYWORDS = {
    "microsoft": ["microsoft", "windows", "win11", "win10", "outlook", "exchange", "office365"],
    "apple": ["apple", "ios", "macos", "iphone", "ipad"],
    "google": ["google", "chrome", "android"],
    "linux": ["linux", "kernel", "ubuntu", "debian", "redhat"]
}

def extract_smart_category(vulnerability: Any, raw_data: Optional[Dict[str, Any]]) -> List[str]:
    """
    Analizza la vulnerabilità e restituisce una lista di categorie/vendor.
    """
    found_categories = set()
    text_to_scan = f"{vulnerability.title} {vulnerability.description}".lower()

    # 1. Cerca Vendor specifici
    for vendor, keywords in VENDOR_KEYWORDS.items():
        if any(kw in text_to_scan for kw in keywords):
            found_categories.add(vendor)

    # 2. Cerca Macro-Categorie (se non abbiamo trovato un vendor o in aggiunta)
    for macro, keywords in MACRO_CATEGORIES.items():
        if any(kw in text_to_scan for kw in keywords):
            found_categories.add(macro)

    # 3. Analisi dati tecnici (CPE)
    if raw_data and "configurations" in raw_data:
        for config in raw_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe_uri = cpe_match.get("criteria", "").lower()
                    # Estrae il vendor dal CPE (es: cpe:2.3:a:VENDOR:PRODUCT:...)
                    parts = cpe_uri.split(":")
                    if len(parts) > 4:
                        found_categories.add(parts[3])

    return list(found_categories)