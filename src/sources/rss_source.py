# src/sources/rss_source.py
import logging
import feedparser
import requests
import re
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Optional, Any
from .base_source import BaseSource
from ..models import Vulnerability

logger = logging.getLogger(__name__)

class RssSource(BaseSource):
    def _extract_cve_id(self, entry) -> str:
        """
        Estrae CVE ID dal contenuto, altrimenti usa un ID alternativo.
        Priorità:
        1. CVE-YYYY-NNNNN nel titolo o descrizione
        2. entry.id se esiste
        3. Parte finale del link
        4. Hash del titolo (fallback)
        """
        # 1. Cerca CVE nel titolo e descrizione
        text = f"{entry.title} {entry.get('summary', '')} {entry.get('description', '')}"
        cve_match = re.search(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
        if cve_match:
            return cve_match.group(0).upper()
        
        # 2. Usa entry.id se presente e non è un URL
        if hasattr(entry, 'id') and entry.id:
            entry_id = str(entry.id).strip()
            # Se l'ID è già un CVE, ritornalo
            if re.match(r'^CVE-\d{4}-\d{4,7}$', entry_id, re.IGNORECASE):
                return entry_id.upper()
            # Se è un path come /node/15578, puliscilo
            if '/' in entry_id:
                entry_id = entry_id.split('/')[-1]
            # Se non è vuoto, usalo con prefisso della fonte
            if entry_id and not entry_id.startswith('http'):
                return f"{self._get_source_prefix()}-{entry_id}"
        
        # 3. Estrai ID dal link
        link = entry.get('link', '')
        if link:
            # Cerca pattern comuni negli URL
            url_id_match = re.search(r'/(?:node|article|post|advisory)/(\d+)', link)
            if url_id_match:
                return f"{self._get_source_prefix()}-{url_id_match.group(1)}"
            
            # Prova l'ultimo segmento dell'URL
            url_parts = link.rstrip('/').split('/')
            if url_parts:
                last_part = url_parts[-1]
                if last_part and not last_part.startswith('http'):
                    return f"{self._get_source_prefix()}-{last_part}"
        
        # 4. Fallback: hash del titolo (per evitare duplicati)
        import hashlib
        title_hash = hashlib.md5(entry.title.encode()).hexdigest()[:8]
        return f"{self._get_source_prefix()}-{title_hash}"
    
    def _get_source_prefix(self) -> str:
        """Genera un prefisso corto per la fonte"""
        # Mappa personalizzata per fonti note
        source_map = {
            "US-CERT": "USCERT",
            "CERT-EU": "CERTEU",
            "ACN": "ACN",
            "ExploitDB": "EDB",
            "The Hacker News": "THN",
            "BleepingComputer": "BLEEPING"
        }
        
        # Cerca match parziale
        for key, prefix in source_map.items():
            if key.lower() in self.name.lower():
                return prefix
        
        # Fallback: prime 3 lettere maiuscole
        clean_name = re.sub(r'[^A-Za-z]', '', self.name)
        return clean_name[:6].upper() or "RSS"

    def fetch(self) -> List[Tuple[Vulnerability, Optional[Dict[str, Any]]]]:
        url = self.config.get("url")
        if not url: return []

        vulnerabilities = []
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            
            # --- SANITIZZAZIONE XML ---
            content = response.text.strip()
            content = re.sub(r'^[^<]*', '', content)
            
            feed = feedparser.parse(content)

            # Controlla se il feed ha problemi critici
            if feed.bozo:
                if feed.entries:
                    logger.debug(f"[{self.name}] Feed con errori minori, ma elaborabile.")
                else:
                    logger.warning(f"[{self.name}] Feed critico malformato (nessuna entry), salto fonte.")
                    return []

            for entry in feed.entries:
                link = entry.get("link", "")
                if not link: 
                    continue

                # Estrai ID (CVE o alternativo)
                vuln_id = self._extract_cve_id(entry)

                # Gestione data di pubblicazione
                pub_date_struct = entry.get("published_parsed") or entry.get("updated_parsed")
                published_date = datetime(*pub_date_struct[:6], tzinfo=timezone.utc) if pub_date_struct else datetime.now(timezone.utc)

                # Determina se ha exploit
                has_exploit = "exploit-db" in url.lower() or "exploit" in entry.title.lower()

                vuln = Vulnerability(
                    id=vuln_id,
                    source=self.name,
                    title=entry.title,
                    link=link,
                    has_public_exploit=has_exploit,
                    published_date=published_date,
                    description=entry.get("summary", entry.get("description", ""))
                )
                vulnerabilities.append((vuln, None))

        except Exception as e:
            logger.error(f"[{self.name}] Errore fetch: {e}")

        logger.info(f"[{self.name}] Trovate {len(vulnerabilities)} voci.")
        return vulnerabilities