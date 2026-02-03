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
            # Rimuove tutto ciò che precede la dichiarazione XML <?xml...
            content = re.sub(r'^[^<]*', '', content)
            
            feed = feedparser.parse(content)

            if not feed.entries and feed.bozo:
                logger.warning(f"[{self.name}] Feed critico malformato, salto fonte.")
                return []

            for entry in feed.entries:
                link = entry.get("link", "")
                if not link: continue

                # Gestione data di pubblicazione
                pub_date_struct = entry.get("published_parsed") or entry.get("updated_parsed")
                published_date = datetime(*pub_date_struct[:6], tzinfo=timezone.utc) if pub_date_struct else datetime.now(timezone.utc)

                has_exploit = "exploit-db" in self.url.lower() or "exploit" in entry.title.lower()

                vuln = Vulnerability(
                    id=entry.id,
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