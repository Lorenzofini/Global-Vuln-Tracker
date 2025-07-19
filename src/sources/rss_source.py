# src/sources/rss_source.py
import logging
import feedparser
import pytz
import requests
from datetime import datetime, timezone
from typing import List
from .base_source import BaseSource
from ..models import Vulnerability

logger = logging.getLogger(__name__)


class RssSource(BaseSource):
    """Gestisce la raccolta di vulnerabilità da feed RSS/Atom."""

    def fetch(self) -> List[Vulnerability]:
        url = self.config.get("url")
        if not url:
            logger.error(f"[{self.name}] URL non specificato nella configurazione.")
            return []

        # logger.info(f"[{self.name}] Sto recuperando dati da feed RSS: {url}")
        feed = feedparser.parse(url)

        # headers = {
        #     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0'
        # }
        #
        # try:
        #     # Passiamo gli header alla richiesta
        #     response = requests.get(url, headers=headers, timeout=15)
        #     response.raise_for_status()
        #     # Passiamo il contenuto della risposta a feedparser invece dell'URL
        #     feed = feedparser.parse(response.content)
        # except requests.RequestException as e:
        #     logger.error(f"[{self.name}] Errore di rete nel recuperare il feed: {e}")
        #     return []

        if feed.bozo:
            logger.warning(f"[{self.name}] Il feed RSS potrebbe essere malformato: {feed.bozo_exception}")

        vulnerabilities = []
        for entry in feed.entries:
            try:
                title = entry.get("title", "N/A")
                link = entry.get("link", "")

                # 'link' è il nostro ID univoco per i feed RSS
                if not link:
                    logger.warning(f"[{self.name}] Trovata voce senza link, la salto: {title}")
                    continue

                # Gestione robusta della data di pubblicazione
                published_date = None
                pub_date_struct = entry.get("published_parsed") or entry.get("updated_parsed")

                if pub_date_struct:
                    # Converte da time.struct_time a datetime
                    dt_naive = datetime(*pub_date_struct[:6])

                    # Se il feedparser non ha aggiunto un fuso orario, lo aggiungiamo noi (assumendo UTC)
                    if dt_naive.tzinfo is None:
                        published_date = dt_naive.replace(tzinfo=timezone.utc)
                    else:
                        # Se c'è già un fuso orario, lo normalizziamo a UTC per coerenza
                        published_date = dt_naive.astimezone(timezone.utc)
                else:
                    # Fallback finale se nessun campo data è stato trovato
                    logger.warning(
                        f"[{self.name}] Data non trovata o non parsabile per '{title}', uso la data attuale.")
                    published_date = datetime.now(timezone.utc)

                vuln = Vulnerability(
                    id=link,
                    source=self.name,
                    title=title.strip(),
                    link=link,
                    published_date=published_date
                )
                vulnerabilities.append(vuln)
            except Exception as e:
                logger.error(f"[{self.name}] Errore nel processare una voce del feed: {e}", exc_info=True)

        logger.info(f"[{self.name}] Trovate {len(vulnerabilities)} voci dal feed.")
        return vulnerabilities
