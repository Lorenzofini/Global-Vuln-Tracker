# src/main.py
import logging
import re
import html
import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import replace
from dotenv import load_dotenv

from .config import load_configuration, load_environment_variables
from .models import Vulnerability
from .state_manager import StateManager
from .notifiers.telegram_notifier import TelegramNotifier
from .notifiers.base_notifier import BaseNotifier
from .admin_notifier import send_admin_alert
from .nvd_helper import fetch_cve_details
from .sources import rss_source, cisa_kev_source, nvd_source, github_source, osv_source

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

SOURCE_HANDLERS = {
    "rss": rss_source.RssSource,
    "cisa_kev": cisa_kev_source.CisaKevSource,
    "nvd": nvd_source.NvdSource,
    "github": github_source.GithubSource,
    "osv": osv_source.OsvSource,
}


def main():
    """Punto di ingresso principale che gestisce il loop di controllo."""
    try:
        load_dotenv()
        env_vars = load_environment_variables()
        config = load_configuration()
        send_admin_alert("✅ **Bot (modalità canale singolo) avviato con successo!**")

        state_manager = StateManager()
        notifier: BaseNotifier = TelegramNotifier(
            token=env_vars["TELEGRAM_BOT_TOKEN"],
            chat_id=env_vars["TELEGRAM_CHAT_ID"]
        )
        credentials = {
            'github_token': env_vars.get('GITHUB_TOKEN'),
            'nvd_api_key': env_vars.get('NVD_API_KEY')
        }
        polling_interval_sec = config['settings']['polling_interval_minutes'] * 60
        global_start_date = datetime.strptime(config['settings']['start_date'], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception as e:
        send_admin_alert(f"<b>Errore critico in inizializzazione:</b>\n<code>{html.escape(str(e))}</code>",
                         critical=True)
        return

    while True:
        current_run_start_time = datetime.now(timezone.utc)
        last_run = state_manager.last_successful_run
        fetch_since_date = last_run - timedelta(hours=1) if last_run else global_start_date

        logger.info(f"Inizio ciclo di controllo. Ricerca novità a partire da: {fetch_since_date.isoformat()}")

        # 1. Recupero Dati
        all_vulnerabilities_with_raw_data: List[Tuple[Vulnerability, Optional[Dict[str, Any]]]] = []
        exploit_db_titles: Set[str] = set()
        for source_config in config.get('sources', []):
            if not source_config.get('enabled', False): continue
            handler_class = SOURCE_HANDLERS.get(source_config.get('type'))
            if not handler_class: continue
            try:
                instance_config = {**source_config, 'credentials': credentials, 'fetch_since': fetch_since_date}
                source_instance = handler_class(**instance_config)
                fetched_vulns = source_instance.fetch()
                if source_config.get('name') == 'ExploitDB':
                    for vuln, _ in fetched_vulns:
                        exploit_db_titles.add(vuln.title.lower())
                all_vulnerabilities_with_raw_data.extend(fetched_vulns)
            except Exception as e:
                send_admin_alert(
                    f"<b>La fonte '{source_config['name']}' ha fallito.</b>\nErrore: <code>{html.escape(str(e))}</code>")

        logger.info(f"Totale voci grezze recuperate: {len(all_vulnerabilities_with_raw_data)}")

        # 2. Processamento, Arricchimento e Filtraggio
        filters_config = config.get('settings', {}).get('filters', {'enabled': False})
        filters_enabled = filters_config.get('enabled', False)
        if filters_enabled:
            logger.info("Filtri per il canale pubblico ATTIVI.")

        new_vulnerabilities: List[Vulnerability] = []
        for vuln, raw_data in all_vulnerabilities_with_raw_data:
            enriched_vuln = vuln
            if enriched_vuln.published_date.tzinfo is None:
                enriched_vuln = replace(enriched_vuln,
                                        published_date=enriched_vuln.published_date.replace(tzinfo=timezone.utc))

            if state_manager.is_processed(enriched_vuln.id) or enriched_vuln.published_date < global_start_date:
                continue

            if enriched_vuln.cvss_score is None:
                text_to_search = enriched_vuln.title + " " + enriched_vuln.description
                cve_match = re.search(r'(CVE-\d{4}-\d{4,7})', text_to_search, re.IGNORECASE)
                if cve_match:
                    cve_id = cve_match.group(1).upper()
                    nvd_data = fetch_cve_details(cve_id, credentials.get('nvd_api_key'))
                    if nvd_data:
                        enriched_vuln = replace(enriched_vuln, **nvd_data)

            has_exploit = False
            cve_match = re.search(r'(CVE-\d{4}-\d{4,7})', enriched_vuln.title, re.IGNORECASE)
            if cve_match and any(cve_match.group(1).lower() in title for title in exploit_db_titles):
                has_exploit = True

            if has_exploit and not enriched_vuln.has_public_exploit:
                enriched_vuln = replace(enriched_vuln, has_public_exploit=True)

            if filters_enabled:
                min_score = filters_config.get('min_cvss_score', 0.0)
                keywords = [k.lower() for k in filters_config.get('keywords', [])]
                logic = filters_config.get('logic', 'OR').upper()
                score_ok = (enriched_vuln.cvss_score is not None and enriched_vuln.cvss_score >= min_score)
                text_to_search = (enriched_vuln.title + " " + enriched_vuln.description).lower()
                keyword_ok = not keywords or any(keyword in text_to_search for keyword in keywords)

                passes_filter = False
                if enriched_vuln.cvss_score is None:
                    passes_filter = keyword_ok
                else:
                    passes_filter = (score_ok and keyword_ok) if logic == 'AND' else (score_ok or keyword_ok)

                if not passes_filter:
                    continue

            new_vulnerabilities.append(enriched_vuln)

        # 3. Notifica
        if new_vulnerabilities:
            logger.info(f"Trovate {len(new_vulnerabilities)} nuove vulnerabilità da notificare.")
            new_vulnerabilities.sort(key=lambda v: v.published_date)

            for vuln in new_vulnerabilities:
                if notifier.send(vuln):
                    state_manager.add_processed(vuln.id)

            state_manager.save()
        else:
            logger.info("Nessuna nuova vulnerabilità trovata.")

        state_manager.update_last_run_time(current_run_start_time)
        elapsed_time = (datetime.now(timezone.utc) - current_run_start_time).total_seconds()
        wait_time = max(0, polling_interval_sec - elapsed_time)
        logger.info(f"Ciclo completato in {elapsed_time:.2f}s. Prossimo controllo tra {wait_time / 60:.1f} min.")
        time.sleep(wait_time)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Arresto manuale.")
        send_admin_alert("ℹ️ **Bot arrestato manualmente.**")
    except Exception as e:
        send_admin_alert(f"<b>ERRORE CRITICO NON GESTITO:</b>\n<code>{html.escape(str(e))}</code>", critical=True)
        # Rilancia l'eccezione per vederla nel log del terminale
        raise