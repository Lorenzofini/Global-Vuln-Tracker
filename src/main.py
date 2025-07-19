# src/main.py
import re
import logging
import html
import time
from datetime import datetime, timezone, timedelta
from typing import List
from dataclasses import replace
from dotenv import load_dotenv  # <-- AGGIUNTO IMPORT

# Importa i nostri moduli
from .config import load_configuration, load_environment_variables
from .models import Vulnerability
from .state_manager import StateManager
from .notifiers.telegram_notifier import TelegramNotifier
from .notifiers.base_notifier import BaseNotifier
from .sources import rss_source, cisa_kev_source, nvd_source, github_source, osv_source
from .nvd_helper import fetch_cve_details
from .admin_notifier import send_admin_alert

# Configurazione del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Mappatura dei tipi di fonte
SOURCE_HANDLERS = {
    "rss": rss_source.RssSource,
    "cisa_kev": cisa_kev_source.CisaKevSource,
    "nvd": nvd_source.NvdSource,
    "github": github_source.GithubSource,
    "osv": osv_source.OsvSource,
}


def main():
    """Punto di ingresso principale dell'applicazione."""
    # Le variabili d'ambiente sono già state caricate dal blocco __main__

    try:
        env_vars = load_environment_variables()
        config = load_configuration()

        # Ora inviamo l'alert di avvio, sicuri che la configurazione sia OK
        logger.info("Avvio del sistema di notifica vulnerabilità...")
        send_admin_alert("✅ **Bot avviato con successo!** Configurazione caricata.")

        state_manager = StateManager()
        notifier: BaseNotifier = TelegramNotifier(
            token=env_vars["TELEGRAM_BOT_TOKEN"],
            chat_id=env_vars["TELEGRAM_CHAT_ID"]
        )

        config['credentials'] = {
            'github_token': env_vars.get('GITHUB_TOKEN'),
            'nvd_api_key': env_vars.get('NVD_API_KEY')
        }

        polling_interval_sec = config['settings']['polling_interval_minutes'] * 60
        global_start_date = datetime.strptime(config['settings']['start_date'], "%Y-%m-%d").replace(tzinfo=timezone.utc)

    except (ValueError, FileNotFoundError, KeyError) as e:
        error_msg = f"<b>Errore critico durante l'inizializzazione:</b>\n<code>{html.escape(str(e))}</code>\nIl bot si sta arrestando."
        logger.critical(error_msg.replace('<b>', '').replace('</b>', '').replace('<code>', '').replace('</code>', ''))
        send_admin_alert(error_msg, critical=True)
        return

    # Loop principale
    while True:
        last_run = state_manager.last_successful_run
        fetch_since_date = last_run - timedelta(hours=1) if last_run else global_start_date

        current_run_start_time = datetime.now(timezone.utc)
        logger.info(f"Inizio ciclo di controllo. Ricerca novità a partire da: {fetch_since_date.isoformat()}")

        all_vulnerabilities: List[Vulnerability] = []
        for source_config in config.get('sources', []):
            if not source_config.get('enabled', False): continue

            handler_class = SOURCE_HANDLERS.get(source_config.get('type'))
            if not handler_class: continue

            try:
                instance_config = {**source_config, 'credentials': config['credentials'],
                                   'fetch_since': fetch_since_date}
                source_instance = handler_class(**instance_config)
                fetched_vulns = source_instance.fetch()
                all_vulnerabilities.extend(fetched_vulns)
            except Exception as e:
                # Alert per il fallimento di una singola fonte
                error_message = f"<b>La fonte '{source_config['name']}' ha fallito.</b>\nErrore: <code>{html.escape(str(e))}</code>"
                logger.error(
                    error_message.replace('<b>', '').replace('</b>', '').replace('<code>', '').replace('</code>', ''))
                send_admin_alert(error_message)

        logger.info(f"Totale voci recuperate da tutte le fonti: {len(all_vulnerabilities)}")

        # Logica di filtro e arricchimento
        filters_config = config.get('settings', {}).get('filters', {'enabled': False})
        filters_enabled = filters_config.get('enabled', False)
        if filters_enabled:
            logger.info("Filtri di notifica ATTIVI.")

        new_vulnerabilities = []
        for vuln in all_vulnerabilities:
            pub_date = vuln.published_date
            vulnerability_to_process = vuln

            if pub_date.tzinfo is None:
                aware_date = pub_date.replace(tzinfo=timezone.utc)
                vulnerability_to_process = replace(vuln, published_date=aware_date)
                pub_date = aware_date

            if (state_manager.is_processed(vulnerability_to_process.id) or
                    pub_date < global_start_date or
                    pub_date < fetch_since_date):
                continue

            if vulnerability_to_process.cvss_score is None:
                text_to_search = vulnerability_to_process.title + " " + vulnerability_to_process.description
                cve_match = re.search(r'(CVE-\d{4}-\d{4,7})', text_to_search, re.IGNORECASE)
                if cve_match:
                    cve_id = cve_match.group(1).upper()
                    nvd_data = fetch_cve_details(cve_id, config['credentials'].get('nvd_api_key'))
                    if nvd_data:
                        vulnerability_to_process = replace(
                            vulnerability_to_process,
                            cvss_score=nvd_data['cvss_score'],
                            cvss_vector=nvd_data['cvss_vector']
                        )

            if filters_enabled:
                min_score = filters_config.get('min_cvss_score', 0.0)
                keywords = [k.lower() for k in filters_config.get('keywords', [])]
                logic = filters_config.get('logic', 'OR').upper()
                score_ok = (vulnerability_to_process.cvss_score is not None and
                            vulnerability_to_process.cvss_score >= min_score)
                text_to_search = (vulnerability_to_process.title + " " + vulnerability_to_process.description).lower()
                keyword_ok = not keywords or any(keyword in text_to_search for keyword in keywords)

                passes_filter = False
                if vulnerability_to_process.cvss_score is None:
                    passes_filter = keyword_ok
                else:
                    passes_filter = (score_ok and keyword_ok) if logic == 'AND' else (score_ok or keyword_ok)

                if not passes_filter:
                    logger.debug(f"Vulnerabilità {vulnerability_to_process.id} scartata dai filtri.")
                    continue

            new_vulnerabilities.append(vulnerability_to_process)

        # Logica di notifica e salvataggio
        if new_vulnerabilities:
            logger.info(f"Trovate {len(new_vulnerabilities)} nuove vulnerabilità da notificare.")
            new_vulnerabilities.sort(key=lambda v: v.published_date)

            for vuln in new_vulnerabilities:
                if notifier.send(vuln):
                    state_manager.add_processed(vuln.id)

            state_manager.save()
        else:
            logger.info("Nessuna nuova vulnerabilità trovata in questo ciclo.")

        state_manager.update_last_run_time(current_run_start_time)

        elapsed_time = (datetime.now(timezone.utc) - current_run_start_time).total_seconds()
        wait_time = max(0, polling_interval_sec - elapsed_time)

        logger.info(
            f"Ciclo completato in {elapsed_time:.2f} secondi. Prossimo controllo previsto alle {(datetime.now(timezone.utc) + timedelta(seconds=wait_time)).strftime('%H:%M:%S')}.")
        time.sleep(wait_time)


if __name__ == "__main__":
    # Carica le variabili d'ambiente dal file .env PRIMA di fare qualsiasi altra cosa.
    load_dotenv()

    try:
        main()
    except KeyboardInterrupt:
        logger.info("Rilevata interruzione manuale (Ctrl+C). Arresto del bot.")
        send_admin_alert("ℹ️ **Bot arrestato manualmente.**")
    except Exception as e:
        error_msg = f"<b>ERRORE NON GESTITO NEL LOOP PRINCIPALE:</b>\n<code>{html.escape(str(e))}</code>\nIl bot si è arrestato in modo anomalo."
        logger.critical(error_msg.replace('<b>', '').replace('</b>', '').replace('<code>', '').replace('</code>', ''),
                        exc_info=True)
        send_admin_alert(error_msg, critical=True)