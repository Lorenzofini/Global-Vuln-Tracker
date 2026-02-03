# src/config.py
import yaml
import os
import logging
from dotenv import load_dotenv
from typing import Dict, Any

logger = logging.getLogger(__name__)

def load_configuration(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Carica la configurazione dal file YAML."""
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logger.info(f"Configurazione caricata con successo da '{config_path}'.")
        return config
    except FileNotFoundError:
        logger.error(f"File di configurazione '{config_path}' non trovato.")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Errore nel parsing del file YAML '{config_path}': {e}")
        raise

def load_environment_variables(env_path: str = ".env") -> Dict[str, str]:
    """Carica le variabili d'ambiente e le valida."""
    # Forza il caricamento dal file .env
    load_dotenv(dotenv_path=env_path, override=True)

    required_vars = ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "ADMIN_CHAT_ID"]
    env_vars = {}

    for var in required_vars:
        value = os.getenv(var)
        if not value:
            raise ValueError(f"Variabile d'ambiente richiesta '{var}' non impostata nel file .env.")
        
        # Validazione specifica per l'ID della chat
        if var == "TELEGRAM_CHAT_ID" and not value.startswith("-100"):
            logger.warning(f"ATTENZIONE: {var} ('{value}') potrebbe non essere un ID Supergruppo/Forum valido. Di solito iniziano con -100.")
            
        env_vars[var] = value

    # Variabili opzionali
    env_vars["GITHUB_TOKEN"] = os.getenv("GITHUB_TOKEN")
    env_vars["NVD_API_KEY"] = os.getenv("NVD_API_KEY")

    logger.info("Variabili d'ambiente caricate correttamente.")
    return env_vars