# src/state_manager.py
import json
import logging
import os
from typing import Set, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class StateManager:
    """
    Gestisce la persistenza dello stato, inclusi gli ID processati
    e la data dell'ultimo ciclo di successo.
    """

    def __init__(self, state_file: str = "processed_vulnerabilities.json"):
        self.state_file_path = state_file
        self._state: Dict[str, Any] = self._load()
        self._processed_ids: Set[str] = set(self._state.get("processed_ids", []))

        # Recupera l'ultima data o None se non presente
        last_run_str = self._state.get("last_successful_run")
        if last_run_str:
            self.last_successful_run: datetime = datetime.fromisoformat(last_run_str)
        else:
            self.last_successful_run: datetime = None

    def _load(self) -> Dict[str, Any]:
        """Carica lo stato dal file JSON."""
        if not os.path.exists(self.state_file_path):
            logger.info(f"File di stato '{self.state_file_path}' non trovato. Verrà creato.")
            return {"processed_ids": [], "last_successful_run": None}

        try:
            with open(self.state_file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    logger.warning("Rilevato vecchio formato del file di stato (lista). "
                                   "Conversione al nuovo formato (dizionario).")
                    # Converte la vecchia lista nel nuovo formato a dizionario
                    return {"processed_ids": data, "last_successful_run": None}

                logger.info(f"Stato caricato da '{self.state_file_path}'.")
                return data
        except (json.JSONDecodeError, IOError) as e:
            logger.error(
                f"Errore nel caricare il file di stato '{self.state_file_path}': {e}. Verrà usato uno stato vuoto.")
            return {"processed_ids": [], "last_successful_run": None}

    def save(self):
        """Salva lo stato corrente nel file JSON."""
        self._state["processed_ids"] = list(self._processed_ids)

        try:
            with open(self.state_file_path, 'w', encoding='utf-8') as f:
                json.dump(self._state, f, indent=2)
            logger.debug(f"Stato salvato correttamente in '{self.state_file_path}'.")
        except IOError as e:
            logger.error(f"Impossibile scrivere sul file di stato '{self.state_file_path}': {e}")

    def is_processed(self, vuln_id: str) -> bool:
        """Controlla se un ID è già stato processato."""
        return vuln_id in self._processed_ids

    def add_processed(self, vuln_id: str):
        """Aggiunge un ID al set di quelli processati."""
        self._processed_ids.add(vuln_id)

    def update_last_run_time(self, run_time: datetime):
        """Aggiorna la data dell'ultimo ciclo di successo e la salva."""
        self.last_successful_run = run_time
        # Convertiamo in stringa formato ISO per la serializzazione JSON
        self._state["last_successful_run"] = run_time.isoformat()
        self.save()

    @property
    def processed_count(self) -> int:
        return len(self._processed_ids)