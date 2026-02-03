# src/state_manager.py
import json
import logging
import os
from typing import Set, Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class StateManager:
    def __init__(self, state_file: str = "processed_vulnerabilities.json"):
        self.state_file_path = state_file
        self._state: Dict[str, Any] = self._load()
        self._processed_ids: Set[str] = set(self._state.get("processed_ids", []))
        
        last_run_str = self._state.get("last_successful_run")
        self.last_successful_run = datetime.fromisoformat(last_run_str) if last_run_str else None

    def _load(self) -> Dict[str, Any]:
        default_state = {"processed_ids": [], "last_successful_run": None}
        if not os.path.exists(self.state_file_path) or os.path.getsize(self.state_file_path) == 0:
            return default_state
        try:
            with open(self.state_file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"File stato corrotto: {e}. Resetting...")
            return default_state

    def save(self):
        """Salva lo stato in modo atomico per evitare corruzioni."""
        self._state["processed_ids"] = list(self._processed_ids)
        temp_file = f"{self.state_file_path}.tmp"
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(self._state, f, indent=2)
            # Sostituzione atomica del file
            os.replace(temp_file, self.state_file_path)
        except Exception as e:
            logger.error(f"Errore critico nel salvataggio dello stato: {e}")

    def is_processed(self, vuln_id: str) -> bool:
        return vuln_id in self._processed_ids

    def add_processed(self, vuln_id: str):
        self._processed_ids.add(vuln_id)

    def update_last_run_time(self, run_time: datetime):
        self.last_successful_run = run_time
        self._state["last_successful_run"] = run_time.isoformat()
        self.save()