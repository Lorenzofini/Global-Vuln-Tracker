# src/sources/base_source.py
import logging  # <-- AGGIUNTO
import time  # <-- AGGIUNTO
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import requests
from ..models import Vulnerability

logger = logging.getLogger(__name__)  # <-- AGGIUNTO


class BaseSource(ABC):
    """Classe base astratta per tutte le fonti di vulnerabilità."""

    def __init__(self, name: str, **kwargs):
        self.name = name
        self.config = kwargs

    @abstractmethod
    def fetch(self) -> List[Vulnerability]:
        """
        Recupera le vulnerabilità dalla fonte.
        Deve restituire una lista di oggetti Vulnerability.
        """
        pass

    # La firma della funzione ora accetta 'params'
    def _make_request(self, url: str, headers: Optional[Dict] = None,
                      params: Optional[Dict] = None) -> requests.Response:
        """
        Metodo helper per effettuare richieste HTTP con gestione degli errori e logica di retry.
        """
        retries = 3
        delay = 5

        for i in range(retries):
            try:
                with requests.Session() as session:
                    # La variabile 'params' ora viene dal parametro della funzione
                    req = requests.Request('GET', url, headers=headers, params=params)
                    prepared_req = session.prepare_request(req)

                    logger.debug(f"[{self.name}] Tentativo {i + 1}/{retries} per URL: {prepared_req.url}")
                    response = session.send(prepared_req, timeout=20)

                response.raise_for_status()
                return response

            except requests.exceptions.RequestException as e:
                logger.warning(f"[{self.name}] Tentativo {i + 1}/{retries} fallito: {e}.")
                if i < retries - 1:
                    logger.info(f"[{self.name}] Riprovo tra {delay} secondi...")
                    time.sleep(delay)
                    delay *= 2
                else:
                    logger.error(f"[{self.name}] Tutti i {retries} tentativi sono falliti per l'URL: {url}")
                    raise ConnectionError(f"Errore di rete per la fonte {self.name} dopo {retries} tentativi.") from e