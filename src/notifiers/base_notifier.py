# src/notifiers/base_notifier.py
from abc import ABC, abstractmethod
from ..models import Vulnerability

class BaseNotifier(ABC):
    """Classe base astratta per tutti i sistemi di notifica."""
    @abstractmethod
    def send(self, vulnerability: Vulnerability) -> bool:
        """
        Invia una notifica per una data vulnerabilità.
        Restituisce True in caso di successo, False altrimenti.
        """
        pass