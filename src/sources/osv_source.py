# src/sources/osv_source.py
import logging
from .rss_source import RssSource

logger = logging.getLogger(__name__)

class OsvSource(RssSource):
    """
    Gestore per OSV.dev.
    Attualmente, utilizza il feed Atom dei commit sul database di vulnerabilità,
    che viene gestito in modo identico a un feed RSS.
    Questa classe separata esiste per consentire una futura implementazione
    che utilizzi l'API specifica di OSV.dev, se necessario.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        logger.debug(f"[{self.name}] Inizializzato come gestore di tipo RSS/Atom.")