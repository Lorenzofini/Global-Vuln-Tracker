import logging
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Tuple
import requests
from datetime import datetime
from ..models import Vulnerability

logger = logging.getLogger(__name__)

class BaseSource(ABC):
    def __init__(self, name: str, type: str = None, enabled: bool = True, 
                 fetch_since: datetime = None, credentials: dict = None, **kwargs):
        self.name = name
        self.type = type
        self.enabled = enabled
        self.fetch_since = fetch_since
        self.credentials = credentials or {}
        self.config = kwargs

    @abstractmethod
    def fetch(self) -> List[Tuple[Vulnerability, Optional[Dict[str, Any]]]]:
        pass

    def _make_request(self, url: str, headers: Optional[Dict] = None,
                      params: Optional[Dict] = None) -> requests.Response:
        retries = 3
        delay = 5
        for i in range(retries):
            try:
                with requests.Session() as session:
                    req = requests.Request('GET', url, headers=headers, params=params)
                    prepared_req = session.prepare_request(req)
                    response = session.send(prepared_req, timeout=25)
                response.raise_for_status()
                return response
            except Exception as e:
                if i < retries - 1:
                    time.sleep(delay)
                    delay *= 2
                else:
                    raise e