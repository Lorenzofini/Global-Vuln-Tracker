# src/sources/github_source.py
import logging
import requests
from datetime import datetime, timedelta, timezone
from typing import List
from .base_source import BaseSource
from ..models import Vulnerability

logger = logging.getLogger(__name__)


class GithubSource(BaseSource):
    """
    Gestisce la raccolta di vulnerabilità da GitHub Security Advisories
    tramite l'API GraphQL di GitHub.
    """
    API_URL = "https://api.github.com/graphql"

    def fetch(self) -> List[Vulnerability]:
        token = self.config.get('credentials', {}).get('github_token')
        if not token:
            logger.warning(f"[{self.name}] Token GitHub non fornito. Fonte disabilitata.")
            return []

        headers = {"Authorization": f"bearer {token}"}

        # Cerchiamo avvisi pubblicati nell'ultimo giorno.
        # GitHub supporta il filtro 'publishedSince'.
        fetch_since = self.config.get('fetch_since')
        since_date_str = fetch_since.isoformat()

        query = """
        query GetSecurityAdvisories($since: DateTime!) {
          securityAdvisories(first: 100, publishedSince: $since, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
            edges {
              node {
                ghsaId
                summary
                permalink
                publishedAt
                description
              }
            }
          }
        }
        """
        variables = {"since": since_date_str}

        logger.info(f"[{self.name}] Sto recuperando avvisi da GitHub pubblicati dopo {since_date_str}")

        try:
            response = requests.post(self.API_URL, headers=headers, json={'query': query, 'variables': variables},
                                     timeout=20)
            response.raise_for_status()
            data = response.json()

            if 'errors' in data:
                logger.error(f"[{self.name}] Errore GraphQL da GitHub: {data['errors']}")
                return []

        except (ConnectionError, requests.exceptions.RequestException, requests.exceptions.JSONDecodeError) as e:
            logger.error(f"[{self.name}] Errore nella richiesta all'API GitHub: {e}")
            return []

        vulnerabilities = []
        advisories = data.get('data', {}).get('securityAdvisories', {}).get('edges', [])

        for edge in advisories:
            try:
                node = edge['node']
                ghsa_id = node.get("ghsaId")
                if not ghsa_id:
                    continue

                published_date = datetime.fromisoformat(node['publishedAt'].replace('Z', ''))

                vuln = Vulnerability(
                    id=ghsa_id,
                    source=self.name,
                    title=f"GitHub Advisory: {node.get('summary', 'N/A')}",
                    link=node.get('permalink'),
                    published_date=published_date,
                    description=node.get('description')
                )
                vulnerabilities.append((vuln, node))
            except (KeyError, TypeError, ValueError) as e:
                logger.error(f"[{self.name}] Errore nel processare un advisory di GitHub: {e}", exc_info=True)

        logger.info(f"[{self.name}] Trovati {len(vulnerabilities)} avvisi da GitHub.")
        return vulnerabilities