"""Plugin contract for findings enrichment."""
from typing import Any, Protocol, List, Dict, Optional


class FindingsEnricher(Protocol):
    """Protocol that premium enrichers must implement.

    Enrichers are discovered via entry_points (group: gerion.enrichers).
    """

    def enrich(
        self,
        findings: List[Dict[str, Any]],
        code_path: str,
        scanner: str,
        raw_output: Any = None,
    ) -> List[Dict[str, Any]]:
        """Enrich normalized findings with premium data.

        Args:
            findings: Normalized finding dicts (from tool_parser).
            code_path: Path to the scanned source code.
            scanner: Scanner type ("SAST", "SCA", "Secrets", "IaC").
            raw_output: Raw scanner output (list/dict) before normalization.

        Returns:
            The findings list with premium fields populated
            (risk_score, reachability, trace, confidence, score_breakdown).
        """
        ...
