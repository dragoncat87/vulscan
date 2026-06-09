"""Finding data model and central findings engine for vulscan."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Hashable


@dataclass
class Finding:
    """Represents one security or compliance finding."""

    rule_id: str
    title: str
    description: str
    severity: str
    file_path: str
    line_number: int | None
    source: str
    mode: str
    cve_id: str | None
    ttp_id: str | None
    threat_ref: str | None
    remediation: str
    timestamp: str
    snippet: str | None = None
    url: str | None = None

    def to_dict(self) -> dict:
        """Return the finding as a plain dictionary."""
        return asdict(self)


SEVERITY_SCORES = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "unknown": 10,
}

MODE_MULTIPLIERS = {
    "detected": 1.0,
    "at_risk": 0.85,
}

SOURCE_MULTIPLIERS = {
    "traditional": 1.0,
    "preventive": 0.95,
}

SEVERITY_ORDER = ["low", "medium", "high", "critical"]
LOGGER_NAME = "vulscan.engine.findings"


def get_snippet(lines: list[str], line_no: int, context: int = 1) -> str:
    """
    Returns a 3-line code snippet centred on line_no.
    Marks the finding line with an arrow.
    """
    start = max(0, line_no - 1 - context)
    end = min(len(lines), line_no + context)
    snippet_lines = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        marker = "→ " if i == line_no else "  "
        snippet_lines.append(f"{marker}{i:4d} │ {line.rstrip()}")
    return "\n".join(snippet_lines)


def score_finding(finding: Finding) -> float:
    """
    Computes a numeric risk score for a single finding.

    Score = severity_score * mode_multiplier * source_multiplier.
    Returns a float rounded to 2 decimal places.
    """
    severity = finding.severity.lower()
    mode = finding.mode.lower()
    source = finding.source.lower()

    severity_score = SEVERITY_SCORES.get(
        severity,
        SEVERITY_SCORES["unknown"],
    )
    mode_multiplier = MODE_MULTIPLIERS.get(mode, 1.0)
    source_multiplier = SOURCE_MULTIPLIERS.get(source, 1.0)
    score = round(severity_score * mode_multiplier * source_multiplier, 2)

    logging.getLogger(LOGGER_NAME).debug(
        "Score calculation for %s in %s:%s = %s "
        "(severity=%s, mode=%s, source=%s)",
        finding.rule_id,
        finding.file_path,
        finding.line_number,
        score,
        severity,
        mode,
        source,
    )

    return score


def _dedupe_key(finding: Finding) -> tuple[Hashable, ...]:
    """Build the composite deduplication key for a finding."""
    if finding.source == "preventive" and finding.line_number is None:
        return (
            finding.file_path,
            finding.rule_id,
            finding.description[:50],
        )

    return (
        finding.file_path,
        finding.line_number,
        finding.rule_id,
    )


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Deduplicates findings across all scanners using a composite key.

    When duplicates exist, keeps the one with the highest score.
    Composite key: (file_path, line_number, rule_id).
    For preventive findings where line_number is None, key is:
    (file_path, rule_id, description[:50]).
    """
    deduped: dict[tuple[Hashable, ...], Finding] = {}

    for finding in findings:
        key = _dedupe_key(finding)
        current = deduped.get(key)

        if current is None:
            deduped[key] = finding
            continue

        if score_finding(finding) > score_finding(current):
            deduped[key] = finding

    return list(deduped.values())


def filter_by_severity(
    findings: list[Finding],
    minimum_severity: str,
) -> list[Finding]:
    """
    Filters findings to only include those at or above the minimum severity.

    Order: critical > high > medium > low.
    Unknown severities are always included.
    """
    minimum = minimum_severity.lower()
    if minimum not in SEVERITY_ORDER:
        minimum = "low"

    minimum_index = SEVERITY_ORDER.index(minimum)
    filtered: list[Finding] = []

    for finding in findings:
        severity = finding.severity.lower()

        if severity not in SEVERITY_ORDER:
            filtered.append(finding)
            continue

        if SEVERITY_ORDER.index(severity) >= minimum_index:
            filtered.append(finding)

    return filtered


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """
    Sorts findings by score descending, then by file_path ascending,
    then by line_number ascending with None last.
    """
    return sorted(
        findings,
        key=lambda finding: (
            -score_finding(finding),
            finding.file_path,
            finding.line_number or 999999,
        ),
    )


def _scanner_name(rule_id: str) -> str | None:
    """Map a rule ID prefix to the scanner category used in summaries."""
    if rule_id.startswith(("CS-", "SG-", "AST-")):
        return "code"
    if rule_id.startswith("CF-"):
        return "config"
    if rule_id.startswith(("API-", "SPEC-")):
        return "api"
    if rule_id.startswith("TP-"):
        return "threat"

    return None


def build_summary(findings: list[Finding]) -> dict:
    """
    Builds a summary dict from a final findings list.

    The summary is used by all output formatters.
    """
    by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    by_source = {
        "traditional": 0,
        "preventive": 0,
    }
    by_mode = {
        "detected": 0,
        "at_risk": 0,
    }
    by_scanner = {
        "code": 0,
        "config": 0,
        "api": 0,
        "threat": 0,
    }

    for finding in findings:
        severity = finding.severity.lower()
        source = finding.source.lower()
        mode = finding.mode.lower()
        scanner = _scanner_name(finding.rule_id)

        if severity in by_severity:
            by_severity[severity] += 1
        if source in by_source:
            by_source[source] += 1
        if mode in by_mode:
            by_mode[mode] += 1
        if scanner is not None:
            by_scanner[scanner] += 1

    total = len(findings)
    risk_score = 0.0
    if total > 0:
        risk_score = round(
            sum(score_finding(finding) for finding in findings) / total,
            2,
        )

    return {
        "total": total,
        "by_severity": by_severity,
        "by_source": by_source,
        "by_mode": by_mode,
        "by_scanner": by_scanner,
        "top_findings": [
            finding.to_dict() for finding in sort_findings(findings)[:5]
        ],
        "risk_score": risk_score,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


class FindingsEngine:
    """
    Central engine that receives raw findings from all scanners,
    deduplicates across sources, scores, filters, sorts, and
    produces a final findings report with summary statistics.
    """

    def __init__(self, minimum_severity: str = "low"):
        self.minimum_severity = minimum_severity
        self.logger = logging.getLogger(LOGGER_NAME)
        self._raw_findings: list[Finding] = []

    def add_findings(self, findings: list[Finding], scanner_name: str) -> None:
        """
        Adds findings from a scanner to the engine.

        Logs count per scanner.
        """
        self.logger.info(
            f"{scanner_name}: {len(findings)} raw finding(s) added."
        )
        self._raw_findings.extend(findings)

    def process(self) -> tuple[list[Finding], dict]:
        """
        Runs the full pipeline.

        1. Cross-scanner deduplication
        2. Severity filtering
        3. Sorting by score
        4. Summary generation

        Returns (final_findings, summary).
        """
        self.logger.info(
            f"Processing {len(self._raw_findings)} total raw findings..."
        )

        deduped = deduplicate_findings(self._raw_findings)
        self.logger.info(
            f"After deduplication: {len(deduped)} finding(s)."
        )

        filtered = filter_by_severity(deduped, self.minimum_severity)
        self.logger.info(
            f"After severity filter ({self.minimum_severity}+): "
            f"{len(filtered)} finding(s)."
        )

        sorted_findings = sort_findings(filtered)
        summary = build_summary(sorted_findings)

        self.logger.info(
            f"Final report: {summary['total']} finding(s). "
            f"Risk score: {summary['risk_score']}."
        )

        return sorted_findings, summary
