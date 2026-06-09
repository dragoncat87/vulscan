"""Output formatting for vulscan reports."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime
import json
import csv
import io
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from vulscan.engine.findings import Finding


LOGGER = logging.getLogger("vulscan.outputs.formatter")
VULSCAN_VERSION = "0.1.0"

SEVERITY_COLOURS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "unknown": "dim",
}

MODE_LABELS = {
    "detected": "[bold red]DETECTED[/bold red]",
    "at_risk": "[bold yellow]AT-RISK[/bold yellow]",
}

HTML_SEVERITY_COLOURS = {
    "critical": "#ff4444",
    "high": "#ff8800",
    "medium": "#ffcc00",
    "low": "#44bb44",
    "unknown": "#999999",
}

CSV_COLUMNS = [
    "rule_id",
    "severity",
    "mode",
    "source",
    "title",
    "file_path",
    "line_number",
    "cve_id",
    "ttp_id",
    "threat_ref",
    "remediation",
    "description",
    "timestamp",
]


class OutputFormatterError(RuntimeError):
    """Raised when a report cannot be written."""


def _now_stamp() -> str:
    """Return a timestamp suitable for report filenames."""
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _field(finding: Finding, name: str, default: object = "") -> object:
    """Safely read a field from a Finding or mapping-like object."""
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _finding_to_dict(finding: Finding) -> dict:
    """Convert a Finding object into a plain dictionary."""
    if isinstance(finding, dict):
        return dict(finding)
    to_dict = getattr(finding, "to_dict", None)
    if callable(to_dict):
        return to_dict()

    return {
        column: _field(finding, column, "")
        for column in CSV_COLUMNS
    }


def _normalise(value: object, default: str = "unknown") -> str:
    """Convert a value to a lowercase string for comparisons."""
    if value is None:
        return default
    text = str(value).strip().lower()
    return text or default


def _html_escape(value: object) -> str:
    """Escape a value for safe use in a self-contained HTML report."""
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _risk_score(summary: dict) -> float:
    """Extract the overall risk score from a summary dictionary."""
    value = (
        summary.get("overall_risk_score")
        or summary.get("risk_score")
        or summary.get("score")
        or 0
    )
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _scan_timestamp(summary: dict) -> str:
    """Extract or generate the scan timestamp for display."""
    timestamp = (
        summary.get("scan_timestamp")
        or summary.get("timestamp")
        or summary.get("generated_at")
    )
    return str(timestamp) if timestamp else datetime.now().isoformat(timespec="seconds")


def _summary_breakdown(
    findings: list[Finding],
    summary: dict,
    summary_keys: tuple[str, ...],
    finding_attr: str,
    expected_keys: tuple[str, ...],
) -> dict[str, int]:
    """Return a count breakdown from summary data or computed findings."""
    for key in summary_keys:
        value = summary.get(key)
        if isinstance(value, dict):
            return {
                str(item_key).lower(): int(item_value)
                for item_key, item_value in value.items()
            }

    counts = {key: 0 for key in expected_keys}
    for finding in findings:
        label = _normalise(_field(finding, finding_attr, "unknown"))
        counts[label] = counts.get(label, 0) + 1
    return counts


def _severity_counts(findings: list[Finding], summary: dict) -> dict[str, int]:
    """Return finding counts by severity."""
    return _summary_breakdown(
        findings,
        summary,
        ("severity", "severity_counts", "by_severity", "severity_breakdown"),
        "severity",
        ("critical", "high", "medium", "low", "unknown"),
    )


def _scanner_counts(findings: list[Finding], summary: dict) -> dict[str, int]:
    """Return finding counts by scanner/source."""
    return _summary_breakdown(
        findings,
        summary,
        ("scanner", "scanner_counts", "by_scanner", "source_breakdown"),
        "source",
        ("code", "config", "api", "threat"),
    )


def _mode_counts(findings: list[Finding], summary: dict) -> dict[str, int]:
    """Return finding counts by detection mode."""
    return _summary_breakdown(
        findings,
        summary,
        ("mode", "mode_counts", "by_mode", "mode_breakdown"),
        "mode",
        ("detected", "at_risk"),
    )


def _total_findings(findings: list[Finding], summary: dict) -> int:
    """Return the total finding count from summary or findings length."""
    value = summary.get("total_findings") or summary.get("total")
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            pass
    return len(findings)


def _format_location(finding: Finding, basename_only: bool = False) -> str:
    """Format a finding location with an optional line number."""
    file_path = str(_field(finding, "file_path", "") or "")
    line_number = _field(finding, "line_number", "")
    location = Path(file_path).name if basename_only and file_path else file_path

    if line_number:
        return f"{location}:{line_number}"
    return location or "-"


def _truncate(text: object, limit: int = 50) -> str:
    """Truncate text to a maximum length, preserving readability."""
    value = "" if text is None else str(text)
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _severity_style(severity: object) -> str:
    """Return the rich style for a severity value."""
    return SEVERITY_COLOURS.get(_normalise(severity), SEVERITY_COLOURS["unknown"])


def _sarif_level(severity: object) -> str:
    """Map vulscan severity to SARIF result level."""
    value = _normalise(severity)
    if value in {"critical", "high"}:
        return "error"
    if value == "medium":
        return "warning"
    return "note"


def _risk_colour(score: float) -> str:
    """Return a CSS colour for an overall risk score."""
    if score >= 75:
        return "#cc0000"
    if score >= 50:
        return "#ff8800"
    if score >= 25:
        return "#ffcc00"
    return "#44bb44"


def _mode_badge_class(mode: object) -> str:
    """Return the CSS class suffix for a finding mode."""
    value = _normalise(mode, "at_risk")
    return "detected" if value == "detected" else "at-risk"


def _ensure_output_dir(output_dir: Path) -> None:
    """Create the output directory, logging and raising on failure."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        LOGGER.warning("Failed to create output directory %s: %s", output_dir, exc)
        raise OutputFormatterError(
            f"Failed to create output directory {output_dir}"
        ) from exc


def _write_text(path: Path, content: str) -> None:
    """Write text content to a file, logging and raising on failure."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        LOGGER.warning("Failed to write report to %s: %s", path, exc)
        raise OutputFormatterError(f"Failed to write report to {path}") from exc


def _score_value(finding: Finding) -> float:
    """Return a numeric score for sorting finding details."""
    try:
        return float(_field(finding, "score", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def _line_number(finding: Finding) -> int:
    """Return a SARIF-compatible line number."""
    try:
        return int(_field(finding, "line_number", 1) or 1)
    except (TypeError, ValueError):
        return 1


def format_terminal(
    findings: list[Finding],
    summary: dict,
    console: Console,
) -> None:
    """
    Render findings to the terminal using rich.

    Shows a summary panel, then a table of all findings, followed by
    detailed panels for the top three highest-scoring findings.
    """
    LOGGER.debug("Formatting %s findings for terminal", len(findings))

    severity_counts = _severity_counts(findings, summary)
    scanner_counts = _scanner_counts(findings, summary)
    mode_counts = _mode_counts(findings, summary)
    total = _total_findings(findings, summary)
    score = _risk_score(summary)
    timestamp = _scan_timestamp(summary)

    summary_text = Text()
    summary_text.append(f"Total findings: {total}\n", style="bold")
    summary_text.append("Severity: ", style="bold")
    for severity in ("critical", "high", "medium", "low", "unknown"):
        count = severity_counts.get(severity, 0)
        if count:
            summary_text.append(
                f"{severity}={count} ",
                style=SEVERITY_COLOURS.get(severity, "dim"),
            )
    summary_text.append("\nScanner: ", style="bold")
    summary_text.append(
        ", ".join(
            f"{scanner}={scanner_counts.get(scanner, 0)}"
            for scanner in ("code", "config", "api", "threat")
        )
    )
    summary_text.append("\nMode: ", style="bold")
    summary_text.append(
        ", ".join(
            f"{mode}={mode_counts.get(mode, 0)}"
            for mode in ("detected", "at_risk")
        )
    )
    summary_text.append(f"\nOverall risk score: {score:g}", style="bold")
    summary_text.append(f"\nScan timestamp: {timestamp}")

    console.print(
        Panel(
            summary_text,
            title="vulscan summary",
            border_style="blue",
            box=box.ROUNDED,
        )
    )

    if not findings:
        minimum_severity = str(summary.get("minimum_severity", "configured"))
        console.print(
            Panel(
                f"No findings at or above {minimum_severity} severity.\n"
                "Looking clean!",
                style="green",
                box=box.ROUNDED,
            )
        )
        return

    table = Table(title="Findings", box=box.SIMPLE_HEAVY)
    for column in ("#", "Severity", "Mode", "Rule", "Title", "Location", "Source", "Snippet"):
        table.add_column(column)

    for index, finding in enumerate(findings, start=1):
        severity = _normalise(_field(finding, "severity", "unknown"))
        mode = _normalise(_field(finding, "mode", "at_risk"), "at_risk")
        snippet = _field(finding, "snippet", "")
        if snippet is not None and snippet != "":
            snippet_preview = _truncate(str(snippet).split("\n")[0], 60)
        else:
            snippet_preview = "—"
        table.add_row(
            str(index),
            f"[{_severity_style(severity)}]{severity.upper()}[/]",
            MODE_LABELS.get(mode, mode.upper()),
            str(_field(finding, "rule_id", "")),
            _truncate(_field(finding, "title", ""), 50),
            _format_location(finding, basename_only=True),
            str(_field(finding, "source", "")),
            snippet_preview,
        )

    console.print(table)

    top_findings = sorted(
        findings,
        key=_score_value,
        reverse=True,
    )[:3]

    for finding in top_findings:
        details = io.StringIO()
        details.write(f"Title: {_field(finding, 'title', '')}\n")
        details.write(f"Rule ID: {_field(finding, 'rule_id', '')}\n")
        details.write(f"Severity: {_field(finding, 'severity', 'unknown')}\n")
        details.write(f"Mode: {_field(finding, 'mode', '')}\n\n")
        details.write(f"Description:\n{_field(finding, 'description', '')}\n")
        snippet = _field(finding, "snippet", "")
        if snippet is not None and snippet != "":
            lines_in_snippet = str(snippet).split("\n")
            snippet_text = "\n".join(f"  {line}" for line in lines_in_snippet)
            details.write(f"\n[bold]Code:[/bold]\n[dim]{snippet_text}[/dim]\n")
        details.write(f"\nLocation: {_format_location(finding)}\n")

        cve_id = _field(finding, "cve_id", "")
        ttp_id = _field(finding, "ttp_id", "")
        if cve_id:
            details.write(f"CVE ID: {cve_id}\n")
        if ttp_id:
            details.write(f"TTP ID: {ttp_id}\n")
        details.write(
            f"\n[green]Remediation:[/green] "
            f"{_field(finding, 'remediation', '')}"
        )

        console.print(
            Panel(
                details.getvalue(),
                title=str(_field(finding, "rule_id", "Finding detail")),
                border_style=_severity_style(_field(finding, "severity", "unknown")),
                box=box.ROUNDED,
            )
        )


def format_json(
    findings: list[Finding],
    summary: dict,
    output_dir: Path,
) -> Path:
    """
    Write findings and summary to a JSON file.

    Returns the output file path.
    """
    LOGGER.debug("Formatting %s findings for JSON", len(findings))
    _ensure_output_dir(output_dir)
    path = output_dir / f"vulscan-report-{_now_stamp()}.json"
    payload = {
        "vulscan_version": VULSCAN_VERSION,
        "summary": summary,
        "findings": [_finding_to_dict(finding) for finding in findings],
    }

    try:
        with path.open("w", encoding="utf-8") as report_file:
            json.dump(payload, report_file, indent=2, default=str)
    except OSError as exc:
        LOGGER.warning("Failed to write JSON report to %s: %s", path, exc)
        raise OutputFormatterError(f"Failed to write JSON report to {path}") from exc

    LOGGER.info("JSON report written to %s", path)
    return path


def format_csv(
    findings: list[Finding],
    output_dir: Path,
) -> Path:
    """
    Write findings to a CSV file.

    Returns the output file path.
    """
    LOGGER.debug("Formatting %s findings for CSV", len(findings))
    _ensure_output_dir(output_dir)
    path = output_dir / f"vulscan-report-{_now_stamp()}.csv"

    try:
        with path.open("w", encoding="utf-8", newline="") as report_file:
            writer = csv.DictWriter(
                report_file,
                fieldnames=CSV_COLUMNS,
                extrasaction="ignore",
            )
            writer.writeheader()
            for finding in findings:
                row = {column: "" for column in CSV_COLUMNS}
                row.update(_finding_to_dict(finding))
                writer.writerow(row)
    except OSError as exc:
        LOGGER.warning("Failed to write CSV report to %s: %s", path, exc)
        raise OutputFormatterError(f"Failed to write CSV report to {path}") from exc

    LOGGER.info("CSV report written to %s", path)
    return path


def format_html(
    findings: list[Finding],
    summary: dict,
    output_dir: Path,
    active_scanners: list[str],
) -> Path:
    """
    Write a self-contained HTML report.

    No external dependencies are used; all CSS is inline. Returns the output
    file path.
    """
    LOGGER.debug("Formatting %s findings for HTML", len(findings))
    _ensure_output_dir(output_dir)
    path = output_dir / f"vulscan-report-{_now_stamp()}.html"

    severity_counts = _severity_counts(findings, summary)
    scanner_counts = _scanner_counts(findings, summary)
    mode_counts = _mode_counts(findings, summary)
    total = _total_findings(findings, summary)
    critical_high = severity_counts.get("critical", 0) + severity_counts.get(
        "high", 0
    )
    detected = mode_counts.get("detected", 0)
    at_risk = mode_counts.get("at_risk", 0)
    score = _risk_score(summary)
    risk_colour = _risk_colour(score)
    timestamp = _scan_timestamp(summary)

    rows = []
    for finding in findings:
        severity = _normalise(_field(finding, "severity", "unknown"))
        mode = _normalise(_field(finding, "mode", "at_risk"), "at_risk")
        severity_colour = HTML_SEVERITY_COLOURS.get(
            severity,
            HTML_SEVERITY_COLOURS["unknown"],
        )
        rows.append(
            "<tr>"
            f"<td><span class='severity' "
            f"style='background:{severity_colour};'>"
            f"{_html_escape(severity.upper())}</span></td>"
            f"<td><span class='badge {_mode_badge_class(mode)}'>"
            f"{_html_escape(mode.replace('_', '-').upper())}</span></td>"
            f"<td>{_html_escape(_field(finding, 'rule_id', ''))}</td>"
            f"<td>{_html_escape(_field(finding, 'title', ''))}</td>"
            f"<td>{_html_escape(_format_location(finding))}</td>"
            f"<td>{_html_escape(_field(finding, 'cve_id', ''))}</td>"
            f"<td>{_html_escape(_field(finding, 'ttp_id', ''))}</td>"
            f"<td>{_html_escape(_field(finding, 'remediation', ''))}</td>"
            "</tr>"
        )

    if not rows:
        rows.append(
            "<tr><td colspan='8' class='empty'>"
            "No findings at or above the configured severity. Looking clean!"
            "</td></tr>"
        )

    max_scanner_count = max(scanner_counts.values(), default=0) or 1
    effective_active = {
        _normalise(scanner)
        for scanner in (active_scanners or ["code", "config", "api"])
    }
    scanner_bars = []
    for scanner in ("code", "config", "api", "threat"):
        count = scanner_counts.get(scanner, 0)
        if scanner not in effective_active:
            scanner_bars.append(
                "<div class='bar-row'>"
                f"<span class='bar-label'>{_html_escape(scanner)}</span>"
                "<div class='bar-track'>"
                "<div class='bar-fill' "
                "style='width:0%;background:#cbd5e1;'></div>"
                "</div>"
                "<span class='bar-count' style='color:#94a3b8;'>—</span>"
                "<span class='bar-badge not-run'>NOT RUN</span>"
                "</div>"
            )
        elif count == 0:
            scanner_bars.append(
                "<div class='bar-row'>"
                f"<span class='bar-label'>{_html_escape(scanner)}</span>"
                "<div class='bar-track'>"
                "<div class='bar-fill' "
                "style='width:100%;background:#22c55e;opacity:0.3;'></div>"
                "</div>"
                "<span class='bar-count' style='color:#16a34a;'>0</span>"
                "<span class='bar-badge clean'>CLEAN</span>"
                "</div>"
            )
        else:
            width = int((count / max_scanner_count) * 100)
            scanner_bars.append(
                "<div class='bar-row'>"
                f"<span class='bar-label'>{_html_escape(scanner)}</span>"
                "<div class='bar-track'>"
                f"<div class='bar-fill' style='width:{width}%;'></div>"
                "</div>"
                f"<span class='bar-count'>{count}</span>"
                "</div>"
            )

    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>vulscan report</title>
  <style>
    body {{
      margin: 0;
      background: #f4f6f8;
      color: #17202a;
      font-family: Arial, Helvetica, sans-serif;
    }}
    header {{
      background: #111827;
      color: #ffffff;
      padding: 32px 40px;
    }}
    header h1 {{
      margin: 0 0 8px 0;
      font-size: 36px;
      letter-spacing: 1px;
    }}
    .timestamp {{
      color: #cbd5e1;
      margin: 0;
    }}
    .risk-score {{
      display: inline-block;
      margin-top: 18px;
      padding: 12px 18px;
      border-radius: 12px;
      background: {risk_colour};
      color: #111827;
      font-size: 30px;
      font-weight: bold;
    }}
    main {{
      padding: 32px 40px;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(4, minmax(150px, 1fr));
      gap: 16px;
      margin-bottom: 30px;
    }}
    .card {{
      background: #ffffff;
      border-radius: 14px;
      box-shadow: 0 6px 18px rgba(15, 23, 42, 0.08);
      padding: 20px;
    }}
    .card-title {{
      color: #64748b;
      font-size: 13px;
      font-weight: bold;
      letter-spacing: .04em;
      text-transform: uppercase;
    }}
    .card-value {{
      margin-top: 10px;
      font-size: 28px;
      font-weight: bold;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: #ffffff;
      border-radius: 14px;
      overflow: hidden;
      box-shadow: 0 6px 18px rgba(15, 23, 42, 0.08);
    }}
    th, td {{
      border-bottom: 1px solid #e5e7eb;
      padding: 12px 14px;
      text-align: left;
      vertical-align: top;
      font-size: 14px;
    }}
    th {{
      background: #e2e8f0;
      color: #0f172a;
      font-size: 12px;
      letter-spacing: .04em;
      text-transform: uppercase;
    }}
    .severity {{
      border-radius: 999px;
      color: #111827;
      display: inline-block;
      font-weight: bold;
      padding: 5px 9px;
    }}
    .badge {{
      border-radius: 999px;
      color: #ffffff;
      display: inline-block;
      font-weight: bold;
      padding: 5px 9px;
    }}
    .detected {{
      background: #dc2626;
    }}
    .at-risk {{
      background: #f97316;
    }}
    .empty {{
      color: #15803d;
      font-weight: bold;
      text-align: center;
    }}
    .scanner-section {{
      margin-top: 32px;
      background: #ffffff;
      border-radius: 14px;
      box-shadow: 0 6px 18px rgba(15, 23, 42, 0.08);
      padding: 22px;
    }}
    .bar-row {{
      align-items: center;
      display: grid;
      grid-template-columns: 80px 1fr 40px 82px;
      gap: 12px;
      margin: 12px 0;
    }}
    .bar-label {{
      font-weight: bold;
      text-transform: uppercase;
    }}
    .bar-track {{
      background: #e5e7eb;
      border-radius: 999px;
      height: 16px;
      overflow: hidden;
    }}
    .bar-fill {{
      background: #2563eb;
      height: 100%;
    }}
    .bar-count {{
      font-weight: bold;
      text-align: right;
    }}
    .bar-badge {{
      border-radius: 999px;
      display: inline-block;
      font-size: 11px;
      font-weight: bold;
      padding: 4px 8px;
      text-align: center;
    }}
    .bar-badge.not-run {{
      background: #e2e8f0;
      color: #64748b;
    }}
    .bar-badge.clean {{
      background: #dcfce7;
      color: #16a34a;
    }}
  </style>
</head>
<body>
  <header>
    <h1>vulscan</h1>
    <p class="timestamp">Scan timestamp: {_html_escape(timestamp)}</p>
    <div class="risk-score">Risk Score: {score:g}</div>
  </header>
  <main>
    <section class="cards">
      <div class="card">
        <div class="card-title">Total Findings</div>
        <div class="card-value">{total}</div>
      </div>
      <div class="card">
        <div class="card-title">Critical + High</div>
        <div class="card-value">{critical_high}</div>
      </div>
      <div class="card">
        <div class="card-title">Detected vs At-Risk</div>
        <div class="card-value">{detected} / {at_risk}</div>
      </div>
      <div class="card">
        <div class="card-title">Risk Score</div>
        <div class="card-value">{score:g}</div>
      </div>
    </section>

    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Mode</th>
          <th>Rule ID</th>
          <th>Title</th>
          <th>Location</th>
          <th>CVE</th>
          <th>TTP</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>

    <section class="scanner-section">
      <h2>By Scanner</h2>
      {''.join(scanner_bars)}
    </section>
  </main>
</body>
</html>
"""

    _write_text(path, html)
    LOGGER.info("HTML report written to %s", path)
    return path


def format_sarif(
    findings: list[Finding],
    summary: dict,
    output_dir: Path,
) -> Path:
    """
    Write findings in SARIF 2.1.0 format.

    The output is compatible with GitHub Advanced Security, VS Code SARIF
    viewer, and standard CI/CD security dashboards. Returns the output file
    path.
    """
    LOGGER.debug("Formatting %s findings for SARIF", len(findings))
    _ensure_output_dir(output_dir)
    path = output_dir / f"vulscan-report-{_now_stamp()}.sarif"

    rules_by_id: dict[str, dict] = {}
    results = []

    for finding in findings:
        rule_id = str(_field(finding, "rule_id", ""))
        title = str(_field(finding, "title", ""))
        description = str(_field(finding, "description", ""))
        severity = str(_field(finding, "severity", "unknown"))
        cve_id = str(_field(finding, "cve_id", "") or "")
        ttp_id = str(_field(finding, "ttp_id", "") or "")

        if rule_id and rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
                "helpUri": "",
                "properties": {
                    "severity": severity,
                    "ttp_id": ttp_id,
                    "cve_id": cve_id,
                },
            }

        results.append(
            {
                "ruleId": rule_id,
                "level": _sarif_level(severity),
                "message": {"text": description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(_field(finding, "file_path", "")),
                            },
                            "region": {
                                "startLine": _line_number(finding),
                            },
                        },
                    }
                ],
                "properties": {
                    "mode": _field(finding, "mode", ""),
                    "source": _field(finding, "source", ""),
                    "remediation": _field(finding, "remediation", ""),
                },
            }
        )

    payload = {
        "$schema": (
            "https://schemastore.azurewebsites.net/schemas/json/"
            "sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vulscan",
                        "version": VULSCAN_VERSION,
                        "informationUri": "https://github.com/vulscan/vulscan",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "properties": {"summary": summary},
            }
        ],
    }

    try:
        with path.open("w", encoding="utf-8") as report_file:
            json.dump(payload, report_file, indent=2, default=str)
    except OSError as exc:
        LOGGER.warning("Failed to write SARIF report to %s: %s", path, exc)
        raise OutputFormatterError(f"Failed to write SARIF report to {path}") from exc

    LOGGER.info("SARIF report written to %s", path)
    return path


class OutputFormatter:
    """
    Render vulscan findings in all requested output formats.

    Supported formats: terminal, json, html, csv, sarif.
    """

    def __init__(
        self,
        findings: list[Finding],
        summary: dict,
        output_formats: list[str],
        output_dir: str,
        minimum_severity: str = "low",
        active_scanners: list[str] | None = None,
        verbose: bool = False,
    ) -> None:
        """Initialize the output formatter."""
        self.findings = findings
        self.summary = summary
        self.output_formats = output_formats
        self.output_dir = Path(output_dir)
        self.minimum_severity = minimum_severity
        self.active_scanners = active_scanners or []
        self.verbose = verbose
        self.console = Console()
        self.logger = logging.getLogger("vulscan.outputs.formatter")
        self.written_files: list[Path] = []

    def format_all(self) -> list[Path]:
        """
        Run all requested formatters.

        Returns a list of file paths written. The list is empty when only
        terminal output is requested.
        """
        for fmt in self.output_formats:
            self.logger.debug(
                "Formatting %s findings as %s",
                len(self.findings),
                fmt,
            )
            if fmt == "terminal":
                terminal_summary = dict(self.summary)
                terminal_summary.setdefault(
                    "minimum_severity",
                    self.minimum_severity,
                )
                format_terminal(self.findings, terminal_summary, self.console)
            elif fmt == "json":
                path = format_json(
                    self.findings,
                    self.summary,
                    self.output_dir,
                )
                self.written_files.append(path)
            elif fmt == "csv":
                path = format_csv(self.findings, self.output_dir)
                self.written_files.append(path)
            elif fmt == "html":
                path = format_html(
                    self.findings,
                    self.summary,
                    self.output_dir,
                    self.active_scanners,
                )
                self.written_files.append(path)
            elif fmt == "sarif":
                path = format_sarif(
                    self.findings,
                    self.summary,
                    self.output_dir,
                )
                self.written_files.append(path)
            else:
                self.logger.warning("Unknown output format: %s", fmt)

        if self.written_files:
            self.console.print(
                f"\n[bold green]Reports written to:"
                f" {self.output_dir}[/bold green]"
            )

        return self.written_files
