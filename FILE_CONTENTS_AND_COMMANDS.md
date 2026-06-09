# vulscan — Full File Contents and WSL Commands

Generated from `AppPrompt.md`.

## Environment setup commands

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y git
python3 -m venv ~/.venvs/vulscan
source ~/.venvs/vulscan/bin/activate
python3 --version
```

Always activate the venv before working on this project:

```bash
source ~/.venvs/vulscan/bin/activate
```

## WSL commands to create the structure

```bash
mkdir -p vulscan/vulscan/scanners
mkdir -p vulscan/vulscan/engine
mkdir -p vulscan/vulscan/outputs
mkdir -p vulscan/vulscan/threat_intel
mkdir -p vulscan/vulscan/plugins
mkdir -p vulscan/tests

touch vulscan/vulscan/__init__.py
touch vulscan/vulscan/cli.py
touch vulscan/vulscan/scanners/__init__.py
touch vulscan/vulscan/scanners/code.py
touch vulscan/vulscan/scanners/config.py
touch vulscan/vulscan/scanners/api.py
touch vulscan/vulscan/engine/__init__.py
touch vulscan/vulscan/engine/findings.py
touch vulscan/vulscan/outputs/__init__.py
touch vulscan/vulscan/outputs/formatter.py
touch vulscan/vulscan/threat_intel/__init__.py
touch vulscan/vulscan/threat_intel/free_feeds.py
touch vulscan/vulscan/threat_intel/ai_engine.py
touch vulscan/vulscan/plugins/__init__.py
touch vulscan/tests/__init__.py
touch vulscan/setup.py
touch vulscan/requirements.txt
touch vulscan/README.md
```

## Install and verify commands

```bash
cd vulscan
pip install -r requirements.txt
pip install -e .
vulscan --help
```

If `vulscan` is not found after install:

```bash
export PATH="$PATH:$(python3 -m site --user-base)/bin"
echo 'export PATH="$PATH:$(python3 -m site --user-base)/bin"' >> ~/.bashrc
source ~/.bashrc
```


# Full file contents

## `vulscan/__init__.py`

```python
"""vulscan package."""

__version__ = "0.1.0"
```

## `vulscan/cli.py`

```python
"""Command-line interface for vulscan."""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import click
from git import Repo
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vulscan import __version__
from vulscan.engine.findings import Finding
from vulscan.outputs.formatter import OutputFormatter
from vulscan.scanners.api import APIScanner
from vulscan.scanners.code import CodeScanner
from vulscan.scanners.config import ConfigScanner
from vulscan.threat_intel.ai_engine import fetch_threat_profile

SCANNER_CHOICES = ("code", "config", "api")
OUTPUT_CHOICES = ("terminal", "json", "html", "csv", "sarif")
SEVERITY_CHOICES = ("low", "medium", "high", "critical")
MODE_CHOICES = ("traditional", "preventive", "both")
DEFAULT_SCANNERS = ("code", "config", "api")
DEFAULT_OUTPUTS = ("terminal",)
SCANNER_CLASSES = {
    "code": CodeScanner,
    "config": ConfigScanner,
    "api": APIScanner,
}

console = Console()
logger = logging.getLogger(__name__)


def configure_logging(verbose: bool) -> None:
    """Configure application logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def is_remote_url(target: str) -> bool:
    """Return True when the target is an HTTP or HTTPS URL."""
    parsed = urlparse(target)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def resolve_target(target: str) -> dict:
    """Resolve a local file, local directory, GitHub URL, or remote URL.

    Args:
        target: Local path or remote URL supplied by the user.

    Returns:
        A dictionary containing target type, resolved path or URL, and temp flag.

    Raises:
        click.UsageError: If the target is invalid or cannot be resolved.
    """
    if not target or not target.strip():
        raise click.UsageError("Target is required and cannot be empty.")

    target = target.strip()

    if is_remote_url(target):
        if "github.com" in target.lower():
            temp_dir = Path(tempfile.mkdtemp(prefix="vulscan-github-"))
            try:
                Repo.clone_from(target, temp_dir)
            except Exception as exc:
                raise click.UsageError(
                    f"Failed to clone GitHub repository '{target}': {exc}"
                ) from exc

            return {
                "type": "github_repo",
                "path": str(temp_dir.resolve()),
                "temp": True,
            }

        return {"type": "remote_url", "path": target, "temp": False}

    local_path = Path(target).expanduser()

    if local_path.is_file():
        return {
            "type": "local_file",
            "path": str(local_path.resolve()),
            "temp": False,
        }

    if local_path.is_dir():
        return {
            "type": "local_dir",
            "path": str(local_path.resolve()),
            "temp": False,
        }

    raise click.UsageError(
        "Invalid target. Provide an existing local file, existing local "
        "directory, GitHub URL, or HTTP/HTTPS URL."
    )


def load_config(config_path: str | None, severity: str) -> dict:
    """Build the runtime configuration dictionary."""
    config: dict = {"minimum_severity": severity}

    if config_path is None:
        return config

    path = Path(config_path).expanduser()
    if not path.is_file():
        raise click.UsageError(
            f"Custom rules config file does not exist: {path}"
        )

    config["config_path"] = str(path.resolve())
    return config


def tag_findings(findings: Iterable[Finding], source: str) -> list[Finding]:
    """Tag each finding with the scan source."""
    tagged_findings = list(findings)
    for finding in tagged_findings:
        finding.source = source
    return tagged_findings


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Deduplicate findings by file path, line number, and rule ID."""
    deduplicated: dict[tuple[str, int | None, str], Finding] = {}
    for finding in findings:
        key = (finding.file_path, finding.line_number, finding.rule_id)
        if key not in deduplicated:
            deduplicated[key] = finding
    return list(deduplicated.values())


def run_selected_scanners(
    selected_scanners: tuple[str, ...],
    target_info: dict,
    config: dict,
) -> list[Finding]:
    """Instantiate selected scanners and return all findings."""
    findings: list[Finding] = []

    for scanner_name in selected_scanners:
        scanner_class = SCANNER_CLASSES[scanner_name]
        scanner = scanner_class(target_info=target_info, config=config)
        scanner_findings = scanner.run()
        findings.extend(scanner_findings)
        logger.debug(
            "Scanner '%s' returned %d findings.",
            scanner_name,
            len(scanner_findings),
        )

    return findings


def run_traditional_scan(
    selected_scanners: tuple[str, ...],
    target_info: dict,
    config: dict,
) -> list[Finding]:
    """Run traditional offline scanning."""
    findings = run_selected_scanners(selected_scanners, target_info, config)
    return tag_findings(findings, source="traditional")


def run_preventive_scan(
    selected_scanners: tuple[str, ...],
    target_info: dict,
    config: dict,
    api_key: str,
) -> list[Finding]:
    """Run preventive scanning with an AI-generated threat profile."""
    preventive_config = dict(config)
    preventive_config["threat_profile"] = fetch_threat_profile(target_info, api_key)
    findings = run_selected_scanners(
        selected_scanners,
        target_info,
        preventive_config,
    )
    return tag_findings(findings, source="preventive")


def print_startup_banner(
    target_info: dict,
    mode: str,
    selected_scanners: tuple[str, ...],
    output_formats: tuple[str, ...],
    api_key_found: bool,
) -> None:
    """Print the vulscan startup banner."""
    table = Table.grid(padding=(0, 1))
    table.add_column(style="bold cyan", justify="right")
    table.add_column(style="white")

    table.add_row("Tool", f"vulscan v{__version__}")
    table.add_row("Target", target_info["path"])
    table.add_row("Mode", mode)
    table.add_row("Scanners", ", ".join(selected_scanners))
    table.add_row("Outputs", ", ".join(output_formats))

    if mode in {"preventive", "both"}:
        status = "found" if api_key_found else "not found"
        table.add_row("Anthropic API key", status)

    console.print(
        Panel(
            table,
            title="[bold green]vulscan startup[/bold green]",
            border_style="green",
        )
    )


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="vulscan")
@click.option(
    "--target",
    required=True,
    help="Path to a local file/directory or a remote URL.",
)
@click.option(
    "--scanner",
    "scanners",
    type=click.Choice(SCANNER_CHOICES),
    multiple=True,
    default=DEFAULT_SCANNERS,
    show_default=True,
    help="Scanner(s) to run. Can be used multiple times.",
)
@click.option(
    "--mode",
    type=click.Choice(MODE_CHOICES),
    default="traditional",
    show_default=True,
    help="Scan mode to run.",
)
@click.option(
    "--output",
    "outputs",
    type=click.Choice(OUTPUT_CHOICES),
    multiple=True,
    default=DEFAULT_OUTPUTS,
    show_default=True,
    help="Output format(s). Can be used multiple times.",
)
@click.option(
    "--output-dir",
    default="./vulscan-results/",
    show_default=True,
    help="Directory to write output files.",
)
@click.option(
    "--severity",
    type=click.Choice(SEVERITY_CHOICES),
    default="low",
    show_default=True,
    help="Minimum severity to report.",
)
@click.option(
    "--config",
    "config_path",
    help="Path to a custom rules config file.",
)
@click.option(
    "--api-key",
    help="Anthropic API key for preventive mode.",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug logging.",
)
def main(
    target: str,
    scanners: tuple[str, ...],
    mode: str,
    outputs: tuple[str, ...],
    output_dir: str,
    severity: str,
    config_path: str | None,
    api_key: str | None,
    verbose: bool,
) -> None:
    """Run the vulscan security/compliance scanner CLI."""
    configure_logging(verbose)

    target_info = resolve_target(target)
    runtime_config = load_config(config_path, severity)
    selected_scanners = scanners or DEFAULT_SCANNERS
    output_formats = outputs or DEFAULT_OUTPUTS
    effective_api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
    api_key_found = bool(effective_api_key)

    print_startup_banner(
        target_info=target_info,
        mode=mode,
        selected_scanners=selected_scanners,
        output_formats=output_formats,
        api_key_found=api_key_found,
    )

    findings: list[Finding] = []

    if mode == "traditional":
        findings = run_traditional_scan(
            selected_scanners,
            target_info,
            runtime_config,
        )
    elif mode == "preventive":
        if not effective_api_key:
            console.print(
                "[yellow]Preventive mode requires an Anthropic API key. "
                "Get one free at https://console.anthropic.com. "
                "Falling back to traditional mode.[/yellow]"
            )
            findings = run_traditional_scan(
                selected_scanners,
                target_info,
                runtime_config,
            )
        else:
            findings = run_preventive_scan(
                selected_scanners,
                target_info,
                runtime_config,
                effective_api_key,
            )
    elif mode == "both":
        findings.extend(
            run_traditional_scan(
                selected_scanners,
                target_info,
                runtime_config,
            )
        )

        if not effective_api_key:
            console.print(
                "[yellow]Preventive mode requires an Anthropic API key. "
                "Get one free at https://console.anthropic.com. "
                "Falling back to traditional mode.[/yellow]"
            )
        else:
            findings.extend(
                run_preventive_scan(
                    selected_scanners,
                    target_info,
                    runtime_config,
                    effective_api_key,
                )
            )

        findings = deduplicate_findings(findings)

    formatter = OutputFormatter(
        findings=findings,
        output_formats=list(output_formats),
        output_dir=output_dir,
    )
    formatter.format_all()


if __name__ == "__main__":
    main()
```

## `vulscan/scanners/__init__.py`

```python
"""Scanner modules for vulscan."""
```

## `vulscan/scanners/code.py`

```python
"""Source code scanner placeholder."""

from __future__ import annotations

from vulscan.engine.findings import Finding


class CodeScanner:
    """Scans source code files for vulnerabilities using AST analysis, regex patterns, and semgrep rules."""

    def __init__(self, target_info: dict, config: dict) -> None:
        """Initialize the code scanner."""
        self.target_info = target_info
        self.config = config

    def run(self) -> list[Finding]:
        """Run the code scanner and return findings."""
        return []
```

## `vulscan/scanners/config.py`

```python
"""Configuration scanner placeholder."""

from __future__ import annotations

from vulscan.engine.findings import Finding


class ConfigScanner:
    """Scans configuration files (YAML, JSON, .env, IaC) for misconfigurations and hardcoded secrets."""

    def __init__(self, target_info: dict, config: dict) -> None:
        """Initialize the configuration scanner."""
        self.target_info = target_info
        self.config = config

    def run(self) -> list[Finding]:
        """Run the configuration scanner and return findings."""
        return []
```

## `vulscan/scanners/api.py`

```python
"""API scanner placeholder."""

from __future__ import annotations

from vulscan.engine.findings import Finding


class APIScanner:
    """Scans API endpoints for OWASP Top 10 vulnerabilities, auth weaknesses, and missing security headers."""

    def __init__(self, target_info: dict, config: dict) -> None:
        """Initialize the API scanner."""
        self.target_info = target_info
        self.config = config

    def run(self) -> list[Finding]:
        """Run the API scanner and return findings."""
        return []
```

## `vulscan/engine/__init__.py`

```python
"""Core engine package for vulscan."""
```

## `vulscan/engine/findings.py`

```python
"""Finding data model for vulscan."""

from __future__ import annotations

from dataclasses import asdict, dataclass


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

    def to_dict(self) -> dict:
        """Return the finding as a plain dictionary."""
        return asdict(self)
```

## `vulscan/outputs/__init__.py`

```python
"""Output formatters for vulscan."""
```

## `vulscan/outputs/formatter.py`

```python
"""Output formatting placeholder for vulscan."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from vulscan.engine.findings import Finding


class OutputFormatter:
    """Formats vulscan findings into terminal, JSON, HTML, CSV, or SARIF output."""

    def __init__(
        self,
        findings: list[Finding],
        output_formats: list[str],
        output_dir: str,
    ) -> None:
        """Initialize the output formatter."""
        self.findings = findings
        self.output_formats = output_formats
        self.output_dir = Path(output_dir).expanduser()
        self.console = Console()

    def format_all(self) -> None:
        """Format findings for all requested outputs."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.console.print("Output formatting not yet implemented.")
```

## `vulscan/threat_intel/__init__.py`

```python
"""Threat intelligence modules for vulscan."""
```

## `vulscan/threat_intel/free_feeds.py`

```python
"""Free threat intelligence feed integrations."""

from __future__ import annotations


def fetch_free_intel(target_info: dict) -> dict:
    """Fetches threat intel from free public sources: CISA KEV, NVD RSS, OSV.dev. No API key required."""
    return {}
```

## `vulscan/threat_intel/ai_engine.py`

```python
"""Anthropic-backed preventive threat intelligence engine placeholder."""

from __future__ import annotations


def fetch_threat_profile(target_info: dict, api_key: str) -> dict:
    """Uses Anthropic Claude Haiku via the Messages API to read live threat news and build a threat profile for the scanned target. Only called when user opts into preventive mode."""
    return {}
```

## `vulscan/plugins/__init__.py`

```python
"""Plugin package for future vulscan extensions."""
```

## `tests/__init__.py`

```python
"""Test package for vulscan."""
```

## `setup.py`

```python
"""Setup configuration for vulscan."""

from setuptools import find_packages, setup


setup(
    name="vulscan",
    version="0.1.0",
    description="Security and compliance scanner CLI skeleton.",
    packages=find_packages(),
    install_requires=[
        "click",
        "gitpython",
        "requests",
        "rich",
        "anthropic",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "vulscan=vulscan.cli:main",
        ],
    },
)
```

## `requirements.txt`

```text
click
gitpython
requests
rich
anthropic
```

## `README.md`

```markdown
# vulscan

`vulscan` is a security/compliance scanner CLI skeleton for local files, local directories, GitHub repositories, and remote URLs.

The target development environment is WSL Kali Linux running on Windows.

## Environment setup for WSL Kali

Run these commands inside WSL Kali before working on the project:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
sudo apt install -y git
python3 -m venv ~/.venvs/vulscan
source ~/.venvs/vulscan/bin/activate
python3 --version
```

Always activate the virtual environment before working on this project:

```bash
source ~/.venvs/vulscan/bin/activate
```

Python must be version 3.10 or newer.

## Project structure

```text
vulscan/
├── vulscan/
│   ├── __init__.py
│   ├── cli.py
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── code.py
│   │   ├── config.py
│   │   └── api.py
│   ├── engine/
│   │   ├── __init__.py
│   │   └── findings.py
│   ├── outputs/
│   │   ├── __init__.py
│   │   └── formatter.py
│   ├── threat_intel/
│   │   ├── __init__.py
│   │   ├── free_feeds.py
│   │   └── ai_engine.py
│   └── plugins/
│       └── __init__.py
├── tests/
│   └── __init__.py
├── setup.py
├── requirements.txt
└── README.md
```

## Install and verify

```bash
pip install -r requirements.txt
pip install -e .
vulscan --help
```

If `vulscan` is not found after installation, run:

```bash
export PATH="$PATH:$(python3 -m site --user-base)/bin"
```

For persistence, add the same line to `~/.bashrc`:

```bash
echo 'export PATH="$PATH:$(python3 -m site --user-base)/bin"' >> ~/.bashrc
source ~/.bashrc
```

## Usage examples

Run all scanners in traditional mode against a local directory:

```bash
vulscan --target ./my-project
```

Run only the code scanner:

```bash
vulscan --target ./my-project --scanner code
```

Run traditional and preventive scanning:

```bash
vulscan --target ./my-project --mode both --api-key "$ANTHROPIC_API_KEY"
```

Run against a GitHub repository:

```bash
vulscan --target https://github.com/example/example-repo.git
```

Run against a remote URL:

```bash
vulscan --target https://example.com --scanner api
```

## CLI options

```text
--target        Required. Path to local file/directory OR remote URL.
--scanner       Optional, multiple. Choices: code, config, api.
--mode          Optional. Choices: traditional, preventive, both.
--output        Optional, multiple. Choices: terminal, json, html, csv, sarif.
--output-dir    Optional. Directory to write output files.
--severity      Optional. Choices: low, medium, high, critical.
--config        Optional. Path to a custom rules config file.
--api-key       Optional. Anthropic API key for preventive mode.
--verbose       Optional boolean flag. Enables debug logging.
--version       Show version and exit.
```

## Current implementation status

This is a working scaffold. Scanner modules and output formatting are placeholders and return safe empty outputs for now. The CLI target resolver, scan mode flow, startup banner, package entry point, and finding data model are implemented.
```
