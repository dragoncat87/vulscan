"""Command-line interface for vulscan."""

from __future__ import annotations

import logging
import os
import shutil
import sys
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
from vulscan.engine.findings import Finding, FindingsEngine
from vulscan.outputs.formatter import OutputFormatter
from vulscan.scanners.api import APIScanner
from vulscan.scanners.code import CodeScanner
from vulscan.scanners.config import ConfigScanner
from vulscan.threat_intel.ai_engine import fetch_threat_profile
from vulscan.threat_intel.free_feeds import fetch_free_intel

SCANNER_CHOICES = ("code", "config", "api")
OUTPUT_CHOICES = ("terminal", "json", "html", "csv", "sarif")
SEVERITY_CHOICES = ("low", "medium", "high", "critical")
FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "none")
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


def setup_logging(verbose: bool) -> None:
    """Configure logging for vulscan. DEBUG if verbose, INFO otherwise."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def configure_logging(verbose: bool) -> None:
    """Configure application logging."""
    setup_logging(verbose)


def resolve_api_key(api_key: str | None) -> str | None:
    """Resolve the Gemini API key from --api-key or GEMINI_API_KEY."""
    return api_key or os.environ.get("GEMINI_API_KEY")


def is_remote_url(target: str) -> bool:
    """Return True when the target is an HTTP or HTTPS URL."""
    parsed = urlparse(target)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def resolve_target(target: str) -> dict:
    """
    Resolves the user-provided target into a structured dict.

    Returns:
        {
            "type": "local_file" | "local_dir" | "github_repo" | "remote_url",
            "path": str,
            "temp": bool
        }

    Raises:
        click.UsageError: if the target is invalid or unreachable.
    """
    # Step 1: Check for remote URLs first, before any path operations
    if target.startswith("http://") or target.startswith("https://"):
        # GitHub repo — clone it
        if "github.com" in target:
            import tempfile
            import git
            try:
                tmp_dir = tempfile.mkdtemp(prefix="vulscan_")
                console = Console()
                console.print(f"[cyan]Cloning {target} ...[/cyan]")
                git.Repo.clone_from(target, tmp_dir)
                return {
                    "type": "github_repo",
                    "path": tmp_dir,
                    "temp": True
                }
            except Exception as e:
                raise click.UsageError(
                    f"Failed to clone GitHub repo: {e}"
                )
        # Other remote URL — treat as API target
        return {
            "type": "remote_url",
            "path": target,
            "temp": False
        }

    # Step 2: Local path — expand ~ and resolve
    local_path = Path(target).expanduser().resolve()

    if not local_path.exists():
        raise click.UsageError(
            f"Invalid target. Provide an existing local file, "
            f"existing local directory, GitHub URL, or HTTP/HTTPS URL."
        )

    if local_path.is_file():
        return {
            "type": "local_file",
            "path": str(local_path),
            "temp": False
        }

    if local_path.is_dir():
        return {
            "type": "local_dir",
            "path": str(local_path),
            "temp": False
        }

    raise click.UsageError(
        f"Target exists but is neither a file nor a directory: {target}"
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
        table.add_row("Gemini API key", status)

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
    "--fail-on",
    type=click.Choice(FAIL_ON_CHOICES),
    default="none",
    show_default=True,
    help=(
        "Exit with code 1 if findings at or above this severity exist. "
        "Use in CI/CD pipelines."
    ),
)
@click.option(
    "--config",
    "config_path",
    help="Path to a custom rules config file.",
)
@click.option(
    "--api-key",
    help="Gemini API key for preventive mode.",
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
    fail_on: str,
    config_path: str | None,
    api_key: str | None,
    verbose: bool,
) -> None:
    """Run the vulscan security/compliance scanner CLI."""
    try:
        setup_logging(verbose)

        resolved = resolve_target(target)
        selected_scanners = scanners or DEFAULT_SCANNERS
        output_formats = outputs or DEFAULT_OUTPUTS
        api_key = resolve_api_key(api_key)
        scanner_config = {"source": "traditional"}

        print_startup_banner(
            target_info=resolved,
            mode=mode,
            selected_scanners=selected_scanners,
            output_formats=output_formats,
            api_key_found=bool(api_key),
        )

        free_intel = fetch_free_intel(resolved)
        console.print(
            "[cyan]Threat intel fetched: "
            f"{free_intel['total_intel_items']} items from CISA KEV, "
            "NVD, and OSV.dev[/cyan]"
        )

        if mode in ("preventive", "both"):
            if api_key is None:
                console.print(
                    "[yellow]No Gemini API key found. Set GEMINI_API_KEY "
                    "or use --api-key. Falling back to traditional "
                    "mode.[/yellow]"
                )
                threat_profile = {}
                effective_mode = "traditional"
            else:
                threat_profile = fetch_threat_profile(
                    resolved,
                    api_key,
                    free_intel,
                )
                effective_mode = mode
                if mode == "preventive":
                    scanner_config["source"] = "preventive"
        else:
            threat_profile = {}
            effective_mode = "traditional"

        engine = FindingsEngine(minimum_severity=severity)

        if "code" in selected_scanners:
            cs = CodeScanner(resolved, scanner_config, threat_profile)
            engine.add_findings(cs.run(), "CodeScanner")

        if "config" in selected_scanners:
            cf = ConfigScanner(resolved, scanner_config, threat_profile)
            engine.add_findings(cf.run(), "ConfigScanner")

        if "api" in selected_scanners:
            ap = APIScanner(resolved, scanner_config, threat_profile)
            engine.add_findings(ap.run(), "APIScanner")

        if effective_mode == "both":
            scanner_config_p = {"source": "preventive"}

            if "code" in selected_scanners:
                cs2 = CodeScanner(resolved, scanner_config_p, threat_profile)
                engine.add_findings(cs2.run(), "CodeScanner-Preventive")

            if "config" in selected_scanners:
                cf2 = ConfigScanner(resolved, scanner_config_p, threat_profile)
                engine.add_findings(cf2.run(), "ConfigScanner-Preventive")

            if "api" in selected_scanners:
                ap2 = APIScanner(resolved, scanner_config_p, threat_profile)
                engine.add_findings(ap2.run(), "APIScanner-Preventive")

        final_findings, summary = engine.process()

        formatter = OutputFormatter(
            findings=final_findings,
            summary=summary,
            output_formats=list(output_formats),
            output_dir=output_dir,
            minimum_severity=severity,
            verbose=verbose,
        )
        formatter.format_all()

        if resolved.get("temp") is True:
            shutil.rmtree(resolved["path"], ignore_errors=True)
            logger.debug("Cleaned up temp directory.")

        severity_order = ["low", "medium", "high", "critical"]

        if fail_on != "none":
            threshold_index = severity_order.index(fail_on)
            triggered = [
                finding for finding in final_findings
                if str(finding.severity).lower()
                in severity_order[threshold_index:]
            ]
            if triggered:
                console.print(
                    f"[red]--fail-on {fail_on}: "
                    f"{len(triggered)} finding(s) at or above threshold.[/red]"
                )
                sys.exit(1)
        else:
            # Original exit code behaviour
            severities = {
                str(finding.severity).lower() for finding in final_findings
            }
            if "critical" in severities:
                sys.exit(2)
            if "high" in severities:
                sys.exit(1)
            sys.exit(0)

    except KeyboardInterrupt:
        console.print("[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except click.UsageError:
        raise
    except Exception as exc:
        if verbose:
            logging.exception("Scan failed.")
        else:
            console.print(
                f"[red]Scan failed: {exc}. "
                "Run with --verbose for details.[/red]"
            )
        sys.exit(1)


if __name__ == "__main__":
    main()
