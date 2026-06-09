"""Configuration file scanner for vulscan."""

from __future__ import annotations

import inspect
import json
import logging
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

try:  # pragma: no cover - dependency availability depends on runtime install.
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

from vulscan.engine.findings import Finding, get_snippet


LOGGER = logging.getLogger("vulscan.scanners.config")

SUPPORTED_CONFIG_FILES: dict[str, str] = {
    ".env": "dotenv",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    "Dockerfile": "dockerfile",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".toml": "toml",
    ".ini": "ini",
    ".cfg": "ini",
    ".conf": "ini",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__",
    "venv", ".venv", "dist", "build",
    "site-packages", "lib", "lib64",
    ".venvs", "eggs", ".eggs",
    ".tox", ".nox", "htmlcov", ".mypy_cache",
    ".pytest_cache", ".ruff_cache"
}

CONFIG_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "CF-001",
        "title": "Hardcoded secret in .env",
        "description": "A likely secret value is hardcoded in a dotenv file.",
        "severity": "critical",
        "pattern": (
            r"(?i)^(SECRET|PASSWORD|PASSWD|API_KEY|TOKEN|AUTH|PRIVATE_KEY)"
            r"\s*=\s*.{4,}"
        ),
        "file_types": ["dotenv"],
        "cve_id": None,
        "ttp_id": "T1552.001",
        "remediation": (
            "Never commit .env files. Add .env to .gitignore. "
            "Use a secrets manager."
        ),
    },
    {
        "rule_id": "CF-002",
        "title": "Default or blank password",
        "description": "A password field appears to use a default or blank value.",
        "severity": "critical",
        "pattern": (
            r"(?i)(password|passwd)\s*[=:]\s*[\"\'`]?"
            r"(password|123456|admin|root|blank|changeme|default)?"
            r"[\"\'`]?\s*$"
        ),
        "file_types": [],
        "cve_id": None,
        "ttp_id": "T1078",
        "remediation": (
            "Set a strong unique password. Never use default credentials."
        ),
    },
    {
        "rule_id": "CF-003",
        "title": "Kubernetes privileged container",
        "description": "A Kubernetes manifest enables privileged container mode.",
        "severity": "critical",
        "pattern": r"privileged\s*:\s*true",
        "file_types": ["yaml"],
        "cve_id": None,
        "ttp_id": "T1611",
        "remediation": (
            "Never run containers in privileged mode. "
            "Use specific capabilities instead."
        ),
    },
    {
        "rule_id": "CF-004",
        "title": "Kubernetes hostNetwork enabled",
        "description": "A Kubernetes manifest enables hostNetwork.",
        "severity": "high",
        "pattern": r"hostNetwork\s*:\s*true",
        "file_types": ["yaml"],
        "cve_id": None,
        "ttp_id": "T1611",
        "remediation": (
            "Disable hostNetwork. It exposes the node network stack "
            "to the container."
        ),
    },
    {
        "rule_id": "CF-005",
        "title": "Docker privileged flag",
        "description": "A docker-compose service enables privileged mode.",
        "severity": "critical",
        "pattern": r"privileged\s*:\s*true",
        "file_types": ["docker-compose"],
        "cve_id": None,
        "ttp_id": "T1611",
        "remediation": (
            "Remove privileged: true. Grant only specific Linux "
            "capabilities needed."
        ),
    },
    {
        "rule_id": "CF-006",
        "title": "Dockerfile running as root",
        "description": "A Dockerfile explicitly switches execution to the root user.",
        "severity": "high",
        "pattern": r"^USER\s+root\s*$",
        "file_types": ["dockerfile"],
        "cve_id": None,
        "ttp_id": "T1078",
        "remediation": (
            "Create a non-root user in your Dockerfile and switch "
            "to it with USER."
        ),
    },
    {
        "rule_id": "CF-007",
        "title": "Dockerfile using latest tag",
        "description": "A Dockerfile uses a mutable latest image tag.",
        "severity": "medium",
        "pattern": r"^FROM\s+\S+:latest",
        "file_types": ["dockerfile"],
        "cve_id": None,
        "ttp_id": None,
        "remediation": (
            "Pin Docker base images to a specific digest or version tag."
        ),
    },
    {
        "rule_id": "CF-008",
        "title": "Terraform open security group (0.0.0.0/0)",
        "description": "A Terraform security group allows traffic from 0.0.0.0/0.",
        "severity": "high",
        "pattern": r"cidr_blocks\s*=\s*\[?\s*\"0\.0\.0\.0/0\"",
        "file_types": ["terraform"],
        "cve_id": None,
        "ttp_id": "T1190",
        "remediation": (
            "Restrict CIDR blocks to known IP ranges. Never expose "
            "0.0.0.0/0 in production."
        ),
    },
    {
        "rule_id": "CF-009",
        "title": "Hardcoded AWS credentials in config",
        "description": "AWS credentials appear to be hardcoded in a config file.",
        "severity": "critical",
        "pattern": (
            r"(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*"
            r"[\"\']?[A-Za-z0-9/+=]{16,}"
        ),
        "file_types": [],
        "cve_id": None,
        "ttp_id": "T1552.001",
        "remediation": (
            "Use IAM roles or environment variables. Never hardcode "
            "AWS credentials."
        ),
    },
    {
        "rule_id": "CF-010",
        "title": "Insecure HTTP endpoint in config",
        "description": "A non-local HTTP endpoint is configured without TLS.",
        "severity": "medium",
        "pattern": (
            r"(?i)(url|endpoint|host|base_url)\s*[=:]\s*"
            r"[\"\']?http://(?!localhost|127\.0\.0\.1)"
        ),
        "file_types": [],
        "cve_id": None,
        "ttp_id": "T1040",
        "remediation": "Use HTTPS endpoints. HTTP transmits data in plaintext.",
    },
    {
        "rule_id": "CF-011",
        "title": "CORS wildcard",
        "description": "CORS appears to allow all origins.",
        "severity": "medium",
        "pattern": (
            r"(?i)(cors|allow.origin|access.control.allow.origin)\s*[=:]\s*"
            r"[\"\']?\*"
        ),
        "file_types": [],
        "cve_id": None,
        "ttp_id": "T1190",
        "remediation": (
            "Restrict CORS to specific trusted origins. "
            "Wildcard allows any site."
        ),
    },
    {
        "rule_id": "CF-012",
        "title": "Debug or verbose logging enabled",
        "description": "Production config may enable debug, verbose, or trace logging.",
        "severity": "low",
        "pattern": (
            r"(?i)(log_level|loglevel|logging)\s*[=:]\s*"
            r"[\"\']?(debug|verbose|trace)[\"\']?"
        ),
        "file_types": [],
        "cve_id": None,
        "ttp_id": None,
        "remediation": (
            "Set log level to INFO or WARNING in production. "
            "Debug logs leak sensitive data."
        ),
    },
    {
        "rule_id": "CF-013",
        "title": "Terraform S3 bucket public access",
        "description": "A Terraform S3 bucket ACL allows public read access.",
        "severity": "critical",
        "pattern": r"acl\s*=\s*[\"\']public-read",
        "file_types": ["terraform"],
        "cve_id": None,
        "ttp_id": "T1530",
        "remediation": (
            "Set S3 bucket ACL to private. Enable Block Public Access settings."
        ),
    },
    {
        "rule_id": "CF-014",
        "title": "Exposed port 22 (SSH) in docker-compose",
        "description": "A docker-compose service exposes SSH on all interfaces or maps 22:22.",
        "severity": "high",
        "pattern": r"[\"\'`]?0\.0\.0\.0:22:|[\"\'`]?22:22",
        "file_types": ["docker-compose"],
        "cve_id": None,
        "ttp_id": "T1021.004",
        "remediation": (
            "Bind SSH to 127.0.0.1 only or use a bastion host."
        ),
    },
]

DEEP_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "CF-D001",
        "title": "Plaintext secret value",
        "check": lambda k, v: any(
            word in k.lower()
            for word in [
                "password",
                "secret",
                "token",
                "key",
                "credential",
                "passwd",
            ]
        )
        and len(v) > 3
        and v not in ["true", "false", "null", ""],
        "severity": "critical",
        "ttp_id": "T1552.001",
        "remediation": "Replace plaintext secret with an environment variable reference.",
    },
    {
        "rule_id": "CF-D002",
        "title": "Insecure protocol in value",
        "check": lambda k, v: v.startswith("http://")
        and not any(h in v for h in ["localhost", "127.0.0.1", "0.0.0.0"]),
        "severity": "medium",
        "ttp_id": "T1040",
        "remediation": "Use HTTPS. HTTP transmits data in plaintext.",
    },
]


def _get_config_file_type(file_path: Path) -> str | None:
    """Return the supported config type for a path, if any."""
    return (
        SUPPORTED_CONFIG_FILES.get(file_path.name)
        or SUPPORTED_CONFIG_FILES.get(file_path.name.lower())
        or SUPPORTED_CONFIG_FILES.get(file_path.suffix.lower())
    )


def _is_supported_config_file(file_path: Path) -> bool:
    """Return True if the path is a supported configuration file."""
    return file_path.is_file() and _get_config_file_type(file_path) is not None


def _is_in_skipped_dir(file_path: Path) -> bool:
    """Return True if any path component belongs to a skipped directory."""
    return any(part in SKIP_DIRS for part in file_path.parts)


def collect_config_files(target_info: dict[str, Any]) -> list[Path]:
    """
    Walks the target and returns all configuration files with supported
    extensions. Skips known dependency and cache directories by checking
    only the immediate directory name of each path component.
    """
    SKIP_DIRS = {
        ".git", "node_modules", "__pycache__",
        "venv", ".venv", "dist", "build",
        "site-packages", ".venvs", "eggs", ".eggs",
        ".tox", ".nox", "htmlcov", ".mypy_cache",
        ".pytest_cache", ".ruff_cache"
    }

    target_type = target_info.get("type") or target_info.get("target_type")
    target_path_str = target_info.get("path") or target_info.get("target") or ""

    # Remote URLs have no files to walk
    if target_type == "remote_url":
        return []

    target_path = Path(target_path_str)

    # Single file
    if target_type == "local_file":
        if _is_supported_config_file(target_path):
            return [target_path]
        return []

    # Directory or cloned repo — walk recursively
    collected: list[Path] = []

    for item in target_path.rglob("*"):
        # Check if ANY component of the path relative to target is a skip dir
        # Only check directory names, not file names
        try:
            relative = item.relative_to(target_path)
        except ValueError:
            continue

        # Skip if any DIRECTORY part of the relative path is in SKIP_DIRS
        # Do NOT check the filename itself — only its parent directories
        skip = False
        for part in relative.parts[:-1]:  # all parts except the filename
            if part in SKIP_DIRS:
                skip = True
                break

        if skip:
            continue

        # Only collect files with supported config file types
        if item.is_file() and _get_config_file_type(item) is not None:
            collected.append(item)

    return collected


def _normalise_constructor_value(name: str, payload: dict[str, Any]) -> Any:
    """Map common Finding constructor parameter names to payload values."""
    aliases = {
        "path": "file_path",
        "filename": "file_path",
        "file": "file_path",
        "line": "line_number",
        "line_no": "line_number",
        "line_number": "line_number",
        "matched_text": "evidence",
        "match": "evidence",
        "message": "description",
        "recommendation": "remediation",
        "fix": "remediation",
        "cve": "cve_id",
        "ttp": "ttp_id",
    }
    return payload.get(aliases.get(name, name))


def _create_finding(payload: dict[str, Any]) -> Finding:
    """
    Create a Finding while staying compatible with the project Finding model.

    The scanner follows the same field names used by the regex scanner. If the
    Finding model exposes a stricter constructor, only accepted parameters are
    passed through and common aliases are resolved.
    """
    try:
        return Finding(**payload)
    except TypeError:
        signature = inspect.signature(Finding)
        filtered: dict[str, Any] = {}

        for name, parameter in signature.parameters.items():
            if name == "self":
                continue

            value = _normalise_constructor_value(name, payload)
            if value is not None:
                filtered[name] = value
            elif parameter.default is inspect.Parameter.empty:
                annotation = parameter.annotation
                if annotation is int:
                    filtered[name] = 0
                elif annotation is bool:
                    filtered[name] = False
                else:
                    filtered[name] = ""

        return Finding(**filtered)


def _finding_from_rule(
    rule: dict[str, Any],
    file_path: Path,
    line_number: int | None,
    evidence: str,
    source: str,
    mode: str,
    snippet: str | None = None,
) -> Finding:
    """Build a Finding instance from a rule and match context."""
    payload = {
        "rule_id": rule.get("rule_id"),
        "title": rule.get("title"),
        "description": rule.get("description", rule.get("title", "")),
        "severity": rule.get("severity", "medium"),
        "file_path": str(file_path),
        "line_number": line_number,
        "evidence": evidence.strip(),
        "cve_id": rule.get("cve_id"),
        "ttp_id": rule.get("ttp_id"),
        "remediation": rule.get("remediation", ""),
        "source": source,
        "mode": mode,
        "scanner": "config",
        "category": "configuration",
        "snippet": snippet,
    }
    return _create_finding(payload)


def _read_text(file_path: Path) -> str | None:
    """Read a file as UTF-8 text, logging unreadable files safely."""
    try:
        return file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        LOGGER.debug("Skipping non-UTF-8 config file: %s", file_path)
    except OSError as exc:
        LOGGER.warning("Unable to read config file %s: %s", file_path, exc)
    return None


def _iter_exploit_conditions(threat_profile: dict[str, Any]) -> Iterable[tuple[dict[str, Any], str]]:
    """Yield preventive threat profile exploit conditions."""
    for index, threat_pattern in enumerate(threat_profile.get("threat_patterns", []), 1):
        if not isinstance(threat_pattern, dict):
            continue

        conditions = threat_pattern.get("exploit_conditions", [])
        if isinstance(conditions, str):
            conditions = [conditions]

        for condition in conditions:
            if isinstance(condition, dict):
                condition_text = str(
                    condition.get("condition")
                    or condition.get("match")
                    or condition.get("text")
                    or ""
                )
            else:
                condition_text = str(condition)

            if condition_text:
                rule = {
                    "rule_id": (
                        threat_pattern.get("rule_id")
                        or threat_pattern.get("id")
                        or f"TP-{index:03d}"
                    ),
                    "title": (
                        threat_pattern.get("title")
                        or threat_pattern.get("name")
                        or "Preventive threat condition matched"
                    ),
                    "description": (
                        threat_pattern.get("description")
                        or f"Exploit condition matched: {condition_text}"
                    ),
                    "severity": threat_pattern.get("severity", "medium"),
                    "cve_id": threat_pattern.get("cve_id"),
                    "ttp_id": threat_pattern.get("ttp_id"),
                    "remediation": threat_pattern.get(
                        "remediation",
                        "Review this configuration against the active threat profile.",
                    ),
                }
                yield rule, condition_text


def _scan_file_with_rules(
    file_path: Path,
    file_type: str,
    rules: list[dict[str, Any]],
    source: str,
    threat_profile: dict[str, Any],
) -> list[Finding]:
    """
    Scan a config file line by line with applicable rules.

    Also matches preventive threat profile exploit conditions by using
    case-insensitive substring matching across individual lines.
    """
    text = _read_text(file_path)
    if text is None:
        return []

    findings: list[Finding] = []
    lines = text.splitlines()

    for rule in rules:
        file_types = rule.get("file_types", [])
        if file_types and file_type not in file_types:
            continue

        try:
            regex = re.compile(str(rule["pattern"]))
        except re.error as exc:
            LOGGER.debug(
                "Skipping invalid config rule regex %s: %s",
                rule.get("rule_id"),
                exc,
            )
            continue

        for line_number, line in enumerate(lines, 1):
            if regex.search(line):
                findings.append(
                    _finding_from_rule(
                        rule=rule,
                        file_path=file_path,
                        line_number=line_number,
                        evidence=line,
                        source=source,
                        mode="detected",
                        snippet=get_snippet(lines, line_number),
                    )
                )

    for rule, condition_text in _iter_exploit_conditions(threat_profile):
        condition_lower = condition_text.lower()
        for line_number, line in enumerate(lines, 1):
            if condition_lower in line.lower():
                findings.append(
                    _finding_from_rule(
                        rule=rule,
                        file_path=file_path,
                        line_number=line_number,
                        evidence=line,
                        source=source,
                        mode="at_risk",
                    )
                )

    return findings


def _load_structured_data(file_path: Path, file_type: str) -> Any:
    """Load YAML or JSON data from a file, returning None on parse failure."""
    text = _read_text(file_path)
    if text is None:
        return None

    try:
        if file_type == "yaml":
            if yaml is None:
                LOGGER.debug("PyYAML is not installed; skipping YAML parse: %s", file_path)
                return None
            return yaml.safe_load(text)
        if file_type == "json":
            return json.loads(text)
    except Exception as exc:  # Parse failure from JSON or YAML libraries.
        LOGGER.debug("Structured config parse failed for %s: %s", file_path, exc)

    return None


def _walk_key_values(data: Any, parent_key: str = "") -> Iterable[tuple[str, str]]:
    """Recursively yield string key-value pairs from nested dict/list data."""
    if isinstance(data, dict):
        for key, value in data.items():
            key_text = str(key)
            path = f"{parent_key}.{key_text}" if parent_key else key_text
            if isinstance(value, str):
                yield path, value
            else:
                yield from _walk_key_values(value, path)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            path = f"{parent_key}[{index}]" if parent_key else f"[{index}]"
            if isinstance(value, str):
                yield path, value
            else:
                yield from _walk_key_values(value, path)


def _scan_structured(
    file_path: Path,
    file_type: str,
    source: str,
) -> list[Finding]:
    """
    Parse YAML and JSON files and inspect nested key-value pairs.

    This catches misconfigurations that span multiple lines and evade simple
    line-by-line regex checks.
    """
    data = _load_structured_data(file_path, file_type)
    if data is None:
        return []

    findings: list[Finding] = []
    for key_path, value in _walk_key_values(data):
        for rule in DEEP_RULES:
            check: Callable[[str, str], bool] = rule["check"]
            try:
                matched = check(key_path, value)
            except Exception as exc:  # pragma: no cover - defensive guard.
                LOGGER.debug(
                    "Deep config rule %s failed for %s: %s",
                    rule.get("rule_id"),
                    file_path,
                    exc,
                )
                matched = False

            if not matched:
                continue

            evidence = f"{key_path}: {value}"
            findings.append(
                _finding_from_rule(
                    rule={
                        "rule_id": rule.get("rule_id"),
                        "title": rule.get("title"),
                        "description": f"Structural config finding at key '{key_path}'.",
                        "severity": rule.get("severity", "medium"),
                        "cve_id": None,
                        "ttp_id": rule.get("ttp_id"),
                        "remediation": rule.get("remediation", ""),
                    },
                    file_path=file_path,
                    line_number=None,
                    evidence=evidence,
                    source=source,
                    mode="detected",
                )
            )

    return findings


class ConfigScanner:
    """
    Scan configuration files for misconfigurations and hardcoded secrets.

    Supported files include YAML, JSON, .env, Dockerfile, docker-compose,
    Kubernetes manifests, Terraform, TOML, INI, CFG, and CONF files. The scanner
    supports traditional rule detection and preventive threat profile matching.
    """

    def __init__(
        self,
        target_info: dict[str, Any],
        config: dict[str, Any],
        threat_profile: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the configuration scanner."""
        self.target_info = target_info
        self.config = config
        self.threat_profile = threat_profile or {}
        self.source = config.get("source", "traditional")
        self.logger = logging.getLogger("vulscan.scanners.config")

    def run(self) -> list[Finding]:
        """
        Run regex and deep structured scanning on all config files.

        Returns deduplicated findings.
        """
        findings: list[Finding] = []
        files = collect_config_files(self.target_info)

        if not files:
            self.logger.info("No supported config files found.")
            return []

        self.logger.info("Scanning %d config file(s)...", len(files))

        for file_path in files:
            file_type = _get_config_file_type(file_path)
            if not file_type:
                self.logger.debug("Skipping unsupported config file: %s", file_path)
                continue

            findings += _scan_file_with_rules(
                file_path,
                file_type,
                CONFIG_RULES,
                self.source,
                self.threat_profile,
            )

            if file_type in ("yaml", "json"):
                findings += _scan_structured(file_path, file_type, self.source)

        deduplicated = self._deduplicate(findings)
        self.logger.info(
            "Config scan complete. %d finding(s) after deduplication.",
            len(deduplicated),
        )
        return deduplicated

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings by (file_path, line_number, rule_id)."""
        seen: set[tuple[Any, Any, Any]] = set()
        unique: list[Finding] = []

        for finding in findings:
            key = (
                getattr(
                    finding,
                    "file_path",
                    getattr(finding, "path", getattr(finding, "filename", None)),
                ),
                getattr(
                    finding,
                    "line_number",
                    getattr(finding, "line", getattr(finding, "line_no", None)),
                ),
                getattr(finding, "rule_id", None),
            )
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique
