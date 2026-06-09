"""Source code scanner for vulscan."""

from __future__ import annotations

import ast
import json
import logging
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from vulscan.engine.findings import Finding, get_snippet
from vulscan.rules.secrets import SECRET_PATTERNS

LOGGER = logging.getLogger("vulscan.scanners.code")

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__",
    "venv", ".venv", "dist", "build",
    "site-packages", "lib", "lib64",
    ".venvs", "eggs", ".eggs",
    ".tox", ".nox", "htmlcov", ".mypy_cache",
    ".pytest_cache", ".ruff_cache"
}

REGEX_RULES = [
    {
        "rule_id": "CS-001",
        "title": "Hardcoded password",
        "description": "A hardcoded password was found in source code.",
        "severity": "critical",
        "pattern": r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
        "languages": [],
        "cve_id": None,
        "ttp_id": "T1552.001",
        "remediation": "Use environment variables or a secrets manager.",
    },
    {
        "rule_id": "CS-002",
        "title": "Hardcoded API key or token",
        "description": "A hardcoded API key or access token was found.",
        "severity": "critical",
        "pattern": (
            r'(?i)(api_key|apikey|secret_key|auth_token|access_token)'
            r'\s*=\s*["\'][^"\']{8,}["\']'
        ),
        "languages": [],
        "cve_id": None,
        "ttp_id": "T1552.001",
        "remediation": (
            "Move secrets to environment variables. Never commit keys to "
            "source control."
        ),
    },
    {
        "rule_id": "CS-003",
        "title": "SQL injection risk",
        "description": (
            "SQL query appears to use string concatenation or interpolation."
        ),
        "severity": "high",
        "pattern": (
            r'(?i)(execute|query|cursor\.execute)\s*\(\s*["\'].*\+'
            r'|f["\'].*SELECT.*\{|f["\'].*INSERT.*\{'
        ),
        "languages": ["python", "java", "php"],
        "cve_id": None,
        "ttp_id": "T1190",
        "remediation": "Use parameterised queries or an ORM.",
    },
    {
        "rule_id": "CS-004",
        "title": "Dangerous eval() usage",
        "description": "eval() can execute arbitrary code if input is unsafe.",
        "severity": "high",
        "pattern": r"\beval\s*\(",
        "languages": ["python", "javascript", "ruby", "php"],
        "cve_id": None,
        "ttp_id": "T1059",
        "remediation": (
            "Avoid eval(). Use safe alternatives like ast.literal_eval() "
            "for Python."
        ),
    },
    {
        "rule_id": "CS-005",
        "title": "Shell injection risk",
        "description": "subprocess is called with shell=True.",
        "severity": "high",
        "pattern": r"subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True",
        "languages": ["python"],
        "cve_id": None,
        "ttp_id": "T1059.004",
        "remediation": "Use shell=False and pass arguments as a list.",
    },
    {
        "rule_id": "CS-006",
        "title": "Insecure deserialization",
        "description": "pickle deserialization can execute code on untrusted data.",
        "severity": "high",
        "pattern": r"\bpickle\.(loads|load)\s*\(",
        "languages": ["python"],
        "cve_id": None,
        "ttp_id": "T1059",
        "remediation": "Avoid pickle for untrusted data. Use JSON or MessagePack.",
    },
    {
        "rule_id": "CS-007",
        "title": "Weak cryptography",
        "description": "MD5 or SHA1 appears to be used.",
        "severity": "medium",
        "pattern": r"(?i)(md5|sha1)\s*\(",
        "languages": [],
        "cve_id": None,
        "ttp_id": "T1600",
        "remediation": (
            "Use SHA-256 or stronger. Avoid MD5 and SHA1 for security "
            "purposes."
        ),
    },
    {
        "rule_id": "CS-008",
        "title": "Debug mode enabled",
        "description": "Debug mode appears to be enabled in Python application code.",
        "severity": "medium",
        "pattern": r"(?i)(DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True)",
        "languages": ["python"],
        "cve_id": None,
        "ttp_id": None,
        "remediation": "Never enable debug mode in production.",
    },
    {
        "rule_id": "CS-009",
        "title": "JWT none algorithm",
        "description": "JWT none algorithm appears to be allowed.",
        "severity": "critical",
        "pattern": r'(?i)algorithm\s*=\s*["\']none["\']',
        "languages": ["python", "javascript"],
        "cve_id": "CVE-2015-9235",
        "ttp_id": "T1550",
        "remediation": (
            "Never allow the none algorithm in JWT. Whitelist only HS256 "
            "or RS256."
        ),
    },
    {
        "rule_id": "CS-010",
        "title": "Open redirect",
        "description": "Redirect appears to use direct user-supplied input.",
        "severity": "medium",
        "pattern": r"(?i)redirect\s*\(\s*request\.(args|params|get)\[",
        "languages": ["python", "javascript"],
        "cve_id": None,
        "ttp_id": "T1566",
        "remediation": (
            "Validate and whitelist redirect URLs. Never redirect to "
            "user-supplied input directly."
        ),
    },
]

_SEMGREP_NOT_FOUND_WARNED = False

SEMGREP_SEVERITY_MAP = {
    "error": "high",
    "warning": "medium",
    "info": "low",
    "note": "low",
    "high": "high",
    "medium": "medium",
    "low": "low",
}


def _map_semgrep_severity(raw: str) -> str:
    """Maps semgrep severity labels to vulscan severity scale."""
    return SEMGREP_SEVERITY_MAP.get(raw.lower().strip(), "low")


def _utc_timestamp() -> str:
    """Return an ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _make_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    file_path: str,
    line_number: int | None,
    source: str,
    mode: str,
    cve_id: str | None = None,
    ttp_id: str | None = None,
    threat_ref: str | None = None,
    remediation: str,
    snippet: str | None = None,
    url: str | None = None,
) -> Finding:
    """Create a Finding with the shared required fields."""
    return Finding(
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        source=source,
        mode=mode,
        cve_id=cve_id,
        ttp_id=ttp_id,
        threat_ref=threat_ref,
        remediation=remediation,
        timestamp=_utc_timestamp(),
        snippet=snippet,
        url=url,
    )


def _is_supported_source_file(path: Path) -> bool:
    """Return True when the path has a supported source-code extension."""
    return path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS


def _is_in_skipped_dir(path: Path) -> bool:
    """Return True when any part of the path is in SKIP_DIRS."""
    return any(part in SKIP_DIRS for part in path.parts)


def collect_files(target_info: dict) -> list[Path]:
    """
    Walks the target and returns all source code files with supported
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

    target_type = target_info.get("type")
    target_path_str = target_info.get("path", "")

    # Remote URLs have no files to walk
    if target_type == "remote_url":
        return []

    target_path = Path(target_path_str)

    # Single file
    if target_type == "local_file":
        if target_path.suffix.lower() in SUPPORTED_EXTENSIONS:
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

        # Only collect files with supported extensions
        if item.is_file() and item.suffix.lower() in SUPPORTED_EXTENSIONS:
            collected.append(item)

    return collected


def _scan_with_regex(
    file_path: Path,
    language: str,
    rules: list[dict],
    source: str,
    threat_profile: dict,
) -> list[Finding]:
    """Scan a file with regex rules and preventive exploit conditions."""
    findings: list[Finding] = []

    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        LOGGER.debug("Skipping file due to UnicodeDecodeError: %s", file_path)
        return []
    except OSError as exc:
        LOGGER.debug("Skipping unreadable file %s: %s", file_path, exc)
        return []

    for pattern in SECRET_PATTERNS:
        for line_number, line in enumerate(lines, start=1):
            if pattern.pattern.search(line):
                findings.append(
                    _make_finding(
                        rule_id=pattern.rule_id,
                        title=pattern.title,
                        description=pattern.description,
                        severity="critical",
                        file_path=str(file_path),
                        line_number=line_number,
                        source=source,
                        mode="detected",
                        ttp_id="T1552.001",
                        remediation=pattern.remediation,
                        snippet=get_snippet(lines, line_number),
                    )
                )

    for rule in rules:
        rule_languages = rule.get("languages", [])
        if rule_languages and language not in rule_languages:
            continue

        for line_number, line in enumerate(lines, start=1):
            if re.search(rule["pattern"], line):
                findings.append(
                    _make_finding(
                        rule_id=rule["rule_id"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        file_path=str(file_path),
                        line_number=line_number,
                        source=source,
                        mode="detected",
                        cve_id=rule.get("cve_id"),
                        ttp_id=rule.get("ttp_id"),
                        remediation=rule["remediation"],
                        snippet=get_snippet(lines, line_number),
                    )
                )

    threat_patterns = threat_profile.get("threat_patterns", [])
    for pattern in threat_patterns:
        for exploit_condition in pattern.get("exploit_conditions", []):
            condition_text = str(exploit_condition)
            if not condition_text:
                continue

            condition_lower = condition_text.lower()
            for line_number, line in enumerate(lines, start=1):
                if condition_lower in line.lower():
                    source_refs = pattern.get("source_refs", [""])
                    findings.append(
                        _make_finding(
                            rule_id="TP-" + str(pattern["pattern_id"]),
                            title=pattern["title"],
                            description=condition_text,
                            severity=pattern["severity"],
                            file_path=str(file_path),
                            line_number=line_number,
                            source=source,
                            mode="at_risk",
                            threat_ref=source_refs[0] if source_refs else "",
                            remediation=pattern["remediation"],
                        )
                    )

    return findings


def _scan_with_ast(file_path: Path, source: str) -> list[Finding]:
    """Perform Python AST analysis for unsafe patterns in .py files."""
    findings: list[Finding] = []

    try:
        source_text = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        LOGGER.debug("Skipping AST scan due to UnicodeDecodeError: %s", file_path)
        return []
    except OSError as exc:
        LOGGER.debug("Skipping AST scan for unreadable file %s: %s", file_path, exc)
        return []

    lines = source_text.splitlines()

    try:
        tree = ast.parse(source_text, filename=str(file_path))
    except (SyntaxError, ValueError, TypeError) as exc:
        LOGGER.debug("AST parse failed for %s: %s", file_path, exc)
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "exec":
                findings.append(
                    _make_finding(
                        rule_id="AST-001",
                        title="Use of exec()",
                        description="exec() executes arbitrary code.",
                        severity="high",
                        file_path=str(file_path),
                        line_number=getattr(node, "lineno", None),
                        source=source,
                        mode="detected",
                        ttp_id="T1059",
                        remediation="Avoid exec(). It executes arbitrary code.",
                        snippet=(
                            get_snippet(lines, node.lineno)
                            if getattr(node, "lineno", None) is not None
                            else None
                        ),
                    )
                )

            if node.func.id == "__import__" and node.args:
                dynamic_args = any(
                    not isinstance(argument, ast.Constant)
                    for argument in node.args
                )
                if dynamic_args:
                    findings.append(
                        _make_finding(
                            rule_id="AST-002",
                            title="Dynamic __import__() usage",
                            description=(
                                "__import__() is called with a dynamic argument."
                            ),
                            severity="medium",
                            file_path=str(file_path),
                            line_number=getattr(node, "lineno", None),
                            source=source,
                            mode="detected",
                            ttp_id="T1059",
                            remediation=(
                                "Avoid dynamic __import__(). Use importlib "
                                "with validation."
                            ),
                            snippet=(
                                get_snippet(lines, node.lineno)
                                if getattr(node, "lineno", None) is not None
                                else None
                            ),
                        )
                    )

        if isinstance(node, ast.Assert):
            findings.append(
                _make_finding(
                    rule_id="AST-003",
                    title="Assert used for security checks",
                    description=(
                        "assert statements are removed when Python runs with -O."
                    ),
                    severity="low",
                    file_path=str(file_path),
                    line_number=getattr(node, "lineno", None),
                    source=source,
                    mode="detected",
                    remediation=(
                        "Never use assert for security validation. Use "
                        "explicit if/raise."
                    ),
                    snippet=(
                        get_snippet(lines, node.lineno)
                        if getattr(node, "lineno", None) is not None
                        else None
                    ),
                )
            )

    return findings


def _scan_with_semgrep(file_path: Path, language: str, source: str) -> list[Finding]:
    """Run semgrep auto rules on the target file, if semgrep is installed."""
    del language

    global _SEMGREP_NOT_FOUND_WARNED

    if shutil.which("semgrep") is None:
        if not _SEMGREP_NOT_FOUND_WARNED:
            LOGGER.warning(
                "Semgrep not found. Falling back to regex and AST scanning only."
            )
            _SEMGREP_NOT_FOUND_WARNED = True
        return []

    try:
        result = subprocess.run(
            ["semgrep", "--config", "auto", "--json", str(file_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        json_output = json.loads(result.stdout or "{}")
    except subprocess.TimeoutExpired:
        LOGGER.warning("Semgrep timed out on %s", file_path)
        return []
    except Exception as exc:
        LOGGER.warning("Semgrep failed on %s: %s", file_path, exc)
        return []

    findings: list[Finding] = []
    for semgrep_result in json_output.get("results", []):
        extra = semgrep_result["extra"]
        metadata = extra.get("metadata", {})
        raw_sev = (
            extra.get("severity")
            or semgrep_result.get("severity")
            or "info"
        )
        severity = _map_semgrep_severity(str(raw_sev))

        try:
            file_lines = Path(semgrep_result["path"]).read_text(errors="replace").splitlines()
            snippet = get_snippet(file_lines, semgrep_result["start"]["line"])
        except Exception:
            snippet = None

        findings.append(
            _make_finding(
                rule_id="SG-" + semgrep_result["check_id"],
                title=extra["message"],
                description=metadata.get("description", ""),
                severity=severity,
                file_path=semgrep_result["path"],
                line_number=semgrep_result["start"]["line"],
                source=source,
                mode="detected",
                cve_id=metadata.get("cve", None),
                ttp_id=None,
                threat_ref=None,
                remediation=metadata.get("fix", "See semgrep rule."),
                snippet=snippet,
            )
        )

    return findings


class CodeScanner:
    """Scan source code files with regex, Python AST, and semgrep rules.

    Supports traditional and preventive scan modes. Skips binary files and
    unsupported extensions gracefully.
    """

    def __init__(
        self,
        target_info: dict,
        config: dict,
        threat_profile: dict | None = None,
    ) -> None:
        """Initialize the code scanner."""
        self.target_info = target_info
        self.config = config
        self.threat_profile = threat_profile or config.get("threat_profile", {}) or {}
        self.source = config.get("source", "traditional")
        self.logger = logging.getLogger("vulscan.scanners.code")

    def run(self) -> list[Finding]:
        """Run all code scanning layers and return deduplicated findings."""
        findings: list[Finding] = []
        files = collect_files(self.target_info)

        if not files:
            self.logger.info("No supported source files found.")
            return []

        self.logger.info("Scanning %d source file(s)...", len(files))

        for file_path in files:
            ext = file_path.suffix.lower()
            language = SUPPORTED_EXTENSIONS.get(ext, "unknown")

            findings += _scan_with_regex(
                file_path,
                language,
                REGEX_RULES,
                self.source,
                self.threat_profile,
            )

            if ext == ".py":
                findings += _scan_with_ast(file_path, self.source)

            findings += _scan_with_semgrep(file_path, language, self.source)

        deduplicated = self._deduplicate(findings)
        self.logger.info(
            "Code scan complete. %d finding(s) after deduplication.",
            len(deduplicated),
        )
        return deduplicated

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings by file path, line number, and rule ID."""
        seen: set[tuple[str, int | None, str]] = set()
        unique: list[Finding] = []

        for finding in findings:
            key = (finding.file_path, finding.line_number, finding.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique
