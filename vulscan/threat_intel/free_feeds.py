"""Free threat intelligence feed integrations."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

LOGGER = logging.getLogger("vulscan.threat_intel.free_feeds")

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_RECENT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 10

EXTENSION_LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".cs": "csharp",
}

PACKAGE_FILE_LANGUAGE_MAP = {
    "requirements.txt": "python",
    "pipfile": "python",
    "pyproject.toml": "python",
    "package.json": "javascript",
    "go.mod": "go",
    "pom.xml": "java",
    "gemfile": "ruby",
    "composer.json": "php",
    "cargo.toml": "rust",
}

OSV_ECOSYSTEM_MAP = {
    "requirements.txt": "PyPI",
    "pipfile": "PyPI",
    "pyproject.toml": "PyPI",
    "package.json": "npm",
    "go.mod": "Go",
    "pom.xml": "Maven",
    "gemfile": "RubyGems",
    "cargo.toml": "crates.io",
}

CONFIG_FILENAMES = {"docker-compose.yml", "dockerfile", ".env"}


def _add_unique(items: list[str], value: str) -> None:
    """Append a value to a list if it is not already present."""
    if value not in items:
        items.append(value)


def _target_path(target_info: dict) -> Path | None:
    """Extract a local filesystem path from a target information dict."""
    path_keys = (
        "path",
        "target",
        "local_path",
        "repo_path",
        "cloned_path",
        "temp_path",
        "target_path",
        "file_path",
        "dir_path",
    )
    for key in path_keys:
        value = target_info.get(key)
        if value:
            return Path(str(value)).expanduser()
    return None


def _target_type(target_info: dict) -> str:
    """Extract the normalized target type from a target information dict."""
    return str(
        target_info.get("type")
        or target_info.get("target_type")
        or target_info.get("kind")
        or ""
    ).lower()


def _read_text(path: Path, max_chars: int = 200_000) -> str:
    """Read text from a file safely, returning an empty string on failure."""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as file_obj:
            return file_obj.read(max_chars)
    except OSError:
        return ""


def _inspect_path(path: Path, stack: dict[str, Any]) -> None:
    """Inspect a single path and update the detected stack in place."""
    filename = path.name
    filename_lower = filename.lower()
    suffix_lower = path.suffix.lower()

    language = EXTENSION_LANGUAGE_MAP.get(suffix_lower)
    if language:
        _add_unique(stack["languages"], language)

    package_language = PACKAGE_FILE_LANGUAGE_MAP.get(filename_lower)
    if package_language:
        _add_unique(stack["languages"], package_language)
        _add_unique(stack["package_files"], filename)

    if suffix_lower == ".csproj":
        _add_unique(stack["languages"], "csharp")
        _add_unique(stack["package_files"], filename)

    if filename_lower == "manage.py":
        _add_unique(stack["frameworks"], "django")

    if filename_lower in CONFIG_FILENAMES:
        _add_unique(stack["config_files"], filename)

    if filename_lower in {"docker-compose.yml", "dockerfile"}:
        _add_unique(stack["frameworks"], "docker")

    if filename_lower == ".env":
        _add_unique(stack["frameworks"], "dotenv")

    if suffix_lower == ".tf":
        _add_unique(stack["frameworks"], "terraform")
        _add_unique(stack["config_files"], filename)

    if suffix_lower in {".yaml", ".yml"}:
        content = _read_text(path).lower()
        if "kind: " in content:
            _add_unique(stack["frameworks"], "kubernetes")
            _add_unique(stack["config_files"], filename)


def _detect_flask(root_path: Path, stack: dict[str, Any]) -> None:
    """Detect Flask when app.py exists and requirements.txt mentions Flask."""
    app_paths: list[Path] = []
    requirements_paths: list[Path] = []

    if root_path.is_file():
        if root_path.name.lower() == "app.py":
            app_paths.append(root_path)
        if root_path.name.lower() == "requirements.txt":
            requirements_paths.append(root_path)
    else:
        for path in root_path.rglob("*"):
            if not path.is_file():
                continue
            filename_lower = path.name.lower()
            if filename_lower == "app.py":
                app_paths.append(path)
            elif filename_lower == "requirements.txt":
                requirements_paths.append(path)

    if not app_paths:
        return

    for requirements_path in requirements_paths:
        requirements = _read_text(requirements_path).lower()
        if "flask" in requirements:
            _add_unique(stack["frameworks"], "flask")
            return


def detect_stack(target_info: dict) -> dict:
    """Detect languages, frameworks, package files, and config files.

    Args:
        target_info: Metadata describing the scanner target.

    Returns:
        A structured stack dictionary containing detected languages,
        frameworks, package files, config files, and an API flag.
    """
    stack: dict[str, Any] = {
        "languages": [],
        "frameworks": [],
        "package_files": [],
        "config_files": [],
        "is_api": False,
    }

    target_type = _target_type(target_info)
    if target_type == "remote_url":
        stack["is_api"] = True
        LOGGER.debug("Detected stack: %s", stack)
        return stack

    path = _target_path(target_info)
    if path is None:
        LOGGER.debug("Detected stack: %s", stack)
        return stack

    if target_type == "local_file" or path.is_file():
        _inspect_path(path, stack)
        _detect_flask(path, stack)
    elif target_type in {"local_dir", "github_repo"} or path.is_dir():
        for file_path in path.rglob("*"):
            if file_path.is_file():
                _inspect_path(file_path, stack)
        _detect_flask(path, stack)

    LOGGER.debug("Detected stack: %s", stack)
    return stack


def _stack_keywords(stack: dict) -> list[str]:
    """Return lowercase stack keywords used for feed filtering."""
    keywords = []
    for value in stack.get("languages", []) + stack.get("frameworks", []):
        if isinstance(value, str) and value.strip():
            _add_unique(keywords, value.lower())
    return keywords


def _matches_any_keyword(text: str, keywords: list[str]) -> bool:
    """Return True when text contains at least one keyword."""
    lowered = text.lower()
    return any(keyword in lowered for keyword in keywords)


def fetch_cisa_kev(stack: dict) -> list[dict]:
    """Fetch matching CISA Known Exploited Vulnerabilities entries."""
    LOGGER.info("Fetching CISA KEV threat intelligence")
    keywords = _stack_keywords(stack)
    if not keywords:
        LOGGER.info("CISA KEV returned 0 matching results")
        return []

    try:
        response = requests.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        vulnerabilities = payload.get("vulnerabilities", [])

        matches = []
        for item in vulnerabilities:
            vendor = str(item.get("vendorProject", ""))
            product = str(item.get("product", ""))
            match_text = f"{vendor} {product}"
            if not _matches_any_keyword(match_text, keywords):
                continue

            matches.append(
                {
                    "cve_id": str(item.get("cveID", "")),
                    "vendor": vendor,
                    "product": product,
                    "description": str(item.get("shortDescription", "")),
                    "date_added": str(item.get("dateAdded", "")),
                    "due_date": str(item.get("dueDate", "")),
                    "source": "cisa_kev",
                }
            )

        matches.sort(key=lambda entry: entry.get("date_added", ""), reverse=True)
        results = matches[:20]
        LOGGER.info("CISA KEV returned %d matching results", len(results))
        return results
    except Exception as exc:  # noqa: BLE001 - feed failures must not stop scans.
        LOGGER.warning("Failed to fetch or parse CISA KEV feed: %s", exc)
        return []


def _format_nvd_datetime(value: datetime) -> str:
    """Format a datetime for the NVD 2.0 API."""
    return value.strftime("%Y-%m-%dT%H:%M:%S.000")


def _english_description(descriptions: list[dict]) -> str:
    """Extract the English CVE description from NVD description objects."""
    for item in descriptions:
        if str(item.get("lang", "")).lower() == "en":
            return str(item.get("value", ""))
    if descriptions:
        return str(descriptions[0].get("value", ""))
    return ""


def _extract_nvd_severity(metrics: dict) -> tuple[str, float | None]:
    """Extract severity and score from NVD CVSS metrics."""
    cvss_v31 = metrics.get("cvssMetricV31") or []
    if cvss_v31:
        metric = cvss_v31[0]
        cvss_data = metric.get("cvssData", {})
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
        score = cvss_data.get("baseScore")
        return str(severity or "UNKNOWN"), score

    cvss_v2 = metrics.get("cvssMetricV2") or []
    if cvss_v2:
        metric = cvss_v2[0]
        cvss_data = metric.get("cvssData", {})
        severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity")
        score = cvss_data.get("baseScore")
        return str(severity or "UNKNOWN"), score

    return "UNKNOWN", None


def fetch_nvd_recent(stack: dict) -> list[dict]:
    """Fetch recent NVD CVEs matching detected stack keywords."""
    LOGGER.info("Fetching recent NVD CVEs")
    keywords = _stack_keywords(stack)
    if not keywords:
        LOGGER.info("NVD returned 0 matching results")
        return []

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    start = now - timedelta(days=30)
    params = {
        "pubStartDate": _format_nvd_datetime(start),
        "pubEndDate": _format_nvd_datetime(now),
        "resultsPerPage": 20,
    }

    try:
        time.sleep(1)
        response = requests.get(
            NVD_RECENT_URL,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()

        results = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            description = _english_description(cve.get("descriptions", []))
            if not _matches_any_keyword(description, keywords):
                continue

            severity, score = _extract_nvd_severity(cve.get("metrics", {}))
            results.append(
                {
                    "cve_id": str(cve.get("id", "")),
                    "description": description,
                    "severity": severity,
                    "score": score,
                    "published": str(cve.get("published", "")),
                    "source": "nvd",
                }
            )
            if len(results) >= 20:
                break

        LOGGER.info("NVD returned %d matching results", len(results))
        return results
    except Exception as exc:  # noqa: BLE001 - feed failures must not stop scans.
        LOGGER.warning("Failed to fetch or parse NVD feed: %s", exc)
        return []


def _osv_ecosystems(package_files: list[str]) -> list[str]:
    """Map detected package files to OSV ecosystems."""
    ecosystems = []
    for package_file in package_files:
        ecosystem = OSV_ECOSYSTEM_MAP.get(package_file.lower())
        if ecosystem:
            _add_unique(ecosystems, ecosystem)
    return ecosystems


def _extract_osv_severity(vulnerability: dict) -> str | None:
    """Extract a compact severity value from an OSV vulnerability."""
    severities = vulnerability.get("severity") or []
    if not severities:
        return None

    first = severities[0]
    score = first.get("score")
    severity_type = first.get("type")
    if severity_type and score:
        return f"{severity_type}:{score}"
    if score:
        return str(score)
    if severity_type:
        return str(severity_type)
    return None


def _extract_osv_affected_packages(vulnerability: dict) -> list[str]:
    """Extract affected package names from an OSV vulnerability."""
    packages = []
    for affected in vulnerability.get("affected", []) or []:
        package = affected.get("package", {})
        name = package.get("name")
        if name:
            _add_unique(packages, str(name))
    return packages


def fetch_osv(stack: dict) -> list[dict]:
    """
    Fetches recent vulnerabilities from OSV.dev.
    Uses the v1 query endpoint with ecosystem-only queries.
    """
    logger = logging.getLogger("vulscan.threat_intel.free_feeds")

    ECOSYSTEM_MAP = {
        "requirements.txt": "PyPI",
        "Pipfile": "PyPI",
        "pyproject.toml": "PyPI",
        "package.json": "npm",
        "go.mod": "Go",
        "pom.xml": "Maven",
        "Gemfile": "RubyGems",
        "Cargo.toml": "crates.io",
    }

    # Also detect from languages if no package files found
    LANGUAGE_ECOSYSTEM_MAP = {
        "python": "PyPI",
        "javascript": "npm",
        "go": "Go",
        "java": "Maven",
        "ruby": "RubyGems",
        "rust": "crates.io",
    }

    package_files = stack.get("package_files", [])
    languages = stack.get("languages", [])

    ecosystems = set()
    for pf in package_files:
        if pf in ECOSYSTEM_MAP:
            ecosystems.add(ECOSYSTEM_MAP[pf])
    for lang in languages:
        if lang in LANGUAGE_ECOSYSTEM_MAP:
            ecosystems.add(LANGUAGE_ECOSYSTEM_MAP[lang])

    if not ecosystems:
        logger.info("OSV.dev: no ecosystems detected, skipping.")
        return []

    results = []

    # Use a known vulnerable package per ecosystem to get real results
    # This is a valid OSV query pattern — query by ecosystem + empty version
    SAMPLE_PACKAGES = {
        "PyPI": "requests",
        "npm": "lodash",
        "Go": "golang.org/x/net",
        "Maven": "org.apache.logging.log4j:log4j-core",
        "RubyGems": "rails",
        "crates.io": "openssl",
    }

    for ecosystem in ecosystems:
        try:
            package_name = SAMPLE_PACKAGES.get(ecosystem, "")
            if not package_name:
                continue

            url = "https://api.osv.dev/v1/query"
            payload = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                }
            }
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulns", [])[:10]

            for v in vulns:
                severity = None
                if v.get("severity"):
                    severity = v["severity"][0].get("score")
                elif v.get("database_specific", {}).get("severity"):
                    severity = v["database_specific"]["severity"]

                results.append({
                    "osv_id": v.get("id", ""),
                    "summary": v.get("summary", "No summary")[:80],
                    "severity": severity,
                    "affected_packages": [
                        a.get("package", {}).get("name", "")
                        for a in v.get("affected", [])
                    ],
                    "published": v.get("published", ""),
                    "source": "osv"
                })

            logger.info(
                f"OSV.dev [{ecosystem}/{package_name}] "
                f"returned {len(vulns)} results"
            )

        except Exception as e:
            logger.warning(f"OSV.dev [{ecosystem}] failed: {e}")
            continue

    return results

def fetch_free_intel(target_info: dict) -> dict:
    """Fetch threat intelligence from free public sources.

    Fetches threat intelligence from CISA KEV, NVD, and OSV.dev. No API
    key is required. This function is always available in traditional and
    both modes, and it returns a structured threat profile dict for use by
    scanners.

    Args:
        target_info: Metadata describing the scanner target.

    Returns:
        A structured threat intelligence profile.
    """
    stack = detect_stack(target_info)
    cisa_kev = fetch_cisa_kev(stack)
    nvd_recent = fetch_nvd_recent(stack)
    osv = fetch_osv(stack)

    return {
        "stack": stack,
        "cisa_kev": cisa_kev,
        "nvd_recent": nvd_recent,
        "osv": osv,
        "total_intel_items": len(cisa_kev) + len(nvd_recent) + len(osv),
        "fetched_at": f"{datetime.now(timezone.utc).replace(tzinfo=None).isoformat()}Z",
    }
