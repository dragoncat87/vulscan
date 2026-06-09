"""API scanner for live endpoints and OpenAPI/Swagger specifications."""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
import urllib3

from vulscan.engine.findings import Finding

try:
    import yaml
except ImportError:  # pragma: no cover - optional dependency in some installs
    yaml = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGGER = logging.getLogger("vulscan.scanners.api")

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

SENSITIVE_ENDPOINTS = [
    "/admin", "/admin/", "/administrator",
    "/api/admin", "/api/v1/admin",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/api-docs", "/openapi.json", "/openapi.yaml",
    "/.env", "/config", "/debug",
    "/actuator", "/actuator/health", "/actuator/env",
    "/metrics", "/health", "/status",
    "/graphql", "/graphiql",
    "/phpinfo.php", "/info.php",
    "/wp-admin", "/wp-login.php",
]

SPEC_FILENAMES = {
    "openapi.json", "openapi.yaml", "openapi.yml",
    "swagger.json", "swagger.yaml", "swagger.yml",
}

TIMEOUT = 10
_PROBE_WARNING_EMITTED = False


def _make_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    file_path: str,
    source: str,
    mode: str = "detected",
    line_number: int | None = None,
    cve_id: str | None = None,
    ttp_id: str | None = None,
    threat_ref: str | None = None,
    remediation: str = "",
) -> Finding:
    """Create a Finding with the scanner's standard field set."""
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
        timestamp=datetime.utcnow().isoformat(),
    )


def _load_spec_file(spec_path: Path) -> dict[str, Any]:
    """Load a JSON or YAML OpenAPI/Swagger spec file."""
    try:
        with spec_path.open("r", encoding="utf-8") as spec_file:
            if spec_path.suffix.lower() == ".json":
                data = json.load(spec_file)
            else:
                if yaml is None:
                    LOGGER.debug("PyYAML is unavailable; skipped %s", spec_path)
                    return {}
                data = yaml.safe_load(spec_file)
    except Exception as exc:
        LOGGER.debug("Could not parse OpenAPI spec %s: %s", spec_path, exc)
        return {}

    if isinstance(data, dict):
        return data

    LOGGER.debug("OpenAPI spec %s did not parse to a dictionary", spec_path)
    return {}


def _find_spec_files_for_target(target_info: dict) -> list[Path]:
    """Find OpenAPI/Swagger spec files for a local target."""
    target_path = Path(target_info.get("path", ""))
    if target_path.is_file():
        return [target_path] if target_path.name in SPEC_FILENAMES else []
    if not target_path.exists():
        LOGGER.debug("Target path does not exist: %s", target_path)
        return []
    return [path for path in target_path.rglob("*") if path.name in SPEC_FILENAMES]


def resolve_api_target(target_info: dict) -> list[str]:
    """
    Return API endpoint URLs to scan.

    - remote_url: returns the configured path as a single URL.
    - local_file/local_dir/github_repo: searches for OpenAPI/Swagger specs,
      extracts servers[].url values, and returns all discovered URLs.
    - returns an empty list when no API targets are found.
    """
    target_type = target_info.get("type")
    target_path = target_info.get("path")

    if target_type == "remote_url" and target_path:
        return [str(target_path)]

    if target_type not in ("local_file", "local_dir", "github_repo"):
        LOGGER.debug("Skipped non-API target type: %s", target_type)
        return []

    urls: list[str] = []
    spec_files = _find_spec_files_for_target(target_info)
    if spec_files:
        LOGGER.info("Found %s OpenAPI/Swagger spec file(s).", len(spec_files))

    for spec_path in spec_files:
        spec = _load_spec_file(spec_path)
        servers = spec.get("servers", []) if spec else []
        server_urls = [
            server.get("url")
            for server in servers
            if isinstance(server, dict) and server.get("url")
        ]

        if server_urls:
            urls.extend(str(url) for url in server_urls)
        else:
            LOGGER.info("OpenAPI spec found but no server URLs defined.")

    return urls


def _check_security_headers(
    url: str,
    response: requests.Response,
    source: str,
) -> list[Finding]:
    """Check response headers for missing security headers."""
    severity_map = {
        "Strict-Transport-Security": "high",
        "Content-Security-Policy": "high",
        "X-Content-Type-Options": "medium",
        "X-Frame-Options": "medium",
    }
    findings: list[Finding] = []

    for header in SECURITY_HEADERS:
        if header in response.headers:
            continue

        severity = severity_map.get(header, "low")
        findings.append(_make_finding(
            rule_id="API-H-" + header[:8].upper().replace("-", ""),
            title=f"Missing security header: {header}",
            description=f"The API response does not include {header}.",
            severity=severity,
            file_path=url,
            source=source,
            ttp_id="T1040",
            remediation=(
                f"Add the {header} response header to all API responses."
            ),
        ))

    return findings


def _check_ssl(url: str, source: str) -> list[Finding]:
    """Check whether the endpoint uses HTTPS and has a valid certificate."""
    findings: list[Finding] = []

    if url.startswith("http://"):
        findings.append(_make_finding(
            rule_id="API-SSL-001",
            title="API uses plaintext HTTP",
            description="The API endpoint is reachable over plaintext HTTP.",
            severity="high",
            file_path=url,
            source=source,
            ttp_id="T1040",
            remediation="Migrate to HTTPS. HTTP exposes all traffic in plaintext.",
        ))
        return findings

    if not url.startswith("https://"):
        LOGGER.debug("Skipped SSL check for unsupported URL scheme: %s", url)
        return findings

    try:
        requests.get(url, timeout=TIMEOUT, verify=True)
    except requests.exceptions.SSLError:
        findings.append(_make_finding(
            rule_id="API-SSL-002",
            title="Invalid or expired SSL certificate",
            description=(
                "The API endpoint uses HTTPS but the SSL certificate could "
                "not be validated."
            ),
            severity="critical",
            file_path=url,
            source=source,
            ttp_id="T1040",
            remediation=(
                "Renew the SSL certificate and ensure the chain is valid."
            ),
        ))
    except requests.exceptions.RequestException as exc:
        LOGGER.debug("SSL validation request failed for %s: %s", url, exc)

    return findings


def _probe_sensitive_endpoints(base_url: str, source: str) -> list[Finding]:
    """
    Probe known sensitive endpoints and flag exposed or discoverable paths.

    Findings are raised when a probe returns 200, 301, 302, or 403.
    """
    global _PROBE_WARNING_EMITTED

    if not _PROBE_WARNING_EMITTED:
        LOGGER.warning(
            "Probing sensitive endpoints — only use on targets you own or "
            "have permission to test."
        )
        _PROBE_WARNING_EMITTED = True

    findings: list[Finding] = []
    severity_map = {
        200: "critical",
        301: "medium",
        302: "medium",
        403: "high",
    }

    for path in SENSITIVE_ENDPOINTS:
        url = base_url.rstrip("/") + path
        try:
            response = requests.get(
                url,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            LOGGER.debug(
                "Sensitive endpoint probe %s returned %s",
                url,
                response.status_code,
            )
        except requests.exceptions.RequestException as exc:
            LOGGER.debug("Sensitive endpoint probe failed for %s: %s", url, exc)
            time.sleep(0.5)
            continue

        if response.status_code in severity_map:
            findings.append(_make_finding(
                rule_id="API-EXP-001",
                title=f"Sensitive endpoint exposed: {path}",
                description=(
                    f"Sensitive endpoint {path} returned HTTP "
                    f"{response.status_code}."
                ),
                severity=severity_map[response.status_code],
                file_path=url,
                source=source,
                ttp_id="T1083",
                remediation=(
                    f"Restrict access to {path}. Remove or protect "
                    "admin/debug endpoints."
                ),
            ))

        time.sleep(0.5)

    return findings


def _check_auth(
    url: str,
    response: requests.Response,
    source: str,
) -> list[Finding]:
    """Check for broken authentication indicators in the response."""
    findings: list[Finding] = []

    if response.status_code == 200 and "/admin" in url:
        findings.append(_make_finding(
            rule_id="API-AUTH-001",
            title="Admin endpoint accessible without authentication",
            description="An admin endpoint returned HTTP 200 without auth context.",
            severity="critical",
            file_path=url,
            source=source,
            ttp_id="T1078",
            remediation="Require authentication for all admin endpoints.",
        ))

    www_authenticate = response.headers.get("WWW-Authenticate", "")
    if "Basic" in www_authenticate:
        findings.append(_make_finding(
            rule_id="API-AUTH-002",
            title="HTTP Basic Authentication in use",
            description="The API advertises HTTP Basic Authentication.",
            severity="high",
            file_path=url,
            source=source,
            ttp_id="T1552",
            remediation=(
                "Replace HTTP Basic Auth with OAuth2 or JWT bearer tokens."
            ),
        ))

    if response.status_code != 200:
        return findings

    body = response.text[:2000]
    body_patterns = [
        (
            r'"token"\s*:\s*"[A-Za-z0-9._-]{20,}"',
            "API-AUTH-003",
            "JWT token exposed in response body",
            "high",
            "The response body appears to expose a token value.",
            "Remove tokens from response bodies unless explicitly required. "
            "Use secure token handling and least-privilege scopes.",
        ),
        (
            r'"password"\s*:\s*"[^"]+"',
            "API-AUTH-004",
            "Password exposed in response body",
            "critical",
            "The response body appears to expose a password value.",
            "Never return passwords in API responses. Remove the field and "
            "rotate exposed credentials.",
        ),
        (
            r'"secret"\s*:\s*"[^"]+"',
            "API-AUTH-005",
            "Secret exposed in response body",
            "critical",
            "The response body appears to expose a secret value.",
            "Never return secrets in API responses. Remove the field and "
            "rotate exposed secrets.",
        ),
    ]

    for pattern, rule_id, title, severity, description, remediation in body_patterns:
        if re.search(pattern, body):
            findings.append(_make_finding(
                rule_id=rule_id,
                title=title,
                description=description,
                severity=severity,
                file_path=url,
                source=source,
                ttp_id="T1552",
                remediation=remediation,
            ))

    return findings


def _nested_value_contains_star(value: Any) -> bool:
    """Return True when a nested value contains a wildcard string."""
    if isinstance(value, dict):
        return any(_nested_value_contains_star(item) for item in value.values())
    if isinstance(value, list):
        return any(_nested_value_contains_star(item) for item in value)
    return isinstance(value, str) and "*" in value


def _contains_cors_wildcard(operation: dict[str, Any]) -> bool:
    """Detect wildcard CORS values in response headers or x-cors metadata."""
    for key, value in operation.items():
        key_lower = str(key).lower()
        if key_lower.startswith("x-cors") and _nested_value_contains_star(value):
            return True

    responses = operation.get("responses", {})
    if not isinstance(responses, dict):
        return False

    for response_definition in responses.values():
        if not isinstance(response_definition, dict):
            continue
        headers = response_definition.get("headers", {})
        if not isinstance(headers, dict):
            continue
        for header_name, header_definition in headers.items():
            if str(header_name).lower() != "access-control-allow-origin":
                continue
            if _nested_value_contains_star(header_definition):
                return True

    return False


def _scan_openapi_spec(spec_path: Path, source: str) -> list[Finding]:
    """Parse an OpenAPI/Swagger spec file and check security misconfigs."""
    spec = _load_spec_file(spec_path)
    if not spec:
        return []

    findings: list[Finding] = []
    file_path = str(spec_path)

    if "security" not in spec or spec.get("security") == []:
        findings.append(_make_finding(
            rule_id="API-SPEC-001",
            title="No global security defined",
            description="The OpenAPI spec does not define global security.",
            severity="high",
            file_path=file_path,
            source=source,
            remediation="Define global security schemes in the OpenAPI spec.",
        ))

    if "http" in spec.get("schemes", []):
        findings.append(_make_finding(
            rule_id="API-SPEC-002",
            title="HTTP scheme listed in OpenAPI spec",
            description="The OpenAPI spec allows plaintext HTTP.",
            severity="high",
            file_path=file_path,
            source=source,
            remediation="Remove http from schemes. Only allow https.",
        ))

    if "securityDefinitions" not in spec and "components" not in spec:
        findings.append(_make_finding(
            rule_id="API-SPEC-003",
            title="No authentication scheme defined",
            description=(
                "The OpenAPI spec does not define authentication schemes."
            ),
            severity="high",
            file_path=file_path,
            source=source,
            remediation=(
                "Define authentication schemes (OAuth2, API key, Bearer) "
                "in your spec."
            ),
        ))

    for server in spec.get("servers", []):
        if not isinstance(server, dict):
            continue
        server_url = str(server.get("url", ""))
        if server_url.startswith("http://"):
            findings.append(_make_finding(
                rule_id="API-SPEC-004",
                title="Server URL uses HTTP",
                description=f"Server URL uses plaintext HTTP: {server_url}",
                severity="high",
                file_path=file_path,
                source=source,
                remediation="Update server URLs to use HTTPS.",
            ))

    paths = spec.get("paths", {})
    cors_found = False
    if isinstance(paths, dict):
        for path_item in paths.values():
            if not isinstance(path_item, dict):
                continue
            for operation in path_item.values():
                if isinstance(operation, dict) and _contains_cors_wildcard(operation):
                    cors_found = True
                    break
            if cors_found:
                break

    if cors_found:
        findings.append(_make_finding(
            rule_id="API-SPEC-005",
            title="Endpoint accepts all origins",
            description=(
                "The OpenAPI spec contains response headers or CORS metadata "
                "that allow wildcard origins."
            ),
            severity="medium",
            file_path=file_path,
            source=source,
            remediation="Restrict CORS to specific trusted origins.",
        ))

    return findings


class APIScanner:
    """
    Scan API endpoints for OWASP API Top 10 risks and misconfigurations.

    The scanner checks live endpoints for authentication weaknesses, missing
    security headers, SSL issues, and exposed sensitive endpoints. It also
    scans OpenAPI/Swagger spec files for security misconfigurations. Only use
    this scanner on targets you own or have explicit permission to test.
    """

    def __init__(
        self,
        target_info: dict,
        config: dict,
        threat_profile: dict | None = None,
    ) -> None:
        """Initialize the API scanner."""
        self.target_info = target_info
        self.config = config
        self.threat_profile = threat_profile or {}
        self.source = config.get("source", "traditional")
        self.logger = logging.getLogger("vulscan.scanners.api")

    def run(self) -> list[Finding]:
        """Run all API scanning checks and return deduplicated findings."""
        findings: list[Finding] = []
        urls = resolve_api_target(self.target_info)

        if self.target_info.get("type") in (
            "local_dir",
            "github_repo",
            "local_file",
        ):
            spec_files = self._find_spec_files()
            if spec_files:
                self.logger.info(
                    "Found %s OpenAPI/Swagger spec file(s).",
                    len(spec_files),
                )
            for spec_path in spec_files:
                findings += _scan_openapi_spec(spec_path, self.source)

        if not urls:
            if not findings:
                self.logger.info("No API targets found.")
            return self._deduplicate(findings)

        self.logger.info("Scanning %s API endpoint(s)...", len(urls))
        self.logger.warning(
            "API scanning sends live HTTP requests. Only scan endpoints you "
            "own or have permission to test."
        )

        for url in urls:
            findings += _check_ssl(url, self.source)

            try:
                response = requests.get(
                    url,
                    timeout=TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                )
                findings += _check_security_headers(url, response, self.source)
                findings += _check_auth(url, response, self.source)
            except requests.exceptions.ConnectionError:
                self.logger.warning("Could not connect to %s", url)
                continue
            except requests.exceptions.Timeout:
                self.logger.warning("Request timed out: %s", url)
                continue
            except Exception as exc:
                self.logger.warning("Unexpected error scanning %s: %s", url, exc)
                continue

            findings += _probe_sensitive_endpoints(url, self.source)

            if self.threat_profile.get("threat_patterns"):
                findings += self._match_threat_profile(url, response)

        deduplicated = self._deduplicate(findings)
        self.logger.info(
            "API scan complete. %s finding(s) after deduplication.",
            len(deduplicated),
        )
        return deduplicated

    def _find_spec_files(self) -> list[Path]:
        """Find OpenAPI/Swagger spec files in local targets."""
        return _find_spec_files_for_target(self.target_info)

    def _match_threat_profile(
        self,
        url: str,
        response: requests.Response,
    ) -> list[Finding]:
        """
        Match threat profile exploit conditions against API response body.

        This is used in preventive mode only.
        """
        findings: list[Finding] = []
        body = response.text[:3000]

        for pattern in self.threat_profile.get("threat_patterns", []):
            for condition in pattern.get("exploit_conditions", []):
                if condition.lower() not in body.lower():
                    continue
                findings.append(Finding(
                    rule_id="TP-" + pattern["pattern_id"],
                    title=pattern["title"],
                    description=condition,
                    severity=pattern["severity"],
                    file_path=url,
                    line_number=None,
                    source=self.source,
                    mode="at_risk",
                    cve_id=None,
                    ttp_id=None,
                    threat_ref=pattern.get("source_refs", [""])[0],
                    remediation=pattern["remediation"],
                    timestamp=datetime.utcnow().isoformat(),
                ))

        return findings

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings by file path, line number, and rule ID."""
        seen: set[tuple[str, int | None, str]] = set()
        unique: list[Finding] = []

        for finding in findings:
            key = (finding.file_path, finding.line_number, finding.rule_id)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)

        return unique
