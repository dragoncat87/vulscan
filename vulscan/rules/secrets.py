"Secret detection rules for vulscan code scanning."

from __future__ import annotations

import re
from typing import NamedTuple


class SecretPattern(NamedTuple):
    """Compiled secret detection pattern."""

    rule_id: str
    title: str
    pattern: re.Pattern[str]
    description: str
    remediation: str


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        rule_id="SEC001",
        title="AWS Access Key",
        pattern=re.compile(r"(?i)(AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        description="An AWS access key appears to be hardcoded in source code.",
        remediation="Revoke the key and move AWS credentials to IAM roles or a secrets manager.",
    ),
    SecretPattern(
        rule_id="SEC002",
        title="AWS Secret Key",
        pattern=re.compile(r'(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?'),
        description="An AWS secret access key appears to be hardcoded in source code.",
        remediation="Revoke the key and store AWS secrets in a managed secrets store.",
    ),
    SecretPattern(
        rule_id="SEC003",
        title="Generic API Key",
        pattern=re.compile(r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,64})["\']'),
        description="A generic API key appears to be hardcoded in source code.",
        remediation="Move API keys to environment variables or a secrets manager.",
    ),
    SecretPattern(
        rule_id="SEC004",
        title="Hardcoded Password",
        pattern=re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'](?!.*\{)([^"\']{6,})["\']'),
        description="A hardcoded password appears to be present in source code.",
        remediation="Remove the password from source control and rotate the credential.",
    ),
    SecretPattern(
        rule_id="SEC005",
        title="Private Key Material",
        pattern=re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        description="Private key material appears to be present in source code.",
        remediation="Remove the private key, rotate it, and store keys securely outside the repository.",
    ),
    SecretPattern(
        rule_id="SEC006",
        title="GitHub Token",
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}"),
        description="A GitHub token appears to be hardcoded in source code.",
        remediation="Revoke the token and use GitHub Actions secrets or a secrets manager.",
    ),
    SecretPattern(
        rule_id="SEC007",
        title="Slack Token",
        pattern=re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,250}"),
        description="A Slack token appears to be hardcoded in source code.",
        remediation="Revoke the token and store Slack credentials in a secrets manager.",
    ),
    SecretPattern(
        rule_id="SEC008",
        title="Generic Secret Assignment",
        pattern=re.compile(r'(?i)(secret|token|auth_token|access_token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']'),
        description="A likely secret or token is assigned directly in source code.",
        remediation="Remove the secret from code and load it securely at runtime.",
    ),
    SecretPattern(
        rule_id="SEC009",
        title="Database Connection String",
        pattern=re.compile(r'(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s"\']+'),
        description="A database connection string with credentials appears in source code.",
        remediation="Move database credentials to environment variables or a secrets manager.",
    ),
    SecretPattern(
        rule_id="SEC010",
        title="AI Provider API Key (Anthropic/OpenAI)",
        pattern=re.compile(r"(sk-ant-[A-Za-z0-9\-_]{32,}|sk-[A-Za-z0-9]{32,})"),
        description="An AI provider API key appears to be hardcoded in source code.",
        remediation="Revoke the key and store it in a secrets manager or protected environment variable.",
    ),
]
