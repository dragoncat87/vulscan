import textwrap
from pathlib import Path
from vulscan.scanners.config import ConfigScanner

def make_scanner(tmp_path):
    return ConfigScanner(
        target_info={"type": "local_dir", "path": str(tmp_path), "temp": False},
        config={"source": "traditional"},
        threat_profile={}
    )

def test_detects_env_secret(tmp_path):
    f = tmp_path / ".env"
    f.write_text("SECRET=my-super-secret-value\n")
    findings = make_scanner(tmp_path).run()
    rule_ids = [f.rule_id for f in findings]
    assert "CF-001" in rule_ids

def test_detects_privileged_container(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text("services:\n  app:\n    privileged: true\n")
    findings = make_scanner(tmp_path).run()
    rule_ids = [f.rule_id for f in findings]
    assert "CF-005" in rule_ids

def test_detects_dockerfile_root(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\nUSER root\nCMD [\"python\", \"app.py\"]\n")
    findings = make_scanner(tmp_path).run()
    rule_ids = [f.rule_id for f in findings]
    assert "CF-006" in rule_ids

def test_detects_terraform_open_cidr(tmp_path):
    f = tmp_path / "main.tf"
    f.write_text('resource "aws_security_group" "sg" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n')
    findings = make_scanner(tmp_path).run()
    rule_ids = [f.rule_id for f in findings]
    assert "CF-008" in rule_ids
