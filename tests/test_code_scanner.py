import textwrap
from pathlib import Path
from vulscan.engine.findings import Finding
from vulscan.scanners.code import CodeScanner

def make_scanner(tmp_path):
    return CodeScanner(
        target_info={"type": "local_dir", "path": str(tmp_path), "temp": False},
        config={"source": "traditional"},
        threat_profile={}
    )

def write_py(tmp_path, code):
    f = tmp_path / "sample.py"
    f.write_text(textwrap.dedent(code))
    return tmp_path

def test_detects_hardcoded_password(tmp_path):
    write_py(tmp_path, 'password = "supersecret123"')
    findings = make_scanner(tmp_path).run()
    rule_ids = [f.rule_id for f in findings]
    assert any(r in rule_ids for r in ["CS-001", "SEC004"])

def test_detects_eval(tmp_path):
    write_py(tmp_path, 'result = eval(user_input)')
    findings = make_scanner(tmp_path).run()
    rule_ids = [f.rule_id for f in findings]
    assert "CS-004" in rule_ids

def test_detects_pickle(tmp_path):
    write_py(tmp_path, 'import pickle\ndata = pickle.loads(raw)')
    findings = make_scanner(tmp_path).run()
    rule_ids = [f.rule_id for f in findings]
    assert "CS-006" in rule_ids

def test_detects_shell_true(tmp_path):
    write_py(tmp_path, 'import subprocess\nsubprocess.run(cmd, shell=True)')
    findings = make_scanner(tmp_path).run()
    rule_ids = [f.rule_id for f in findings]
    assert "CS-005" in rule_ids

def test_detects_aws_key(tmp_path):
    write_py(tmp_path, 'key = "AKIAIOSFODNN7EXAMPLE"')
    findings = make_scanner(tmp_path).run()
    rule_ids = [f.rule_id for f in findings]
    assert "SEC001" in rule_ids

def test_clean_code_no_critical(tmp_path):
    write_py(tmp_path, '''
import os
import secrets
API_KEY = os.environ["API_KEY"]
token = secrets.token_hex(32)
def greet(name: str) -> str:
    return f"Hello, {name}"
''')
    findings = make_scanner(tmp_path).run()
    critical = [f for f in findings if f.severity == "critical"]
    assert not critical

def test_finding_has_snippet(tmp_path):
    write_py(tmp_path, 'x = 1\ny = 2\nresult = eval(user_input)\nz = 3')
    findings = make_scanner(tmp_path).run()
    eval_findings = [f for f in findings if f.rule_id == "CS-004"]
    assert eval_findings
    assert eval_findings[0].snippet is not None
    assert "eval" in eval_findings[0].snippet

def test_finding_has_correct_line(tmp_path):
    write_py(tmp_path, 'x = 1\ny = 2\nresult = eval(user_input)\nz = 3')
    findings = make_scanner(tmp_path).run()
    eval_findings = [f for f in findings if f.rule_id == "CS-004"]
    assert eval_findings[0].line_number == 3
