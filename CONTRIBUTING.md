# Contributing to vulscan

Thank you for your interest in contributing to **vulscan**.

vulscan is a security scanner CLI tool by **Drago**  
GitHub: [Dragoncat87](https://github.com/Dragoncat87)

Contributions are welcome, whether you are fixing bugs, adding detection rules, improving documentation, or helping make the project more reliable.

## Ways to Contribute

### 1. Report Bugs

If you find a bug, please open a GitHub Issue and include:

- A clear description of the problem
- Steps to reproduce
- Expected behaviour
- Actual behaviour
- vulscan version
- OS and Python version
- Full error output, preferably with `--verbose`

Please do not report security vulnerabilities through public issues. See `SECURITY.md` instead.

### 2. Add Detection Rules

Detection rules and scanner patterns live in the following files:

- `vulscan/rules/secrets.py`  
  For secret detection rules.

- `vulscan/scanners/code.py`  
  For code pattern detection.

- `vulscan/scanners/config.py`  
  For configuration pattern detection.

When adding a new detection rule, please include a matching test case.

### 3. Improve Documentation

Documentation improvements are welcome.

Examples include:

- Fixing unclear explanations
- Adding usage examples
- Improving CLI help text
- Updating installation instructions
- Documenting scanner behaviour

### 4. Submit Pull Requests

Pull requests should be focused and easy to review.

Before opening a PR, please make sure your changes are tested and follow the project style guidelines.

## Development Setup

Clone the repository:

```bash
git clone https://github.com/Dragoncat87/vulscan.git
cd vulscan
