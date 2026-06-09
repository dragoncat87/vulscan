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
