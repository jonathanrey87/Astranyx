# Argus

> Mobile Application Security Research Framework

Argus is a Python framework for mobile application security research. It automates metadata extraction, investigation setup, threat modeling, focus analysis, evidence collection, and reporting for iOS application assessments.

---

## Features

- 📱 iOS application metadata extraction
- 🔍 Guided investigation workflow
- 🛡 Threat model generation
- 🎯 Focus report generation
- 📂 Investigation workspaces
- 📝 Evidence management
- 📊 Dashboard
- 📄 Report generation
- ✅ Investigation review

---

## Installation

```bash
git clone https://github.com/jonathanrey87/Argus.git

cd Argus

python -m venv .venv

source .venv/bin/activate

pip install -e .
```

---

## Quick Start

Extract applications

```bash
python -m argus.cli extract
```

Start an investigation

```bash
python -m argus.cli investigate com.openai.chat ~/apps.json
```

Review

```bash
python -m argus.cli review evidence/INV_ChatGPT
```

Dashboard

```bash
python -m argus.cli dashboard
```

---

## Architecture

```
Dashboard
     │
Investigation
     │
 ├── Threat
 ├── Focus
 ├── Playbooks
 ├── Evidence
 └── Reports
```

---

## Testing

```bash
pytest -v
```

---

## Current Release

**v0.5.0-alpha**

---

## License

MIT
