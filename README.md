# Argus

Argus is a mobile application security research framework focused on iOS application assessment.

## Features

- iOS application metadata extraction
- Threat modeling
- Focus reports
- Investigation workspaces
- Evidence management
- Investigation dashboard
- Report generation
- Investigation review

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

Extract installed apps

```bash
python -m argus.cli extract
```

Start an investigation

```bash
python -m argus.cli investigate com.openai.chat ~/apps.json
```

Review evidence

```bash
python -m argus.cli review evidence/INV_ChatGPT
```

Generate report

```bash
python -m argus.cli report evidence/INV_ChatGPT
```

Open dashboard

```bash
python -m argus.cli dashboard
```

---

## Testing

```bash
pytest -v
```

---

## Current Status

Current release:

v0.5.0-alpha

---

## License

MIT
