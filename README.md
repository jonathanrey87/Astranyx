<div align="center">

# ASTRANYX

**Investigation Engine**

Where signals emerge from the dark.

`Version 4.0.0a1` · `Alpha` · `Python 3.11+`

</div>

Astranyx is a security-analysis framework for reviewing source code, JavaScript bundles, and WordPress plugins.

It combines pattern discovery, data-flow analysis, validation evidence, confidence scoring, attack-surface classification, and reporting—helping analysts separate suspicious behavior from findings with demonstrated security impact.

## Core principles

Astranyx follows four operating principles:

- **Observe** — identify routes, sinks, trust boundaries, and security-relevant patterns.
- **Correlate** — connect findings with validation routines, data flow, and context.
- **Prioritize** — rank findings using evidence, confidence, and demonstrated impact.
- **Defend** — produce actionable reports and remediation guidance.

Astranyx records evidence without assuming that every suspicious response or code pattern is exploitable.

## Implemented capabilities

### JavaScript analysis

Astranyx can analyze directories containing JavaScript bundles and identify patterns associated with:

- Network requests
- Authentication and OAuth
- GraphQL
- Uploads
- Administrative functionality
- Collaboration features
- Application routes

Results can be written to JSON and associated with an Astranyx investigation workspace.

### WordPress plugin analysis

The WordPress scanner includes checks for:

- Public REST routes
- Missing authorization checks
- Dynamic includes
- Deserialization
- SSRF sinks
- SQL queries
- React dangerous sinks
- Upload functionality
- Taint-flow relationships

The analyzer applies nearby validation and safe-pattern evidence to reduce noise.

### Analysis framework

The analysis package currently includes:

- Data-flow graphs
- Call graphs
- Trust classification
- Taint analysis
- Validation-routine detection
- Evidence-based finding decisions
- Pluggable analysis stages
- A default evidence-analysis pipeline

### Evidence gate

The evidence gate rejects findings that lack observable security impact.

Current decision categories include:

| Category | Required evidence |
|---|---|
| PII disclosure | A non-empty sensitive value |
| CRLF/header injection | A separate injected response header |
| Open redirect | A final destination outside trusted domains |
| CORS | Cross-origin access to authenticated sensitive data |
| HTTP 500 | Data exposure, authorization impact, stack disclosure, or measurable availability impact |
| GraphQL | Unauthorized protected data |
| Health endpoint | Sensitive operational data rather than status alone |

A successful query, wildcard CORS header, generic server error, or public health response is not automatically considered reportable.

### Reporting

Astranyx contains support for:

- HTML
- Markdown
- JSON
- CSV
- SARIF
- Source previews
- Confidence summaries
- Risk summaries
- Attack-surface classification

## Requirements

- Python 3.11 or newer
- Linux, macOS, or another Python-compatible environment
- A virtual environment is recommended

Runtime dependencies, including OpenTelemetry and Arize tracing support, are declared in `pyproject.toml` and installed automatically with Astranyx:

```bash
python -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .
```

For development and testing:

```bash
python -m pip install pytest
```

## Command-line interface

Show available commands:

```bash
python -m astranyx.cli --help
```

### Analyze JavaScript

```bash
python -m astranyx.cli js analyze ./path/to/javascript
```

Write the report to a specific file:

```bash
python -m astranyx.cli js analyze ./path/to/javascript \
  --output report.json
```

Recursively discover JavaScript files in nested directories:

```bash
python -m astranyx.cli js analyze ./path/to/javascript \
  --recursive \
  --output report.json
```

Recursive reports preserve paths relative to the analysis root, such as `assets/js/app.js`.

Associate results with an investigation:

```bash
python -m astranyx.cli js analyze ./path/to/javascript \
  --investigation investigations/INV-YYYYMMDD-HHMMSS
```

### Audit a WordPress plugin

```bash
python -m astranyx.cli wordpress ./path/to/plugin
```

Only analyze plugins and code that you own or are authorized to assess.

### Run an investigation

Create an empty workspace with default metadata:

```bash
astranyx investigate
```

Run automatic local-target detection and the compatible analyzers:

```bash
astranyx investigate ./path/to/authorized-target
```

Choose the complete local web profile and identify the analyst:

```bash
astranyx investigate /path/to/authorized-target \
  --profile web \
  --analyst "Jonathan Mendiola"
```

Available profiles are `auto`, `web`, `javascript`, and `wordpress`. Recursive
discovery is enabled by default and can be disabled with `--no-recursive`.
`--target` remains available as a compatibility alias for the positional path.

The command creates a timestamped workspace containing directories for analysis,
API evidence, HTML, JavaScript, logs, notes, reports, and screenshots. With a
target, Astranyx runs each selected analyzer, isolates module failures, updates
`metadata.json`, and writes `manifest.json` with SHA-256 hashes for every generated
analysis and report artifact.

Choose a different workspace parent directory when needed:

```bash
astranyx investigate ./authorized-target \
  --workspace-root ./casework
```

Example completed workspace:

```text
investigations/INV-YYYYMMDD-HHMMSS/
├── analysis/javascript.json
├── reports/wordpress/
│   ├── index.html
│   ├── findings.csv
│   ├── findings.json
│   └── findings.sarif
├── manifest.json
└── metadata.json
```

### Generate reports

```bash
python -m astranyx.cli report ./path/to/report.json
```

## Evidence-pipeline example

```python
from astranyx.analysis.pipeline import build_default_pipeline

pipeline = build_default_pipeline()

result = pipeline.execute(
    {
        "finding_evidence": [
            {
                "category": "graphql",
                "protected_data": False,
            },
            {
                "category": "http_500",
                "data_exposure": True,
            },
        ]
    }
)

for decision in result["evidence_decisions"]:
    print(decision.reportable, decision.reason)

print("Reportable findings:", result["reportable_findings"])
```

In this example, anonymous GraphQL execution without protected data is rejected, while a server error with demonstrated data exposure is retained.

## Project structure

```text
astranyx/
├── analysis/       Evidence gates, pipeline, taint, and validation
├── commands/       CLI command implementations
├── core/           Reports, HTML, SARIF, and source previews
├── graph/          Call, data-flow, and trust graphs
├── intelligence/   Classification, scoring, risk, and recommendations
├── investigation/  Investigation workspace management
├── modules/        Language and artifact analyzers
├── output/         HTML and Markdown writers
├── parsers/        Parser interfaces
├── plugins/        Analysis and workflow plugins
├── services/       Checklists, playbooks, data, and status
└── wordpress/      WordPress scanning and analysis
```

## Testing

Run the complete test suite:

```bash
python -m pytest -q
```

The current suite covers:

- Evidence decisions
- Analysis-pipeline execution
- Validation detection
- Taint analysis
- Intermediate representation
- Call graphs
- Data-flow graphs
- Trust analysis
- Parsers
- Reports
- Review workflows
- Checklists
- Playbooks
- Status and threat functionality

## Tracing

Astranyx supports optional Arize/OpenTelemetry tracing.

Set both variables before running the CLI:

```bash
export ARIZE_SPACE_ID='your-space-id'
export ARIZE_API_KEY='your-api-key'
```

If tracing credentials are absent, Astranyx is intended to run without exporting traces.

Never commit tracing credentials, session tokens, cookies, or API keys.

## Development status

Astranyx is under active development. Current limitations include:

- Alpha APIs and data formats
- The evidence pipeline is available through `build_default_pipeline()` but is not yet connected to every scanner and report path
- Some modules use different finding models
- CLI and investigation behavior are still evolving
- Documentation and packaging require further validation

## Roadmap

Planned work includes:

- Unified finding and evidence models
- Evidence-gate integration across scanners
- Cross-file taint propagation
- Historical comparison and baselines
- Framework-specific analyzers
- Expanded report schemas
- Plugin interfaces
- Dependency and packaging cleanup
- Additional integration tests

Roadmap items are plans, not completed capabilities.

## Responsible use

Use Astranyx only on:

- Systems and code you own
- Local test environments
- Explicitly authorized security assessments
- Bug-bounty assets that are clearly in scope

Avoid collecting unrelated users’ private data, bypassing rate limits, causing availability impact, or treating scanner output as proof without independent validation.

## Author

Created by Jonathan Mendiola.

## License

A `LICENSE` file exists in the repository but currently contains no license text. Add the intended license before distributing the project.
