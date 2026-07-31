 █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
███████║██████╔╝██║  ███╗██║   ██║███████╗
██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝

══════════════════════════════════════════════════════════════════════

                           ◉ ARGUS

              THREAT INTELLIGENCE AUTOMATION FRAMEWORK

                 Transforming Code Into Intelligence

               Observe • Correlate • Prioritize • Defend

══════════════════════════════════════════════════════════════════════

# Argus

Argus is an alpha-stage security analysis and threat-intelligence framework for reviewing source code, JavaScript bundles, and WordPress plugins.

It combines pattern-based discovery, data-flow analysis, validation evidence, confidence scoring, attack-surface classification, and report generation. Argus is designed to help analysts distinguish observable behavior from security findings that have demonstrated impact.

> Current version: `3.0.0a1`  
> Status: Alpha — interfaces and report formats may change.

## Core principles

Argus follows four operating principles:

- **Observe** — identify routes, sinks, trust boundaries, and security-relevant patterns.
- **Correlate** — connect findings with validation routines, data flow, and context.
- **Prioritize** — rank findings using evidence, confidence, and demonstrated impact.
- **Defend** — produce actionable reports and remediation guidance.

Argus records evidence without assuming that every suspicious response or code pattern is exploitable.

## Implemented capabilities

### JavaScript analysis

Argus can analyze directories containing JavaScript bundles and identify patterns associated with:

- Network requests
- Authentication and OAuth
- GraphQL
- Uploads
- Administrative functionality
- Collaboration features
- Application routes

Results can be written to JSON and associated with an Argus investigation workspace.

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

Argus contains support for:

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

The current alpha imports OpenTelemetry and Arize tracing modules at CLI startup. Until runtime dependencies are declared in `pyproject.toml`, install them manually:

```bash
python -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install opentelemetry-api arize-otel
```

For development and testing:

```bash
python -m pip install pytest
```

## Command-line interface

Show available commands:

```bash
python -m argus.cli --help
```

### Analyze JavaScript

```bash
python -m argus.cli js analyze ./path/to/javascript
```

Write the report to a specific file:

```bash
python -m argus.cli js analyze ./path/to/javascript \
  --output report.json
```

Associate results with an investigation:

```bash
python -m argus.cli js analyze ./path/to/javascript \
  --investigation investigations/INV-YYYYMMDD-HHMMSS
```

### Audit a WordPress plugin

```bash
python -m argus.cli wordpress ./path/to/plugin
```

Only analyze plugins and code that you own or are authorized to assess.

### Create an investigation workspace

```bash
python -m argus.cli investigate
```

The command creates a timestamped workspace containing directories for analysis, evidence, logs, reports, screenshots, JavaScript, and notes.

### Generate reports

```bash
python -m argus.cli report ./path/to/report.json
```

## Evidence-pipeline example

```python
from argus.analysis.pipeline import build_default_pipeline

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
argus/
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

Argus supports optional Arize/OpenTelemetry tracing.

Set both variables before running the CLI:

```bash
export ARIZE_SPACE_ID='your-space-id'
export ARIZE_API_KEY='your-api-key'
```

If tracing credentials are absent, Argus is intended to run without exporting traces.

Never commit tracing credentials, session tokens, cookies, or API keys.

## Development status

Argus is under active development. Current limitations include:

- Alpha APIs and data formats
- Runtime dependencies are not yet fully declared in `pyproject.toml`
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

Use Argus only on:

- Systems and code you own
- Local test environments
- Explicitly authorized security assessments
- Bug-bounty assets that are clearly in scope

Avoid collecting unrelated users’ private data, bypassing rate limits, causing availability impact, or treating scanner output as proof without independent validation.

## Author

Created by Jonathan Mendiola.

## License

A `LICENSE` file exists in the repository but currently contains no license text. Add the intended license before distributing the project.

