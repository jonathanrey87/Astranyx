import json
import re
from pathlib import Path
from time import perf_counter

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from argus.investigation.manager import InvestigationManager

tracer = trace.get_tracer("argus.modules.js")


PATTERNS = {
    "network_fetch": r"fetch\(",
    "axios": r"axios",
    "graphql": r"graphql|mutation|operationName|query",
    "oauth": r"oauth|saml|scim|sso",
    "auth": r"token|csrf|session|cookie|webauthn|passkey",
    "uploads": r"upload|attachment|file|files|import|export",
    "collaboration": (r"invite|team|organization|workspace|member|permission|comment"),
    "admin": r"admin|internal|staff|employee",
}


ROUTE_PATTERN = re.compile(
    r"""["'`]((?:https?://|/)[A-Za-z0-9._~:/?#@!$&()*+,;=%\-\[\]]+)["'`]"""
)


def _raise_analysis_error(span, error_type, message):
    """Record and raise an analysis input error."""
    span.set_attribute(
        "argus.error.type",
        error_type,
    )
    span.set_status(Status(StatusCode.ERROR, message))

    raise SystemExit(f"[!] {message}")


def _validate_source(base, span):
    """Validate the JavaScript source directory."""
    if not base.exists():
        _raise_analysis_error(
            span,
            "path_not_found",
            f"Path not found: {base}",
        )

    if not base.is_dir():
        _raise_analysis_error(
            span,
            "not_a_directory",
            f"Path is not a directory: {base}",
        )


def _discover_javascript_files(base, span, recursive=False):
    """Discover JavaScript files in the requested scope."""
    with tracer.start_as_current_span("argus.js.discover_files") as discovery_span:
        js_files = sorted(base.rglob("*.js") if recursive else base.glob("*.js"))

        discovery_span.set_attribute(
            "argus.javascript.files_discovered",
            len(js_files),
        )

    if not js_files:
        _raise_analysis_error(
            span,
            "no_javascript_files",
            f"No JavaScript files found in {base}",
        )

    return js_files


def _extract_findings(text):
    """Count security-related patterns in JavaScript text."""
    findings = {}

    for name, pattern in PATTERNS.items():
        matches = re.findall(
            pattern,
            text,
            flags=re.IGNORECASE,
        )

        if matches:
            findings[name] = len(matches)

    return findings


def _scan_javascript_file(file_path):
    """Read and scan one JavaScript file."""
    text = file_path.read_text(
        encoding="utf-8",
        errors="ignore",
    )

    findings = _extract_findings(text)
    routes = ROUTE_PATTERN.findall(text)

    return text, findings, routes


def _scan_javascript_files(js_files, base):
    """Scan JavaScript files and collect results."""
    results = {}
    routes = set()
    failed_files = 0
    total_findings = 0

    with tracer.start_as_current_span("argus.js.scan_files") as scan_span:
        for file_path in js_files:
            report_path = file_path.relative_to(base).as_posix()
            with tracer.start_as_current_span("argus.js.scan_file") as file_span:
                file_span.set_attribute(
                    "argus.file.name",
                    file_path.name,
                )
                file_span.set_attribute(
                    "argus.file.path",
                    str(file_path),
                )

                try:
                    text, findings, file_routes = _scan_javascript_file(file_path)
                except Exception as exc:
                    failed_files += 1

                    file_span.record_exception(exc)
                    file_span.set_status(
                        Status(
                            StatusCode.ERROR,
                            str(exc),
                        )
                    )

                    print(f"[!] Failed reading " f"{file_path}: {exc}")
                    continue

                finding_count = sum(findings.values())

                file_span.set_attribute(
                    "argus.file.size_characters",
                    len(text),
                )
                file_span.set_attribute(
                    "argus.file.finding_categories",
                    len(findings),
                )
                file_span.set_attribute(
                    "argus.file.findings_total",
                    finding_count,
                )
                file_span.set_attribute(
                    "argus.file.routes_found",
                    len(file_routes),
                )

                total_findings += finding_count
                routes.update(file_routes)

                if findings:
                    results[report_path] = findings

        processed_files = len(js_files) - failed_files

        scan_span.set_attribute(
            "argus.javascript.files_processed",
            processed_files,
        )
        scan_span.set_attribute(
            "argus.javascript.files_failed",
            failed_files,
        )
        scan_span.set_attribute(
            "argus.javascript.findings_total",
            total_findings,
        )
        scan_span.set_attribute(
            "argus.javascript.routes_unique",
            len(routes),
        )

    return (
        results,
        routes,
        failed_files,
        total_findings,
    )


def _build_report(
    base,
    js_files,
    failed_files,
    results,
    routes,
):
    """Build the JavaScript analysis report."""
    return {
        "target": base.name,
        "files_analyzed": len(js_files) - failed_files,
        "summary": results,
        "routes": sorted(routes),
    }


def _write_report(output, result_json):
    """Write an optional standalone JSON report."""
    if not output:
        return None

    with tracer.start_as_current_span("argus.js.write_report") as output_span:
        output_path = Path(output).expanduser()

        output_span.set_attribute(
            "argus.output.path",
            str(output_path),
        )

        try:
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            output_path.write_text(
                result_json,
                encoding="utf-8",
            )
        except Exception as exc:
            output_span.record_exception(exc)
            output_span.set_status(
                Status(
                    StatusCode.ERROR,
                    str(exc),
                )
            )
            raise

        output_span.set_attribute(
            "argus.output.bytes",
            len(result_json.encode("utf-8")),
        )

    print(f"[+] Report written to {output_path}")

    return output_path


def _update_investigation(
    investigation,
    base,
    output_path,
    duration_ms,
    js_files,
    failed_files,
    results,
    total_findings,
    routes,
):
    """Update investigation metadata after analysis."""
    if not investigation:
        return

    with tracer.start_as_current_span("argus.js.update_investigation") as metadata_span:
        try:
            manager = InvestigationManager(investigation)

            manager.set_target(str(base))

            manager.add_module(
                name="javascript",
                status="completed",
                duration_ms=duration_ms,
                details={
                    "files": len(js_files),
                    "files_processed": (len(js_files) - failed_files),
                    "files_failed": failed_files,
                    "files_with_findings": len(results),
                    "findings_total": total_findings,
                    "finding_categories": sum(
                        len(file_findings) for file_findings in results.values()
                    ),
                    "routes": len(routes),
                    "source_path": str(base),
                    "output_report": (str(output_path) if output_path else None),
                },
            )

            metadata_span.set_attribute(
                "argus.investigation.updated",
                True,
            )
            metadata_span.set_attribute(
                "argus.investigation.path",
                str(investigation),
            )
        except Exception as exc:
            metadata_span.record_exception(exc)
            metadata_span.set_status(
                Status(
                    StatusCode.ERROR,
                    str(exc),
                )
            )
            raise


def _set_final_span_attributes(
    span,
    js_files,
    failed_files,
    results,
    total_findings,
    routes,
    duration_ms,
):
    """Record final JavaScript analysis metrics."""
    span.set_attribute(
        "argus.javascript.files_analyzed",
        len(js_files) - failed_files,
    )
    span.set_attribute(
        "argus.javascript.files_with_findings",
        len(results),
    )
    span.set_attribute(
        "argus.javascript.findings_total",
        total_findings,
    )
    span.set_attribute(
        "argus.javascript.routes_unique",
        len(routes),
    )
    span.set_attribute(
        "argus.javascript.files_failed",
        failed_files,
    )
    span.set_attribute(
        "argus.duration_ms",
        duration_ms,
    )

    span.set_status(Status(StatusCode.OK))


def analyze(path, output=None, investigation=None, recursive=False):
    """
    Analyze JavaScript files for security-related patterns and routes.

    Args:
        path:
            Directory containing JavaScript files.

        output:
            Optional path where the JSON report will be written.

        investigation:
            Optional Argus investigation workspace. When supplied,
            metadata.json is updated automatically.

    Returns:
        Dictionary containing the JavaScript analysis report.
    """
    started = perf_counter()

    with tracer.start_as_current_span("argus.js.analyze") as span:
        base = Path(path).expanduser()

        span.set_attribute(
            "argus.module",
            "javascript",
        )
        span.set_attribute(
            "argus.target.path",
            str(base),
        )
        span.set_attribute(
            "argus.target.name",
            base.name,
        )
        span.set_attribute(
            "argus.output.enabled",
            output is not None,
        )
        span.set_attribute(
            "argus.investigation.enabled",
            investigation is not None,
        )

        if investigation:
            span.set_attribute(
                "argus.investigation.path",
                str(investigation),
            )

        _validate_source(base, span)

        js_files = _discover_javascript_files(
            base,
            span,
            recursive=recursive,
        )

        (
            results,
            routes,
            failed_files,
            total_findings,
        ) = _scan_javascript_files(js_files, base)

        report = _build_report(
            base,
            js_files,
            failed_files,
            results,
            routes,
        )

        result_json = json.dumps(
            report,
            indent=2,
        )

        output_path = _write_report(
            output,
            result_json,
        )

        duration_ms = round(
            (perf_counter() - started) * 1000,
            2,
        )

        _update_investigation(
            investigation,
            base,
            output_path,
            duration_ms,
            js_files,
            failed_files,
            results,
            total_findings,
            routes,
        )

        _set_final_span_attributes(
            span,
            js_files,
            failed_files,
            results,
            total_findings,
            routes,
            duration_ms,
        )

        print(result_json)

        return report
