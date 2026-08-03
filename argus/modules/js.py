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
    "collaboration": (
        r"invite|team|organization|workspace|member|permission|comment"
    ),
    "admin": r"admin|internal|staff|employee",
}


ROUTE_PATTERN = re.compile(
    r"""["'`]((?:https?://|/)[A-Za-z0-9._~:/?#@!$&()*+,;=%\-\[\]]+)["'`]"""
)


def analyze(path, output=None, investigation=None):
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

        span.set_attribute("argus.module", "javascript")
        span.set_attribute("argus.target.path", str(base))
        span.set_attribute("argus.target.name", base.name)
        span.set_attribute("argus.output.enabled", output is not None)
        span.set_attribute(
            "argus.investigation.enabled",
            investigation is not None,
        )

        if investigation:
            span.set_attribute(
                "argus.investigation.path",
                str(investigation),
            )

        if not base.exists():
            message = f"Path not found: {base}"

            span.set_attribute(
                "argus.error.type",
                "path_not_found",
            )
            span.set_status(
                Status(StatusCode.ERROR, message)
            )

            raise SystemExit(f"[!] {message}")

        if not base.is_dir():
            message = f"Path is not a directory: {base}"

            span.set_attribute(
                "argus.error.type",
                "not_a_directory",
            )
            span.set_status(
                Status(StatusCode.ERROR, message)
            )

            raise SystemExit(f"[!] {message}")

        # Discover JavaScript files.
        with tracer.start_as_current_span(
            "argus.js.discover_files"
        ) as discovery_span:
            js_files = sorted(base.glob("*.js"))

            discovery_span.set_attribute(
                "argus.javascript.files_discovered",
                len(js_files),
            )

        if not js_files:
            message = f"No JavaScript files found in {base}"

            span.set_attribute(
                "argus.error.type",
                "no_javascript_files",
            )
            span.set_status(
                Status(StatusCode.ERROR, message)
            )

            raise SystemExit(f"[!] {message}")

        results = {}
        routes = set()
        failed_files = 0
        total_findings = 0

        # Scan all discovered files.
        with tracer.start_as_current_span(
            "argus.js.scan_files"
        ) as scan_span:
            for file_path in js_files:
                with tracer.start_as_current_span(
                    "argus.js.scan_file"
                ) as file_span:
                    file_span.set_attribute(
                        "argus.file.name",
                        file_path.name,
                    )
                    file_span.set_attribute(
                        "argus.file.path",
                        str(file_path),
                    )

                    try:
                        text = file_path.read_text(
                            encoding="utf-8",
                            errors="ignore",
                        )
                    except Exception as exc:
                        failed_files += 1

                        file_span.record_exception(exc)
                        file_span.set_status(
                            Status(
                                StatusCode.ERROR,
                                str(exc),
                            )
                        )

                        print(
                            f"[!] Failed reading "
                            f"{file_path}: {exc}"
                        )
                        continue

                    file_span.set_attribute(
                        "argus.file.size_characters",
                        len(text),
                    )

                    findings = {}

                    for name, pattern in PATTERNS.items():
                        matches = re.findall(
                            pattern,
                            text,
                            flags=re.IGNORECASE,
                        )

                        if matches:
                            match_count = len(matches)
                            findings[name] = match_count
                            total_findings += match_count

                    file_routes = ROUTE_PATTERN.findall(text)

                    for route in file_routes:
                        routes.add(route)

                    file_span.set_attribute(
                        "argus.file.finding_categories",
                        len(findings),
                    )
                    file_span.set_attribute(
                        "argus.file.findings_total",
                        sum(findings.values()),
                    )
                    file_span.set_attribute(
                        "argus.file.routes_found",
                        len(file_routes),
                    )

                    if findings:
                        results[file_path.name] = findings

            scan_span.set_attribute(
                "argus.javascript.files_processed",
                len(js_files) - failed_files,
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

        report = {
            "target": base.name,
            "files_analyzed": len(js_files) - failed_files,
            "summary": results,
            "routes": sorted(routes),
        }

        result_json = json.dumps(
            report,
            indent=2,
        )

        # Write the optional standalone JSON report.
        if output:
            with tracer.start_as_current_span(
                "argus.js.write_report"
            ) as output_span:
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

                    output_span.set_attribute(
                        "argus.output.bytes",
                        len(result_json.encode("utf-8")),
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

                print(
                    f"[+] Report written to {output_path}"
                )

        duration_ms = round(
            (perf_counter() - started) * 1000,
            2,
        )

        # Update investigation metadata when requested.
        if investigation:
            with tracer.start_as_current_span(
                "argus.js.update_investigation"
            ) as metadata_span:
                try:
                    manager = InvestigationManager(
                        investigation
                    )

                    manager.set_target(str(base))

                    manager.add_module(
                        name="javascript",
                        status="completed",
                        duration_ms=duration_ms,
                        details={
                            "files": len(js_files),
                            "files_processed": (
                                len(js_files) - failed_files
                            ),
                            "files_failed": failed_files,
                            "files_with_findings": len(results),
                            "findings_total": total_findings,
                            "finding_categories": sum(
                                len(file_findings)
                                for file_findings
                                in results.values()
                            ),
                            "routes": len(routes),
                            "source_path": str(base),
                            "output_report": (
                                str(Path(output).expanduser())
                                if output
                                else None
                            ),
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

        span.set_attribute(
            "argus.javascript.files_analyzed",
            len(js_files),
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

        print(result_json)

        return report
