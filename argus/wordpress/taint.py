import re
from dataclasses import dataclass


@dataclass
class TaintFinding:
    source: str
    sink: str
    variable: str
    confidence: int
    reason: str


SOURCES = [
    r"\$_GET",
    r"\$_POST",
    r"\$_REQUEST",
    r"\$_COOKIE",
    r"\$_FILES",
    r"\$_SERVER",
    r"php://input",
]


SINKS = [
    "eval",
    "exec",
    "system",
    "shell_exec",
    "passthru",
    "include",
    "require",
    "wp_remote_get",
    "wp_remote_post",
    "curl_init",
    "file_get_contents",
    "$wpdb->query",
]


ASSIGNMENT = re.compile(r"(\$[A-Za-z0-9_]+)\s*=\s*(.+);")


def analyze(lines):
    tainted = {}
    findings = []

    for line in lines:
        match = ASSIGNMENT.search(line)

        if match:
            var = match.group(1)
            rhs = match.group(2)

            for src in SOURCES:
                if re.search(src, rhs):
                    tainted[var] = src

        for sink in SINKS:
            if sink in line:
                for var, source in tainted.items():
                    if var in line:
                        findings.append(
                            TaintFinding(
                                source=source,
                                sink=sink,
                                variable=var,
                                confidence=95,
                                reason=f"{var} flows from {source} into {sink}",
                            )
                        )

    return findings
