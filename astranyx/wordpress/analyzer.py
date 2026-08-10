from astranyx.intelligence.safe_patterns import reduce_noise
from astranyx.wordpress.sql import analyze_sql_finding


def get_context(lines, line_number, radius=8):
    start = max(0, line_number - radius - 1)
    end = min(len(lines), line_number + radius)
    return "\n".join(lines[start:end])


def analyze_finding(finding, lines):
    context = get_context(lines, finding.line)

    finding.confidence = 50
    finding.reason = "Manual review required."

    if finding.category == "React Dangerous Sink":
        if any(
            x in context
            for x in (
                "DOMPurify",
                "htmlspecialchars",
                "esc_html",
                ".replace(/</g",
                "&lt;",
                "&amp;",
            )
        ):
            finding.confidence = 5
            finding.reason = "HTML escaping/sanitization detected before rendering."
        else:
            finding.confidence = 80
            finding.reason = "No obvious escaping found near DOM sink."

    elif finding.category == "Public REST Permission":
        if any(
            x in context
            for x in (
                "current_user_can",
                "ensurePermission",
                "manage_options",
                "Capabilities::Check",
            )
        ):
            finding.confidence = 15
            finding.reason = "Authorization check found near route."
        else:
            finding.confidence = 90
            finding.reason = "Public REST route without nearby authorization."

    elif finding.category == "Dynamic Include":
        if any(
            x in context
            for x in (
                "$_GET",
                "$_POST",
                "$_REQUEST",
                "$_FILES",
            )
        ):
            finding.confidence = 85
            finding.reason = "Include path may be influenced by user input."
        else:
            finding.confidence = 10
            finding.reason = "Include path appears internal."

    elif finding.category == "Deserialization":
        if "allowed_classes" in context:
            finding.confidence = 5
            finding.reason = "allowed_classes protection detected."
        else:
            finding.confidence = 65
            finding.reason = "Verify serialized data origin."

    elif finding.category == "SSRF Sink":
        if "wp_remote_get" in context or "wp_remote_post" in context:
            finding.confidence = 75
            finding.reason = "Outbound HTTP request detected."
        elif "file_get_contents" in context:
            finding.confidence = 10
            finding.reason = "Likely local file read."
        else:
            finding.confidence = 40
            finding.reason = "Manual review recommended."

    elif finding.category == "SQL Query":
        finding = analyze_sql_finding(finding, context)

    finding = reduce_noise(finding, context)
    return finding
