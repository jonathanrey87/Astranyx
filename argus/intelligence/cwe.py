CWE_MAP = {
    "SQL Query": {
        "cwe": "CWE-89",
        "owasp": "A03 Injection",
        "cvss": "8.8",
    },
    "Possible Unsafe SQL": {
        "cwe": "CWE-89",
        "owasp": "A03 Injection",
        "cvss": "9.1",
    },
    "React Dangerous Sink": {
        "cwe": "CWE-79",
        "owasp": "A03 Injection",
        "cvss": "6.1",
    },
    "DOM Sink": {
        "cwe": "CWE-79",
        "owasp": "A03 Injection",
        "cvss": "6.1",
    },
    "SSRF Sink": {
        "cwe": "CWE-918",
        "owasp": "A10 SSRF",
        "cvss": "8.6",
    },
    "Public REST Permission": {
        "cwe": "CWE-862",
        "owasp": "A01 Broken Access Control",
        "cvss": "8.1",
    },
    "Public AJAX Route": {
        "cwe": "CWE-862",
        "owasp": "A01 Broken Access Control",
        "cvss": "8.1",
    },
    "Upload Handler": {
        "cwe": "CWE-434",
        "owasp": "A05 Security Misconfiguration",
        "cvss": "8.8",
    },
    "Deserialization": {
        "cwe": "CWE-502",
        "owasp": "A08 Software and Data Integrity Failures",
        "cvss": "8.1",
    },
    "Dynamic Include": {
        "cwe": "CWE-98",
        "owasp": "A03 Injection",
        "cvss": "9.0",
    },
    "Dangerous Function": {
        "cwe": "CWE-94",
        "owasp": "A03 Injection",
        "cvss": "9.8",
    },
    "Potential Taint Flow": {
        "cwe": "CWE-20",
        "owasp": "A03 Injection",
        "cvss": "8.0",
    },
}


def get_mapping(category):
    return CWE_MAP.get(category, {
        "cwe": "N/A",
        "owasp": "N/A",
        "cvss": "N/A",
    })
