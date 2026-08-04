from __future__ import annotations

from enum import Enum


class TrustLevel(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    EXTERNAL = "external"
    CONFIGURATION = "configuration"
    DATABASE = "database"
    UNKNOWN = "unknown"


class TrustEngine:

    def classify(self, value: str) -> TrustLevel:

        value = value.lower()

        prefixes = (
            "params",
            "request",
            "cookies",
            "headers",
            "json",
            "body",
            "query",
            "form",
        )

        if value.startswith(prefixes):
            return TrustLevel.UNTRUSTED

        if value.startswith(("env", "settings", "config")):
            return TrustLevel.CONFIGURATION

        if value.startswith(("db", "database", "record", "model")):
            return TrustLevel.DATABASE

        if value.startswith(("http", "https", "uri", "url")):
            return TrustLevel.EXTERNAL

        return TrustLevel.UNKNOWN
