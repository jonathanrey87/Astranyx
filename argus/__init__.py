from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("argus-security")
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = ["__version__"]
