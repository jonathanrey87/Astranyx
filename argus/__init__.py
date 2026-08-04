from importlib.metadata import PackageNotFoundError
from importlib.metadata import version


try:
    __version__ = version("argus-security")
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = ["__version__"]
