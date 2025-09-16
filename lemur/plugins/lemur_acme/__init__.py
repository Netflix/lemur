try:
    from importlib.metadata import version, PackageNotFoundError
    VERSION = version(__name__)
except (ImportError, PackageNotFoundError, Exception):
    VERSION = "unknown"
