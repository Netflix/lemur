try:
    from importlib.metadata import version
    VERSION = version(__name__)
except Exception as e:
    VERSION = "unknown"
