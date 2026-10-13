"""WS-R bounded diagnostics. Exception messages and credentials are never logged."""
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import threading

LOGGER = logging.getLogger('ws_r')
LOGGER.addHandler(logging.NullHandler())
LOGGER.propagate = False
LOCK = threading.Lock()


class QuietHandler(RotatingFileHandler):
    def handleError(self, record):
        # Logging must not produce stderr tracebacks or replace a scan failure.
        pass


def configure(path):
    """Return False if diagnostics cannot be written; never mask the scan result."""
    try:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        handler = QuietHandler(path, maxBytes=1048576, backupCount=2, encoding='utf-8')
        try:
            path.chmod(0o600)
        except OSError:
            pass
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        with LOCK:
            for old in list(LOGGER.handlers):
                LOGGER.removeHandler(old)
                old.close()
            LOGGER.addHandler(handler)
            LOGGER.setLevel(logging.INFO)
        return True
    except Exception:
        return False


def record(stage, exc):
    """Log structural diagnostics only, without exception strings or locals."""
    try:
        frames = []
        tb = exc.__traceback__
        while tb is not None:
            frames.append(f'{Path(tb.tb_frame.f_code.co_filename).name}:{tb.tb_lineno}')
            tb = tb.tb_next
        LOGGER.error('%s: %s [%s]', stage, type(exc).__name__, ', '.join(frames[-8:]))
    except Exception:
        pass
    return type(exc).__name__


def close():
    with LOCK:
        for handler in list(LOGGER.handlers):
            try:
                handler.close()
            except Exception:
                pass
            LOGGER.removeHandler(handler)
        LOGGER.addHandler(logging.NullHandler())
