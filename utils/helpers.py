import psutil
from typing import Any, Callable, Optional


def safe_proc_call(proc: psutil.Process,
                   method: Callable,
                   default: Any = None,
                   *args,
                   **kwargs) -> Any:
    try:
        return method(*args, **kwargs)
    except psutil.AccessDenied:
        return default if default is not None else None
    except psutil.NoSuchProcess:
        return default if default is not None else None
    except Exception as e:
        return default if default is not None else None


def is_system_process(pid: int, name: str) -> bool:
    SYSTEM_PIDS = {0, 4}
    SYSTEM_NAMES = {
        'Registry', 'csrss.exe', 'smss.exe', 'wininit.exe',
        'services.exe', 'lsass.exe', 'winlogon.exe', 'System'
    }

    return pid in SYSTEM_PIDS or name in SYSTEM_NAMES


def format_bytes(bytes_value: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.2f} TB"