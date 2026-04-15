import psutil
from typing import Set, List, Optional
from utils.helpers import safe_proc_call, is_system_process
import config


class AudioDetector:
    def __init__(self):
        self.audio_pids: Set[int] = set()

    def scan(self) -> Set[int]:
        self.audio_pids = set()

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']

                if is_system_process(pid, name):
                    continue

                if self._has_audio_dll(proc):
                    self.audio_pids.add(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return self.audio_pids

    def _has_audio_dll(self, proc: psutil.Process) -> bool:
        try:
            maps = safe_proc_call(proc, proc.memory_maps, default=[])

            for mmap in maps:
                if not hasattr(mmap, 'path') or not mmap.path:
                    continue

                path_lower = mmap.path.lower()

                for dll in config.AUDIO_DLLS:
                    if dll in path_lower:
                        return True

        except Exception:
            pass

        return False

    def check_specific_pid(self, pid: int) -> bool:
        try:
            proc = psutil.Process(pid)
            return self._has_audio_dll(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False