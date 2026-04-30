import psutil
from typing import Set, List, Optional, Dict, Any
from utils.helpers import safe_proc_call, is_system_process
import config


class CameraDetector:
    def __init__(self):
        self.camera_pids: Set[int] = set()
        self.camera_processes: List[Dict[str, Any]] = []

    def scan(self) -> Set[int]:
        self.camera_pids = set()
        self.camera_processes = []

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']

                if is_system_process(pid, name):
                    continue

                found_dlls = self._get_camera_dlls(proc)

                if found_dlls:
                    self.camera_pids.add(pid)
                    try:
                        exe = safe_proc_call(proc, proc.exe, "unknown")
                    except:
                        exe = "unknown"

                    self.camera_processes.append({
                        'pid': pid,
                        'name': name,
                        'exe': exe,
                        'dlls': found_dlls,
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return self.camera_pids

    def _get_camera_dlls(self, proc: psutil.Process) -> List[str]:
        found_dlls = []
        try:
            maps = safe_proc_call(proc, proc.memory_maps, default=[])

            for mmap in maps:
                if not hasattr(mmap, 'path') or not mmap.path:
                    continue

                path_lower = mmap.path.lower()

                for dll in config.CAMERA_DLLS:
                    if dll in path_lower:
                        dll_name = path_lower.split('\\')[-1]
                        if dll_name not in found_dlls:
                            found_dlls.append(dll_name)

        except Exception:
            pass

        return found_dlls

    def check_specific_pid(self, pid: int) -> bool:
        try:
            proc = psutil.Process(pid)
            return len(self._get_camera_dlls(proc)) > 0
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def get_process_info(self, pid: int) -> Optional[Dict[str, Any]]:
        for proc_info in self.camera_processes:
            if proc_info['pid'] == pid:
                return proc_info
        return None

    def get_all_camera_processes(self) -> List[Dict[str, Any]]:
        return self.camera_processes