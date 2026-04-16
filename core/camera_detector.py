"""
Детектор использования веб-камеры через анализ загруженных DLL.
"""
import psutil
from typing import Set, List, Optional, Dict, Any
from utils.helpers import safe_proc_call, is_system_process
import config


class CameraDetector:
    """Обнаруживает процессы, потенциально использующие веб-камеру."""

    def __init__(self):
        self.camera_pids: Set[int] = set()
        self.camera_processes: List[Dict[str, Any]] = []

    def scan(self) -> Set[int]:
        """
        Сканирует все процессы на наличие видео-DLL.

        Returns:
            Множество PID процессов, загрузивших видео-DLL.
        """
        self.camera_pids = set()
        self.camera_processes = []

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']

                # Пропускаем системные процессы
                if is_system_process(pid, name):
                    continue

                # Проверяем загруженные DLL
                found_dlls = self._get_camera_dlls(proc)

                if found_dlls:
                    self.camera_pids.add(pid)

                    # Сохраняем детальную информацию
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
        """
        Возвращает список видео-DLL, загруженных в процесс.

        Args:
            proc: объект процесса

        Returns:
            Список найденных DLL (пустой, если ничего не найдено)
        """
        found_dlls = []

        try:
            maps = safe_proc_call(proc, proc.memory_maps, default=[])

            for mmap in maps:
                if not hasattr(mmap, 'path') or not mmap.path:
                    continue

                path_lower = mmap.path.lower()

                for dll in config.CAMERA_DLLS:
                    if dll in path_lower:
                        # Извлекаем только имя файла из пути
                        dll_name = path_lower.split('\\')[-1]
                        if dll_name not in found_dlls:
                            found_dlls.append(dll_name)

        except Exception:
            pass

        return found_dlls

    def check_specific_pid(self, pid: int) -> bool:
        """
        Проверяет конкретный PID на наличие видео-DLL.

        Args:
            pid: идентификатор процесса

        Returns:
            True, если процесс использует видео-DLL
        """
        try:
            proc = psutil.Process(pid)
            return len(self._get_camera_dlls(proc)) > 0
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def get_process_info(self, pid: int) -> Optional[Dict[str, Any]]:
        """
        Возвращает детальную информацию о процессе с камерой.

        Args:
            pid: идентификатор процесса

        Returns:
            Словарь с информацией или None
        """
        for proc_info in self.camera_processes:
            if proc_info['pid'] == pid:
                return proc_info
        return None

    def get_all_camera_processes(self) -> List[Dict[str, Any]]:
        """Возвращает список всех процессов, использующих камеру."""
        return self.camera_processes