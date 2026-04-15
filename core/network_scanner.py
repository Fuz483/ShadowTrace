import psutil
from typing import List, Dict, Any, Optional
from utils.helpers import safe_proc_call, is_system_process
import config


class NetworkScanner:
    def __init__(self):
        self.connections: List[Dict[str, Any]] = []

    def scan(self) -> List[Dict[str, Any]]:
        self.connections = []

        for conn in psutil.net_connections(kind='inet'):
            if conn.status != 'ESTABLISHED' or not conn.raddr:
                continue

            if conn.pid in (0, 4):
                continue

            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            if self._is_ignored_ip(remote_ip):
                continue

            if remote_port in config.IGNORED_PORTS:
                continue

            proc_info = self._get_process_info(conn.pid)
            if proc_info is None:
                continue

            if is_system_process(conn.pid, proc_info['name']):
                continue

            self.connections.append({
                'pid': conn.pid,
                'name': proc_info['name'],
                'exe': proc_info['exe'],
                'local_port': conn.laddr.port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'status': conn.status,
            })

        return self.connections

    def _is_ignored_ip(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in config.IGNORED_IP_PREFIXES)

    def _get_process_info(self, pid: int) -> Optional[Dict[str, str]]:
        try:
            proc = psutil.Process(pid)

            name = safe_proc_call(proc, proc.name, "unknown")
            exe = safe_proc_call(proc, proc.exe, "")

            if name == "unknown" or name is None:
                return None

            return {'name': name, 'exe': exe}

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def get_unique_pids(self) -> set:
        return {conn['pid'] for conn in self.connections}