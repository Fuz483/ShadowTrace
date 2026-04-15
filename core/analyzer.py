import json
import os
from typing import List, Dict, Any, Set
from datetime import datetime

from core.network_scanner import NetworkScanner
from core.audio_detector import AudioDetector
import config


class ShadowTraceAnalyzer:
    def __init__(self):
        self.network_scanner = NetworkScanner()
        self.audio_detector = AudioDetector()
        self.whitelist = self._load_whitelist()
        self.alerts: List[Dict[str, Any]] = []

    def _load_whitelist(self) -> Set[str]:
        whitelist_path = config.WHITELIST_FILE
        os.makedirs(os.path.dirname(whitelist_path), exist_ok=True)

        if not os.path.exists(whitelist_path):
            with open(whitelist_path, 'w', encoding='utf-8') as f:
                json.dump(config.DEFAULT_WHITELIST, f, indent=2, ensure_ascii=False)
            return set(config.DEFAULT_WHITELIST['process_names'])

        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return {name.lower() for name in data.get('process_names', [])}
        except (json.JSONDecodeError, IOError):
            return set(config.DEFAULT_WHITELIST['process_names'])

    def scan(self) -> List[Dict[str, Any]]:
        print("[*] Сканирование сетевых соединений...")
        network_connections = self.network_scanner.scan()
        network_pids = self.network_scanner.get_unique_pids()

        print(f"[*] Найдено {len(network_connections)} сетевых соединений")
        print(f"[*] Уникальных PID с сетью: {len(network_pids)}")

        print("[*] Сканирование аудио-активности...")
        audio_pids = self.audio_detector.scan()
        print(f"[*] Найдено {len(audio_pids)} PID с аудио-DLL")

        suspicious_pids = network_pids & audio_pids
        print(f"[*] Подозрительных PID (пересечение): {len(suspicious_pids)}")

        self.alerts = []
        for pid in suspicious_pids:
            process_name = self._get_process_name_from_connections(pid, network_connections)

            if process_name and process_name.lower() in self.whitelist:
                print(f"[i] Пропущен (whitelist): {process_name} (PID: {pid})")
                continue

            pid_connections = [c for c in network_connections if c['pid'] == pid]

            alert = {
                'timestamp': datetime.now().isoformat(),
                'pid': pid,
                'name': process_name,
                'exe': pid_connections[0]['exe'] if pid_connections else 'unknown',
                'connections': pid_connections,
                'remote_ips': list({c['remote_ip'] for c in pid_connections}),
            }
            self.alerts.append(alert)

        return self.alerts

    def _get_process_name_from_connections(self, pid: int, connections: List[Dict]) -> str:
        for conn in connections:
            if conn['pid'] == pid:
                return conn['name']
        return f"PID_{pid}"

    def print_alerts(self):
        if not self.alerts:
            print("\n[+] Подозрительной активности не обнаружено.")
            return

        print(f"\n[!] ОБНАРУЖЕНО ПОДОЗРИТЕЛЬНЫХ ПРОЦЕССОВ: {len(self.alerts)}")
        print("=" * 70)

        for i, alert in enumerate(self.alerts, 1):
            print(f"\n[{i}] {alert['name']} (PID: {alert['pid']})")
            print(f"    Исполняемый файл: {alert['exe']}")
            print(f"    Удалённые адреса: {', '.join(alert['remote_ips'])}")
            print(f"    Соединения:")
            for conn in alert['connections']:
                print(f"      - {conn['remote_ip']}:{conn['remote_port']} (локальный порт: {conn['local_port']})")

        print("\n" + "=" * 70)

    def save_alerts_to_log(self):
        if not self.alerts:
            return

        os.makedirs(config.LOGS_DIR, exist_ok=True)
        log_path = os.path.join(config.LOGS_DIR, 'alerts.log')

        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"\n{'=' * 60}\n")
            f.write(f"Сканирование: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Найдено алертов: {len(self.alerts)}\n")
            f.write(f"{'=' * 60}\n")

            for alert in self.alerts:
                f.write(f"\nПроцесс: {alert['name']} (PID: {alert['pid']})\n")
                f.write(f"Файл: {alert['exe']}\n")
                f.write(f"IP-адреса: {', '.join(alert['remote_ips'])}\n")
                for conn in alert['connections']:
                    f.write(f"  -> {conn['remote_ip']}:{conn['remote_port']}\n")
            f.write(f"\n{'=' * 60}\n")

        print(f"[*] Алерты сохранены в {log_path}")