import json
import os
from typing import List, Dict, Any, Set
from datetime import datetime
from enum import Enum

from core.network_scanner import NetworkScanner
from core.audio_detector import AudioDetector
from core.camera_detector import CameraDetector
import config


class ThreatLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ShadowTraceAnalyzer:
    def __init__(self, scan_mode: str = "full"):
        self.scan_mode = scan_mode
        self.network_scanner = NetworkScanner()
        self.audio_detector = AudioDetector() if scan_mode in ('audio', 'full') else None
        self.camera_detector = CameraDetector() if scan_mode in ('camera', 'full') else None
        self.whitelist = self._load_whitelist()
        self.alerts: List[Dict[str, Any]] = []

        self.stats = {
            'network_connections': 0,
            'audio_processes': 0,
            'camera_processes': 0,
            'alerts': 0,
        }

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
        network_connections = self.network_scanner.scan()
        network_pids = self.network_scanner.get_unique_pids()
        self.stats['network_connections'] = len(network_connections)

        audio_pids: Set[int] = set()
        camera_pids: Set[int] = set()

        if self.audio_detector:
            audio_pids = self.audio_detector.scan()
            self.stats['audio_processes'] = len(audio_pids)

        if self.camera_detector:
            camera_pids = self.camera_detector.scan()
            self.stats['camera_processes'] = len(camera_pids)

        self.alerts = []

        for pid in network_pids:
            process_name = self._get_process_name_from_connections(pid, network_connections)
            if process_name and process_name.lower() in self.whitelist:
                continue

            has_audio = pid in audio_pids
            has_camera = pid in camera_pids

            if not has_audio and not has_camera:
                continue

            threat_level = self._calculate_threat_level(has_audio, has_camera, pid)

            pid_connections = [c for c in network_connections if c['pid'] == pid]

            audio_info = None
            camera_info = None

            if has_audio and self.audio_detector:
                audio_info = self.audio_detector.get_process_info(pid)

            if has_camera and self.camera_detector:
                camera_info = self.camera_detector.get_process_info(pid)

            alert = {
                'timestamp': datetime.now().isoformat(),
                'pid': pid,
                'name': process_name,
                'exe': pid_connections[0]['exe'] if pid_connections else 'unknown',
                'has_audio': has_audio,
                'has_camera': has_camera,
                'threat_level': threat_level.value,
                'threat_level_name': config.THREAT_LEVELS[threat_level.value],
                'connections': pid_connections,
                'remote_ips': list({c['remote_ip'] for c in pid_connections}),
                'audio_info': audio_info,
                'camera_info': camera_info,
            }
            self.alerts.append(alert)

        threat_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        self.alerts.sort(key=lambda x: threat_order.get(x['threat_level'], 4))

        self.stats['alerts'] = len(self.alerts)

        return self.alerts

    def _calculate_threat_level(self, has_audio: bool, has_camera: bool, pid: int) -> ThreatLevel:
        score = 0

        if has_audio and has_camera:
            score += 40
        elif has_camera:
            score += 30
        elif has_audio:
            score += 20

        try:
            import psutil
            proc = psutil.Process(pid)
            exe = safe_proc_call(proc, proc.exe, "").lower()

            if '\\temp\\' in exe or '\\appdata\\local\\temp\\' in exe:
                score += 30

            elif '\\appdata\\' in exe and '\\microsoft\\' not in exe:
                score += 15

            try:
                if not proc.is_running():
                    score += 10
            except:
                pass

        except:
            pass

        if score >= 60:
            return ThreatLevel.CRITICAL
        elif score >= 40:
            return ThreatLevel.HIGH
        elif score >= 20:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

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
        print("=" * 80)

        for i, alert in enumerate(self.alerts, 1):
            threat_colors = {
                'CRITICAL': '\033[91m',
                'HIGH': '\033[93m',
                'MEDIUM': '\033[94m',
                'LOW': '\033[92m',
            }
            reset_color = '\033[0m'

            color = threat_colors.get(alert['threat_level'], '')

            print(f"\n{color}[{i}] {alert['name']} (PID: {alert['pid']}){reset_color}")
            print(f"    Уровень угрозы: {alert['threat_level_name']}")
            print(f"    Исполняемый файл: {alert['exe']}")

            activities = []
            if alert['has_audio']:
                activities.append("🎤 Аудио")
            if alert['has_camera']:
                activities.append("📷 Камера")
            print(f"    Активность: {', '.join(activities)}")

            if alert.get('audio_info') and alert['audio_info'].get('dlls'):
                print(f"    Аудио-DLL: {', '.join(alert['audio_info']['dlls'][:3])}")
            if alert.get('camera_info') and alert['camera_info'].get('dlls'):
                print(f"    Видео-DLL: {', '.join(alert['camera_info']['dlls'][:3])}")

            print(f"    Удалённые адреса: {', '.join(alert['remote_ips'])}")
            print(f"    Соединения:")
            for conn in alert['connections']:
                print(f"      - {conn['remote_ip']}:{conn['remote_port']} (локальный порт: {conn['local_port']})")

        print("\n" + "=" * 80)

    def save_alerts_to_log(self):
        if not self.alerts:
            return

        os.makedirs(config.LOGS_DIR, exist_ok=True)
        log_path = os.path.join(config.LOGS_DIR, 'alerts.log')

        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"\n{'=' * 80}\n")
            f.write(f"Сканирование: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Режим: {self.scan_mode}\n")
            f.write(f"Найдено алертов: {len(self.alerts)}\n")
            f.write(f"{'=' * 80}\n")

            for alert in self.alerts:
                f.write(f"\nПроцесс: {alert['name']} (PID: {alert['pid']})\n")
                f.write(f"Уровень угрозы: {alert['threat_level_name']}\n")
                f.write(f"Файл: {alert['exe']}\n")
                f.write(f"Аудио: {'Да' if alert['has_audio'] else 'Нет'}\n")
                f.write(f"Камера: {'Да' if alert['has_camera'] else 'Нет'}\n")
                f.write(f"IP-адреса: {', '.join(alert['remote_ips'])}\n")
                for conn in alert['connections']:
                    f.write(f"  -> {conn['remote_ip']}:{conn['remote_port']}\n")
            f.write(f"\n{'=' * 80}\n")

        print(f"[*] Алерты сохранены в {log_path}")

    def get_stats(self) -> Dict[str, int]:
        return self.stats