import customtkinter as ctk
import threading
import queue
from datetime import datetime
from typing import List, Dict, Any
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.analyzer import ShadowTraceAnalyzer
import config

# Настройка темы
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class ShadowTraceGUI:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.title("ShadowTrace - Детектор скрытой слежки")
        self.window.geometry("900x650")

        self.window.grid_rowconfigure(1, weight=1)
        self.window.grid_columnconfigure(0, weight=1)

        self.update_queue = queue.Queue()
        self.scanning_active = False

        self.analyzer = ShadowTraceAnalyzer()

        self.current_alerts: List[Dict[str, Any]] = []
        self.network_connections: List[Dict[str, Any]] = []
        self.audio_pids: set = set()

        self._create_header()
        self._create_main_area()
        self._create_footer()

        self._process_queue()

    def _create_header(self):
        header_frame = ctk.CTkFrame(self.window, corner_radius=0)
        header_frame.grid(row=0, column=0, sticky="ew", padx=0, pady=0)

        title_label = ctk.CTkLabel(
            header_frame,
            text="🛡️ ShadowTrace",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        title_label.pack(side="left", padx=20, pady=10)

        self.status_label = ctk.CTkLabel(
            header_frame,
            text="● Готов к сканированию",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.status_label.pack(side="left", padx=10, pady=10)

        button_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        button_frame.pack(side="right", padx=20, pady=10)

        self.scan_button = ctk.CTkButton(
            button_frame,
            text="🔍 Сканировать",
            command=self._start_scan,
            width=120,
            height=32
        )
        self.scan_button.pack(side="left", padx=5)

        self.stop_button = ctk.CTkButton(
            button_frame,
            text="⏹️ Стоп",
            command=self._stop_scan,
            width=80,
            height=32,
            fg_color="gray",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)

        self.export_button = ctk.CTkButton(
            button_frame,
            text="📄 Экспорт",
            command=self._export_results,
            width=80,
            height=32,
            fg_color="transparent",
            border_width=1
        )
        self.export_button.pack(side="left", padx=5)

    def _create_main_area(self):
        self.tabview = ctk.CTkTabview(self.window)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)

        self.tabview.add("🚨 Алерты")
        self.tabview.tab("🚨 Алерты").grid_columnconfigure(0, weight=1)
        self.tabview.tab("🚨 Алерты").grid_rowconfigure(0, weight=1)

        self.alerts_text = ctk.CTkTextbox(
            self.tabview.tab("🚨 Алерты"),
            font=ctk.CTkFont(size=13, family="Consolas"),
            wrap="none"
        )
        self.alerts_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        self.tabview.add("🌐 Сеть")
        self.tabview.tab("🌐 Сеть").grid_columnconfigure(0, weight=1)
        self.tabview.tab("🌐 Сеть").grid_rowconfigure(0, weight=1)

        self.network_text = ctk.CTkTextbox(
            self.tabview.tab("🌐 Сеть"),
            font=ctk.CTkFont(size=12, family="Consolas"),
            wrap="none"
        )
        self.network_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        self.tabview.add("🎤 Аудио")
        self.tabview.tab("🎤 Аудио").grid_columnconfigure(0, weight=1)
        self.tabview.tab("🎤 Аудио").grid_rowconfigure(0, weight=1)

        self.audio_text = ctk.CTkTextbox(
            self.tabview.tab("🎤 Аудио"),
            font=ctk.CTkFont(size=12, family="Consolas"),
            wrap="none"
        )
        self.audio_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        self.tabview.add("✅ Whitelist")
        self.tabview.tab("✅ Whitelist").grid_columnconfigure(0, weight=1)
        self.tabview.tab("✅ Whitelist").grid_rowconfigure(0, weight=1)
        self.tabview.tab("✅ Whitelist").grid_rowconfigure(1, weight=0)

        self.whitelist_text = ctk.CTkTextbox(
            self.tabview.tab("✅ Whitelist"),
            font=ctk.CTkFont(size=12, family="Consolas")
        )
        self.whitelist_text.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        whitelist_buttons = ctk.CTkFrame(self.tabview.tab("✅ Whitelist"), fg_color="transparent")
        whitelist_buttons.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        ctk.CTkButton(
            whitelist_buttons,
            text="➕ Добавить процесс",
            command=self._add_to_whitelist,
            width=150,
            height=30
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            whitelist_buttons,
            text="💾 Сохранить",
            command=self._save_whitelist,
            width=100,
            height=30,
            fg_color="transparent",
            border_width=1
        ).pack(side="left", padx=5)

        self._load_whitelist_display()

    def _create_footer(self):
        footer_frame = ctk.CTkFrame(self.window, height=30, corner_radius=0)
        footer_frame.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        footer_frame.grid_propagate(False)

        self.info_label = ctk.CTkLabel(
            footer_frame,
            text="Запустите от имени Администратора для полного доступа",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        self.info_label.pack(side="left", padx=20, pady=5)

        self.time_label = ctk.CTkLabel(
            footer_frame,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        self.time_label.pack(side="right", padx=20, pady=5)

    def _start_scan(self):
        if self.scanning_active:
            return

        self.scanning_active = True
        self.scan_button.configure(state="disabled", text="⏳ Сканирование...")
        self.stop_button.configure(state="normal", fg_color="#D32F2F")
        self.status_label.configure(text="● Сканирование...", text_color="#FFA500")

        self.alerts_text.delete("1.0", "end")
        self.network_text.delete("1.0", "end")
        self.audio_text.delete("1.0", "end")

        scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
        scan_thread.start()

    def _scan_worker(self):
        try:
            self.update_queue.put(("status", "● Сканирование сети...", "#FFA500"))
            network_connections = self.analyzer.network_scanner.scan()
            network_pids = self.analyzer.network_scanner.get_unique_pids()

            self.network_connections = network_connections
            self.update_queue.put(("network", network_connections))

            self.update_queue.put(("status", "● Сканирование аудио...", "#FFA500"))
            audio_pids = self.analyzer.audio_detector.scan()

            self.audio_pids = audio_pids
            self.update_queue.put(("audio", audio_pids))

            self.update_queue.put(("status", "● Анализ результатов...", "#FFA500"))

            suspicious_pids = network_pids & audio_pids

            alerts = []
            for pid in suspicious_pids:
                process_name = self._get_process_name(pid)

                if process_name and process_name.lower() in self.analyzer.whitelist:
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
                alerts.append(alert)

            self.current_alerts = alerts
            self.update_queue.put(("alerts", alerts))

            if alerts:
                self.update_queue.put(("status", f"⚠️ Найдено {len(alerts)} подозрительных процессов", "#FF0000"))
            else:
                self.update_queue.put(("status", "✅ Подозрительной активности не обнаружено", "#00FF00"))

        except Exception as e:
            self.update_queue.put(("error", str(e)))
        finally:
            self.update_queue.put(("scan_complete", None))

    def _process_queue(self):
        try:
            while True:
                msg = self.update_queue.get_nowait()
                msg_type = msg[0]

                if msg_type == "status":
                    self.status_label.configure(text=msg[1], text_color=msg[2])

                elif msg_type == "network":
                    self._display_network_connections(msg[1])

                elif msg_type == "audio":
                    self._display_audio_pids(msg[1])

                elif msg_type == "alerts":
                    self._display_alerts(msg[1])

                elif msg_type == "error":
                    self.status_label.configure(text=f"❌ Ошибка: {msg[1]}", text_color="#FF0000")

                elif msg_type == "scan_complete":
                    self.scanning_active = False
                    self.scan_button.configure(state="normal", text="🔍 Сканировать")
                    self.stop_button.configure(state="disabled", fg_color="gray")
                    self.time_label.configure(text=f"Последнее сканирование: {datetime.now().strftime('%H:%M:%S')}")

        except queue.Empty:
            pass
        finally:
            self.window.after(100, self._process_queue)

    def _display_alerts(self, alerts: List[Dict[str, Any]]):
        self.alerts_text.delete("1.0", "end")

        if not alerts:
            self.alerts_text.insert("end", "✅ Подозрительной активности не обнаружено.\n")
            self.alerts_text.insert("end", "\nЭто хорошо! Ваша система выглядит чистой.")
            return

        self.alerts_text.insert("end", f"⚠️ НАЙДЕНО ПОДОЗРИТЕЛЬНЫХ ПРОЦЕССОВ: {len(alerts)}\n")
        self.alerts_text.insert("end", "=" * 70 + "\n\n")

        for i, alert in enumerate(alerts, 1):
            self.alerts_text.insert("end", f"[{i}] ")
            self.alerts_text.insert("end", f"{alert['name']} ", "alert_name")
            self.alerts_text.insert("end", f"(PID: {alert['pid']})\n")
            self.alerts_text.insert("end", f"    📁 Файл: {alert['exe']}\n")
            self.alerts_text.insert("end", f"    🌐 Удалённые адреса:\n")

            for conn in alert['connections']:
                self.alerts_text.insert("end", f"       → {conn['remote_ip']}:{conn['remote_port']} ")
                self.alerts_text.insert("end", f"(локальный порт: {conn['local_port']})\n", "dim")

            self.alerts_text.insert("end", "\n")

        self.alerts_text.tag_config("alert_name", foreground="#FF6B6B")
        self.alerts_text.tag_config("dim", foreground="#666666")

    def _display_network_connections(self, connections: List[Dict[str, Any]]):
        self.network_text.delete("1.0", "end")

        self.network_text.insert("end", f"🌐 АКТИВНЫЕ СЕТЕВЫЕ СОЕДИНЕНИЯ: {len(connections)}\n")
        self.network_text.insert("end", "=" * 80 + "\n\n")

        self.network_text.insert("end", f"{'PID':<8} {'Процесс':<25} {'Лок.порт':<10} {'Удалённый адрес':<25}\n",
                                 "header")
        self.network_text.insert("end", "-" * 80 + "\n")

        for conn in sorted(connections, key=lambda x: x['name']):
            line = f"{conn['pid']:<8} {conn['name'][:24]:<25} {conn['local_port']:<10} {conn['remote_ip']}:{conn['remote_port']}\n"
            self.network_text.insert("end", line)

        self.network_text.tag_config("header", foreground="#4A90D9")

    def _display_audio_pids(self, pids: set):
        self.audio_text.delete("1.0", "end")

        self.audio_text.insert("end", f"🎤 ПРОЦЕССЫ С АУДИО-DLL: {len(pids)}\n")
        self.audio_text.insert("end", "=" * 60 + "\n\n")

        for pid in sorted(pids):
            try:
                import psutil
                proc = psutil.Process(pid)
                name = proc.name()
                exe = proc.exe()

                self.audio_text.insert("end", f"PID: {pid:<8} ")
                self.audio_text.insert("end", f"{name}\n", "process_name")
                self.audio_text.insert("end", f"     📁 {exe}\n\n", "dim")
            except:
                self.audio_text.insert("end", f"PID: {pid:<8} ")
                self.audio_text.insert("end", "[недоступен]\n\n", "dim")

        self.audio_text.tag_config("process_name", foreground="#50C878")
        self.audio_text.tag_config("dim", foreground="#666666")

    def _load_whitelist_display(self):
        self.whitelist_text.delete("1.0", "end")

        self.whitelist_text.insert("end", "✅ БЕЛЫЙ СПИСОК ПРОЦЕССОВ\n", "header")
        self.whitelist_text.insert("end", "=" * 40 + "\n\n")
        self.whitelist_text.insert("end", "Эти процессы игнорируются при сканировании:\n\n", "dim")

        for process in sorted(self.analyzer.whitelist):
            self.whitelist_text.insert("end", f"  ✓ ")
            self.whitelist_text.insert("end", f"{process}\n", "process_item")

        self.whitelist_text.tag_config("header", foreground="#4A90D9")
        self.whitelist_text.tag_config("dim", foreground="#666666")
        self.whitelist_text.tag_config("process_item", foreground="#50C878")

    def _add_to_whitelist(self):
        dialog = ctk.CTkInputDialog(
            text="Введите имя процесса (например, zoom.exe):",
            title="Добавить в белый список"
        )
        process_name = dialog.get_input()

        if process_name:
            self.analyzer.whitelist.add(process_name.lower())
            self._load_whitelist_display()

    def _save_whitelist(self):
        import json

        try:
            data = {
                "process_names": list(self.analyzer.whitelist),
                "description": "Процессы, которые игнорируются при сканировании"
            }

            with open(config.WHITELIST_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            self._show_message("Успех", "Белый список сохранён!")
        except Exception as e:
            self._show_message("Ошибка", f"Не удалось сохранить: {e}")

    def _export_results(self):
        if not self.current_alerts:
            self._show_message("Информация", "Нет данных для экспорта.")
            return

        from tkinter import filedialog

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"shadowtrace_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"ShadowTrace Export - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n\n")

                    f.write(f"Найдено алертов: {len(self.current_alerts)}\n\n")

                    for alert in self.current_alerts:
                        f.write(f"Процесс: {alert['name']} (PID: {alert['pid']})\n")
                        f.write(f"Файл: {alert['exe']}\n")
                        f.write(f"IP-адреса: {', '.join(alert['remote_ips'])}\n")
                        for conn in alert['connections']:
                            f.write(f"  -> {conn['remote_ip']}:{conn['remote_port']}\n")
                        f.write("\n")

                    f.write("\n" + "=" * 60 + "\n")
                    f.write("Сетевые соединения:\n")
                    for conn in self.network_connections:
                        f.write(f"  {conn['name']} -> {conn['remote_ip']}:{conn['remote_port']}\n")

                self._show_message("Успех", f"Результаты сохранены в:\n{file_path}")
            except Exception as e:
                self._show_message("Ошибка", f"Не удалось экспортировать: {e}")

    def _stop_scan(self):
        self.scanning_active = False
        self.status_label.configure(text="● Сканирование остановлено", text_color="gray")

    def _get_process_name(self, pid: int) -> str:
        for conn in self.network_connections:
            if conn['pid'] == pid:
                return conn['name']
        return f"PID_{pid}"

    def _show_message(self, title: str, message: str):
        dialog = ctk.CTkToplevel(self.window)
        dialog.title(title)
        dialog.geometry("400x150")
        dialog.transient(self.window)
        dialog.grab_set()

        label = ctk.CTkLabel(dialog, text=message, font=ctk.CTkFont(size=13), wraplength=350)
        label.pack(pady=20, padx=20)

        button = ctk.CTkButton(dialog, text="OK", command=dialog.destroy, width=100)
        button.pack(pady=10)

        dialog.update_idletasks()
        x = self.window.winfo_x() + (self.window.winfo_width() - dialog.winfo_width()) // 2
        y = self.window.winfo_y() + (self.window.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

    def run(self):
        self.window.mainloop()


def main():
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] ВНИМАНИЕ: Запустите от имени Администратора для полной функциональности!")

    app = ShadowTraceGUI()
    app.run()


if __name__ == "__main__":
    main()