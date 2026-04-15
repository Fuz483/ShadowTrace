import sys
import argparse


def main():
    parser = argparse.ArgumentParser(description='ShadowTrace')
    parser.add_argument('--gui', action='store_true', help='Запустить графический интерфейс')
    parser.add_argument('--cli', action='store_true', help='Запустить консольную версию')
    args = parser.parse_args()

    if args.cli:
        from core.analyzer import ShadowTraceAnalyzer
        analyzer = ShadowTraceAnalyzer()
        alerts = analyzer.scan()
        analyzer.print_alerts()
    else:
        try:
            from gui import main as gui_main
            gui_main()
        except ImportError as e:
            print(f"[!] Ошибка импорта GUI: {e}")
            print("[*] Установите CustomTkinter: pip install customtkinter")
            print("[*] Запускаю консольную версию...")
            from core.analyzer import ShadowTraceAnalyzer
            analyzer = ShadowTraceAnalyzer()
            alerts = analyzer.scan()
            analyzer.print_alerts()


if __name__ == "__main__":
    main()