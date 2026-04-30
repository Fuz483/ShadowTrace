import sys
import argparse


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='ShadowTrace - обнаружение процессов, использующих микрофон/камеру и сеть одновременно',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument('--gui', action='store_true', help='Запустить графический интерфейс')
    parser.add_argument('--cli', action='store_true', help='Запустить консольную версию')

    parser.add_argument(
        '--mode',
        choices=['audio', 'camera', 'full'],
        default='full',
        help='Режим сканирования (по умолчанию: full)'
    )

    parser.add_argument('--verbose', '-v', action='store_true', help='Подробный вывод')
    parser.add_argument('--save', '-s', action='store_true', help='Сохранить результаты в лог')

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.cli:
        from core.analyzer import ShadowTraceAnalyzer

        analyzer = ShadowTraceAnalyzer(scan_mode=args.mode)
        alerts = analyzer.scan()
        analyzer.print_alerts()

        if args.save:
            analyzer.save_alerts_to_log()

    else:
        try:
            from gui import main as gui_main
            gui_main()
        except ImportError as e:
            print(f"[!] Ошибка импорта GUI: {e}")
            print("[*] Установите CustomTkinter: pip install customtkinter")
            print("[*] Запускаю консольную версию...")

            from core.analyzer import ShadowTraceAnalyzer
            analyzer = ShadowTraceAnalyzer(scan_mode=args.mode)
            alerts = analyzer.scan()
            analyzer.print_alerts()


if __name__ == "__main__":
    main()