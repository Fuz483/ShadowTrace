"""
ShadowTrace - Детектор скрытого шпионского ПО.
"""
import sys
import argparse


def create_parser() -> argparse.ArgumentParser:
    """Создаёт парсер аргументов командной строки."""
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

    # По умолчанию запускаем GUI
    if args.cli:
        from core.analyzer import ShadowTraceAnalyzer

        print(r"""
   _____ __         __      _____
  / ___// /_  ___  / /_____/ ___/_________ ___
  \__ \/ __ \/ _ \/ __/ __/ __// ___/ __ `__ \
 ___/ / / / /  __/ /_/ /_/ /_  / /  / / / / / /
/____/_/ /_/\___/\__/\__/____/_/  /_/ /_/ /_/
        """)
        print(f"        Детектор скрытой слежки v1.1.0")
        print(f"        Режим: {args.mode}")
        print()

        analyzer = ShadowTraceAnalyzer(scan_mode=args.mode)
        alerts = analyzer.scan()
        analyzer.print_alerts()

        if args.save:
            analyzer.save_alerts_to_log()

        # Статистика
        stats = analyzer.get_stats()
        print(f"\n[*] Статистика сканирования:")
        print(f"    Сетевых соединений: {stats['network_connections']}")
        print(f"    Аудио-процессов: {stats['audio_processes']}")
        print(f"    Видео-процессов: {stats['camera_processes']}")
        print(f"    Алертов: {stats['alerts']}")

    else:
        # GUI режим
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