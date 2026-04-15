import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
WHITELIST_FILE = os.path.join(DATA_DIR, 'whitelist.json')

# Аудио-библиотеки Windows (признак работы со звуком)
AUDIO_DLLS = [
    'winmm.dll',
    'wdmaud.drv',
    'audioses.dll',
    'mmdevapi.dll',
    'dsound.dll',
    'audioeng.dll',
    'avrt.dll',
]

# Видео-библиотеки (для будущего расширения)
VIDEO_DLLS = [
    'ksuser.dll',
    'vidcap.ax',
    'dshowcore.dll',
]

IGNORED_IP_PREFIXES = (
    '127.',
    '0.',
    '224.',
    '239.',
    '255.',
    '169.254.',
)

IGNORED_PORTS = {0, 137, 138, 139, 445}

SYSTEM_PROCESS_NAMES = {
    'Registry', 'csrss.exe', 'smss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'winlogon.exe', 'System',
    'svchost.exe', 'dwm.exe', 'spoolsv.exe', 'MsMpEng.exe',
}

DEFAULT_WHITELIST = {
    "process_names": [
        "chrome.exe",
        "firefox.exe",
        "msedge.exe",
        "zoom.exe",
        "discord.exe",
        "slack.exe",
        "teams.exe",
        "skype.exe",
        "obs64.exe",
        "audacity.exe",
    ],
    "description": "Процессы, которые игнорируются при сканировании"
}

SCAN_INTERVAL_SECONDS = 5
MAX_PROCESS_AGE_SECONDS = 60