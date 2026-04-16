import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
WHITELIST_FILE = os.path.join(DATA_DIR, 'whitelist.json')

# Аудио-библиотеки Windows (признак работы со звуком)
AUDIO_DLLS = [
    'winmm.dll',        # Windows Multimedia API
    'wdmaud.drv',       # WDM Audio driver
    'audioses.dll',     # Audio Session API
    'mmdevapi.dll',     # MMDevice API
    'dsound.dll',       # DirectSound
    'audioeng.dll',     # Audio Engine
    'avrt.dll',         # Audio/Video Rendering
]

# Видео-библиотеки Windows (признак работы с веб-камерой)
CAMERA_DLLS = [
    'ksuser.dll',           # Kernel Streaming (основная для камеры)
    'vidcap.ax',            # Video Capture ActiveX
    'qcap.dll',             # DirectShow Capture
    'mf.dll',               # Media Foundation
    'mfplat.dll',           # Media Foundation Platform
    'mfreadwrite.dll',      # Media Foundation Read/Write
    'dshowcore.dll',        # DirectShow Core
    'devenum.dll',          # Device Enumerator
    'msvfw32.dll',          # Video for Windows
    'avicap32.dll',         # AVI Capture
    'cameraplatform.dll',   # Windows Camera Platform
    'windows.media.capture.dll',  # UWP Camera API
    'webcam.dll',           # Common webcam wrapper
    'uvc.dll',              # USB Video Class driver
]

# Комбинированный список (для обратной совместимости)
MEDIA_DLLS = list(set(AUDIO_DLLS + CAMERA_DLLS))

# Сетевые настройки
IGNORED_IP_PREFIXES = (
    '127.',      # localhost
    '0.',        # нулевая сеть
    '224.',      # multicast
    '239.',      # multicast
    '255.',      # broadcast
    '169.254.',  # APIPA
)

IGNORED_PORTS = {0, 137, 138, 139, 445}  # NetBIOS, SMB

# Системные процессы (пропускаем при сканировании)
SYSTEM_PROCESS_NAMES = {
    'Registry', 'csrss.exe', 'smss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'winlogon.exe', 'System',
    'svchost.exe', 'dwm.exe', 'spoolsv.exe', 'MsMpEng.exe',
}

# Белый список по умолчанию
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
        "obs.exe",
        "audacity.exe",
        "webcamoid.exe",
        "videosrt.exe",
    ],
    "description": "Процессы, которые игнорируются при сканировании"
}

# Настройки сканирования
SCAN_INTERVAL_SECONDS = 5
MAX_PROCESS_AGE_SECONDS = 60

# Уровни угрозы
THREAT_LEVELS = {
    'LOW': 'Низкий',
    'MEDIUM': 'Средний',
    'HIGH': 'Высокий',
    'CRITICAL': 'Критический',
}

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
