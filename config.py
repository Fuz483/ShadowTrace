import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
WHITELIST_FILE = os.path.join(DATA_DIR, 'whitelist.json')

AUDIO_DLLS = [
    'winmm.dll',
    'wdmaud.drv',
    'audioses.dll',
    'mmdevapi.dll',
    'dsound.dll',
    'audioeng.dll',
    'avrt.dll',
]

CAMERA_DLLS = [
    'ksuser.dll',
    'vidcap.ax',
    'qcap.dll',
    'mf.dll',
    'mfplat.dll',
    'mfreadwrite.dll',
    'dshowcore.dll',
    'devenum.dll',
    'msvfw32.dll',
    'avicap32.dll',
    'cameraplatform.dll',
    'windows.media.capture.dll',
    'webcam.dll',
    'uvc.dll',
]

MEDIA_DLLS = list(set(AUDIO_DLLS + CAMERA_DLLS))

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
        "obs.exe",
        "audacity.exe",
        "webcamoid.exe",
        "videosrt.exe",
    ],
    "description": "Процессы, которые игнорируются при сканировании"
}

SCAN_INTERVAL_SECONDS = 5
MAX_PROCESS_AGE_SECONDS = 60

THREAT_LEVELS = {
    'LOW': 'Низкий',
    'MEDIUM': 'Средний',
    'HIGH': 'Высокий',
    'CRITICAL': 'Критический',
}

AUDIO_DLLS = [
    'winmm.dll',
    'wdmaud.drv',
    'audioses.dll',
    'mmdevapi.dll',
    'dsound.dll',
    'audioeng.dll',
    'avrt.dll',
]

VIDEO_DLLS = [
    'ksuser.dll',
    'vidcap.ax',
    'dshowcore.dll',
]
