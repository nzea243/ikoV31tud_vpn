#!/usr/bin/env python3
import requests
import random
import base64
import re
from urllib.parse import unquote, quote

# ─── Заголовок файла (не трогать) ────────────────────────────────────────────
HEADER = """\
#profile-title: nzea234vpnツ
#announce: Не работает подписка, обнови ее на две стрелочки
#support-url: https://t.me/nzea_tri_bykvi
#profile-update-interval: 3
#profile-locked: true
#profile-type: encrypted
#profile-locked: true
#hide-settings: 1"""

SEPARATOR_WIFI   = "vless://info@0.0.0.0:443?type=tcp&security=none#для wifi и моб инет без бс👇"
SEPARATOR_BYPASS = "vless://info@0.0.0.0:443?type=tcp&security=none#для обхода бс👇"

# ─── Источники ────────────────────────────────────────────────────────────────
WIFI_SOURCES = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/new/all_new.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/nzea243/okak/refs/heads/main/sub.txt",
]

BYPASS_SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/VOID-Anonymity/V.O.I.D-VPN_Bypass/refs/heads/main/url_work.txt",
    "https://sub.obbhod.online/premium",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/whitelist_full",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/refs/heads/main/checked/RU_Best/ru_white_all_WHITE.txt",
    "https://gitverse.ru/api/repos/kfwlru/sub/raw/branch/main/212.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
]

VALID_PREFIXES = ('vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria2://', 'hy2://', 'tuic://')

# ─── Флаги стран ──────────────────────────────────────────────────────────────
FLAG_RE = re.compile(r'[\U0001F1E0-\U0001F1FF]{2}')
RUSSIAN_FLAG = '🇷🇺'
RUSSIAN_TEXT_RE = re.compile(r'\b(RU|Russia|Россия|RUS)\b', re.IGNORECASE)

# Двухбуквенные коды стран для fallback
KNOWN_CC = {
    'US','DE','FR','GB','NL','FI','SE','NO','PL','CZ','AT','BE','CH','DK',
    'ES','IT','PT','HU','RO','BG','TR','UA','BY','KZ','AZ','GE','AM','MD',
    'LT','LV','EE','SK','SI','HR','RS','MK','BA','AL','ME','JP','KR','CN',
    'HK','TW','SG','MY','ID','TH','VN','IN','PK','BD','LK','NP','MN',
    'KG','TJ','TM','UZ','IL','AE','SA','QA','KW','BH','OM','JO','LB',
    'IR','IQ','EG','ZA','NG','KE','GH','ET','TZ','MA','DZ','TN',
    'CA','MX','BR','AR','CL','CO','PE','VE','AU','NZ','RU',
}
CC_RE = re.compile(r'\b([A-Z]{2})\b')

def cc_to_flag(cc: str) -> str:
    return ''.join(chr(0x1F1E0 + ord(c) - ord('A')) for c in cc.upper())

def parse_country(remark: str):
    """Возвращает (флаг, is_foreign)"""
    # 1. Ищем флаг-эмодзи
    flags = FLAG_RE.findall(remark)
    if flags:
        flag = flags[0]
        return flag, flag != RUSSIAN_FLAG

    # 2. Текстовые паттерны для России
    if RUSSIAN_TEXT_RE.search(remark):
        return RUSSIAN_FLAG, False

    # 3. Двухбуквенный код страны
    for code in CC_RE.findall(remark):
        if code in KNOWN_CC:
            return cc_to_flag(code), code != 'RU'

    # 4. Неизвестно
    return None, True  # None → "unknown", is_foreign=True

# ─── Работа с конфигами ───────────────────────────────────────────────────────
def get_remark(config: str) -> str:
    if '#' in config:
        return unquote(config.split('#', 1)[1])
    return ''

def set_remark(config: str, remark: str) -> str:
    base = config.split('#', 1)[0] if '#' in config else config
    return base + '#' + quote(remark, safe='')

def rename_config(config: str, section: str) -> str:
    """section = 'wifi' или 'обход бс'"""
    remark = get_remark(config)
    flag, is_foreign = parse_country(remark)

    flag_str = flag if flag else '🏳 unknown'
    ai_tag   = ' (ai)' if is_foreign else ''
    new_remark = f"{flag_str}{ai_tag} {section}"
    return set_remark(config, new_remark)

def fetch_configs(url: str) -> list:
    try:
        r = requests.get(url, timeout=20, headers={'User-Agent': 'Mozilla/5.0'})
        r.raise_for_status()
        text = r.text.strip()

        # Попытка base64-декода
        try:
            decoded = base64.b64decode(text + '==').decode('utf-8', errors='ignore')
            if any(decoded.startswith(p) for p in VALID_PREFIXES):
                text = decoded
        except Exception:
            pass

        configs = [
            line.strip() for line in text.splitlines()
            if line.strip() and any(line.strip().startswith(p) for p in VALID_PREFIXES)
        ]
        print(f"  ✓ {url.split('/')[-1][:40]}: {len(configs)} конфигов")
        return configs

    except Exception as e:
        print(f"  ✗ {url}: {e}")
        return []

def fetch_all(sources: list) -> list:
    result = []
    for url in sources:
        result.extend(fetch_configs(url))
    return result

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("📡 Загружаю wifi конфиги...")
    wifi_pool = fetch_all(WIFI_SOURCES)

    print("\n📡 Загружаю bypass конфиги...")
    bypass_pool = fetch_all(BYPASS_SOURCES)

    print(f"\nПул: wifi={len(wifi_pool)}, bypass={len(bypass_pool)}")

    wifi_sample   = random.sample(wifi_pool,   min(150, len(wifi_pool)))
    bypass_sample = random.sample(bypass_pool, min(150, len(bypass_pool)))

    wifi_renamed   = [rename_config(c, 'wifi')     for c in wifi_sample]
    bypass_renamed = [rename_config(c, 'обход бс') for c in bypass_sample]

    output_lines = [
        HEADER,
        '',
        SEPARATOR_WIFI,
        *wifi_renamed,
        '',
        SEPARATOR_BYPASS,
        *bypass_renamed,
    ]

    with open('tri_228.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))

    print(f"\n✅ Готово! wifi: {len(wifi_renamed)}, bypass: {len(bypass_renamed)}")

if __name__ == '__main__':
    main()
