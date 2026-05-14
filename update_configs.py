#!/usr/bin/env python3
import requests
import random
import base64
import re
from urllib.parse import unquote, quote, urlparse

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

WIFI_SOURCES = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/new/all_new.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/nzea243/okak/refs/heads/main/sub.txt",
    "https://mifa.world/hysteria",
    "https://mifa.world/vless",
    "https://mifa.world/other",
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

# ─── База стран ───────────────────────────────────────────────────────────────
# Маппинг: всё что распознаём → (код ISO, флаг)
def _flag(cc):
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc.upper())

# Список: (паттерн для поиска, код страны)
# Порядок важен — более специфичные паттерны раньше
COUNTRY_PATTERNS: list[tuple[re.Pattern, str]] = []

_NAMES = [
    # Россия
    ('RU', ['🇷🇺', 'Russia', 'Россия', 'RUS', r'\bRU\b']),
    # СНГ и ближнее зарубежье
    ('UA', ['🇺🇦', 'Ukraine', 'Украина', r'\bUA\b']),
    ('BY', ['🇧🇾', 'Belarus', 'Беларусь', r'\bBY\b']),
    ('KZ', ['🇰🇿', 'Kazakhstan', 'Казахстан', r'\bKZ\b']),
    ('UZ', ['🇺🇿', 'Uzbekistan', 'Узбекистан', r'\bUZ\b']),
    ('AZ', ['🇦🇿', 'Azerbaijan', r'\bAZ\b']),
    ('GE', ['🇬🇪', 'Georgia', r'\bGE\b']),
    ('AM', ['🇦🇲', 'Armenia', r'\bAM\b']),
    ('MD', ['🇲🇩', 'Moldova', r'\bMD\b']),
    ('KG', ['🇰🇬', 'Kyrgyzstan', r'\bKG\b']),
    ('TJ', ['🇹🇯', 'Tajikistan', r'\bTJ\b']),
    ('TM', ['🇹🇲', 'Turkmenistan', r'\bTM\b']),
    # Европа
    ('DE', ['🇩🇪', 'Germany', 'Deutschland', 'Германия', r'\bDE\b']),
    ('FR', ['🇫🇷', 'France', 'Франция', r'\bFR\b']),
    ('GB', ['🇬🇧', 'United Kingdom', 'UK', 'Britain', r'\bGB\b']),
    ('NL', ['🇳🇱', 'Netherlands', 'Holland', r'\bNL\b']),
    ('FI', ['🇫🇮', 'Finland', r'\bFI\b']),
    ('SE', ['🇸🇪', 'Sweden', r'\bSE\b']),
    ('NO', ['🇳🇴', 'Norway', r'\bNO\b']),
    ('PL', ['🇵🇱', 'Poland', r'\bPL\b']),
    ('CZ', ['🇨🇿', 'Czech', r'\bCZ\b']),
    ('AT', ['🇦🇹', 'Austria', r'\bAT\b']),
    ('CH', ['🇨🇭', 'Switzerland', r'\bCH\b']),
    ('BE', ['🇧🇪', 'Belgium', r'\bBE\b']),
    ('DK', ['🇩🇰', 'Denmark', r'\bDK\b']),
    ('ES', ['🇪🇸', 'Spain', r'\bES\b']),
    ('IT', ['🇮🇹', 'Italy', r'\bIT\b']),
    ('PT', ['🇵🇹', 'Portugal', r'\bPT\b']),
    ('HU', ['🇭🇺', 'Hungary', r'\bHU\b']),
    ('RO', ['🇷🇴', 'Romania', r'\bRO\b']),
    ('BG', ['🇧🇬', 'Bulgaria', r'\bBG\b']),
    ('TR', ['🇹🇷', 'Turkey', 'Турция', r'\bTR\b']),
    ('LT', ['🇱🇹', 'Lithuania', r'\bLT\b']),
    ('LV', ['🇱🇻', 'Latvia', r'\bLV\b']),
    ('EE', ['🇪🇪', 'Estonia', r'\bEE\b']),
    ('SK', ['🇸🇰', 'Slovakia', r'\bSK\b']),
    ('SI', ['🇸🇮', 'Slovenia', r'\bSI\b']),
    ('HR', ['🇭🇷', 'Croatia', r'\bHR\b']),
    ('RS', ['🇷🇸', 'Serbia', r'\bRS\b']),
    ('AL', ['🇦🇱', 'Albania', r'\bAL\b']),
    ('ME', ['🇲🇪', 'Montenegro', r'\bME\b']),
    ('MK', ['🇲🇰', 'Macedonia', r'\bMK\b']),
    ('IS', ['🇮🇸', 'Iceland', r'\bIS\b']),
    ('LU', ['🇱🇺', 'Luxembourg', r'\bLU\b']),
    ('MT', ['🇲🇹', 'Malta', r'\bMT\b']),
    ('CY', ['🇨🇾', 'Cyprus', r'\bCY\b']),
    # Азия
    ('JP', ['🇯🇵', 'Japan', 'Япония', r'\bJP\b']),
    ('KR', ['🇰🇷', 'Korea', r'\bKR\b']),
    ('CN', ['🇨🇳', 'China', 'Китай', r'\bCN\b']),
    ('HK', ['🇭🇰', 'Hong Kong', r'\bHK\b']),
    ('TW', ['🇹🇼', 'Taiwan', r'\bTW\b']),
    ('SG', ['🇸🇬', 'Singapore', r'\bSG\b']),
    ('MY', ['🇲🇾', 'Malaysia', r'\bMY\b']),
    ('ID', ['🇮🇩', 'Indonesia', r'\bID\b']),
    ('TH', ['🇹🇭', 'Thailand', r'\bTH\b']),
    ('VN', ['🇻🇳', 'Vietnam', r'\bVN\b']),
    ('IN', ['🇮🇳', 'India', r'\bIN\b']),
    ('PK', ['🇵🇰', 'Pakistan', r'\bPK\b']),
    ('BD', ['🇧🇩', 'Bangladesh', r'\bBD\b']),
    ('MN', ['🇲🇳', 'Mongolia', r'\bMN\b']),
    # Ближний Восток
    ('AE', ['🇦🇪', 'Emirates', 'UAE', r'\bAE\b']),
    ('SA', ['🇸🇦', 'Saudi', r'\bSA\b']),
    ('TR', ['🇹🇷', 'Turkey', r'\bTR\b']),
    ('IL', ['🇮🇱', 'Israel', r'\bIL\b']),
    ('IR', ['🇮🇷', 'Iran', r'\bIR\b']),
    ('IQ', ['🇮🇶', 'Iraq', r'\bIQ\b']),
    # Африка
    ('ZA', ['🇿🇦', 'South Africa', r'\bZA\b']),
    ('NG', ['🇳🇬', 'Nigeria', r'\bNG\b']),
    ('EG', ['🇪🇬', 'Egypt', r'\bEG\b']),
    # Америка
    ('US', ['🇺🇸', 'United States', 'USA', r'\bUS\b']),
    ('CA', ['🇨🇦', 'Canada', r'\bCA\b']),
    ('MX', ['🇲🇽', 'Mexico', r'\bMX\b']),
    ('BR', ['🇧🇷', 'Brazil', r'\bBR\b']),
    ('AR', ['🇦🇷', 'Argentina', r'\bAR\b']),
    ('CL', ['🇨🇱', 'Chile', r'\bCL\b']),
    ('CO', ['🇨🇴', 'Colombia', r'\bCO\b']),
    # Океания
    ('AU', ['🇦🇺', 'Australia', r'\bAU\b']),
    ('NZ', ['🇳🇿', 'New Zealand', r'\bNZ\b']),
]

# Строим скомпилированный список паттернов
_FLAG_RE = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
_BUILT_PATTERNS: list[tuple[re.Pattern, str, str]] = []  # (pattern, cc, flag)
for cc, aliases in _NAMES:
    flag = _flag(cc)
    for alias in aliases:
        # Флаг-эмодзи — ищем напрямую
        if any(ord(c) > 127 for c in alias):
            try:
                _BUILT_PATTERNS.append((re.compile(re.escape(alias)), cc, flag))
            except re.error:
                pass
        # Двухбуквенный код вида \bXX\b — только UPPERCASE, без IGNORECASE
        elif re.fullmatch(r'\\b[A-Z]{2}\\b', alias):
            _BUILT_PATTERNS.append((re.compile(alias), cc, flag))
        # Полное название страны — case-insensitive
        else:
            try:
                _BUILT_PATTERNS.append((re.compile(alias, re.IGNORECASE), cc, flag))
            except re.error:
                pass

RUSSIA_CC = 'RU'

def detect_country(remark: str) -> tuple[str, str] | None:
    """
    Возвращает (flag_emoji, country_code) или None если страна не определена.
    Порядок: флаг-эмодзи в тексте → паттерны по имени → None.
    """
    # 1. Прямой поиск флага-эмодзи
    flags = _FLAG_RE.findall(remark)
    if flags:
        flag = flags[0]
        # Определяем код страны по флагу
        cc_chars = [chr(ord(c) - 0x1F1E6 + ord('A')) for c in flag]
        cc = ''.join(cc_chars)
        return flag, cc

    # 2. Текстовые паттерны
    for pattern, cc, flag in _BUILT_PATTERNS:
        if pattern.search(remark):
            return flag, cc

    return None  # Страна не определена → конфиг пропускаем

# ─── Работа с конфигами ───────────────────────────────────────────────────────
def get_remark(config: str) -> str:
    if '#' in config:
        return unquote(config.split('#', 1)[1])
    return ''

def set_remark(config: str, remark: str) -> str:
    base = config.split('#', 1)[0] if '#' in config else config
    return base + '#' + quote(remark, safe='')

def rename_config(config: str, section: str) -> str | None:
    """
    Возвращает переименованный конфиг или None если страна не определена.
    """
    remark = get_remark(config)
    result = detect_country(remark)
    if result is None:
        return None  # пропускаем — нет локации

    flag, cc = result
    is_foreign = (cc != RUSSIA_CC)
    ai_tag = ' (ai)' if is_foreign else ''
    new_remark = f"{flag}{ai_tag} {section}"
    return set_remark(config, new_remark)

# ─── Загрузка конфигов ────────────────────────────────────────────────────────
def fetch_configs(url: str) -> list[str]:
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
        print(f"  ✓ ...{url[-45:]}: {len(configs)}")
        return configs
    except Exception as e:
        print(f"  ✗ {url}: {e}")
        return []

def random_split(total: int, n: int) -> list[int]:
    """Разбивает total на n случайных частей (каждая >= 1)"""
    weights = [random.random() for _ in range(n)]
    s = sum(weights)
    counts = [max(1, int(w / s * total)) for w in weights]
    diff = total - sum(counts)
    for _ in range(abs(diff)):
        idx = random.randint(0, n - 1)
        counts[idx] = max(1, counts[idx] + (1 if diff > 0 else -1))
    return counts

def sample_from_sources(sources: list[str], total: int, section: str) -> list[str]:
    """
    Загружает из каждого источника, берёт случайное кол-во с каждого,
    переименовывает, пропускает конфиги без локации.
    Итого: ровно total конфигов (или меньше если пулы маленькие).
    """
    pools = []
    for url in sources:
        c = fetch_configs(url)
        if c:
            pools.append(c)

    if not pools:
        return []

    counts = random_split(total, len(pools))
    result = []

    for pool, count in zip(pools, counts):
        candidates = random.sample(pool, min(count * 3, len(pool)))  # берём с запасом
        added = 0
        for cfg in candidates:
            if added >= count:
                break
            renamed = rename_config(cfg, section)
            if renamed is not None:
                result.append(renamed)
                added += 1

    # Если не набрали total — добираем из всех пулов
    if len(result) < total:
        all_remaining = []
        for pool in pools:
            for cfg in pool:
                renamed = rename_config(cfg, section)
                if renamed is not None and renamed not in result:
                    all_remaining.append(renamed)
        random.shuffle(all_remaining)
        need = total - len(result)
        result.extend(all_remaining[:need])

    random.shuffle(result)
    return result[:total]

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("📡 Загружаю wifi конфиги...")
    wifi = sample_from_sources(WIFI_SOURCES, 150, 'wifi')

    print("\n📡 Загружаю bypass конфиги...")
    bypass = sample_from_sources(BYPASS_SOURCES, 150, 'обход бс')

    output = '\n'.join([
        HEADER, '',
        SEPARATOR_WIFI,
        *wifi, '',
        SEPARATOR_BYPASS,
        *bypass,
    ])

    with open('tri_228.txt', 'w', encoding='utf-8') as f:
        f.write(output)

    print(f"\n✅ Готово! wifi: {len(wifi)}, bypass: {len(bypass)}")

if __name__ == '__main__':
    main()
