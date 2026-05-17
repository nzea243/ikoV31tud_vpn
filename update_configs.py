#!/usr/bin/env python3
import requests
import random
import base64
import re
from datetime import datetime, timezone
from urllib.parse import unquote, quote, urlparse

# ─── Заголовок файла ──────────────────────────────────────────────────────────
def build_header():
    now = datetime.now(timezone.utc).strftime('%H:%M %d.%m.%Y UTC')
    return f"""\
#profile-title: nzea234vpnツ
#announce: Последний апдейт на GitHub: {now} | Не работает — обнови подписку на две стрелочки
#support-url: https://t.me/nzea_tri_bykvi
#profile-update-interval: 1
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
    "https://etoneya.best/1",
    "https://gist.github.com/DestroyST6767/f00837ad379aa3272183fdaabcfd50da.txt",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/wifi",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/ru/vless.txt",
    "https://subrostunnel.vercel.app/gen.txt",
    "https://rostunnel.vercel.app/mega.txt",
    "https://raw.githubusercontent.com/modrinthmodification-create/ownedvpn/main/subscription.txt",
    "https://alley.serv00.net/youtube",
    "https://alley.serv00.net/other",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta6BL.txt",
    "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/main/subscriptions/FreeCFGHub1.txt",
    "https://raw.githubusercontent.com/Kirill39127/-my-sub/refs/heads/main/sub.txt",
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
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/merged.txt",
    "https://gist.github.com/DestroyST6767/50af50221ca1858ba2084efc0f524fbc.txt",
    "https://drive.usercontent.google.com/download?id=1Rl6jIlf2Ula__J9F9nRmCuE6RFdqMTgk&export=download&confirm=t",
    "https://raw.githubusercontent.com/AirLinkVPN1/AirLinkVPN/refs/heads/main/rkn_white_list",
    "https://raw.githubusercontent.com/dequar/deqwl/refs/heads/main/deray.txt",
    "https://gitflic.ru/project/sigil/my-new-cool-project/blob/raw?file=whitelist",
    "https://raw.githubusercontent.com/Sanuyyq/sub-storage1/refs/heads/main/bs.txt",
    "https://raw.githubusercontent.com/ewecrow78-gif/whitelist1/main/list.txt",
    "https://ety.twinkvibe.gay/whitelist",
    "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta6.txt",
]

VALID_PREFIXES = ('vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://', 'hysteria2://', 'hy2://', 'tuic://')

# ─── База стран ───────────────────────────────────────────────────────────────
def _flag(cc):
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc.upper())

COUNTRY_PATTERNS: list[tuple[re.Pattern, str]] = []

_NAMES = [
    ('RU', ['🇷🇺', 'Russia', 'Россия', 'RUS', r'\bRU\b']),
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
    ('AE', ['🇦🇪', 'Emirates', 'UAE', r'\bAE\b']),
    ('SA', ['🇸🇦', 'Saudi', r'\bSA\b']),
    ('IL', ['🇮🇱', 'Israel', r'\bIL\b']),
    ('IR', ['🇮🇷', 'Iran', r'\bIR\b']),
    ('IQ', ['🇮🇶', 'Iraq', r'\bIQ\b']),
    ('ZA', ['🇿🇦', 'South Africa', r'\bZA\b']),
    ('NG', ['🇳🇬', 'Nigeria', r'\bNG\b']),
    ('EG', ['🇪🇬', 'Egypt', r'\bEG\b']),
    ('US', ['🇺🇸', 'United States', 'USA', r'\bUS\b']),
    ('CA', ['🇨🇦', 'Canada', r'\bCA\b']),
    ('MX', ['🇲🇽', 'Mexico', r'\bMX\b']),
    ('BR', ['🇧🇷', 'Brazil', r'\bBR\b']),
    ('AR', ['🇦🇷', 'Argentina', r'\bAR\b']),
    ('CL', ['🇨🇱', 'Chile', r'\bCL\b']),
    ('CO', ['🇨🇴', 'Colombia', r'\bCO\b']),
    ('AU', ['🇦🇺', 'Australia', r'\bAU\b']),
    ('NZ', ['🇳🇿', 'New Zealand', r'\bNZ\b']),
]

_FLAG_RE = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
_BUILT_PATTERNS: list[tuple[re.Pattern, str, str]] = []
for cc, aliases in _NAMES:
    flag = _flag(cc)
    for alias in aliases:
        if any(ord(c) > 127 for c in alias):
            try:
                _BUILT_PATTERNS.append((re.compile(re.escape(alias)), cc, flag))
            except re.error:
                pass
        elif re.fullmatch(r'\\b[A-Z]{2}\\b', alias):
            _BUILT_PATTERNS.append((re.compile(alias), cc, flag))
        else:
            try:
                _BUILT_PATTERNS.append((re.compile(alias, re.IGNORECASE), cc, flag))
            except re.error:
                pass

RUSSIA_CC = 'RU'

def detect_country(remark: str) -> tuple[str, str] | None:
    flags = _FLAG_RE.findall(remark)
    if flags:
        flag = flags[0]
        cc_chars = [chr(ord(c) - 0x1F1E6 + ord('A')) for c in flag]
        cc = ''.join(cc_chars)
        return flag, cc
    for pattern, cc, flag in _BUILT_PATTERNS:
        if pattern.search(remark):
            return flag, cc
    return None

# ─── Работа с конфигами ───────────────────────────────────────────────────────
def get_remark(config: str) -> str:
    if '#' in config:
        return unquote(config.split('#', 1)[1])
    return ''

def set_remark(config: str, remark: str) -> str:
    base = config.split('#', 1)[0] if '#' in config else config
    return base + '#' + quote(remark, safe='')

def rename_config(config: str, section: str) -> str | None:
    remark = get_remark(config)
    result = detect_country(remark)
    if result is None:
        return None
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
    weights = [random.random() for _ in range(n)]
    s = sum(weights)
    counts = [max(1, int(w / s * total)) for w in weights]
    diff = total - sum(counts)
    for _ in range(abs(diff)):
        idx = random.randint(0, n - 1)
        counts[idx] = max(1, counts[idx] + (1 if diff > 0 else -1))
    return counts

def sample_from_sources(sources: list[str], total: int, section: str) -> list[str]:
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
        candidates = random.sample(pool, min(count * 3, len(pool)))
        added = 0
        for cfg in candidates:
            if added >= count:
                break
            renamed = rename_config(cfg, section)
            if renamed is not None:
                result.append(renamed)
                added += 1

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
    wifi = sample_from_sources(WIFI_SOURCES, 100, 'wifi @nzea_tri_bykvi')

    print("\n📡 Загружаю bypass конфиги...")
    bypass = sample_from_sources(BYPASS_SOURCES, 100, 'обход бс @nzea_tri_bykvi')

    output = '\n'.join([
        build_header(), '',
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
