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

# ─── Флаги стран ──────────────────────────────────────────────────────────────
FLAG_RE = re.compile(r'[\U0001F1E0-\U0001F1FF]{2}')
RUSSIAN_FLAG = '🇷🇺'

# Расширенные паттерны для России
RU_PATTERNS = [
    r'\b(ru|rus|russia|россия|рус|рф|мск|москва|spb|питер|петербург|saint-petersburg)\b',
    r'[._-](ru|rus|russia)[._-]?',
    r'\.ru\b',
    r'\b(russian)\b',
]
RUSSIAN_TEXT_RE = re.compile('|'.join(RU_PATTERNS), re.IGNORECASE)

# Карта городов → код страны
CITY_TO_CC = {
    # Германия
    'frankfurt': 'DE', 'fra': 'DE', 'de-fra': 'DE', 'berlin': 'DE', 'munich': 'DE', 'munchen': 'DE', 'hamburg': 'DE',
    # Нидерланды
    'amsterdam': 'NL', 'ams': 'NL', 'nl-ams': 'NL', 'rotterdam': 'NL',
    # Великобритания
    'london': 'GB', 'lon': 'GB', 'gb-lon': 'GB', 'manchester': 'GB', 'uk': 'GB', 'england': 'GB',
    # США
    'new-york': 'US', 'ny': 'US', 'us-ny': 'US', 'nyc': 'US', 'los-angeles': 'US', 'la': 'US',
    'chicago': 'US', 'miami': 'US', 'dallas': 'US', 'seattle': 'US', 'atlanta': 'US', 'silicon': 'US',
    'san-francisco': 'US', 'sf': 'US', 'phoenix': 'US', 'denver': 'US', 'usa': 'US', 'america': 'US',
    'united-states': 'US', 'us': 'US',
    # Финляндия
    'helsinki': 'FI', 'hel': 'FI', 'fi-hel': 'FI',
    # Швеция
    'stockholm': 'SE', 'se-sto': 'SE',
    # Норвегия
    'oslo': 'NO', 'norway': 'NO',
    # Польша
    'warsaw': 'PL', 'pl-waw': 'PL', 'krakow': 'PL',
    # Чехия
    'prague': 'CZ', 'cz-prg': 'CZ',
    # Австрия
    'vienna': 'AT', 'at-vie': 'AT',
    # Швейцария
    'zurich': 'CH', 'ch-zrh': 'CH', 'geneva': 'CH',
    # Дания
    'copenhagen': 'DK',
    # Испания
    'madrid': 'ES', 'barcelona': 'ES', 'es-mad': 'ES',
    # Италия
    'milan': 'IT', 'it-mil': 'IT', 'rome': 'IT',
    # Португалия
    'lisbon': 'PT', 'portugal': 'PT',
    # Венгрия
    'budapest': 'HU',
    # Румыния
    'bucharest': 'RO', 'ro-buh': 'RO',
    # Болгария
    'sofia': 'BG',
    # Турция
    'istanbul': 'TR', 'tr-ist': 'TR', 'turkey': 'TR', 'ankara': 'TR',
    # Украина
    'kyiv': 'UA', 'kiev': 'UA', 'ua-iev': 'UA', 'kharkiv': 'UA', 'odesa': 'UA', 'odessa': 'UA',
    # Беларусь
    'minsk': 'BY',
    # Казахстан
    'almaty': 'KZ', 'kz-ala': 'KZ', 'astana': 'KZ', 'nur-sultan': 'KZ', 'kazakhstan': 'KZ',
    # Азербайджан
    'baku': 'AZ',
    # Грузия
    'tbilisi': 'GE', 'ge-tbs': 'GE',
    # Армения
    'yerevan': 'AM',
    # Молдова
    'chisinau': 'MD',
    # Литва
    'vilnius': 'LT',
    # Латвия
    'riga': 'LV',
    # Эстония
    'tallinn': 'EE',
    # Словакия
    'bratislava': 'SK',
    # Словения
    'ljubljana': 'SI',
    # Хорватия
    'zagreb': 'HR',
    # Сербия
    'belgrade': 'RS',
    # Япония
    'tokyo': 'JP', 'jp-tyo': 'JP', 'osaka': 'JP', 'japan': 'JP',
    # Корея
    'seoul': 'KR', 'kr-seo': 'KR', 'korea': 'KR',
    # Китай/Азия
    'hong-kong': 'HK', 'hk': 'HK', 'hk-hkg': 'HK', 'taiwan': 'TW', 'taipei': 'TW', 'tw-tpe': 'TW',
    'singapore': 'SG', 'sg-sin': 'SG', 'sg': 'SG', 'malaysia': 'MY', 'kuala-lumpur': 'MY',
    'indonesia': 'ID', 'jakarta': 'ID', 'thailand': 'TH', 'bangkok': 'TH', 'th-bkk': 'TH',
    'vietnam': 'VN', 'hanoi': 'VN', 'ho-chi-minh': 'VN',
    'india': 'IN', 'mumbai': 'IN', 'in-bom': 'IN', 'delhi': 'IN',
    'philippines': 'PH', 'manila': 'PH',
    # Израиль
    'tel-aviv': 'IL', 'israel': 'IL',
    # ОАЭ
    'dubai': 'AE', 'ae-dxb': 'AE', 'uae': 'AE', 'emirates': 'AE',
    # Саудовская Аравия
    'saudi': 'SA', 'riyadh': 'SA',
    # Катар
    'qatar': 'QA', 'doha': 'QA',
    # Кувейт
    'kuwait': 'KW',
    # Канада
    'canada': 'CA', 'toronto': 'CA', 'ca-yyz': 'CA', 'vancouver': 'CA', 'montreal': 'CA',
    # Мексика
    'mexico': 'MX',
    # Бразилия
    'brazil': 'BR', 'sao-paulo': 'BR', 'br-gru': 'BR',
    # Аргентина
    'argentina': 'AR', 'buenos-aires': 'AR',
    # Чили
    'chile': 'CL', 'santiago': 'CL',
    # Колумбия
    'colombia': 'CO', 'bogota': 'CO',
    # Австралия
    'australia': 'AU', 'sydney': 'AU', 'au-syd': 'AU', 'melbourne': 'AU',
    # Новая Зеландия
    'new-zealand': 'NZ', 'auckland': 'NZ',
    # Франция
    'france': 'FR', 'paris': 'FR', 'fr-par': 'FR',
    # Ирландия
    'ireland': 'IE', 'dublin': 'IE',
    # Исландия
    'iceland': 'IS', 'reykjavik': 'IS',
    # Люксембург
    'luxembourg': 'LU',
    # Мальта
    'malta': 'MT',
    # Кипр
    'cyprus': 'CY', 'nicosia': 'CY',
    # Греция
    'greece': 'GR', 'athens': 'GR',
    # ЮАР
    'south-africa': 'ZA', 'johannesburg': 'ZA', 'za-jnb': 'ZA',
    # Нигерия
    'nigeria': 'NG', 'lagos': 'NG',
    # Кения
    'kenya': 'KE', 'nairobi': 'KE',
    # Египет
    'egypt': 'EG', 'cairo': 'EG',
    # Иран
    'iran': 'IR', 'tehran': 'IR',
    # Пакистан
    'pakistan': 'PK', 'karachi': 'PK',
    # Бангладеш
    'bangladesh': 'BD', 'dhaka': 'BD',
    # Шри-Ланка
    'sri-lanka': 'LK', 'colombo': 'LK',
    # Монголия
    'mongolia': 'MN', 'ulaanbaatar': 'MN',
    # Узбекистан
    'uzbekistan': 'UZ', 'tashkent': 'UZ',
    # Киргизия
    'kyrgyzstan': 'KG', 'bishkek': 'KG',
    # Россия
    'moscow': 'RU', 'msk': 'RU', 'saint-petersburg': 'RU', 'petersburg': 'RU',
    'novosibirsk': 'RU', 'yekaterinburg': 'RU', 'kazan': 'RU', 'nn': 'RU',
    'rostov': 'RU', 'samara': 'RU', 'ufa': 'RU', 'krasnoyarsk': 'RU',
    'voronezh': 'RU', 'volgograd': 'RU', 'perm': 'RU',
}

# Двухбуквенные коды стран
KNOWN_CC = {
    'US','DE','FR','GB','NL','FI','SE','NO','PL','CZ','AT','BE','CH','DK',
    'ES','IT','PT','HU','RO','BG','TR','UA','BY','KZ','AZ','GE','AM','MD',
    'LT','LV','EE','SK','SI','HR','RS','MK','BA','AL','ME','JP','KR','CN',
    'HK','TW','SG','MY','ID','TH','VN','IN','PK','BD','LK','NP','MN',
    'KG','TJ','TM','UZ','IL','AE','SA','QA','KW','BH','OM','JO','LB',
    'IR','IQ','EG','ZA','NG','KE','GH','ET','TZ','MA','DZ','TN',
    'CA','MX','BR','AR','CL','CO','PE','VE','AU','NZ','RU',
    'IE','IS','LU','MT','CY','GR','PH','LA','KH','MM',
}

CC_RE = re.compile(r'\b([a-zA-Z]{2})\b', re.IGNORECASE)

def cc_to_flag(cc: str) -> str:
    return ''.join(chr(0x1F1E0 + ord(c) - ord('A')) for c in cc.upper())

def parse_country(remark: str):
    """Возвращает (флаг, is_foreign)"""
    remark_lower = remark.lower()

    # 1. Ищем флаг-эмодзи
    flags = FLAG_RE.findall(remark)
    if flags:
        flag = flags[0]
        return flag, flag != RUSSIAN_FLAG

    # 2. Текстовые паттерны для России
    if RUSSIAN_TEXT_RE.search(remark):
        return RUSSIAN_FLAG, False

    # 3. Поиск города в remark
    for city, cc in CITY_TO_CC.items():
        pattern = r'(?:^|[._\-\s])' + re.escape(city) + r'(?:$|[._\-\s\d])'
        if re.search(pattern, remark_lower):
            return cc_to_flag(cc), cc != 'RU'

    # 4. Двухбуквенный код страны (регистронезависимый)
    for code in CC_RE.findall(remark):
        code_upper = code.upper()
        if code_upper in KNOWN_CC:
            return cc_to_flag(code_upper), code_upper != 'RU'

    # 5. Проверяем TLD доменов
    tld_to_cc = {
        '.ru': 'RU', '.su': 'RU', '.рф': 'RU',
        '.de': 'DE', '.nl': 'NL', '.fr': 'FR', '.uk': 'GB', '.gb': 'GB',
        '.fi': 'FI', '.se': 'SE', '.no': 'NO', '.pl': 'PL', '.cz': 'CZ',
        '.at': 'AT', '.be': 'BE', '.ch': 'CH', '.dk': 'DK', '.es': 'ES',
        '.it': 'IT', '.pt': 'PT', '.hu': 'HU', '.ro': 'RO', '.bg': 'BG',
        '.tr': 'TR', '.ua': 'UA', '.by': 'BY', '.kz': 'KZ', '.az': 'AZ',
        '.ge': 'GE', '.am': 'AM', '.md': 'MD', '.lt': 'LT', '.lv': 'LV',
        '.ee': 'EE', '.sk': 'SK', '.si': 'SI', '.hr': 'HR', '.rs': 'RS',
        '.jp': 'JP', '.kr': 'KR', '.cn': 'CN', '.hk': 'HK', '.tw': 'TW',
        '.sg': 'SG', '.my': 'MY', '.id': 'ID', '.th': 'TH', '.vn': 'VN',
        '.in': 'IN', '.pk': 'PK', '.bd': 'BD', '.lk': 'LK', '.np': 'NP',
        '.mn': 'MN', '.kg': 'KG', '.tj': 'TJ', '.tm': 'TM', '.uz': 'UZ',
        '.il': 'IL', '.ae': 'AE', '.sa': 'SA', '.qa': 'QA', '.kw': 'KW',
        '.bh': 'BH', '.om': 'OM', '.jo': 'JO', '.lb': 'LB', '.ir': 'IR',
        '.iq': 'IQ', '.eg': 'EG', '.za': 'ZA', '.ng': 'NG', '.ke': 'KE',
        '.gh': 'GH', '.et': 'ET', '.tz': 'TZ', '.ma': 'MA', '.dz': 'DZ',
        '.tn': 'TN', '.ca': 'CA', '.mx': 'MX', '.br': 'BR', '.ar': 'AR',
        '.cl': 'CL', '.co': 'CO', '.pe': 'PE', '.ve': 'VE', '.au': 'AU',
        '.nz': 'NZ', '.us': 'US', '.ie': 'IE', '.is': 'IS', '.lu': 'LU',
        '.mt': 'MT', '.cy': 'CY', '.gr': 'GR', '.ph': 'PH',
    }
    for tld, cc in tld_to_cc.items():
        if tld in remark_lower:
            return cc_to_flag(cc), cc != 'RU'

    # 6. Неизвестно
    return None, True

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
