#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mozvpn.py — реквизиты прокси Mozilla VPN / Firefox IP Protection + авто-TOTP
+ автообновление proxyPass + локальные прокси на чистом Python (движок proxy.py).

НОВОЕ В ЭТОЙ ВЕРСИИ (2026-09-18, исправление «неверный код 2FA»):
  6) ИСПРАВЛЕНО: сгенерированный TOTP-код не совпадал с кодом в приложении-
     аутентификаторе, сервер отвечал «неверный код». Аутентификация сессии
     при этом проходила (Bearer fxs_<tokenID> принимался, иначе был бы
     401 errno 110) — отклонялось именно ЗНАЧЕНИЕ кода. Три возможные
     причины, все устранены:
       a) РАССИНХРОН ЧАСОВ. pyotp генерировал код по локальному времени
          ПК, а сервер и мобильное приложение живут по своему. Теперь скрипт
          при КАЖДОМ HTTP-ответе вычитывает заголовок Date серверов Mozilla/
          Guardian и считает TOTP от скорректированного времени
          (функции _note_server_date()/synced_time()). Смещение печатается
          в консоль, если оно больше 3 с.
       b) ИГНОРИРОВАЛИСЬ ПАРАМЕТРЫ QR. Из otpauth:// ссылки брался только
          secret, а digits/period/algorithm жёстко зашиты (6/30/SHA1). Теперь
          decode_qr_totp() разбирает все параметры, они сохраняются в
          credentials.json (totp_digits/totp_period/totp_algorithm) и
          используются при генерации.
       c) НЕПОДТВЕРЖДЁННЫЙ СЕКРЕТ. Если 2FA пересоздавался, а qr.png —
          старая картинка, секрет просто не тот, и никакая точность часов
          не поможет. Теперь после декодирования QR скрипт показывает
          сгенерированный код и просит сверить его с приложением-
          аутентификатором; при несовпадении можно ввести секрет (base32)
          вручную или указать путь к другой картинке. Секрет валидируется
          как корректный base32 (validate_totp_secret).
     ЗАОДНО: повторные попытки после «неверного кода» больше не шлют тот же
     код в том же 30-секундном окне — скрипт дожидается следующего окна
     (wait_next_totp_window) и генерирует свежий код с пересинхронизированным
     временем.

  1) ИСПРАВЛЕНО чтение QR (--qr). Актуальный zxing-cpp (>= 2.x, nanobind)
     НЕ принимает путь к файлу: read_barcodes() ждёт numpy-array / PIL.Image /
     QImage / buffer, поэтому был TypeError "str does not support the buffer
     protocol". Теперь картинка открывается через Pillow и в decode-функцию
     передаётся PIL.Image (штатно поддерживаемый тип, подтверждено README
     zxing-cpp: wrappers/python — "from PIL import Image; img = Image.open(...);
     zxingcpp.read_barcodes(img)").
  2) sing-box ЗАМЕНЁН на proxy.py (pip-пакет `proxy.py`, чистый Python,
     ноль внешних бинарников; используется, в частности, pip и ray-project).
     Готовой pip-библиотеки с точным функционалом sing-box (локальный прокси
     -> TLS к апстрим-прокси -> CONNECT с Bearer) не существует: ProxyPoolPlugin
     из proxy.py умеет только Basic user:pass по plain TCP, pproxy не умеет TLS
     к апстриму и давно не обновлялся, mitmproxy требует установки своего CA.
     Поэтому используется proxy.py как движок + крошечный плагин на его
     официальном API (по образцу встроенного ProxyPoolPlugin): плагин делает
     TCP+TLS к апстриму Mozilla (TcpServerConnection.wrap) и подписывает
     CONNECT / plain-запросы заголовком Proxy-Authorization: Bearer <proxyPass>.
     ОДИН процесс `python -m proxy` обслуживает ВСЕ города (флаг --ports),
     апстрим выбирается по локальному порту клиентского подключения.
     Токен плагин перечитывает из JSON-файла при каждом запросе -> смена
     proxyPass НЕ требует перезапуска процесса.
  3) Текущий TOTP-код (и остаток времени его действия) печатается в консоль.
  4) ИСПРАВЛЕНО ложное «❌ Требуется подтверждение входа по email»
     (верифицировано по исходникам mozilla/fxa, main, 2026-09-18):
       - POST /v1/account/login может вернуть verified=false,
         verificationMethod='email'/'email-otp', verificationReason='login'
         (sign-in confirmation для «нового устройства/IP») — в т.ч. для
         аккаунтов с включённым TOTP (getSessionVerificationStatus в
         lib/routes/utils/signin.js: при !tokenVerified метод по умолчанию
         — 'email'). Старая версия при любом vm, начинающемся с «email»,
         сразу падала с требованием подтвердить вход по почте.
       - POST /v1/session/verify/totp (lib/routes/totp.js) аутентифицирует
         сессию стратегиями ['sessionTokenBearer','sessionToken'] и НЕ
         проверяет sessionToken.verificationMethodValue: по валидному коду
         он вызывает db.verifyTokensWithMethod(token.id, 'totp-2fa') и
         помечает сессию верифицированной (AAL2). Т.е. TOTP-верификация
         работает, даже когда логин вернул verificationMethod 'email'.
       - Обратный путь — код из письма (POST /v1/session/verify_code,
         lib/routes/session.js) — для TOTP-аккаунтов намеренно заблокирован:
         сервер бросает insufficientAal(), чтобы TOTP-аккаунт не мог
         верифицировать сессию на AAL1 через email-код. Значит, для
         2FA-аккаунтов «подтверждение по email» — тупиковая ветка.
       - Вывод: при наличии TOTP-секрета скрипт теперь ВСЕГДА пробует
         /session/verify/totp, независимо от заявленного сервером метода
         (кроме неподтверждённого аккаунта, reason 'signup'). Если на
         аккаунте TOTP не включён (errno 155 TOTP_TOKEN_NOT_FOUND) —
         скрипт честно сообщает об этом.
     Заодно: генератор TOTP-кода дожидается нового 30-секундного окна,
     если текущий код почти истёк (убирает ложные «неверный код» из-за
     рассинхрона часов клиента/сервера).
  5) pip-зависимости (все с готовыми wheel'ями для Windows/Linux/macOS):
         pip install pyotp zxing-cpp Pillow proxy.py

БЫСТРЫЙ СТАРТ (Windows 11 / Linux / macOS):
  pip install pyotp zxing-cpp Pillow proxy.py
  # первый запуск: логин, пароль, QR-картинка
  python mozvpn.py --email a@b.c --password '***' --qr qr.png --use-sing-box
  # далее можно вообще без аргументов — всё закэшировано:
  python mozvpn.py --use-sing-box

Поток получения реквизитов:
  1. POST /v1/account/credentials/status -> версия стретчинга (v1/v2) + clientSalt
  1a. /v1/account/login (email+authPW) -> sessionToken  [только без кэша сессии]
  1b. при 2FA: /v1/session/verify/totp (verificationMethod "totp-2fa")
  2. POST api.accounts.firefox.com/v1/oauth/token (grant fxa-credentials, auth sessionToken)
  3. POST vpn.mozilla.org/api/v1/fpn/activate  (direct token activation, как в Firefox)
  4. GET  vpn.mozilla.org/api/v1/fpn/token -> proxyPass JWT
  5. Remote Settings (collection vpn-serverlist) -> список серверов

ИСПРАВЛЕНИЕ 403 «no_entitlement» (2026-09-17, причина найдена и исправлена):
  Симптом: OAuth-токен получался, Guardian /api/v1/fpn/token отвечал
  HTTP 403 «нет подписки/энтайтлмента», хотя вход в аккаунт успешен
  (Mozilla даже присылает письмо о новом входе).

  Причина: неправильный scope OAuth-токена. Скрипт запрашивал только
  «https://identity.mozilla.com/apps/mozillavpn» (старое имя скоупа
  десктопного приложения Mozilla VPN). Для встроенного VPN Firefox
  (IP Protection / «Built-in VPN») Guardian требует ПАРУ скоупов
      profile https://identity.mozilla.com/apps/vpn
  именно в таком виде:
    - «profile» нужен Guardian'у, чтобы по токену идентифицировать аккаунт
      и подтверждать энтайтлмент;
    - канонический VPN-скоуп для десктопного Firefox —
      «https://identity.mozilla.com/apps/vpn» (именно он фигурирует
      в исходниках mozilla/fxa как VPN-скоуп Firefox Desktop).
  Токен с одним лишь apps/mozillavpn проходит верификацию, но
  энтайтлмент не подтверждается -> Guardian возвращает 403.

  Источники (проверено по Интернету 2026-09-17):
    - рабочая открытая реализация этого же флоу
      (github.com/multi-zhangyang/firefox-ip-protection-pool,
      refresh_tokens.py): FX_CLIENT_ID = "5882386c6d801776",
      SCOPES = "profile https://identity.mozilla.com/apps/vpn";
      GET {guardian}/api/v1/fpn/token, HTTP 403 мапится на «no_entitlement»,
      HTTP 401 — на «reauth_required», 429 — квота/Retry-After;
    - исходники Firefox toolkit/components/ipprotection/fxa/
      (IPPFxaActivateAuthProvider.sys.mjs): «direct token activation flow»
      через POST /api/v1/fpn/activate с FxA Bearer-токеном;
    - Mozilla Connect (2026-09): Built-in VPN beta, выкатка US/UK/DE/FR,
      лимит 50 ГБ/мес — если аккаунт/регион не охвачены, 403 останется
      ПОСЛЕ исправления скрипта (это уже не баг скрипта).

ИСПРАВЛЕНИЕ SERVERLIST (2026-09-17):
  Актуальная коллекция Remote Settings — «vpn-serverlist» (записи вида
  {code, name, cities: [{code, name, servers: [...]}], filter_expression,
  locked}); старая коллекция «ip-protection» больше не используется.
  Реализован безопасный подмножественный разбор filter_expression
  (JEXL: env.version|versionCompare("X") op 0 и env.country == "XX"),
  default Firefox version = 156.0 (--firefox-version). Заголовки к
  Guardian приведены к десктопному Firefox: Accept/Content-Type:
  application/json + Cache-Control/Pragma: no-cache.

ИСПРАВЛЕНИЕ (причина ложного «errno 103 Incorrect password»):
  Скрипт раньше считал authPW неправильно (соль = голый email, info="authPW"),
  плюс не поддерживал миграцию Mozilla на key-stretching v2:
    v1: PBKDF2-SHA256(pw, "identity.mozilla.com/picl/v1/quickStretch:"+email, 1000)
    v2: PBKDF2-SHA256(pw, clientSalt, 650000)   # clientSalt с /account/credentials/status
  далее authPW = HKDF-SHA256(stretch, info="identity.mozilla.com/picl/v1/authPW", salt="")
  Для v2-аккаунтов clientSalt содержит СЛУЧАЙНЫЙ токен — обязателен запрос
  /v1/account/credentials/status перед логином.
  Источники: mozilla/fxa lib/routes/utils/client-key-stretch.ts, signin.js,
  mozilla/PyFxA fxa/crypto.py (get_key_stretch_version, StretchedPassword).

ИСПРАВЛЕНИЕ 2FA (2026-09-17, верифицировано по исходникам mozilla/fxa):
  Симптом: /session/verify/totp отвечал 401 errno 110
  «Invalid authentication token: Missing authentication».
  Причина: скрипт слал  Authorization: Bearer fxs_<СЫРОЙ sessionToken>,
  а сервер ждёт  Authorization: Bearer fxs_<tokenID>,  где tokenID —
  HKDF-дериват от sessionToken. Сыроий токен в БД не находился, цепочка
  стратегий ['sessionTokenBearer', 'sessionToken'] падала на Hawk-фолбэк,
  который и выдавал «Missing authentication» (это сообщение библиотеки Hawk
  об отсутствующем Hawk-заголовке, а не проблема с самим sessionToken).

  Актуальная схема (ADR-0022, FXA-9392, статус 2026-04-23 — «client-side
  Bearer migration complete»; проверено по main на 2026-09-17):

  1. Сервер (packages/fxa-auth-server/lib/routes/auth-schemes/bearer-fxa-token.js):
       приём строго по regex ^Bearer fxs_([0-9a-f]{64})$  (64 hex в НИЖНЕМ регистре),
       далее лукап сессии в БД по этому id — БД ключирована именно производным
       tokenID, а не сырым sessionToken.

  2. Официальный клиент (packages/fxa-auth-client/lib/bearer.ts):
       bearerHeader(token, kind) = "Bearer " + prefix + "_" + id,  где
       id = deriveTokenCredentials(sessionToken, "sessionToken").id
     Деривация (packages/fxa-auth-client/lib/hawk.ts, deriveHawkCredentials —
     схема-нейтральная, используется и для Bearer, и ранее для Hawk):
       material = HKDF-SHA256(ikm = bytes(sessionToken),
                              salt = "",
                              info = "identity.mozilla.com/picl/v1/sessionToken",
                              L = 96)
       tokenID     = hex(material[0:32])    # -> "fxs_<tokenID>"
       reqHMACkey  =     material[32:64]    # ключ Hawk-MAC (фолбэк)
       bundleKey   = hex(material[64:96])   # не используется здесь
     Один HKDF-стрим на 96 байт; его первые 32 байта совпадают с классическим
     tokenID старого Hawk-протокола.
     СВЕРЕНО с официальными тест-векторами onepw (mozilla.github.io/ecosystem-
     platform/explanation/onepw-protocol): sessionToken a0a1...bebf ->
     tokenID c0a29dcf...1595ab, reqHMACkey 9d8f2299...2febc0. Совпадает.

  3. Hawk-фолбэк: серверная схема (auth-schemes/hawk-fxa-token.js) парсит
     Hawk-заголовок, берёт атрибут id и ищет сессию по нему (MAC на сервере
     сейчас НЕ проверяется), но для совместимости с возможным старым
     деплоем Hawk-заголовок ниже подписывается полноценно (id=tokenID,
     key=reqHMACkey, реальный MAC + hash тела).

  Поэтому: bearer_session() теперь деривит tokenID, при 401/errno 110
  выполняется один повтор с полноценным Hawk-заголовком.

  ДОПОЛНЕНИЕ (2026-09-18, lib/routes/totp.js, роут /session/verify/totp):
  роут НЕ требует, чтобы verificationMethod сессии был 'totp-2fa' —
  стратегии ['sessionTokenBearer', 'sessionToken'], по валидному коду
  db.verifyTokensWithMethod(sessionToken.id, 'totp-2fa') помечает сессию
  верифицированной при ЛЮБОМ исходном verificationMethod. А обратный путь
  (/session/verify_code, lib/routes/session.js) для TOTP-аккаунтов бросает
  insufficientAal. Поэтому при наличии TOTP-секрета верифицировать сессию
  нужно (и можно) только через /session/verify/totp.

ИСПРАВЛЕНИЕ OAUTH (2026-09-17, верифицировано по исходникам mozilla/fxa, main):
  Симптом: POST https://oauth.accounts.firefox.com/v1/token с
    {"grant_type": "fxa-session-token", ...}
  отвечал 400 errno 109 «Invalid request parameter», validation keys ['grant_type'].

  Причина: grant type "fxa-session-token" больше НЕ существует. Валидный enum
  grant_type на /v1/token (packages/fxa-auth-server/lib/routes/oauth/token.js,
  PAYLOAD_SCHEMA / Joi-альтернативы роута /oauth/token):
      authorization_code | refresh_token | fxa-credentials |
      urn:ietf:params:oauth:grant-type:token-exchange
  (errno 109 в OAuth-server = «invalid request parameter», невалидный
  grant_type отклоняется валидатором раньше всего остального.)

  Актуальная схема получения access token по sessionToken (без identity
  assertion на стороне клиента):

    POST https://api.accounts.firefox.com/v1/oauth/token      <- auth-server!
    Authorization: Bearer fxs_<tokenID>                        (как у 2FA)
    Content-Type: application/json
    {"grant_type": "fxa-credentials",
     "client_id": "5882386c6d801776",         # Firefox Desktop
     "scope": "profile https://identity.mozilla.com/apps/vpn",
     "access_type": "online"}

  Обработчик (token.js, роут /oauth/token, case 'fxa-credentials'):
    - требует аутентификацию sessionToken (стратегии sessionTokenBearer /
      sessionToken — наш заголовок Bearer fxs_<tokenID>);
    - сам генерирует identity assertion через makeAssertionJWT(config,
      sessionToken) — assertion на клиенте строить НЕ нужно;
    - validateAssertionGrant требует у клиента canGrant=true И
      publicClient=true — у Firefox Desktop оба флага выставлены (подтверждено
      конфигами fxa-dev/fxa-selfhosting; token.js, комментарий VPN-in-Desktop
      bandaid FXA-14159: «Firefox Desktop is the only client that mints a
      VPN token for every signed-in user» — то есть desktop штатно получает
      VPN-scope токен через fxa-credentials);
    - access_type=online (по умолчанию) — refresh_token не выдаётся, это
      нормально: proxyPass-флоу выполняется за один прогон.

  Фолбэк scope: если сервер отклонит основной scope (errno 114 invalid
  scopes), скрипт повторяет запрос с «profile https://identity.mozilla.com/
  apps/mozillavpn». Оба варианта содержат profile — это ключевое отличие
  от прежней версии скрипта.

WAF / Bot Management (актуально на 2026-09):
  api.accounts.firefox.com защищён Fastly Next-Gen WAF + Bot Management
  (НЕ F5 — 406 с пустым телом это дефолтный blocking-код Fastly, а cookie
  _fs_ch_cp_* — challenge-cookie Fastly; подтверждено в Mikescher/
  firefox-sync-client#21 и офиц. документацией Fastly). Challenge чисто
  алгоритмический (JS proof-of-work + clientmetrics), браузер НЕ нужен.

  Скрипт решает challenge сам, по алгоритму PR #22 (stv0g, merged
  2026-06-14) в firefox-sync-client, который основан на
  github.com/pagpeter/fastly-antibot:
    GET accounts.firefox.com/       -> id скрипта _fs-ch-<id>
    GET /_fs-ch-<id>/script.js      -> token (regex init([...], "tok"))
    POST /_fs-ch-<id>/pat           -> best-effort (Apple PAT)
    POST /_fs-ch-<id>/fst-post-back -> список challenge'ей + новый tok
    pow: SHA256(base+2 символа)==hash   -> 3844 варианта, мгновенно
    clientmetrics: статичная заглушка (webdriver:false)
    POST решений -> Set-Cookie _fs_ch_cp_* (Domain=.firefox.com, ~1 час)
  Кука кэшируется в ~/.config/mozvpn/fastly-cookie.json (50 минут).

  При 406+пустое тело на любом *.firefox.com запрос challenge решается
  автоматически и запрос повторяется один раз. --session-token остался
  как фолбэк, если Fastly изменит разметку challenge.

Использование:
  python3 mozvpn.py                                  # интерактивно (one-shot)
  python3 mozvpn.py --email a@b.c --password '***' --qr qr.png   # 1-й запуск
  python3 mozvpn.py --qr qr.png                      # добавить/обновить TOTP-секрет из QR
  python3 mozvpn.py --watch                          # цикл автообновления токена
  python3 mozvpn.py --use-sing-box                   # + локальные прокси (движок proxy.py)
  python3 mozvpn.py --use-proxy                      # то же самое (алиас)
  python3 mozvpn.py --session-token <hex>            # фолбэк
  python3 mozvpn.py --session-token <hex> --totp 123456
  python3 mozvpn.py --country US --city "New York" --test
  python3 mozvpn.py --max-proxies 10                 # ограничить число локальных прокси
  python3 mozvpn.py --refresh-margin 45              # за сколько сек до exp обновлять
  python3 mozvpn.py --firefox-version 156.0          # фильтр Remote Settings
  python3 mozvpn.py --json out.json / --no-save

Переменные окружения: MOZVPN_EMAIL, MOZVPN_PASSWORD, MOZVPN_SESSION_TOKEN,
  MOZVPN_TOTP, MOZVPN_TOTP_SECRET
Результат по умолчанию сохраняется рядом со скриптом: mozvpn-YYYYMMDD-HHMMSS.json
Кэши (все с mode 600):
  ~/.config/mozvpn/session.json        — sessionToken
  ~/.config/mozvpn/credentials.json    — email/password/totp_secret (+digits/period/algorithm)
  ~/.config/mozvpn/fastly-cookie.json  — кука Fastly WAF
  ~/.config/mozvpn/pyproxy/            — плагин proxy.py, JSON-мап (токен+апстримы), лог
"""

import argparse, base64, binascii, getpass, hashlib, hmac, http.cookiejar, json, os, re
import sys, time, socket, subprocess, signal, atexit
import urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs, unquote
from datetime import timezone
from email.utils import parsedate_to_datetime

# ---- опциональные зависимости (все — популярные пакеты с готовыми wheel'ями
# ---- для Windows/Linux/macOS; системные утилиты НЕ требуются) ----
try:
    import pyotp
except ImportError:
    pyotp = None
try:
    import zxingcpp
except ImportError:
    zxingcpp = None
try:
    from PIL import Image
except ImportError:
    Image = None

FXA_AUTH      = "https://api.accounts.firefox.com/v1"
FXA_OAUTH     = "https://oauth.accounts.firefox.com/v1"
GUARDIAN      = "https://vpn.mozilla.org"
FXA_CLIENT_ID = "5882386c6d801776"                       # Firefox Desktop (публичный)

# ВАЖНО: scope — ПАРА «profile + VPN-scope». Без «profile» Guardian не может
# подтвердить энтайтлмент и отвечает 403 no_entitlement (см. шапку файла).
# Порядок: основной (проверен рабочей сторонней реализацией 2026-09),
# затем фолбэк с legacy-именем VPN-скоупа.
OAUTH_SCOPES  = ("profile https://identity.mozilla.com/apps/vpn",
                 "profile https://identity.mozilla.com/apps/mozillavpn")

RS_SERVERLIST = ("https://firefox.settings.services.mozilla.com/v1"
                 "/buckets/main/collections/vpn-serverlist/records")

DEFAULT_FIREFOX_VERSION = "156.0"

# Заголовки как у Firefox (для шагов после логина — Guardian, Remote Settings)
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) "
                  "Gecko/20100101 Firefox/156.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "application/json",
}

CONF_DIR    = os.path.join(os.path.expanduser("~"), ".config", "mozvpn")
CACHE       = os.path.join(CONF_DIR, "session.json")
CRED_CACHE  = os.path.join(CONF_DIR, "credentials.json")
FASTLY_CACHE = os.path.join(CONF_DIR, "fastly-cookie.json")
PYPROXY_DIR = os.path.join(CONF_DIR, "pyproxy")
PYPROXY_PLUGIN = os.path.join(PYPROXY_DIR, "mozvpn_proxy_plugin.py")
PYPROXY_MAP = os.path.join(PYPROXY_DIR, "mozvpn-proxy-map.json")
PYPROXY_LOG = os.path.join(PYPROXY_DIR, "proxy.log")
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))

# Диапазон портов локальных прокси и базовый порт
LOCAL_PORT_BASE  = 20000
LOCAL_PORT_RANGE = 20000      # порты 20000..39999

class MozVpnError(RuntimeError):
    """Ошибка бизнес-логики (логин/OAuth/Guardian), не фатальная для цикла."""

WAF_MESSAGE = """❌ HTTP 406 от *.firefox.com даже после автоматического решения challenge.

Похоже, Fastly изменил разметку/алгоритм challenge. Первым делом сверьте regex'и:
  - github.com/pagpeter/fastly-antibot (pkg/solver/solver.go — regex'ы script id и token)
  - PR #22 в Mikescher/firefox-sync-client (файл syncclient/fastly.go — порт этого алгоритма)

Фолбэк — переиспользуйте сессию Firefox:
  1) Войдите в Mozilla-аккаунт в браузере Firefox (2FA вводится там).
  2) Извлеките sessionToken из профиля, например утилитой firefox_decrypt
     (github.com/unode/firefox_decrypt): запись «Firefox Accounts credentials»
     хранит JSON с полем sessionToken.
  3) Запустите:  python3 mozvpn.py --session-token <hex> --email you@example.com
"""

# ---------------- синхронизация времени с серверами Mozilla ----------------
# TOTP считается от Unix-времени: если часы ПК уходят, сгенерированный код
# не совпадает с кодом в мобильном приложении, и /session/verify/totp честно
# отвечает «неверный код». Лечение: из КАЖДОГО HTTP-ответа серверов Mozilla
# вычитывается заголовок Date, по разнице строится смещение, и TOTP
# генерируется для скорректированного времени. Заодно смещение печатается,
# если оно заметное (диагностика «почему коды не совпадают»).

_TIME_OFFSET = 0.0   # серверное минус локальное время, секунды


def _note_server_date(headers):
    """Вычисляет смещение локальных часов относительно сервера по Date."""
    global _TIME_OFFSET
    try:
        if not headers:
            return
        ds = headers.get("Date") or headers.get("date")
        if not ds:
            return
        dt = parsedate_to_datetime(ds)
        if dt.tzinfo is None:                    # наивное время => трактуем как UTC
            dt = dt.replace(tzinfo=timezone.utc)
        _TIME_OFFSET = dt.timestamp() - time.time()
    except Exception:
        pass


def synced_time() -> float:
    """Локальное время, скорректированное по серверам Mozilla (для TOTP)."""
    return time.time() + _TIME_OFFSET


def time_offset() -> float:
    """Текущее смещение (серверное − локальное), секунды."""
    return _TIME_OFFSET


def wait_next_totp_window(period: int):
    """Спит до начала следующего TOTP-окна (по скорректированному времени)."""
    now = synced_time()
    time.sleep(max(0.5, period - (now % period) + 0.7))


# ---------------- Fastly Next-Gen WAF challenge solver ----------------
# Порт алгоритма PR #22 (stv0g) firefox-sync-client / pagpeter/fastly-antibot
# на чистый stdlib. Challenge неинтерактивный: JS PoW + clientmetrics.

FASTLY_UA   = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
FASTLY_PAGE = "https://accounts.firefox.com/"

COOKIE_JAR = http.cookiejar.CookieJar()
_OPENER    = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(COOKIE_JAR))
_fastly_state = {"solved": False, "failed": False}


def _is_firefox_host(url: str) -> bool:
    h = urlparse(url).hostname or ""
    return h == "firefox.com" or h.endswith(".firefox.com")


def _add_cookie(name: str, value: str, domain: str = ".firefox.com"):
    COOKIE_JAR.set_cookie(http.cookiejar.Cookie(
        version=0, name=name, value=value,
        port=None, port_specified=False,
        domain=domain, domain_specified=True, domain_initial_dot=True,
        path="/", path_specified=True,
        secure=False, expires=None, discard=False,
        comment=None, comment_url=None, rest={}, rfc2109=False))


def load_fastly_cache() -> bool:
    try:
        with open(FASTLY_CACHE) as f:
            c = json.load(f)
        if c.get("name") and c.get("value") and c.get("expiresAt", 0) > time.time() + 60:
            _add_cookie(c["name"], c["value"])
            return True
    except Exception:
        pass
    return False


def save_fastly_cache(name: str, value: str):
    try:
        os.makedirs(os.path.dirname(FASTLY_CACHE), exist_ok=True)
        with open(FASTLY_CACHE, "w") as f:
            json.dump({"name": name, "value": value,
                       "expiresAt": time.time() + 50 * 60}, f)
        _chmod600(FASTLY_CACHE)
    except OSError:
        pass


def _fastly_http(method: str, url: str, data=None, headers=None, timeout=30):
    """HTTP для challenge-флоу; ответ возвращается сырым (bytes)."""
    h = {"User-Agent": FASTLY_UA, "Accept-Language": "en-US,en;q=0.9"}
    h.update(headers or {})
    body = None
    if data is not None:
        body = (data if isinstance(data, bytes)
                else json.dumps(data, separators=(",", ":")).encode())
    r = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with _OPENER.open(r, timeout=timeout) as resp:
            _note_server_date(resp.headers)
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        _note_server_date(e.headers)
        return e.code, e.read()


def _fastly_postback(domain: str, script_id: str, referer: str,
                     token: str, data) -> dict:
    payload = json.dumps({"token": token, "data": data},
                         separators=(",", ":")).encode()
    status, body = _fastly_http(
        "POST", f"{domain}/_fs-ch-{script_id}/fst-post-back", payload,
        {"Referer": referer, "Accept": "application/json",
         "Content-Type": "application/json"})
    if status != 200 or not body:
        raise RuntimeError(f"fst-post-back вернул HTTP {status}")
    return json.loads(body)


def _solve_pow(base: str, target_hex: str) -> str:
    """SHA256(base + 2 символа из [a-zA-Z0-9]) == hash — перебор 3844 вариантов."""
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    target = (target_hex or "").lower()
    for a in charset:
        for b in charset:
            suffix = a + b
            if hashlib.sha256((base + suffix).encode()).hexdigest() == target:
                return suffix
    return ""


def _solve_clientmetrics_stub() -> dict:
    # Минимальные значения — достаточно по live-тестам (pypi.org, accounts.firefox.com)
    return {"ty": "clientmetrics",
            "webdriver": False,
            "bot_detection_result": {"bot_detected": False, "bot_kind": None},
            "browser_metrics": {"client_data": "{}", "error_trace": '""'}}


def fastly_solve_challenge(target_url: str = FASTLY_PAGE):
    """Полный флоу Fastly challenge. Возвращает (cookie_name, cookie_value)."""
    u = urlparse(target_url)
    domain = f"{u.scheme}://{u.hostname}"
    referer = target_url

    # 1. страница с challenge -> id скрипта
    status, body = _fastly_http("GET", target_url, headers={
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
    html = body.decode("utf-8", "replace")
    m = (re.search(r"script\.src = '\/_fs-ch-([^\/]+)\/script\.js\?reload=true'", html)
         or re.search(r'_fs-ch-([^/\'"?\s]+)', html))
    if not m:
        raise RuntimeError("id скрипта challenge не найден на странице")
    script_id = m.group(1)

    # 2. script.js -> token
    status, body = _fastly_http(
        "GET", f"{domain}/_fs-ch-{script_id}/script.js?reload=true",
        headers={"Referer": referer, "Accept": "*/*"})
    m = re.search(r'init\(\[[^\]]*\],\s*"([^"]+)"', body.decode("utf-8", "replace"))
    if not m:
        raise RuntimeError("token не найден в script.js")
    token = m.group(1)

    # 3. PAT (Apple Private Access Token) — best-effort, ошибки игнорируются
    _fastly_http("POST", f"{domain}/_fs-ch-{script_id}/pat?token={token}",
                 headers={"Referer": referer, "Accept": "text/plain",
                          "Content-Type": "application/json"})

    # 4. init post-back -> список challenge'ей + новый token
    init = _fastly_postback(domain, script_id, referer, token,
                            [{"ty": "pat", "auth": ""}])
    token = init.get("tok", token)

    # 5. решаем challenge'и
    solutions = []
    for ch in init.get("ch", []):
        ty = ch.get("ty")
        if ty == "pow":
            d = ch.get("data", {})
            solutions.append({"ty": "pow", "base": d.get("base"),
                              "answer": _solve_pow(d.get("base", ""), d.get("hash", "")),
                              "hmac": d.get("hmac"), "expires": d.get("expires")})
        elif ty == "clientmetrics":
            solutions.append(_solve_clientmetrics_stub())
        else:
            print(f"⚠️  Неизвестный тип Fastly challenge '{ty}' — пропускаю.")

    # 6. отправляем решения -> Set-Cookie _fs_ch_cp_*
    final = _fastly_postback(domain, script_id, referer, token, solutions)
    if final.get("status") != "success":
        raise RuntimeError(f"challenge не решён (status={final.get('status')!r})")

    for c in COOKIE_JAR:
        if c.name.startswith("_fs_ch_cp_"):
            return c.name, c.value
    raise RuntimeError("куки _fs_ch_cp_* не получена после успешного решения")


def ensure_fastly_cookie() -> bool:
    """Кука Fastly: кэш -> решение challenge. True = кука в jar готова."""
    if _fastly_state["solved"]:
        return True
    if _fastly_state["failed"]:
        return False
    if load_fastly_cache():
        _fastly_state["solved"] = True
        print("♻️  Использую кэшированную куку Fastly (_fs_ch_cp_*).")
        return True
    print("🛡️  Fastly Bot Management: решаю PoW-challenge ...")
    try:
        name, value = fastly_solve_challenge()
        save_fastly_cache(name, value)
        _fastly_state["solved"] = True
        print(f"✅ Кука {name} получена (валидна ~1 час).")
        return True
    except Exception as e:
        _fastly_state["failed"] = True
        print(f"❌ Не удалось решить Fastly challenge: {e}")
        return False


# ---------------- crypto: FxA password stretching v1 + v2 ----------------
# Верифицировано по mozilla/PyFxA (fxa/crypto.py) и mozilla/fxa
# (lib/routes/utils/client-key-stretch.ts):
#   v1: salt = "identity.mozilla.com/picl/v1/quickStretch:" + email,  1000 итер.
#   v2: salt = clientSalt с /account/credentials/status,           650000 итер.
#   обе: authPW = HKDF-SHA256(stretch, info="identity.mozilla.com/picl/v1/authPW", salt="")

NAMESPACE_V1 = "identity.mozilla.com/picl/v1/quickStretch:"
NAMESPACE_V2 = "identity.mozilla.com/picl/v1/quickStretchV2:"
HKDF_INFO    = "identity.mozilla.com/picl/v1/authPW"
PBKDF2_ITER_V1 = 1000
PBKDF2_ITER_V2 = 650000

def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t; i += 1
    return out[:length]

def derive_auth_pw(stretched: bytes) -> str:
    """authPW = HKDF(stretched, info=HKDF_INFO, salt='') — общий для v1 и v2."""
    return hkdf_sha256(stretched, HKDF_INFO.encode()).hex()

def compute_authpw_v1(email: str, password: str) -> str:
    """v1-стретчинг: соль содержит нормализованный email."""
    salt = (NAMESPACE_V1 + email).encode()
    quick = hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                                PBKDF2_ITER_V1, 32)
    return derive_auth_pw(quick)

def compute_authpw_v2(client_salt: str, password: str) -> str:
    """v2-стретчинг: соль (со случайным токеном) ОБЯЗАТЕЛЬНО с сервера."""
    if not client_salt.startswith(NAMESPACE_V2):
        raise ValueError(f"clientSalt не v2-формата: {client_salt!r}")
    quick = hashlib.pbkdf2_hmac("sha256", password.encode(), client_salt.encode(),
                                PBKDF2_ITER_V2, 32)   # ~0.3–1 с в C-реализации hashlib
    return derive_auth_pw(quick)

# ---------------- sessionToken -> (tokenID, reqHMACkey) ----------------
# Верифицировано по mozilla/fxa (main, 2026-09-17):
#   fxa-auth-client/lib/bearer.ts:  Authorization: "Bearer fxs_" + id,
#     id = deriveTokenCredentials(sessionToken, "sessionToken").id
#   fxa-auth-client/lib/hawk.ts:    ОДИН HKDF-SHA256(ikm=sessionToken, salt="",
#     info="identity.mozilla.com/picl/v1/sessionToken", L=96);
#     id=[0:32] hex, reqHMACkey=[32:64], bundleKey=[64:96] hex.
#   fxa-auth-server/.../bearer-fxa-token.js: ^Bearer fxs_([0-9a-f]{64})$,
#     лукап сессии в БД по ЭТОМУ id (БД ключирована производным tokenID).
# Сверено с официальными тест-векторами onepw:
#   sessionToken=a0a1...bebf -> tokenID=c0a29dcf...1595ab,
#   reqHMACkey=9d8f2299...2febc0.  Совпадает (проверено расчётом).
# ВАЖНО: в заголовок Bearer идёт ПРОИЗВОДНЫЙ tokenID, а НЕ сырой sessionToken.

TOKEN_DERIVE_INFO = b"identity.mozilla.com/picl/v1/sessionToken"

def derive_session_credentials(session_token: str):
    """(tokenID_hex, reqHMACkey_bytes) из сырого sessionToken (hex)."""
    material = hkdf_sha256(bytes.fromhex(session_token), TOKEN_DERIVE_INFO, 64)
    return material[:32].hex(), material[32:64]

def bearer_session(session_token: str) -> dict:
    """Актуальная схема Mozilla (ADR-0022, FXA-9392): префиксные Bearer-токены.
    Формат: 'Authorization: Bearer fxs_<tokenID>', где tokenID —
    HKDF-дериват от sessionToken (так же, как официальный fxa-auth-client)."""
    token_id, _ = derive_session_credentials(session_token)
    return {"Authorization": f"Bearer fxs_{token_id}"}

def hawk_session(session_token: str, method: str, path: str,
                 payload: bytes, host: str = "api.accounts.firefox.com",
                 port: int = 443) -> dict:
    """Полноценный Hawk-заголовок (фолбэк, если Bearer-стратегия не принята).
    id=tokenID, key=reqHMACkey — те же дериваты, что в onepw/Hawk-эпохе.
    Текущий сервер MAC не проверяет (hawk-fxa-token.js), но для старых
    деплоев подписываем честно: normalized string + HMAC-SHA256 + hash тела."""
    token_id, req_hmac_key = derive_session_credentials(session_token)
    ts = str(int(time.time()))
    nonce = base64.b64encode(os.urandom(8)).decode()
    body_hash = base64.b64encode(hashlib.sha256(payload).digest()).decode()
    normalized = "\n".join([
        "hawk.1.header", ts, nonce,
        method.upper(), path, host.lower(), str(port), body_hash, "",
    ]) + "\n"
    mac = base64.b64encode(
        hmac.new(req_hmac_key, normalized.encode(), hashlib.sha256).digest()
    ).decode()
    return {"Authorization":
            f'Hawk id="{token_id}", ts="{ts}", nonce="{nonce}", '
            f'hash="{body_hash}", mac="{mac}"'}

# ---------------- http ----------------

def req(method: str, url: str, data=None, headers=None, timeout=30, _fastly_retry=False):
    h = dict(BROWSER_HEADERS); h.update(headers or {})
    body = json.dumps(data).encode() if data is not None else None
    r = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with _OPENER.open(r, timeout=timeout) as resp:
            _note_server_date(resp.headers)     # синхронизация времени для TOTP
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        _note_server_date(e.headers)            # и из ошибочных ответов тоже
        raw = e.read()
        # Fastly NGWAF блокирует небраузерных клиентов кодом 406 с пустым телом,
        # пока нет валидной куки _fs_ch_cp_*. Решаем challenge и повторяем раз.
        if (e.code == 406 and not raw and not _fastly_retry
                and _is_firefox_host(url) and ensure_fastly_cookie()):
            return req(method, url, data, headers, timeout, _fastly_retry=True)
        try:    return e.code, (json.loads(raw) if raw else {})
        except Exception: return e.code, {}

# ---------------- кэши сессии / реквизитов ----------------

def _chmod600(path: str):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

def save_cache(email, session_token):
    try:
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        with open(CACHE, "w") as f:
            json.dump({"email": email, "sessionToken": session_token}, f)
        _chmod600(CACHE)
    except OSError:
        pass

_CRED_KEYS = ("email", "password", "totp_secret",
              "totp_digits", "totp_period", "totp_algorithm")

def load_credentials() -> dict:
    """{email, password, totp_secret, totp_digits, totp_period, totp_algorithm}."""
    try:
        with open(CRED_CACHE) as f:
            c = json.load(f)
        if not isinstance(c, dict):
            c = {}
    except Exception:
        c = {}
    return {k: c.get(k) for k in _CRED_KEYS}

def save_credentials(**kw):
    """Дополняет credentials.json новыми известными полями (merge)."""
    creds = load_credentials()
    for k in _CRED_KEYS:
        v = kw.get(k)
        if v is None or v == "":
            continue
        if k in ("totp_digits", "totp_period"):
            try:
                v = int(v)
            except (TypeError, ValueError):
                continue
        creds[k] = v
    if not any(creds.get(k) for k in _CRED_KEYS):
        return
    try:
        os.makedirs(os.path.dirname(CRED_CACHE), exist_ok=True)
        with open(CRED_CACHE, "w") as f:
            json.dump(creds, f)
        _chmod600(CRED_CACHE)
    except OSError:
        pass

def totp_params_from(creds: dict):
    """(digits, period, algorithm) из credentials.json; дефолт 6/30/SHA1."""
    digits, period, algorithm = 6, 30, "SHA1"
    try:
        digits = int(creds.get("totp_digits") or 6)
    except (TypeError, ValueError):
        pass
    try:
        period = int(creds.get("totp_period") or 30)
    except (TypeError, ValueError):
        pass
    algorithm = (creds.get("totp_algorithm") or "SHA1").upper()
    return digits, period, algorithm

# ---------------- TOTP: QR -> секрет -> код ----------------

def _normalize_totp_secret(secret: str) -> str:
    return re.sub(r"\s+", "", secret).upper()

def validate_totp_secret(secret: str) -> str:
    """Нормализует и проверяет секрет как корректный base32."""
    s = _normalize_totp_secret(secret)
    if not s:
        raise MozVpnError("❌ Пустой TOTP-секрет.")
    try:
        base64.b32decode(s + "=" * (-len(s) % 8), casefold=True)
    except (binascii.Error, ValueError) as e:
        raise MozVpnError(f"❌ TOTP-секрет не является корректным base32: {e}")
    return s

_TOTP_DIGESTS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256,
                 "SHA512": hashlib.sha512}

def _totp_object(secret: str, digits=6, period=30, algorithm="SHA1"):
    if pyotp is None:
        raise MozVpnError("Для генерации TOTP нужен пакет pyotp:\n"
                          "    pip install pyotp")
    digest = _TOTP_DIGESTS.get(str(algorithm).upper())
    if digest is None:
        raise MozVpnError(f"❌ Неизвестный TOTP-алгоритм: {algorithm!r} "
                          f"(ожидался SHA1/SHA256/SHA512)")
    try:
        digits = int(digits); period = int(period)
    except (TypeError, ValueError):
        raise MozVpnError(f"❌ Некорректные параметры TOTP: digits={digits}, period={period}")
    try:
        return pyotp.TOTP(_normalize_totp_secret(secret), digits=digits,
                          interval=period, digest=digest)
    except Exception as e:
        raise MozVpnError(f"❌ Не удалось инициализировать TOTP из секрета: {e}")

def totp_generate(secret: str, digits=6, period=30, algorithm="SHA1"):
    """(код, осталось_секунд) по СКОРРЕКТИРОВАННОМУ времени серверов Mozilla."""
    t = _totp_object(secret, digits, period, algorithm)
    now = synced_time()
    return t.at(now), int(period - (now % period))

def decode_qr_totp(path: str) -> dict:
    """Декодирует картинку с QR (otpauth://totp/...) и возвращает ВСЕ параметры:
    {secret, digits, period, algorithm}. zxing-cpp >= 2.x (nanobind) НЕ принимает
    путь к файлу (TypeError: str does not support the buffer protocol) —
    read_barcodes() ожидает объект изображения, поэтому файл открываем через
    Pillow и передаём PIL.Image (штатно поддерживаемый тип, см. README
    zxing-cpp: wrappers/python). Без системных утилит."""
    if zxingcpp is None:
        raise MozVpnError("Для чтения QR нужен пакет zxing-cpp:\n"
                          "    pip install zxing-cpp pyotp Pillow")
    if Image is None:
        raise MozVpnError("Для чтения QR-файла нужен пакет Pillow:\n"
                          "    pip install Pillow")
    if not os.path.isfile(path):
        raise MozVpnError(f"QR-файл не найден: {path}")
    try:
        im = Image.open(path)
        im.load()   # данные должны остаться доступными после закрытия файла
    except Exception as e:
        raise MozVpnError(f"Не удалось открыть картинку {path}: {e}")
    results = zxingcpp.read_barcodes(im)
    if not results:
        raise MozVpnError(f"QR-код не найден в файле: {path}")
    otpauth = None
    for r in results:
        text = r.text or ""
        if text.startswith("otpauth://"):
            otpauth = text
            break
    if otpauth is None:
        raise MozVpnError(f"В файле {path} нет otpauth:// QR-кода: "
                          f"{results[0].text[:80]!r}")
    parsed = urlparse(otpauth)
    if parsed.scheme != "otpauth" or parsed.netloc != "totp":
        raise MozVpnError(f"QR не является TOTP (otpauth://totp): {otpauth[:80]}")
    qs = parse_qs(parsed.query)
    secret = (qs.get("secret") or [None])[0]
    if not secret:
        raise MozVpnError(f"В QR отсутствует параметр secret: {otpauth[:80]}")

    def _int_param(name, default):
        try:
            return int((qs.get(name) or [default])[0])
        except (TypeError, ValueError):
            return default

    return {"secret": validate_totp_secret(unquote(secret)),
            "digits": _int_param("digits", 6),
            "period": _int_param("period", 30),
            "algorithm": ((qs.get("algorithm") or ["SHA1"])[0] or "SHA1").upper()}

def print_current_totp(secret, creds=None):
    """Печатает текущий TOTP-код и остаток времени его действия."""
    if not secret:
        return
    try:
        digits, period, algorithm = totp_params_from(creds) if creds else (6, 30, "SHA1")
        code, valid = totp_generate(secret, digits, period, algorithm)
        off = time_offset()
        off_s = f", смещение часов {off:+.1f} с" if abs(off) >= 1 else ""
        print(f"🔢 Текущий TOTP-код: {code} (действует ещё {valid} с{off_s})")
    except MozVpnError as e:
        print(e)

def make_totp_provider(args, creds):
    """Возвращает callable() -> код TOTP или None.
    Приоритет: --totp (фикс.) -> --totp-secret/MOZVPN_TOTP_SECRET -> кэш секрета.
    Коды генерируются по времени, скорректированному по серверам Mozilla
    (см. _note_server_date), с учётом digits/period/algorithm из QR.
    Сгенерированные коды печатаются в консоль. Если текущий код почти истёк
    (< 4 с до конца окна), генератор дожидается следующего окна — иначе
    сервер может не успеть принять код в последние секунды окна."""
    fixed = (args.totp or "").strip() or None
    secret = (args.totp_secret or "").strip() or creds.get("totp_secret")
    digits, period, algorithm = totp_params_from(creds)
    if fixed:
        return lambda: re.sub(r"[\s\-]+", "", fixed)
    if secret:
        def _gen():
            now = synced_time()
            valid = period - (now % period)
            if valid < 4:
                time.sleep(valid + 0.5)
            code, valid2 = totp_generate(secret, digits, period, algorithm)
            print(f"🔢 Сгенерирован TOTP-код: {code} (окно {int(period)} с, "
                  f"осталось {int(valid2)} с)")
            return code
        return _gen
    return None

# ---------------- JWT helpers ----------------

def jwt_payload(token: str) -> dict:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}

def jwt_exp(token: str) -> int:
    """exp из payload proxyPass JWT; 0 если не разобрать."""
    try:
        return int(jwt_payload(token).get("exp") or 0)
    except Exception:
        return 0

# ---------------- FxA auth ----------------

def get_credentials_status(email: str):
    """Версия стретчинга аккаунта: ("v1"|"v2", clientSalt|None).
    По PyFxA Client.get_key_stretch_version(). При ошибке — фолбэк на v1."""
    status, d = req("POST", FXA_AUTH + "/account/credentials/status",
                    {"email": email})
    if status == 200 and d.get("currentVersion") in ("v1", "v2"):
        return d["currentVersion"], d.get("clientSalt")
    return "v1", None

def fxa_login(email: str, password: str, totp_provider=None,
              interactive: bool = True, tp=None) -> str:
    """Вход в аккаунт. Возвращает sessionToken.
    totp_provider: callable() -> 6-значный код (генерируется самим скриптом).
    tp: (digits, period, algorithm) параметры TOTP для пауз между попытками.
    interactive=False: никаких input(), при отсутствии кода — MozVpnError."""
    digits_n, period, algorithm = (tp or (6, 30, "SHA1"))
    period = int(period)
    email_norm = email.strip().lower()

    # 0. Определяем версию key-stretching и считаем authPW соответствующей схемой.
    #    Для v2 clientSalt берём с сервера — он содержит случайный токен.
    version, client_salt = get_credentials_status(email_norm)
    print(f"🔐 Версия key-stretching аккаунта: {version}"
          + (" (650k итераций PBKDF2)" if version == "v2" else ""))
    off = time_offset()
    if abs(off) >= 3:
        print(f"⏱ Часы компьютера расходятся с серверами Mozilla на {off:+.1f} с; "
              f"TOTP будет генерироваться по серверному времени.")
    if version == "v2" and client_salt:
        auth_pw = compute_authpw_v2(client_salt, password)
    else:
        auth_pw = compute_authpw_v1(email_norm, password)

    status, d = req("POST", FXA_AUTH + "/account/login",
                    {"email": email_norm, "authPW": auth_pw})
    if status == 406:
        raise MozVpnError(WAF_MESSAGE)
    if status != 200:
        errno = d.get("errno"); msg = d.get("message", d)
        if errno == 102: raise MozVpnError("❌ Аккаунт не найден.")
        if errno == 103: raise MozVpnError("❌ Неверный пароль (errno 103). "
                                  "Если входили через Google/Apple — сначала задайте пароль: "
                                  "accounts.firefox.com → Settings.")
        if errno == 114: raise MozVpnError("❌ Аккаунт заблокирован (повторите позже).")
        if errno in (142, 144): raise MozVpnError("❌ Вход с этим email запрещён / пароль не задан "
                                         "(аккаунт создан через Google/Apple). Задайте пароль: "
                                         "accounts.firefox.com → Settings.")
        raise MozVpnError(f"❌ Ошибка входа ({status}): {msg}")

    verified = d.get("verified")
    email_verified = d.get("emailVerified")
    if verified is None:  # поле deprecated -> новые поля
        verified = bool(d.get("sessionVerified")) and bool(email_verified)
    if not verified:
        vm = d.get("verificationMethod") or ""
        vr = d.get("verificationReason") or ""
        session_ok = False

        # ИСПРАВЛЕНИЕ 2026-09-18 (проверено по исходникам mozilla/fxa, main):
        #  1) POST /v1/session/verify/totp (lib/routes/totp.js) аутентифицирует
        #     сессию стратегиями ['sessionTokenBearer', 'sessionToken'] и НЕ
        #     смотрит на sessionToken.verificationMethodValue: по валидному
        #     коду он вызывает db.verifyTokensWithMethod(token.id, 'totp-2fa')
        #     и помечает сессию верифицированной (AAL2). Значит, TOTP-
        #     верификация работает, даже когда /account/login вернул
        #     verificationMethod 'email'/'email-otp' (sign-in confirmation
        #     для «нового устройства/IP», verificationReason 'login').
        #  2) Обратный путь — код из письма (POST /v1/session/verify_code,
        #     lib/routes/session.js) — для аккаунтов с включённым TOTP
        #     заблокирован на сервере намеренно: сервер бросает
        #     insufficientAal(), чтобы TOTP-аккаунт не мог верифицировать
        #     сессию на AAL1 через email-код. «Подтверждение по email» для
        #     2FA-аккаунтов — тупиковая ветка по построению сервера.
        #  Вывод: при наличии TOTP-секрета (или интерактивного ввода кода)
        #     пробуем /session/verify/totp ВСЕГДА, независимо от заявленного
        #     сервером метода. Исключение — неподтверждённый аккаунт
        #     (verificationReason 'signup'): там нужно верифицировать сам
        #     email, TOTP не поможет.
        try_totp = (vr != "signup" and email_verified is not False
                    and (totp_provider is not None or interactive))
        if try_totp or vm in ("totp-2fa", "totp"):
            if vm and vm not in ("totp-2fa", "totp"):
                print(f"ℹ️  Сервер запросил подтверждение входа методом '{vm}' "
                      f"(причина: {vr or 'login'}). Для TOTP-аккаунтов сервер "
                      f"принимает /session/verify/totp независимо от заявленного "
                      f"метода — пробую TOTP.")
            for attempt in range(3):
                if totp_provider is not None:
                    raw = totp_provider()
                elif interactive:
                    raw = input("🔐 Код двухфакторной аутентификации (TOTP): ").strip()
                else:
                    raise MozVpnError("❌ Аккаунт требует 2FA, а TOTP-секрет неизвестен. "
                                      "Запустите с --qr <картинка> или --totp-secret.")
                code = re.sub(r"[\s\-]+", "", raw)   # "226 829" -> "226829"
                if not code.isdigit():
                    print("⚠️  Код должен состоять только из цифр.")
                    continue
                url = FXA_AUTH + "/session/verify/totp"
                body = json.dumps({"code": code}).encode()
                s2, d2 = req("POST", url, {"code": code},
                             bearer_session(d["sessionToken"]))
                if (s2 == 401 and d2.get("errno") == 110):
                    # Bearer не принят (лаг/откат деплоя) — фолбэк на полноценный Hawk
                    s2, d2 = req("POST", url, {"code": code},
                                 hawk_session(d["sessionToken"], "POST",
                                              "/v1/session/verify/totp", body))
                if s2 == 200 and d2.get("success"):
                    session_ok = True
                    break
                # errno 155 = TOTP_TOKEN_NOT_FOUND: на аккаунте TOTP НЕ
                # включён — TOTP-верификация невозможна по определению,
                # дальше пробовать бессмысленно, уходим в ветку email.
                if s2 == 400 and d2.get("errno") == 155:
                    print("ℹ️  У аккаунта на сервере TOTP не включён "
                          "(TOTP_TOKEN_NOT_FOUND) — TOTP-верификация невозможна.")
                    break
                if s2 == 200:
                    # Сервер отклонил значение кода. Не шлём тот же код в том
                    # же окне — дожидаемся следующего и генерируем свежий
                    # (время заодно пересинхронизируется ответом сервера).
                    if attempt < 2:
                        off = time_offset()
                        hint = (f" Смещение часов: {off:+.1f} с." if abs(off) >= 3
                                else " Часы в норме.")
                        print("⚠️  Сервер отклонил код. Проверьте, что секрет "
                              "совпадает с приложением-аутентификатором (в т.ч. "
                              "не пересоздавался ли 2FA после сохранения QR)."
                              + hint + " Жду следующее окно ...")
                        wait_next_totp_window(period)
                    else:
                        raise MozVpnError("❌ Код 2FA не подошёл три раза подряд "
                                          "(в разных временных окнах). Сверьте "
                                          "TOTP-секрет с приложением: перезапустите "
                                          "с --qr <свежий QR> — возможно, 2FA "
                                          "пересоздавался, и qr.png устарел.")
                else:
                    raise MozVpnError(f"❌ Ошибка проверки 2FA ({s2}): {d2} "
                                      "(проверьте sessionToken / аккаунт)")
        if not session_ok:
            if email_verified is False or vr == "signup":
                raise MozVpnError("❌ Email аккаунта не подтверждён (регистрация). "
                                  "Подтвердите email по ссылке из письма Mozilla, "
                                  "затем повторите вход.")
            if vm.startswith("email") or not vm:
                raise MozVpnError("❌ Требуется подтверждение входа по email, а у "
                                  "аккаунта не включён TOTP (иначе скрипт верифицировал "
                                  "бы сессию сам). Что делать:\n"
                                  "   1) Откройте почту, найдите письмо Mozilla\n"
                                  "      «New sign-in to Firefox» и подтвердите вход\n"
                                  "      (либо введите код из письма на accounts.firefox.com);\n"
                                  "   2) после этого повторите запуск скрипта — сессия\n"
                                  "      станет доверенной, и подтверждение больше\n"
                                  "      не потребуется;\n"
                                  "   3) либо включите TOTP в настройках аккаунта\n"
                                  "      (Two-step authentication) — тогда скрипт\n"
                                  "      обойдёт email-подтверждение полностью;\n"
                                  "   4) либо войдите в браузере Firefox и запустите\n"
                                  "      скрипт с --session-token <hex>.")
            raise MozVpnError(f"❌ Сессия не подтверждена (метод: {vm or 'неизвестен'}, "
                              f"причина: {vr}).")
    return d["sessionToken"]

def oauth_token(session_token: str) -> str:
    """OAuth access token через grant_type=fxa-credentials.

    Проверено по mozilla/fxa main (2026-09-17), routes/oauth/token.js:
      - grant 'fxa-session-token' УДАЛЁН -> 400 errno 109 (бывшая ошибка скрипта);
      - валидные grant_type: authorization_code | refresh_token |
        fxa-credentials | urn:ietf:params:oauth:grant-type:token-exchange;
      - роут POST /v1/oauth/token на AUTH-сервере принимает fxa-credentials
        с авторизацией sessionToken (Authorization: Bearer fxs_<tokenID>),
        assertion строится на сервере (makeAssertionJWT) — клиенту не нужна
        ключевая материал аккаунта;
      - клиент должен иметь canGrant=true и publicClient=true — у
        Firefox Desktop (5882386c6d801776) оба флага выставлены.

    ИСПРАВЛЕНИЕ 2026-09-17 (причина HTTP 403 от Guardian):
      scope должен быть ПАРОЙ «profile + VPN-scope». Проверенная рабочая
      комбинация (открытая реализация того же флоу, refresh_tokens.py):
          "profile https://identity.mozilla.com/apps/vpn"
      Без «profile» Guardian не может подтвердить энтайтлмент и отвечает
      403 no_entitlement. Фолбэк — то же с legacy-именем VPN-скоупа
      «apps/mozillavpn» (тоже с profile).

    При errno 114 (invalid scopes) пробуем следующий scope из списка.
    Бросает MozVpnError (в т.ч. при протухшем sessionToken — errno 110/106/125)."""
    last_err = None
    for scope in OAUTH_SCOPES:
        status, d = req("POST", FXA_AUTH + "/oauth/token",
                        {"grant_type": "fxa-credentials",
                         "client_id": FXA_CLIENT_ID,
                         "scope": scope,
                         "access_type": "online"},
                        bearer_session(session_token))
        if status == 200 and d.get("access_token"):
            if scope != OAUTH_SCOPES[0]:
                print(f"ℹ️  Основной scope отклонён сервером, использован '{scope}'.")
            return d["access_token"]
        last_err = (status, d)
        if status == 400 and d.get("errno") == 114:
            print(f"⚠️  Scope '{scope}' не разрешён (errno 114), пробую следующий ...")
            continue
        if status == 401 and d.get("errno") == 110:
            raise MozVpnError("❌ sessionToken недействителен/истёк (errno 110) — "
                              "требуется перелогин.")
        if status == 400 and d.get("errno") in (106, 125):
            raise MozVpnError("❌ sessionToken недействителен/заблокирован — "
                              "требуется перелогин.")
        raise MozVpnError(f"❌ OAuth-токен не получен ({status}): {d}")
    raise MozVpnError(f"❌ OAuth: все scope отклонены сервером (errno 114). Последняя ошибка: {last_err}")

def oauth_destroy(access_token: str):
    """Best-effort отзыв OAuth access token после получения proxyPass."""
    try:
        req("POST", FXA_OAUTH + "/destroy", {"token": access_token})
    except Exception:
        pass

# ---------------- Guardian ----------------

def guardian_headers(access_token: str) -> dict:
    """Заголовки Guardian в форме десктопного Firefox (проверено 2026-09-17):
    Accept/Content-Type: application/json + no-cache на token/usage/status/
    activate запросах."""
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

def guardian_pass(oauth: str):
    """POST /api/v1/fpn/activate (direct token activation, как в Firefox)
    -> GET /api/v1/fpn/token (ProxyPass JWT).
    Возвращает (token, until, headers_dict). Бросает MozVpnError."""
    auth = guardian_headers(oauth)

    # enroll — как IPPFxaActivateAuthProvider.sys.mjs в Firefox
    # («direct token activation flow by calling Guardian's POST /api/v1/fpn/
    # activate endpoint with the FxA Bearer token»).
    s1, d1 = req("POST", GUARDIAN + "/api/v1/fpn/activate", headers=auth)
    if s1 in (200, 201, 204):
        print(f"✅ Guardian: enroll выполнен (HTTP {s1}).")
    else:
        print(f"⚠️  /fpn/activate → HTTP {s1} {str(d1)[:120]} (продолжаю: токен "
              f"Guardian выдаёт и без enroll'а)")

    # ProxyPass JWT
    r = urllib.request.Request(GUARDIAN + "/api/v1/fpn/token",
                               headers=auth, method="GET")
    try:
        with _OPENER.open(r, timeout=30) as resp:
            _note_server_date(resp.headers)
            raw = resp.read()
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            status = resp.status
    except urllib.error.HTTPError as e:
        _note_server_date(e.headers)
        raw = e.read()
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        status = e.code
    try:
        d = json.loads(raw) if raw else {}
    except ValueError:
        d = {}

    if status != 200:
        detail = ""
        if isinstance(d, dict):
            detail = d.get("error") or d.get("message") or json.dumps(d)[:200]
        if status == 403:
            raise MozVpnError("❌ proxyPass не получен (HTTP 403, no_entitlement).\n"
                     "   Это НЕ ошибка входа: OAuth-токен принят, но у аккаунта\n"
                     "   нет энтайтлмента Firefox IP Protection (Built-in VPN).\n"
                     "   Возможные причины и что делать:\n"
                     "   1) Функция ещё не включена в вашем браузере: откройте\n"
                     "      Firefox 149+ → значок VPN на тулбаре → включите один\n"
                     "      раз до состояния «зелёный индикатор» (первое включение\n"
                     "      подключает энтайтлмент к аккаунту).\n"
                     "   2) Built-in VPN beta выкатывается по регионам (на\n"
                     "      2026-09: US/UK/DE/FR). Если вы вне списка — 403\n"
                     "      останется независимо от скрипта.\n"
                     "   3) Если вход в Mozilla-аккаунт был через Google/Apple\n"
                     "      или аккаунт новый — дождитесь полной активации\n"
                     "      аккаунта и повторите.")
        if status == 401:
            raise MozVpnError("❌ proxyPass не получен (HTTP 401, reauth_required): "
                              "сессия/FxA-токен отклонены Guardian'ом — требуется перелогин.")
        if status == 429:
            retry = hdrs.get("retry-after", "?")
            raise MozVpnError(f"❌ proxyPass не получен (HTTP 429): квота исчерпана, "
                              f"повторите через {retry} с.")
        if status == 451:
            raise MozVpnError("❌ proxyPass не получен (HTTP 451): регион недоступен.")
        raise MozVpnError(f"❌ proxyPass не получен (HTTP {status}): {detail or 'пустой ответ'}")
    token = d.get("token")
    if not token:
        raise MozVpnError(f"❌ В ответе Guardian нет поля 'token': {str(d)[:200]}")
    return token, d.get("until"), hdrs

def print_quota(hdrs: dict):
    """Печатает квоту из заголовков X-Quota-* ответа Guardian."""
    if not hdrs:
        return
    if hdrs.get("x-quota-unlimited", "").lower() == "true":
        print("📊 Квота: безлимитная (x-quota-unlimited: true).")
        return
    limit = hdrs.get("x-quota-limit")
    remaining = hdrs.get("x-quota-remaining")
    reset = hdrs.get("x-quota-reset")
    if limit is not None and remaining is not None:
        print(f"📊 Квота: осталось {remaining} из {limit}"
              + (f", сброс: {reset}" if reset else "") + ".")

# ---------------- server list ----------------

# --- filter_expression (JEXL-подмножество) для коллекции vpn-serverlist ---
_VER_FILTER = re.compile(
    r'^env\.version\|versionCompare\("([0-9A-Za-z.]+)"\)\s*(>=|<=|==|!=|>|<)\s*0$')
_COUNTRY_FILTER = re.compile(r'^env\.country\s*(==|!=)\s*"([A-Za-z]{2,3})"$')

def _version_key(value: str):
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+))?\s*", value, re.I)
    if not m:
        return ((0,), 3, 0)
    nums = tuple(int(p) for p in m.group(1).split("."))
    rank = {"a": 0, "b": 1, "rc": 2}.get((m.group(2) or "").lower(), 3)
    return (nums, rank, int(m.group(3) or 0))

def _version_cmp(left: str, right: str) -> int:
    ln, lr, lp = _version_key(left)
    rn, rr, rp = _version_key(right)
    w = max(len(ln), len(rn))
    ln += (0,) * (w - len(ln)); rn += (0,) * (w - len(rn))
    return ((ln, lr, lp) > (rn, rr, rp)) - ((ln, lr, lp) < (rn, rr, rp))

def filter_ok(expression, firefox_version: str, client_country: str) -> bool:
    """Безопасное подмножество JEXL из vpn-serverlist. Неизвестное выражение
    -> False (fail closed), чтобы не получить несовместимые с клиентом ноды."""
    if not expression or not str(expression).strip():
        return True
    for term in (p.strip() for p in str(expression).split("&&")):
        m = _VER_FILTER.fullmatch(term)
        if m:
            c = _version_cmp(firefox_version, m.group(1))
            ok = {">=": c >= 0, "<=": c <= 0, "==": c == 0,
                  "!=": c != 0, ">": c > 0, "<": c < 0}[m.group(2)]
        else:
            m = _COUNTRY_FILTER.fullmatch(term)
            if not m:
                return False
            eq = client_country.upper() == m.group(2).upper()
            ok = eq if m.group(1) == "==" else not eq
        if not ok:
            return False
    return True

def server_entry(srv: dict) -> dict | None:
    """Нормализация одной ноды vpn-serverlist. None = непригодна."""
    host = (srv.get("hostname") or "").strip()
    try:
        port = int(srv.get("port") or 443)
    except (TypeError, ValueError):
        port = 443
    proto = phost = pport = pscheme = tmpl = None
    protocols = srv.get("protocols") or []
    for p in protocols:
        if not isinstance(p, dict):
            continue
        if (p.get("name") or "").lower() == "connect":
            proto = "connect"
            phost = p.get("host") or p.get("hostname") or host
            pport = p.get("port") or port
            pscheme = p.get("scheme") or "https"
            tmpl = p.get("templateString")
            break
    if proto is None:
        if protocols and isinstance(protocols[0], dict):
            # MASQUE-only нода: отдаём как unsupported (CONNECT не заявлен)
            p = protocols[0]
            proto = p.get("name") or "unknown"
            phost = p.get("host") or p.get("hostname") or host
            pport = p.get("port") or port
            pscheme = p.get("scheme") or "https"
        else:
            proto = srv.get("protocol") or "connect"
            phost = host
            pport = port
            pscheme = srv.get("scheme") or "https"
    try:
        pport = int(pport)
    except (TypeError, ValueError):
        return None
    if not phost or not (1 <= pport <= 65535):
        return None
    return {"hostname": host or phost,
            "port": port,
            "protocol": proto,
            "protocolHost": phost,
            "protocolPort": pport,
            "scheme": pscheme,
            "templateString": tmpl,
            "quarantined": bool(srv.get("quarantined"))}

def build_city(city: dict) -> dict:
    servers = [e for e in (server_entry(s) for s in city.get("servers", []))
               if e and not e["quarantined"] and e["protocol"] == "connect"]
    return {"cityName": city.get("name"), "cityCode": city.get("code"),
            "serverCount": len(servers), "servers": servers}

def normalize_serverlist(records, firefox_version: str,
                         client_country: str, include_locked: bool):
    """Коллекция vpn-serverlist: записи {code,name,cities,filter_expression,
    locked} (+ запись REC с рекомендованным выходом)."""
    countries, recommended = {}, None
    for r in records:
        if not isinstance(r, dict):
            continue
        cc = (r.get("code") or "").upper()
        if not cc:
            continue
        if not filter_ok(r.get("filter_expression"), firefox_version, client_country):
            continue
        locked = bool(r.get("locked"))
        if locked and not include_locked:
            continue
        cities_out = {}
        for city in r.get("cities") or []:
            if not isinstance(city, dict):
                continue
            if (locked or bool(city.get("locked"))) and not include_locked:
                continue
            b = build_city(city)
            if b["servers"]:
                cities_out[city.get("code")] = b
        if cc == "REC":
            if cities_out:
                first = next(iter(cities_out.values()))
                recommended = {"countryCode": "REC",
                               "countryName": "Recommended",
                               "cityName": first["cityName"],
                               "cityCode": first["cityCode"],
                               "servers": [s for c in cities_out.values()
                                           for s in c["servers"]]}
            continue
        c = countries.setdefault(cc, {
            "countryCode": cc,
            "countryName": r.get("name") or cc,
            "locked": locked,
            "cities": {}})
        c["cities"].update(cities_out)
    locations = [{"countryCode": c["countryCode"], "countryName": c["countryName"],
                  "locked": c["locked"],
                  "cities": list(c["cities"].values())}
                 for c in countries.values()]
    locations = [l for l in locations if l["cities"]]
    locations.sort(key=lambda l: l["countryCode"])
    return locations, recommended

def normalize_classic(countries):
    """Фолбэк: Guardian /api/v2/servers (публичная схема Mozilla VPN)."""
    locations = []
    for c in countries:
        cities = []
        for city in c.get("cities", []):
            entry = {"cityName": city.get("name"), "cityCode": city.get("code"),
                     "servers": city.get("servers", [])}
            b = build_city(entry)
            if b["servers"]:
                cities.append(b)
        if cities:
            locations.append({"countryCode": c.get("code"), "countryName": c.get("name"),
                              "locked": bool(c.get("locked")), "cities": cities})
    return locations, None

def fetch_serverlist(firefox_version: str = DEFAULT_FIREFOX_VERSION,
                     client_country: str = "",
                     include_locked: bool = False):
    s, d = req("GET", RS_SERVERLIST)
    if s == 200 and d.get("data"):
        return normalize_serverlist(d["data"], firefox_version,
                                    client_country, include_locked)
    s, d = req("GET", GUARDIAN + "/api/v2/servers")           # fallback, публичный
    if s == 200:
        return normalize_classic(d.get("countries", []))
    raise MozVpnError("❌ Список серверов не загружен ни из Remote Settings (vpn-serverlist), "
                      "ни от Guardian (/api/v2/servers).")

def select_locations(locations, recommended, country=None, city=None):
    """Фильтрация локаций по --country/--city (как в оригинале)."""
    out = locations
    if country:
        out = [l for l in out
               if country.lower() in (l["countryCode"].lower(), (l["countryName"] or "").lower())]
    res = []
    for l in out:
        l2 = dict(l)
        if city:
            l2["cities"] = [c for c in l2["cities"]
                            if city.lower() in ((c["cityName"] or "").lower())]
        if l2["cities"]:
            res.append(l2)
    return res

# ---------------- локальные прокси на proxy.py (вместо sing-box) ----------------

def port_for_location(country_code: str, city_code: str, used: set) -> int:
    """Детерминированный порт 20000..39999 от локации (SHA-256)."""
    key = f"{country_code}|{city_code or ''}"
    h = int(hashlib.sha256(key.encode()).hexdigest(), 16)
    port = LOCAL_PORT_BASE + h % LOCAL_PORT_RANGE
    while port in used:
        port = LOCAL_PORT_BASE + (port - LOCAL_PORT_BASE + 1) % LOCAL_PORT_RANGE
    used.add(port)
    return port

def port_is_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()

# Плагин для proxy.py: локальный HTTP-прокси -> TLS к апстрим-прокси Mozilla
# -> CONNECT/plain-запрос с Proxy-Authorization: Bearer <proxyPass>.
# Написан по образцу встроенного ProxyPoolPlugin (тот же официальный API:
# TcpUpstreamConnectionHandler + HttpProxyBasePlugin), дополнения:
#   - TLS к апстриму через TcpServerConnection.wrap() (Mozilla требует TLS);
#   - заголовок Bearer вместо Basic (ProxyPoolPlugin умеет только user:pass);
#   - выбор апстрима по ЛОКАЛЬНОМУ порту клиентского подключения (один процесс
#     proxy.py обслуживает все города через --ports);
#   - токен перечитывается из JSON-файла при каждом запросе (mtime-кэш),
#     поэтому ротация proxyPass НЕ требует перезапуска процесса.
PYPROXY_PLUGIN_SOURCE = r'''
"""mozvpn-прокси: плагин proxy.py (https://pypi.org/project/proxy.py/).

Локальный HTTP-прокси -> TLS к апстрим-прокси Mozilla VPN -> CONNECT с
Proxy-Authorization: Bearer <proxyPass>. Файл генерируется mozvpn.py.
"""
import json
import logging
import os
import threading
from typing import Optional

from proxy.core.base import TcpUpstreamConnectionHandler
from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser
from proxy.http.exception import HttpProtocolException

logger = logging.getLogger(__name__)

_MAP_LOCK = threading.Lock()
_MAP_CACHE = None
_MAP_MTIME = 0.0


def _load_map(path):
    """JSON-мап {token, upstreams: {local_port: [host, port]}} с mtime-кэшем."""
    global _MAP_CACHE, _MAP_MTIME
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return _MAP_CACHE or {}
    with _MAP_LOCK:
        try:
            if _MAP_CACHE is None or mtime != _MAP_MTIME:
                with open(path, "r", encoding="utf-8") as f:
                    _MAP_CACHE = json.load(f)
                _MAP_MTIME = mtime
        except Exception:
            if _MAP_CACHE is None:
                _MAP_CACHE = {}
    return _MAP_CACHE or {}


class MozVpnUpstreamPlugin(TcpUpstreamConnectionHandler, HttpProxyBasePlugin):
    """По одному апстриму Mozilla на локальный порт (мап в MOZVPN_MAP_FILE)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._map_file = os.environ.get("MOZVPN_MAP_FILE", "")

    def _local_port(self) -> int:
        # Локальный порт, на который подключился клиент — ключ выбора апстрима.
        return self.client.connection.getsockname()[1]

    def _upstream_for(self, local_port: int):
        m = _load_map(self._map_file) if self._map_file else {}
        return (m.get("upstreams") or {}).get(str(local_port))

    def _current_token(self) -> str:
        m = _load_map(self._map_file) if self._map_file else {}
        return m.get("token") or ""

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        # Своя апстрим-соединение: TCP + TLS к прокси Mozilla. Возвращаем None,
        # чтобы движок proxy.py НЕ устанавливал своё соединение к целевому хосту.
        local_port = self._local_port()
        upstream = self._upstream_for(local_port)
        if not upstream:
            raise HttpProtocolException(
                "mozvpn: нет апстрима для локального порта %d" % local_port)
        host, port = str(upstream[0]), int(upstream[1])
        self.initialize_upstream(host, port)
        assert self.upstream
        try:
            self.upstream.connect()
            # TLS handshake (внутри wrap — блокирующий), затем non-blocking режим
            self.upstream.wrap(hostname=host, as_non_blocking=True)
        except TimeoutError:
            raise HttpProtocolException(
                "mozvpn: таймаут подключения к апстриму %s:%d" % (host, port))
        except ConnectionRefusedError:
            raise HttpProtocolException(
                "mozvpn: апстрим %s:%d отклонил подключение" % (host, port))
        except Exception as e:
            raise HttpProtocolException(
                "mozvpn: ошибка TLS к апстриму %s:%d: %r" % (host, port, e))
        logger.debug("mozvpn: TLS к апстриму %s:%d установлен", host, port)
        return None

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        """Первый (инициирующий) запрос: подписываем Bearer и отправляем апстриму.
        Для CONNECT дальнейший обмен идёт сырым туннелем через
        handle_client_data/handle_upstream_data."""
        if not self.upstream:
            return request
        token = self._current_token()
        if not token:
            raise HttpProtocolException("mozvpn: proxyPass-токен ещё не записан")
        if request.has_header(b"proxy-authorization"):
            request.del_headers([b"proxy-authorization"])
        request.add_header(b"proxy-authorization", b"Bearer " + token.encode("ascii"))
        if not request.is_https_tunnel:
            # Плоские HTTP-запросы: без keep-alive к апстриму, чтобы каждый
            # запрос заново шёл с авторизацией (токен ротируется ~раз/10 мин).
            if request.has_header(b"connection"):
                request.del_headers([b"connection"])
            request.add_header(b"connection", b"close")
        self.upstream.queue(memoryview(request.build(for_proxy=True)))
        return request

    def handle_client_data(self, raw: memoryview) -> Optional[memoryview]:
        """Сырые данные клиента (тело туннеля CONNECT / следующие запросы)."""
        if not self.upstream:
            return None
        self.upstream.queue(raw)
        return raw

    def handle_upstream_data(self, raw: memoryview) -> None:
        """Сырые данные апстрима -> клиенту (в т.ч. «200 Connection established»)."""
        self.client.queue(raw)

    def handle_upstream_chunk(self, chunk: memoryview) -> Optional[memoryview]:
        # Не вызывается: соединение к апстриму принадлежит плагину.
        return chunk

    def on_upstream_connection_close(self) -> None:
        if self.upstream and not self.upstream.closed:
            logger.debug("mozvpn: закрытие соединения к апстриму")
            self.upstream.close()
            self.upstream = None
'''

class PyProxyManager:
    """Поднимает/обновляет локальные HTTP-прокси на движке proxy.py:
    один процесс `python -m proxy` на ВСЕ города (флаг --ports). Токен
    обновляется перезаписью JSON-мапа — без рестарта процесса."""

    def __init__(self, args):
        self.args = args
        self.proc = None
        self.proxies = []     # [{port, country, countryCode, city, cityCode, host, upstreamPort, label}]
        self._upstreams = {}  # {str(port): [host, port]}
        try:
            import importlib.util
            if importlib.util.find_spec("proxy") is None:
                raise ImportError
        except ImportError:
            raise MozVpnError("❌ Не установлен пакет proxy.py (движок локальных прокси):\n"
                              "    pip install proxy.py")

    def _write_plugin(self):
        os.makedirs(PYPROXY_DIR, exist_ok=True)
        old = None
        try:
            with open(PYPROXY_PLUGIN, "r", encoding="utf-8") as f:
                old = f.read()
        except OSError:
            pass
        if old != PYPROXY_PLUGIN_SOURCE:
            with open(PYPROXY_PLUGIN, "w", encoding="utf-8") as f:
                f.write(PYPROXY_PLUGIN_SOURCE)

    def _write_map(self, token: str):
        os.makedirs(PYPROXY_DIR, exist_ok=True)
        data = json.dumps({"token": token, "upstreams": self._upstreams})
        tmp = PYPROXY_MAP + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data)
        _chmod600(tmp)
        # os.replace не атомарен относительно читающего плагина на Windows —
        # при конфликте доступа повторяем несколько раз.
        for attempt in range(5):
            try:
                os.replace(tmp, PYPROXY_MAP)
                break
            except OSError:
                if attempt == 4:
                    raise
                time.sleep(0.2)
        _chmod600(PYPROXY_MAP)

    def build_proxies(self, locations, token: str):
        """Формирует список прокси и пишет мап (порты — по хэшу локации)."""
        used, proxies, upstreams = set(), [], {}
        max_p = self.args.max_proxies or 0
        n = 0
        for loc in locations:
            for city in loc["cities"]:
                srv = next((s for s in city["servers"] if s["protocol"] == "connect"), None)
                if srv is None:
                    continue
                port = port_for_location(loc["countryCode"], city.get("cityCode") or "", used)
                label = f"{loc['countryName']}/{city['cityName']}"
                upstreams[str(port)] = [srv["protocolHost"], srv["protocolPort"]]
                proxies.append({"port": port, "country": loc["countryName"],
                                "countryCode": loc["countryCode"],
                                "city": city["cityName"], "cityCode": city.get("cityCode"),
                                "host": srv["protocolHost"],
                                "upstreamPort": srv["protocolPort"],
                                "label": label})
                n += 1
                if max_p and n >= max_p:
                    break
            if max_p and n >= max_p:
                break
        self.proxies = proxies
        self._upstreams = upstreams
        self._write_plugin()
        self._write_map(token)
        return proxies

    def start_all(self):
        """Запускает один процесс proxy.py на все свободные порты."""
        free, busy = [], []
        for p in self.proxies:
            (free if port_is_free(p["port"]) else busy).append(p)
        for p in busy:
            print(f"⚠️  Порт {p['port']} занят — пропускаю {p['label']} "
                  f"(занят чужим процессом?).")
        if not free:
            raise MozVpnError("❌ Нет свободных портов для локальных прокси.")
        env = dict(os.environ, MOZVPN_MAP_FILE=PYPROXY_MAP)
        cmd = [sys.executable, "-m", "proxy",
               "--hostname", "127.0.0.1",
               "--ports", *[str(p["port"]) for p in free],
               "--threaded",                       # thread/conn — блокирующий
               "--num-workers", "1",               # TLS-handshake в плагине
               "--num-acceptors", "1",             # не мешает соседним портам
               "--timeout", "600",                 # idle-туннели живут 10 мин
               "--log-level", "WARNING",
               "--log-file", PYPROXY_LOG,
               "--plugins", "mozvpn_proxy_plugin.MozVpnUpstreamPlugin"]
        self.proc = subprocess.Popen(cmd, cwd=PYPROXY_DIR, env=env,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        # Дожидаемся, пока порты начнут слушать (или процесс умрёт).
        deadline = time.time() + 15
        failed = []
        for p in free:
            while time.time() < deadline:
                if self.proc.poll() is not None:
                    break
                if not port_is_free(p["port"]):
                    break
                time.sleep(0.2)
            if port_is_free(p["port"]):
                failed.append(p)
        if self.proc.poll() is not None:
            raise MozVpnError(f"❌ proxy.py завершился сразу (код {self.proc.returncode}). "
                              f"См. лог: {PYPROXY_LOG}")
        if failed:
            ports = ", ".join(str(p["port"]) for p in failed)
            print(f"⚠️  Порты не поднялись: {ports} (см. лог {PYPROXY_LOG}).")
        print(f"🚀 proxy.py поднят (pid {self.proc.pid}): {len(free) - len(failed)} "
              f"прокси на 127.0.0.1, лог: {PYPROXY_LOG}")
        for p in free:
            if p in failed:
                continue
            print(f"   127.0.0.1:{p['port']}  {p['label']:<28} -> "
                  f"{p['host']}:{p['upstreamPort']}")

    def update_token(self, token: str):
        """Перезапись токена в JSON-мапе. Плагин перечитает его при следующем
        запросе (mtime-кэш) — рестарт процесса НЕ нужен. Действующие туннели
        со старым токеном завершатся по exp proxyPass, клиенты переподключатся."""
        self._write_map(token)
        print("🔁 proxy.py: записан новый proxyPass (применится к новым "
              "подключениям без рестарта).")

    def check_running(self):
        """Перезапуск, если процесс proxy.py не поднят или умер."""
        if not self.proxies:
            return
        if self.proc is not None and self.proc.poll() is None:
            return
        if self.proc is not None:
            print(f"⚠️  proxy.py завершился (код {self.proc.returncode}) — "
                  f"перезапускаю ...")
            self.proc = None
        try:
            self.start_all()
        except MozVpnError as e:
            print(e)

    def stop_all(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            print("🛑 proxy.py остановлен.")
            self.proc = None

# ---------------- оркестрация: сессия -> токен ----------------

def ensure_session(args, creds, totp_provider, interactive=True, force_relogin=False) -> str:
    """sessionToken: аргумент -> кэш -> перелогин по сохранённым реквизитам.
    Бросает MozVpnError, если войти невозможно."""
    session_token = args.session_token
    email = args.email or creds.get("email")

    if session_token and not all(ch in "0123456789abcdefABCDEF" for ch in session_token):
        raise MozVpnError("❌ sessionToken должен быть hex-строкой.")
    if session_token:
        session_token = session_token.lower()
        return session_token

    if not force_relogin and not args.relogin and os.path.exists(CACHE):
        try:
            c = json.load(open(CACHE))
            email = email or c.get("email")
            st = c.get("sessionToken")
            if st:
                print(f"♻️  Кэшированная сессия ({email}). --relogin для нового входа.")
                return st
        except Exception:
            pass

    # Перелогин
    email = email or (input("Email Mozilla-аккаунта: ").strip() if interactive else None)
    if not email:
        raise MozVpnError("❌ Email не задан (нет ни аргумента, ни кэша).")
    pw = args.password or creds.get("password")
    if not pw:
        if interactive:
            pw = getpass.getpass("Пароль: ")
        else:
            raise MozVpnError("❌ Пароль не задан (нет ни аргумента, ни кэша реквизитов).")
    print("🔑 Вход в Mozilla Accounts...")
    st = fxa_login(email, pw, totp_provider, interactive=interactive,
                   tp=totp_params_from(creds))
    save_cache(email, st)
    save_credentials(email=email, password=pw)
    print(f"💾 sessionToken закэширован: {CACHE}")
    return st

def obtain_proxy_pass(session_token: str):
    """Полная цепочка OAuth -> Guardian -> proxyPass. Возвращает (token, until, hdrs)."""
    print("🎫 Получение OAuth-токена (grant fxa-credentials, scope "
          "'profile https://identity.mozilla.com/apps/vpn')...")
    oauth = oauth_token(session_token)
    print("🛡️  Активация Guardian и получение proxyPass...")
    token, until, ghdrs = guardian_pass(oauth)
    oauth_destroy(oauth)   # best-effort отзыв OAuth access token
    return token, until, ghdrs

def save_result(args, token, until, session_token, email, recommended, locations, out_path=None):
    now = time.time()
    fetched_at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) \
               + f".{int(now % 1 * 1000):03d}Z"
    result = {"fetchedAt": fetched_at,
              "proxyPass": {"token": token, "validUntil": until},
              "sessionToken": session_token,
              "email": email,
              "recommended": recommended,
              "locations": locations}
    if args.no_save:
        return None
    out = out_path or args.json or os.path.join(
        SCRIPT_DIR, "mozvpn-" + time.strftime("%Y%m%d-%H%M%S", time.gmtime(now)) + ".json")
    with open(out, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"💾 JSON сохранён: {out}")
    return out

# ---------------- long-running менеджер (watch / локальные прокси) ----------------

_STOP = False
def _on_signal(signum, frame):
    global _STOP
    _STOP = True

def run_manager(args, creds, totp_provider):
    """Цикл: держит proxyPass свежим (перевыпуск за --refresh-margin сек до
    exp, перелогин при протухшем sessionToken), опционально держит локальные
    прокси proxy.py."""
    sb = None
    if args.use_sing_box:
        sb = PyProxyManager(args)
    locations, recommended = None, None
    json_out = args.json or None
    session_token, force_relogin = None, False
    relogin_backoff = 0
    totp_secret = (args.totp_secret or "").strip() or creds.get("totp_secret")

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    def cleanup():
        if sb:
            print("\n🧹 Остановка локальных прокси ...")
            sb.stop_all()
    atexit.register(cleanup)

    while not _STOP:
        try:
            session_token = ensure_session(
                args, creds, totp_provider,
                interactive=not args.no_input,
                force_relogin=force_relogin)
            force_relogin = False
            relogin_backoff = 0

            token, until, ghdrs = obtain_proxy_pass(session_token)
            exp = jwt_exp(token)
            exp_str = time.strftime("%H:%M:%S", time.gmtime(exp)) if exp else "?"
            print(f"✅ proxyPass получен, действителен до: {until} (exp {exp_str} UTC)")

            if locations is None:
                print("🌐 Загрузка списка серверов (Remote Settings: vpn-serverlist)...")
                locations_all, recommended = fetch_serverlist(
                    args.firefox_version, args.client_country, args.include_locked)
                locations = select_locations(locations_all, recommended,
                                             args.country, args.city)
                total = sum(c["serverCount"] for l in locations for c in l["cities"])
                print(f"✅ Стран: {len(locations)}, доступных серверов: {total}")

            print_quota(ghdrs)
            print_current_totp(totp_secret, creds)
            print("\n📋 Свежий proxyPass JWT:")
            print(token)

            json_out = save_result(args, token, until, session_token,
                                   args.email or creds.get("email"),
                                   recommended, locations, out_path=json_out)

            if sb:
                sb.check_running()
                if not sb.proxies:
                    sb.build_proxies(locations, token)
                    print(f"\n🌐 Локальные прокси proxy.py ({len(sb.proxies)} шт.):")
                    sb.start_all()
                else:
                    sb.update_token(token)

            # спим до exp - margin
            if not exp:
                print("⚠️  exp из JWT не извлечён — обновлю через 300 с.")
                sleep_s = 300
            else:
                sleep_s = exp - args.refresh_margin - int(time.time())
            if sleep_s < 5:
                sleep_s = 5
            print(f"⏳ Следующее обновление через {sleep_s} с "
                  f"({time.strftime('%H:%M:%S', time.gmtime(time.time() + sleep_s))} UTC). "
                  f"Ctrl+C для выхода.\n")
            # спим короткими интервалами, чтобы реагировать на Ctrl+C
            slept = 0
            while slept < sleep_s and not _STOP:
                time.sleep(2)
                slept += 2
            if _STOP:
                break

        except MozVpnError as e:
            msg = str(e)
            print(msg)
            if "перелогин" in msg or "недействителен" in msg or "истёк" in msg \
               or "reauth" in msg:
                print("🔁 Требуется перелогин — пробую по сохранённым реквизитам ...")
                force_relogin = True
                time.sleep(min(60, 5 * (relogin_backoff + 1)))
                relogin_backoff += 1
            else:
                time.sleep(30)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"⚠️  Непредвиденная ошибка: {e!r} — повторю через 30 с.")
            time.sleep(30)

    cleanup()

# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser(description="Mozilla VPN proxy credentials (Firefox IP Protection) "
                                 "+ авто-TOTP + автообновление + локальные прокси на proxy.py")
    ap.add_argument("--email",       default=os.environ.get("MOZVPN_EMAIL"))
    ap.add_argument("--password",    default=os.environ.get("MOZVPN_PASSWORD"))
    ap.add_argument("--session-token", dest="session_token",
                    default=os.environ.get("MOZVPN_SESSION_TOKEN"),
                    help="sessionToken аккаунта Mozilla — фолбэк, если Fastly challenge не решён")
    ap.add_argument("--totp",        default=os.environ.get("MOZVPN_TOTP"),
                    help="код 2FA (TOTP) вручную, иначе генерируется из секрета")
    ap.add_argument("--totp-secret", dest="totp_secret",
                    default=os.environ.get("MOZVPN_TOTP_SECRET"),
                    help="TOTP-секрет (base32) напрямую, альтернатива --qr")
    ap.add_argument("--qr", metavar="FILE",
                    help="картинка с QR-кодом TOTP: при первом запуске укажите путь — "
                         "секрет сохранится и коды будут генерироваться сами")
    ap.add_argument("--watch", action="store_true",
                    help="непрерывно обновлять proxyPass за --refresh-margin сек до истечения")
    ap.add_argument("--use-sing-box", "--use-proxy", dest="use_sing_box", action="store_true",
                    help="поднимать локальные HTTP-прокси (движок proxy.py, чистый Python, "
                         "без внешних утилит; флаг --use-sing-box сохранён для совместимости)")
    ap.add_argument("--max-proxies", type=int, default=0,
                    help="макс. число локальных прокси (0 = все города)")
    ap.add_argument("--no-input", action="store_true",
                    help="не задавать интерактивных вопросов (для автономного цикла)")
    ap.add_argument("--refresh-margin", type=int, default=45,
                    help="за сколько секунд до exp proxyPass обновлять токен (по умолчанию 45)")
    ap.add_argument("--country"); ap.add_argument("--city")
    ap.add_argument("--test", action="store_true", help="проверить прокси (внешний IP)")
    ap.add_argument("--firefox-version", default=DEFAULT_FIREFOX_VERSION,
                    help="версия Firefox для filter_expression Remote Settings (по умолчанию 156.0)")
    ap.add_argument("--client-country", default="",
                    help="код страны для env.country в filter_expression (по умолчанию не задан)")
    ap.add_argument("--include-locked", action="store_true",
                    help="включить записи/ноды, помеченные locked")
    ap.add_argument("--json", metavar="FILE", help="путь для JSON (по умолчанию — рядом со скриптом)")
    ap.add_argument("--no-save", action="store_true", help="не сохранять JSON в файл")
    ap.add_argument("--relogin", action="store_true", help="игнорировать кэш сессии")
    a = ap.parse_args()

    # --- QR -> TOTP-секрет (первый запуск) + подтверждение сверкой с приложением ---
    if a.qr:
        try:
            info = decode_qr_totp(a.qr)
        except MozVpnError as e:
            sys.exit(str(e))
        secret = info.pop("secret")
        # Защита от «молча неверного секрета» (устаревший QR, другой аккаунт,
        # пересозданный 2FA): показываем код и просим сверить с приложением.
        if not a.no_input and sys.stdin.isatty():
            try:
                code, valid = totp_generate(secret, info["digits"],
                                            info["period"], info["algorithm"])
                print(f"🔢 Код, сгенерированный из распознанного QR: {code} "
                      f"(действует ещё {valid} с)")
                ans = input("Совпадает ли он с кодом в приложении-аутентификаторе? [Y/n]: "
                            ).strip().lower()
            except MozVpnError as e:
                sys.exit(str(e))
            if ans in ("n", "no", "н", "нет"):
                manual = input("Вставьте TOTP-секрет (base32) из приложения или путь к "
                               "другой QR-картинке (Enter — отмена): ").strip()
                if not manual:
                    sys.exit("❌ Отменено: секрет из QR не совпал с приложением.\n"
                             "   Если 2FA пересоздавался — скачайте свежий QR: "
                             "accounts.firefox.com → Settings → Two-step authentication.")
                if os.path.isfile(manual):
                    try:
                        info = decode_qr_totp(manual)
                        secret = info.pop("secret")
                    except MozVpnError as e:
                        sys.exit(str(e))
                else:
                    try:
                        secret = validate_totp_secret(manual)
                    except MozVpnError as e:
                        sys.exit(str(e))
        save_credentials(email=a.email, totp_secret=secret,
                         totp_digits=info["digits"], totp_period=info["period"],
                         totp_algorithm=info["algorithm"])
        print(f"✅ TOTP-секрет сохранён в {CRED_CACHE} (mode 600); параметры: "
              f"{info['digits']} цифр, окно {info['period']} с, {info['algorithm']}.")
        print("   Коды 2FA генерируются автоматически (pyotp) по времени серверов Mozilla.")

    creds = load_credentials()
    if a.email:
        save_credentials(email=a.email)
    if a.password:
        save_credentials(password=a.password)
        creds = load_credentials()
    if a.totp_secret:
        try:
            save_credentials(totp_secret=validate_totp_secret(a.totp_secret))
        except MozVpnError as e:
            sys.exit(str(e))
        creds = load_credentials()

    totp_provider = make_totp_provider(a, creds)

    if a.use_sing_box or a.watch:
        run_manager(a, creds, totp_provider)
        return

    # -------- one-shot режим (как раньше) --------
    try:
        session_token = ensure_session(a, creds, totp_provider, interactive=True)
        token, until, ghdrs = obtain_proxy_pass(session_token)
        exp = jwt_exp(token)
        print(f"✅ proxyPass получен, действителен до: {until}"
              + (f" (exp {time.strftime('%H:%M:%S', time.gmtime(exp))} UTC)" if exp else ""))
        print("🌐 Загрузка списка серверов (Remote Settings: vpn-serverlist)...")
        locations_all, recommended = fetch_serverlist(a.firefox_version,
                                                      a.client_country,
                                                      a.include_locked)
        locations = select_locations(locations_all, recommended, a.country, a.city)
        total = sum(c["serverCount"] for l in locations for c in l["cities"])
        print(f"✅ Стран: {len(locations)}, доступных серверов: {total}\n")
        print_quota(ghdrs)
        print_current_totp((a.totp_secret or "").strip() or creds.get("totp_secret"), creds)
    except MozVpnError as e:
        sys.exit(str(e))

    now = time.time()
    result = {"fetchedAt": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
               + f".{int(now % 1 * 1000):03d}Z",
              "proxyPass": {"token": token, "validUntil": until},
              "sessionToken": session_token,
              "email": a.email or creds.get("email"),
              "recommended": recommended,
              "locations": locations}

    def print_server(s):
        print(f"    curl -x https://{s['protocolHost']}:{s['protocolPort']} "
              f'--proxy-header "Proxy-Authorization: Bearer {token}" '
              f"https://ifconfig.me")

    if recommended:
        print(f"⭐ Рекомендованный сервер: {recommended['countryName']} / "
              f"{recommended['cityName']}")
        for s in recommended["servers"]:
            print_server(s)
        print()

    for l in locations:
        for c in l["cities"]:
            for s in c["servers"]:
                line = (f"{l['countryCode']:<3} {l['countryName'][:15]:<15} "
                        f"{(c['cityName'] or '')[:15]:<15} {(s['protocol'] or '-')[:8]:<8} "
                        f"{(s['scheme'] or '-'):<6} {s['protocolHost']}:{s['protocolPort']}")
                print(line + ("  [locked]" if l["locked"] else ""))
                if s["protocol"] == "connect":
                    print_server(s)

    print("\n📋 Bearer-токен (proxyPass JWT):")
    print(token)
    print("\n🔑 sessionToken (для повторных запусков):")
    print(session_token)

    if not a.no_save:
        out = a.json or os.path.join(SCRIPT_DIR, "mozvpn-"
                    + time.strftime("%Y%m%d-%H%M%S", time.gmtime(now)) + ".json")
        with open(out, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n💾 JSON сохранён: {out}")

    if a.test:
        candidates = ([s for s in (recommended or {}).get("servers", [])]
                      + [s for l in locations for c in l["cities"] for s in c["servers"]])
        for s in candidates:
            if s["protocol"] != "connect":
                continue
            print(f"\n🧪 Тест {s['protocolHost']}:{s['protocolPort']} ...")
            r = subprocess.run(
                ["curl", "-sS", "-m", "20", "-x", f"https://{s['protocolHost']}:{s['protocolPort']}",
                 "--proxy-header", f"Proxy-Authorization: Bearer {token}",
                 "https://ifconfig.me"], capture_output=True, text=True)
            print("   Внешний IP:", (r.stdout.strip() or r.stderr.strip())[:100])
            return

if __name__ == "__main__":
    main()
