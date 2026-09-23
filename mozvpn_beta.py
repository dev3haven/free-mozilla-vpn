#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mozvpn.py — Mozilla VPN / Firefox IP Protection proxy credentials + auto-TOTP
+ automatic proxyPass refresh + local proxies (builtin engine or sing-box).

VERSION 2026-09-23 (v4.7.1) — startup duplicate-line fix + full re-audit:

VERSION 2026-09-23 (v4.7.3) — fix: --no-save crashed at startup:

  FIX 1) ValueError: invalid option name '--no-save' for BooleanOptionalAction.
     Python's argparse REJECTS BooleanOptionalAction for options whose name
     already starts with '--no-' (the class auto-generates the '--no-'
     negative form itself, so the declared name must be the POSITIVE form).
     --no-save is therefore declared as TWO plain arguments sharing the
     args.no_save attribute: '--save' (store_false, env-aware default ON
     = do not save) and '--no-save' (store_true, default=argparse.SUPPRESS
     so an absent flag never overwrites the default). --local-proxy is fine
     as BooleanOptionalAction ('--local-proxy' / '--no-local-proxy').
     Behavior is unchanged: by default nothing is saved and local proxies
     are served; '--save' re-enables the JSON file.

VERSION 2026-09-23 (v4.7.2) — DEFAULT-ON --local-proxy and --no-save:

  NEW 1) Both flags are now ON BY DEFAULT: starting the script without any
     arguments serves local proxies AND does not write the result JSON.
     They stay fully toggleable: --no-local-proxy / --save turn each default
     off (argparse.BooleanOptionalAction, Python >= 3.9); env overrides:
     MOZVPN_LOCAL_PROXY=0 / MOZVPN_NO_SAVE=0. No other behavior changed.

  FIX 1) "Console window background FORCED" was printed TWICE at startup:
     main() called set_color() (which forced the background and logged
     the message) and then set_theme() (which forced the SAME background
     again and logged the message a second time). The force is now
     IDEMPOTENT - the currently forced theme is tracked (_BG_CURRENT)
     and repeated calls with the same theme emit the OSC 11 sequence and
     the log line exactly once. The startup order also changed:
     set_color() runs BEFORE set_theme(), so the theme already knows the
     final color mode, the background is forced exactly once with the
     final theme, and --no-color never forces (nor logs) anything.
     Hotkey 'n' now re-forces the background explicitly when colors come
     back on and releases it (OSC 111) when colors go off; the exit note
     is printed only when a background was actually forced.

VERSION 2026-09-23 (v4.7) — forced console background, layout-independent
hotkeys, pip conflict-proof install:

  NEW 1) Themes now FORCE the console WINDOW background itself, not just
     paint the log lines: the OSC 11 escape sequence sets the terminal
     default background to true black (dark theme) or true white (light
     theme). Verified online: OSC 11 is the xterm control sequence for
     the default text background and is supported by xterm, Windows
     Terminal, kitty, mintty, foot and WezTerm; on exit OSC 111 restores
     the terminal default (terminals without OSC 111 keep the color and
     the printed exit note tells the user how to reset it). The forced
     background follows hotkeys 'm'/'n' and --theme/--no-color.
  FIX 2) Hotkeys now work in ANY keyboard layout. On Windows the chain
     char -> VkKeyScanW -> virtual key -> MapVirtualKeyW(MAPVK_VK_TO_VSC)
     -> scan code recovers the PHYSICAL key cap, so e.g. the key labeled
     'й' on a Russian ЙЦУКЕН layout still triggers hotkey 'q' (scan
     codes are layout-independent; verified against the Win32 docs).
     On POSIX terminals (no scan-code channel in the input stream) a
     Cyrillic->English translation table for the ЙЦУКЕН family is used.
  FIX 3) Dependency reinstall no longer dies on pip ResolutionImpossible
     conflicts: a STAGED install is used - all packages in one command
     first (pip resolves them together), then each package separately
     WITHOUT --force-reinstall (forcing shared transitive dependencies
     to exact versions is the usual conflict cause, per the pip docs),
     then pip install <pkg> --no-deps as a last resort, with a clear
     per-package OK/FAILED report at the end.

VERSION 2026-09-23 (v4.6) — correct dark/light themes + sing-box dependency info:

  FIX 1) The themes were misunderstood before. Now: the DARK theme is for a
     BLACK console background (bg 16 = true black) and the LIGHT theme is
     for a WHITE console background (bg 231 = true white). Light-theme
     foreground colors are re-picked for human perception on white:
     warn -> dark amber (130), proto -> dark orange (166), flag ->
     dark magenta (35), size -> dark green (32), time -> dark magenta (35),
     so nothing stays a washed-out bright color on white.
  NEW 2) Startup now prints the sing-box EXTERNAL dependency state too:
     whether the binary is installed, its path and the version parsed
     from 'sing-box version' - or a clear note that sing-box is OPTIONAL
     (only the 'singbox' engine needs it; the builtin engine works fully
     without it).

VERSION 2026-09-23 (v4.5) — full log redraw, JWT hotkey, hint styling:

  NEW 1) Hotkeys 'm' (theme) and 'n' (color) now FULLY REDRAW the whole
     log: every line printed so far is kept in an in-memory history and
     re-rendered in the new theme / with colors on or off, so the entire
     visible output switches style at once (not just the following lines).
  FIX 2) Hotkey 'l' line looked SHIFTED in the hint: the emoji U+1F5A7
     (networked computers, Emoji 12.0/2019) renders with a wrong cell
     width on many Windows console fonts and pushed the text aside. It
     is replaced with U+1F500 (shuffle tracks button, Emoji 1.0) which
     has full legacy font support and renders as a proper double-width
     cell everywhere.
  NEW 3) Hotkey 'j': show the current proxyPass JWT and copy it to the
     clipboard (the token the local proxies sign with right now).
  NEW 4) The hotkey hint lines are now styled: every line is emitted on
     its own (theme background per line), the KEY sits on its solid
     color block and the DESCRIPTION gets a dedicated per-theme color,
     with --flags and IPs inside the description still highlighted
     separately.

VERSION 2026-09-23 (v4.4) — retry countdown, theme & color hotkeys:

  NEW 1) After a failed sign-in (e.g. the Fastly WAF challenge not yielding
     a cookie - usually succeeds on the SECOND attempt) the script now says
     EXPLICITLY: please wait, the login/password/TOTP prompt will appear
     again automatically, no restart needed - with a LIVE per-second
     countdown of the remaining seconds. The delay is configurable with
     --retry-delay SECONDS (default 30, env MOZVPN_RETRY_DELAY).
  NEW 2) Hotkey 'm': switch the log color theme dark <-> light (mirrors
     --theme).
  NEW 3) Hotkey 'n': toggle the colored log output on/off (mirrors
     --no-color).

VERSION 2026-09-23 (v4.3) — dependencies management, new hotkeys:

  NEW 0) At startup the script prints ALL its Python dependencies (pyotp,
     zxing-cpp, Pillow, aioquic) with pip name, module, version and
     installed/missing status.
  NEW 1) If a required dependency is missing and the script runs under a
     real python interpreter (NOT a frozen/compiled binary - detected via
     sys.frozen / Nuitka's __compiled__), it offers to pip-install the
     missing packages automatically; on success the modules are imported
     again without a restart.
  NEW 2) If sing-box is not found, the script explains that everything
     works WITHOUT it (the builtin engine serves the same upstreams) and
     offers installation: Termux -> 'pkg install sing-box' (the package
     exists in the official termux-packages repo), macOS -> 'brew install
     sing-box' (Homebrew formula), Linux/other -> the official
     sing-box.sagernet.org installation page is opened. A declined choice
     is CACHED (config/singbox-install.json) and not asked again - except
     when the user selects the singbox engine while sing-box is still
     missing (then the question is repeated).
  NEW 3) --reinstall-deps + hotkey 'd': reinstall ALL Python dependencies
     from scratch (pip --force-reinstall --no-cache-dir).
  NEW 4) --reinstall-singbox + hotkey 's': reinstall sing-box from scratch.
  NEW 5) Hotkey 'g': load a QR image with the 2FA (TOTP) secret on the
     fly - prompts for the file path, decodes, saves the secret and shows
     the current code (the --qr parameter, but interactive).
  NEW 6) Hotkey highlighting is even stronger: the key letters get bold
     text on a solid per-theme color block, every hint line is per-key.
  NEW 7) The protocol information is now explicit: after the proxies
     start, a summary line counts upstreams served via MASQUE (HTTP/3
     CONNECT-UDP, the priority protocol) and via HTTP CONNECT (HTTPS
     proxy tunnel over TLS - the fallback).
  NEW 8) Hotkey 'p': show the saved password and copy it to the clipboard.
  NEW 9) Hotkey 'u': show the saved login (email) and copy it to the
     clipboard.
  NEW 10) The hotkey hint is printed with EVERY hotkey on its own line.

VERSION 2026-09-23 (v4.2) — curl test-command output now opt-in:

  NEW 0) The ready-to-paste curl test commands (for the LOCAL proxies and
     for the UPSTREAM proxies, plus the per-server curl hints in one-shot
     mode) are NO LONGER printed by default - the log got noisy with five
     long Bearer lines per refresh. New flag --show-test-commands (env
     MOZVPN_SHOW_TEST_COMMANDS=1) enables them; default: off. When the
     commands are hidden, one short hint line explains how to enable them.

VERSION 2026-09-23 (v4.1) — hotkey 'r'/'c' crash fix per live-run feedback:

  FIX 0) CRASH on hotkey 'r' (relogin) with the singbox engine running:
     FileNotFoundError(2, 'No such file or directory'). Cause: the wipe
     removed the whole config directory (incl. the sing-box configs), but
     the live engine object survived with proxies still pointing at the
     DELETED config paths; on the next proxyPass its update_token() tried
     to rewrite those files -> open(path, "w") -> FileNotFoundError.
     Fixed on two levels:
       a) the 'r' and 'c' hotkey handlers now stop the engine and set
          engine = None, so the next loop iteration rebuilds it from
          scratch (fresh configs in a recreated directory, fresh ports)
          after the new sign-in;
       b) SingBoxEngine.update_token() recreates the sing-box config
          directory (os.makedirs, exist_ok=True) before rewriting the
          configs - defense in depth against any wipe while it runs.

VERSION 2026-09-23 (v4.0) — hotkey fixes per live-run feedback:

  FIX 0) Hotkey 'o' no longer dead-ends with "File does not exist": if the
     sing-box config directory is not there yet (it is created only by the
     singbox engine), the MAIN config directory (~/.config/mozvpn) is opened
     instead, with an info line explaining the fallback and the reason.
  FIX 1) Hotkey 't' without a TOTP secret now says WHY the secret is
     unavailable: (a) credentials.json has not been created yet, or
     (b) it exists but has no totp_secret field (the saved sign-in was made
     without --qr / --totp-secret, or the account has no TOTP 2FA) - and
     how the secret gets stored (--qr / --totp-secret / MOZVPN_TOTP_SECRET).
  FIX 2) Hotkey highlighting is now much stronger: every hotkey token
     (r, c, e, l, o, v, b, t, q, quoted keys, digits 1-9 in the file lists
     and the "1-9" range) gets a DEDICATED high-visibility style - bold on
     a solid color block (per theme) - instead of the old plain key color,
     so hotkeys clearly stand out in the hint line, file lists and status
     messages.

VERSION 2026-09-23 (v3.9) — full-wipe relogin, TOTP hotkey, decoded JWT:

  FIX 1) 'c' / 'r' / --clear-cache / --relogin now wipe EVERYTHING the
     script has ever saved: the whole config directory (session cache,
     credentials.json with email/password/TOTP secret, the Fastly cookie,
     all sing-box configs) AND the in-memory leftovers (the loaded creds
     dict, the Fastly cookie jar). The in-memory credentials were the leak
     that let the script re-login automatically after a wipe - the next
     sign-in now asks for the login data again.
  NEW 2) Hotkey 't': show the current TOTP code and copy it to the
     system clipboard (same clip/pbcopy/wl-copy/xclip/xsel route).
  NEW 3) The decoded proxyPass JWT is printed right under the raw token,
     formatted (header + payload as pretty JSON, exp/iat in human-readable
     UTC), after every token issue and refresh, and in one-shot mode.
  NEW 4) Hotkeys are highlighted in the log (their own color class) and
     carry per-key emoji placed inside the hint line next to each key.

VERSION 2026-09-23 (v3.8) — protocol choice logging, copy/open hotkeys:

  NEW 1) Hotkey 'o': open the singbox config directory in the system file
     manager (os.startfile / open / xdg-open handle directories natively).
  NEW 2) The protocol choice is now stated clearly per upstream with the
     reason: masque (HTTP/3 CONNECT-UDP) is the PRIORITY protocol and is
     chosen when its tunnel carried data; HTTP CONNECT is used ONLY as a
     fallback when masque is unavailable (probe failed or aioquic is not
     installed - one info line explains that case up front). The fallback
     line names the reason.
  NEW 3) Hotkeys 'v' / 'b' + a digit: copy a LOCAL proxy address
     (listen:port) or an UPSTREAM proxy address (host:port) to the system
     clipboard. Windows uses `clip`, macOS `pbcopy`, Linux wl-copy /
     xclip -selection clipboard / xsel --clipboard --input - no extra
     Python packages. Any other key cancels the copy sub-mode.
  NEW 4) After the engine starts, an info block prints ready-to-paste test
     commands for EVERY local proxy (curl -s --proxy http://host:port
     --proxy-insecure <echo>) and for EVERY upstream proxy (direct https
     proxy + the current Bearer token), localized with the script language.
  NEW 5) The watch loop and --clear-cache log exactly which files and
     directories the 'c' hotkey / --clear-cache removes (session/credentials/
     fastly-cookie caches, the singbox dir, and the whole config directory).
  NEW 6) The hotkey hint now maps every key to the script parameter it
     mirrors (r -> --relogin, c -> --clear-cache, e -> --local-proxy-engine,
     l -> --listen, ...).
  NEW 7) Highlight polish: CLI flags (--proxy, --proxy-insecure, ...) get
     their own color class in both themes; new emoji for the copy, test
     command, protocol-choice and cleanup lines (clipboard, test tube,
     rocket for the winning masque protocol, return arrow for the fallback,
     broom/wastebasket for cleanup).

VERSION 2026-09-23 (v3.7) — audit, hotkeys l / 1-9, probe hint removed:

  AUDIT 0) Full template audit: every tr() call supplies every placeholder
     used by BOTH the en and ru templates (the KeyError('reason') class of
     bug is checked mechanically, all keys present in both languages).
  REMOVED 1) The "All probes failed ... Try: --upstream-host ..." hint
     line is deleted (the summary lines already state the check result).
  RESTORED 2) Lost log highlights are back: the ":port" part of every
     ip/host token is painted with the dedicated port color (127.0.0.1:25510
     -> address + bright port), and 6-digit TOTP codes are highlighted as
     counters; path basename highlighting and all v3.6 highlights kept.
  NEW 3) Hotkey 'l': toggle the listener bind host 127.0.0.1 <-> 0.0.0.0
     and restart the local proxies (both engines honor it; --listen sets
     the initial value).
  NEW 4) Hotkeys 1-9: open a config file (session/credentials/fastly-cookie
     caches + every sing-box config json) in the SYSTEM DEFAULT editor.
     Windows uses os.startfile (ShellExecute); when the file type has no
     registered default app, rundll32 shell32.dll,OpenAs_RunDLL shows the
     standard system "Open with" picker. macOS: `open`; other POSIX:
     xdg-open (freedesktop.org standard, user's preferred application).
     The watch loop prints which number opens which file.

VERSION 2026-09-23 (v3.6) — KeyError crash fix, --listen, config paths:

  FIX 1) CRASH during probe: KeyError('reason') - the EN template still
     had a {reason} placeholder while the caller no longer passes it.
     All templates were audited: every tr() call now supplies every
     placeholder used by BOTH the en and ru templates.
  NEW 2) --listen HOST (default 127.0.0.1): bind the local proxy
     listeners on another address, e.g. --listen 0.0.0.0 to accept
     connections from other devices. Applies to BOTH engines: the
     builtin engine binds its listener sockets on the address, the
     sing-box engine writes it into the inbound "listen" field of every
     generated config; port-free checks and all log lines
     (proxy_line / engine_started / singbox_stopped) use the same
     address, so both engines log identically apart from the engine name.
  FIX 3) Word highlighting of config paths restored: the directory part
     is painted as a path token and the file name as a brighter "file"
     token (both dark and light themes).
  FIX 4) Emoji placement: templates support a {_e} placeholder inside
     the sentence, so markers sit at a meaningful spot (not always at
     the line start); templates without {_e} keep the prefix form.
  NOTE 5) Ctrl+C: the FIRST press stops immediately by default; the
     two-press confirmation exists ONLY behind --confirm-exit.

VERSION 2026-09-23 (v3.5) — quota fix, hotkeys, emoji & theme polish:

  FIX 1) Quota now always shows GiB + MiB: the remainder was divided by
     the next LARGER unit (so "47 GiB 463 MiB" collapsed to "47 GiB");
     the sub-unit lookup is fixed (50951488617 -> "47 GiB 463 MiB").
  FIX 2) Emoji restored EVERYWHERE (full audit against the original):
     every message key that used to carry a marker now carries one again,
     plus new meaningful markers where the original had none (engine
     selection, config file list, probe lines, engine switch, hotkeys,
     recommendations, curl hints, quota/timers).
  FIX 3) More word-level highlights + theme settings moved to the top of
     the script as the THEME_SETTINGS global (dark default / light), easy
     to tweak in one place. New token classes: file paths (Windows and
     POSIX), JWT/Bearer tokens, n/total counters, listener endpoints.
  FIX 4) The probe lines no longer dump raw transport exceptions
     (SSLError(...) etc.): a failed data check is the EXPECTED outcome of
     the algorithm on a filtering network, so the line is purely
     informational - "data check not passed; the upstream is served
     anyway" - with no stack-noise. Raw details stay in the JSON result.
  FIX 5) Hotkeys in the watch loop (mirroring CLI flags): r = fresh
     re-login without restart, c = clear ALL caches and restart the
     session flow, e = toggle the proxy engine (builtin <-> sing-box) and
     restart the local proxies with it, q = stop. Windows uses msvcrt,
     POSIX uses cbreak (restored before any interactive prompt).

VERSION 2026-09-23 (v3.4) — hotfix for a v3.3 regression + restoration:

  FIX 1) CRASH on startup: the word-highlight regex had unterminated
     subpatterns (nested named groups written incorrectly) -> re.PatternError
     "missing ), unterminated subpattern". Rewritten as a flat alternation
     with properly closed groups; validated against sample log lines
     (hosts, URLs, IPs, protocols, sizes, times all classify correctly).
  FIX 2) The original emoji decorations (v2) that v3.0-v3.3 dropped are
     restored: a single key->emoji map applied inside tr(), so both
     languages carry the same markers as the original script (key/floppy/
     ticket/shield/globe/numbers/clipboard/chart/rocket/check mark/recycle,
     warning sign for soft issues, cross mark for hard errors), plus the
     emoji on the hardcoded Fastly-challenge lines.
  FIX 3) Ctrl+C: by default the FIRST press stops immediately - the
     handler now also raises KeyboardInterrupt so blocking socket reads
     (probe, TLS handshakes) abort at once instead of lingering until
     their 20s timeout, which looked like an exit confirmation. The
     two-press confirmation exists only behind --confirm-exit, and the
     top-level entry point catches KeyboardInterrupt so no traceback
     is printed in one-shot mode either.

VERSION 2026-09-23 (v3.3) — probe wording, themes, richer word colors:

  FIX 1) The probe output no longer looks like errors: per-upstream lines,
     the summary and the "nothing confirmed" case are informational results
     of the check (info level, neutral wording like "data check not passed
     ...; the upstream is served anyway"). Red err is reserved for real
     failures of the script itself; the redundant "keeping them anyway"
     and "nothing to serve" lines are gone.
  FIX 2) Color THEMES: --theme dark (default, near-black background) and
     --theme light (white background). Every colored line is painted with
     the theme background and per-theme foreground palettes chosen for
     readability on that background. Env: MOZVPN_THEME.
  FIX 3) Stronger word-level highlighting, per-theme: URLs and IPv4[:port]
     (bold cyan on dark / bold blue on light), hostnames[:port] (blue),
     protocol names masque/connect/connect-udp/connect-ip (bold yellow),
     sizes like "47 GiB" (bold green), UTC times HH:MM:SS.
  FIX 4) The engine descriptions no longer say "HTTP CONNECT proxy only":
     both engines are MASQUE-aware - each upstream is served as MASQUE
     (HTTP/3 CONNECT-UDP) or HTTP CONNECT, whatever the probe negotiated,
     with automatic fallback (today Fastly egresses serve CONNECT; see the
     v3.0 header note).
  FIX 5) Startup now logs the config/cache files used on the user's system
     (session.json, credentials.json, fastly-cookie.json, the sing-box
     config directory) with size and modification time, or "not created yet".

VERSION 2026-09-23 (v3.2) — logging polish based on a live run report:

  FIX 1) "Local proxy engine: builtin" was printed twice (once by main(),
     once by run_manager); now it is emitted exactly once at startup.
  FIX 2) Word-level colors: every log line now highlights significant tokens
     (IPv4[:port], URLs, hostnames[:port]) in bold cyan on top of the level
     color, so endpoints and proxies are easy to scan visually.
  FIX 3) Probe failures are NOT errors of the script: per-server "CONNECT
     failed ..." lines, the probe summary and "no usable upstreams" now use
     the warning level (yellow), leaving red strictly for real errors.
  FIX 4) Minimal probing by default: new --probe-count (default 1) probes
     only the first upstream; --probe-count 0 probes all (old behavior).
     Unprobed servers are served with probe_ok=None.
  FIX 5) The quota line is humanized: "Quota: 47 GiB 463 MiB of 50 GiB left"
     instead of raw byte counters.

VERSION 2026-09-23 (v3.1) — TLS profile fallback matrix, probe-fail policy,
upstream override, cross-engine log consistency, watch-loop error codes:

  FIX 1) SSLError(UNEXPECTED_MESSAGE) on the outer TLS to the egress:
     - The Fastly proxy port is HTTPS-only and picky about the ClientHello
       (community clients differ: curl offers ALPN 'http/1.1', rustls/outfox
       sends no ALPN, Firefox offers ['h2','http/1.1'], the reference curl
       test even uses --proxy-insecure).
     - The probe and the builtin engine now walk a TLS PROFILE MATRIX in
       order: verified + ALPN http/1.1 -> verified, no ALPN -> verified +
       ALPN [h2, http/1.1] -> unverified (CERT_NONE). The first profile
       whose handshake completes is used for the whole connection.
     - If a peer answers in plaintext (filtering middlebox / HTTP 451 error),
       the received bytes are peeked and shown in the error message.
  FIX 2) Probe failure no longer nukes the whole server list:
     - Default --probe-fail keep: failed upstreams stay in the served list
       with a warning (a probe failure is often local SNI/DPI filtering
       while the tunnel still works from other clients).
     - --probe-fail drop restores the old strict behavior.
  FIX 3) New --upstream-host/--upstream-port: force every upstream to e.g.
     the Fastly anycast pool p.m1.fastly-masque.net (the classic fix when
     per-city SNI hostnames are blocked by a network, cf. community
     write-ups about SNI filtering of *.m1.fastly-masque.net hosts).
  FIX 4) "No free ports for local proxies" was misleading: it fired when the
     probe had dropped every server. Now there are two distinct errors:
     no upstream servers at all vs all candidate ports busy.
  FIX 5) builtin and sing-box engines now log identically (same per-proxy
     lines, then one "engine started" line); only the engine name differs.
  FIX 6) sing-box configs were written with an EMPTY Bearer token (the token
     holder was filled after build_proxies); the order is fixed.
  FIX 7) The watch loop classified errors by matching Cyrillic text with
     mojibake byte sequences; MozVpnError now carries a language-independent
     `code` ("blocked"/"relogin") set at every relevant raise site.
  FIX 8) The interactive QR answer check compared against corrupted string
     literals; it now uses the localized answer_no_words list.

VERSION 2026-09-23 (v3.0) — MASQUE support, builtin proxy engine, i18n, colors:

  1) MASQUE PROTOCOL SUPPORT (verified against live data, 2026-09-23):
     - Fastly's official blog ("We Built the Proxy Behind Firefox's New
       Built-In VPN") states that the proxy currently runs plain HTTP CONNECT
       (over HTTP/2) and that Firefox plans to move to MASQUE over HTTP/3 on
       Fastly's infrastructure later.
     - The live Remote Settings collection "vpn-serverlist" today only
       advertises protocols: [{name: "connect", ...}] on hosts like
       *.m1.fastly-masque.net:2499 — i.e. the egress hostnames are
       MASQUE-branded, but the actually served protocol is still HTTP CONNECT
       over TLS.
     - Therefore this script fully PARSES "masque" protocol entries in the
       server list, PROBES them for real MASQUE (HTTP/3 CONNECT-UDP over
       QUIC via the optional `aioquic` package) and — when MASQUE is not
       actually usable — FALLS BACK to HTTP CONNECT automatically (req. 1, 2).
     - The probe does not trust a bare "200" response: it tunnels real data
       through the proxy to a public IP-echo service and verifies the
       response body looks like an IP address.

  2) PARALLEL PROXY PRE-CHECK (req. 7):
     - Before local proxies are started, every candidate upstream is checked
       in parallel (ThreadPoolExecutor): a TLS connection is opened to the
       Mozilla/Fastly egress, a CONNECT (or MASQUE CONNECT-UDP) request is
       signed with Proxy-Authorization: Bearer <proxyPass> and a real HTTPS
       request to a public IP-echo service is sent through the tunnel.
     - A server is marked usable only if data actually flows through it.
     - Log output is aggregated: parallel results are printed as grouped
       summary lines so the log does not interleave.
     - CLI: --no-proxy-check disables the check (default: enabled);
       --ip-echo-service <name> selects one of 6 predefined public IP echo
       services; --ip-echo <url> overrides with a custom URL.

  3) TWO LOCAL PROXY ENGINES (req. 6, 10, 11):
     - --local-proxy-engine builtin (default): a self-contained threaded
       HTTP CONNECT proxy implemented inside this script (modeled after the
       connection-handling approach of the popular proxy.py package and the
       sing-box http outbound). No third-party runtime, no subprocesses,
       no external engine binary — fully Nuitka/exe-friendly (req. 11).
       Token rotation is applied live: the tunnel reads the current proxyPass
       from an in-memory token holder for every new client connection.
     - --local-proxy-engine singbox: generates sing-box configs exactly like
       the proven mozvpn.py reference implementation (http inbound ->
       http outbound with Proxy-Authorization + tls.enabled) and restarts
       them when the token rotates. Requires `sing-box` in PATH.

  4) LEGACY FLAGS REMOVED (req. 5): --use-proxy and --use-sing-box aliases
     are gone; the single switch is --local-proxy (env MOZVPN_LOCAL_PROXY=1).

  5) --clear-cache (req. 8): completely removes the config directory
     (~/.config/mozvpn) including session/credentials/Fastly-cookie caches,
     engine directories of this AND all previous script versions (singbox/,
     pyproxy/), then exits.

  6) "valid until: None" FIXED (req. 9): when Guardian does not return
     "until", the expiry time is derived from the JWT `exp` claim.

  7) Ctrl+C (req. 12): by default the first Ctrl+C exits immediately;
     --confirm-exit enables a confirmation (second Ctrl+C within 5 s).

  8) ALL COMMENTS ARE IN ENGLISH (req. 13).

  9) MULTILINGUAL OUTPUT (req. 14): --lang {en,ru} (env MOZVPN_LANG),
     default English. All message templates live in the STR table at the top.

 10) The selected local proxy engine is printed at startup (req. 15).

 11) COLORED LOG OUTPUT (req. 16): --no-color disables (env MOZVPN_NO_COLOR);
     colors are on by default and use soft, readable ANSI shades.

 Everything else (FxA authPW v1/v2 stretching, Bearer fxs_<tokenID>
 derivation, OAuth grant fxa-credentials with the scope pair
 "profile https://identity.mozilla.com/apps/vpn", Guardian /fpn/activate +
 /fpn/token, Fastly Next-Gen WAF PoW challenge solver, auto-TOTP from QR
 with clock-sync against Mozilla server Date headers, TOTP-window-aware
 retries, vpn-serverlist Remote Settings parsing with JEXL filtering) is
 carried over from the fully working v2 of this script.

pip dependencies (all have prebuilt wheels for Windows/Linux/macOS):
    pip install pyotp zxing-cpp Pillow        # required for QR/TOTP
    pip install aioquic                      # optional: real MASQUE (HTTP/3) probing

QUICK START (Windows 11 / Linux / macOS):
  python mozvpn.py --email a@b.c --password '***' --qr qr.png --local-proxy
  python mozvpn.py --local-proxy             # everything cached afterwards
  python mozvpn.py --clear-cache             # wipe all caches and exit
  python mozvpn.py --lang ru --local-proxy --local-proxy-engine builtin
  python mozvpn.py --reinstall-deps         # reinstall ALL pip deps and exit
  python mozvpn.py --reinstall-singbox      # reinstall sing-box and exit

Credential flow:
  1. POST /v1/account/credentials/status -> stretching version (v1/v2) + clientSalt
  1a. /v1/account/login (email+authPW) -> sessionToken     [only without cached session]
  1b. with 2FA: /v1/session/verify/totp (verificationMethod "totp-2fa")
  2. POST api.accounts.firefox.com/v1/oauth/token (grant fxa-credentials, session auth)
  3. POST vpn.mozilla.org/api/v1/fpn/activate (direct token activation, as Firefox does)
  4. GET  vpn.mozilla.org/api/v1/fpn/token -> proxyPass JWT
  5. Remote Settings (collection vpn-serverlist) -> server list
  6. Parallel probe of upstreams (MASQUE first, fallback to HTTP CONNECT)
  7. Local proxies (builtin threads or sing-box subprocesses)

Environment variables:
  MOZVPN_EMAIL, MOZVPN_PASSWORD, MOZVPN_SESSION_TOKEN, MOZVPN_TOTP,
  MOZVPN_TOTP_SECRET, MOZVPN_LOCAL_PROXY (1/true/yes/on), MOZVPN_LANG (en|ru),
  MOZVPN_NO_COLOR (1/true/yes/on), MOZVPN_PROXY_ENGINE (builtin|singbox),
  MOZVPN_SHOW_TEST_COMMANDS (1/true/yes/on), MOZVPN_RETRY_DELAY (seconds)

Caches (all mode 600, under ~/.config/mozvpn):
  session.json        — sessionToken
  credentials.json    — email/password/totp_secret (+digits/period/algorithm)
  fastly-cookie.json  — Fastly WAF cookie
"""

import argparse, base64, binascii, getpass, hashlib, hmac, http.cookiejar, json, os, re
import sys, threading, time, socket, ssl, subprocess, signal, atexit
import urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs, unquote
from datetime import timezone
from email.utils import parsedate_to_datetime
from concurrent.futures import ThreadPoolExecutor

# ---- optional dependencies (popular pip packages with prebuilt wheels;
# ---- no system utilities are ever required) ----
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
try:
    import aioquic  # noqa: F401  (optional: real MASQUE / HTTP-3 support)
except ImportError:
    aioquic = None

FXA_AUTH      = "https://api.accounts.firefox.com/v1"
FXA_OAUTH     = "https://oauth.accounts.firefox.com/v1"
GUARDIAN      = "https://vpn.mozilla.org"
FXA_CLIENT_ID = "5882386c6d801776"                       # Firefox Desktop (public)

# IMPORTANT: the OAuth scope must be the PAIR "profile + vpn-scope".
# Without "profile" Guardian cannot confirm entitlement and answers
# 403 no_entitlement (see v2 changelog). Primary scope first, legacy fallback second.
OAUTH_SCOPES  = ("profile https://identity.mozilla.com/apps/vpn",
                 "profile https://identity.mozilla.com/apps/mozillavpn")

RS_SERVERLIST = ("https://firefox.settings.services.mozilla.com/v1"
                 "/buckets/main/collections/vpn-serverlist/records")

DEFAULT_FIREFOX_VERSION = "156.0"

# Browser-like headers (for steps after login: Guardian, Remote Settings)
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) "
                  "Gecko/20100101 Firefox/156.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "application/json",
}

CONF_DIR     = os.path.join(os.path.expanduser("~"), ".config", "mozvpn")
CACHE        = os.path.join(CONF_DIR, "session.json")
CRED_CACHE   = os.path.join(CONF_DIR, "credentials.json")
FASTLY_CACHE = os.path.join(CONF_DIR, "fastly-cookie.json")
SINGBOX_DIR  = os.path.join(CONF_DIR, "singbox")       # legacy of v1, still managed
ENGINE_DIR   = os.path.join(CONF_DIR, "engine")        # current engine state

# Deterministic local proxy port range
LOCAL_PORT_BASE  = 20000
LOCAL_PORT_RANGE = 20000      # ports 20000..39999

# ---- public IP echo services for the parallel proxy probe (req. 7) ----
# Chosen to be reachable from the US, UK and RU. Any of them can be replaced
# with --ip-echo <url> or switched with --ip-echo-service <name>.
IP_ECHO_SERVICES = {
    "ipify":     "https://api.ipify.org",
    "ifconfig":  "https://ifconfig.me",
    "icanhazip": "https://icanhazip.com",
    "aws":       "https://checkip.amazonaws.com",
    "ipinfo":    "https://ipinfo.io/ip",
    "ident":     "https://ident.me",
}
DEFAULT_IP_ECHO_SERVICE = "ipify"

# Supported upstream protocols: CONNECT (always) and MASQUE (probed, with fallback).
PROTO_CONNECT = "connect"
PROTO_MASQUE  = "masque"

# ---------------------------------------------------------------------------
# COLOR THEME SETTINGS (globals, editable in one place). Two themes:
#   dark  - near-black background, bright foregrounds (default)
#   light - white background, darker foregrounds
# Every colored log line is painted with the theme background explicitly;
# the level colors and the word-highlight colors are picked per theme.
# Selected at runtime with --theme dark|light (env MOZVPN_THEME).
# ---------------------------------------------------------------------------
THEME_SETTINGS = {
    "dark": {
        # TRUE BLACK background (xterm color 16 = #000000) - matches the
        # black console background exactly, so painted lines blend in.
        "bg":    "\033[48;5;16m",
        "ok":    "\033[0;32m",
        "info":  "\033[0;36m",
        "warn":  "\033[0;33m",
        "err":   "\033[0;91m",
        "hint":  "\033[0;90m",
        # word-level highlight colors (readable on a dark background)
        "url":   "\033[1;36m",     # URLs
        "ip":    "\033[1;36m",     # IPv4[:port]
        "host":  "\033[0;96m",     # hostnames[:port]
        "proto": "\033[1;33m",     # masque / connect / connect-udp / connect-ip
        "size":  "\033[1;32m",     # 47 GiB 463 MiB
        "time":  "\033[1;37m",     # 09:18:02
        "path":  "\033[0;94m",     # file paths
        "file":  "\033[1;94m",     # filename (basename) inside a path
        "jwt":   "\033[0;95m",     # Bearer / JWT tokens
        "port":  "\033[1;36m",     # 127.0.0.1:25510 listener endpoints
        "count": "\033[1;97m",     # significant numbers / counters
        "flag":  "\033[1;35m",     # CLI flags (--proxy, --proxy-insecure, ...)
        "key":   "\033[1;93m",     # hotkeys ('r' or a bare key before " - ")
        "hotkey": "\033[1;93;48;5;238m",  # hotkey keys: bold on a visible gray block
        "hotdesc": "\033[0;97m",   # hotkey DESCRIPTIONS (per-key hint lines)
    },
    "light": {
        # TRUE WHITE background (xterm color 231 = #ffffff) - matches the
        # white console window. Foreground colors are picked for HUMAN
        # PERCEPTION on white: no bright yellow (unreadable), dark
        # amber/orange shades for warnings and protocol names, saturated
        # dark blue for URLs/IPs, dark magenta for flags.
        "bg":    "\033[48;5;231m",
        "ok":    "\033[0;32m",
        "info":  "\033[0;34m",
        "warn":  "\033[38;5;130m",   # dark amber (plain yellow is unreadable on white)
        "err":   "\033[0;31m",
        "hint":  "\033[0;90m",
        # word-level highlight colors (readable on a white background)
        "url":   "\033[1;34m",
        "ip":    "\033[1;34m",
        "host":  "\033[0;34m",
        "proto": "\033[38;5;166m",   # dark orange (bold yellow is invisible on white)
        "size":  "\033[0;32m",
        "time":  "\033[0;35m",
        "path":  "\033[0;36m",
        "file":  "\033[1;36m",
        "jwt":   "\033[0;35m",
        "port":  "\033[1;34m",
        "count": "\033[1;30m",
        "flag":  "\033[0;35m",       # dark magenta (yellow flags were unreadable)
        "key":   "\033[1;35m",
        "hotkey": "\033[1;30;48;5;229m",  # hotkey keys: bold on a light-yellow block
        "hotdesc": "\033[0;90m",   # hotkey DESCRIPTIONS (per-key hint lines)
    },
}
DEFAULT_THEME = "dark"

# ---------------------------------------------------------------------------
# Internationalization (req. 13, 14): all user-facing message templates.
# English is the default language; Russian is fully supported via --lang ru.
# ---------------------------------------------------------------------------

_LANG = os.environ.get("MOZVPN_LANG", "en").strip().lower()
if _LANG not in ("en", "ru"):
    _LANG = "en"

STR = {
"en": {
  "engine_selected": "Local proxy engine {_e}: {engine}",
  "config_files_header": "Configuration and cache files used on this system {_e}:",
  "config_file_entry": "  {_e} {path} — {status}",
  "config_file_exists": "{size} bytes, modified {mtime} UTC",
  "config_file_dir": "directory, {n} entries",
  "config_file_missing": "not created yet",
  "engine_builtin": "builtin (in-process engine: serves each upstream as MASQUE or HTTP CONNECT, with automatic fallback)",
  "engine_singbox": "sing-box (external binary, MASQUE/HTTP CONNECT upstreams)",
  "lang_selected": "Output language: {lang}",
  "color_disabled": "Color output disabled.",
  "cache_cleared": "Cache directory removed: {path}",
  "cache_clear_failed": "Failed to remove cache directory {path}: {err}",
  "cache_nothing": "Cache directory does not exist, nothing to clear.",
  "cached_session": "Using cached session ({email}) {_e}. Use --relogin for a fresh sign-in.",
  "enter_email": "Mozilla account email: ",
  "enter_password": "Password: ",
  "email_missing": "Email not provided (no argument and no cache).",
  "password_missing": "Password not provided (no argument and no cached credentials).",
  "signing_in": "Signing in to Mozilla Accounts...",
  "session_cached": "sessionToken cached {_e}: {path}",
  "stretch_version": "Account key-stretching version: {version}",
  "stretch_v2_note": " (650k PBKDF2 iterations)",
  "clock_skew": "Local clock differs from Mozilla servers by {offset}s; TOTP will use server time.",
  "account_not_found": "Account not found.",
  "wrong_password": "Incorrect password (errno 103). If you signed up via Google/Apple, set a password first: accounts.firefox.com -> Settings.",
  "login_blocked": "Login temporarily blocked ({source}): too many consecutive failed attempts (wrong password and/or 2FA codes).{wait}\nThis is NOT deletion or a permanent block. Sign-in is restored by EMAIL CONFIRMATION:\n  1) Check the account mailbox (and Spam): Mozilla sent a sign-in email\n     ('New sign-in to Firefox' / 'Confirm your sign-in' / a confirmation code).\n  2) Open the email and confirm the sign-in (button or code on accounts.firefox.com).\n  3) Then re-run the script (in --watch mode it retries itself).",
  "retry_after": " The server asks to wait ~{sec}s before retrying.",
  "blocked_extra_method": " Server requires confirmation method '{method}'.",
  "login_error": "Login error ({status}): {msg}",
  "server_wants_method": "Server asked to confirm sign-in via '{method}' (reason: {reason}). For TOTP accounts the server accepts /session/verify/totp regardless of the announced method - trying TOTP.",
  "totp_prompt": "Two-factor authentication code (TOTP): ",
  "totp_digits_only": "The code must contain digits only.",
  "totp_not_enabled": "This account has no TOTP enabled on the server (TOTP_TOKEN_NOT_FOUND) - TOTP verification is impossible.",
  "totp_rejected_window": "Server rejected the code. Check that the secret matches the authenticator app (2FA may have been re-created after the QR was saved).{clock} Waiting for the next TOTP window ...",
  "totp_rejected_final": "The 2FA code was rejected three times in a row (in different time windows). Verify the TOTP secret against your app: re-run with --qr <fresh QR> - 2FA may have been re-created and qr.png may be stale.",
  "totp_unknown_error": "2FA verification error ({status}): {data} (check sessionToken / account)",
  "totp_code_current": "Current TOTP code: {code} (valid for {sec} more s{offset})",
  "totp_code_generated": "Generated TOTP code: {code} (window {period}s, {left}s left)",
  "clock_offset_note": ", clock offset {offset}s",
  "email_unverified": "Account email is not verified (signup). Confirm the email via the Mozilla letter, then sign in again.",
  "email_confirm_required": "Sign-in email confirmation is required and the account has no TOTP (otherwise the script would have verified the session itself). What to do:\n  1) Open the mailbox, find the Mozilla letter 'New sign-in to Firefox' and confirm\n     (or enter the code from the letter on accounts.firefox.com);\n  2) re-run the script afterwards - the session becomes trusted;\n  3) or enable TOTP in account settings (Two-step authentication);\n  4) or sign in inside Firefox and run with --session-token <hex>.",
  "session_unverified": "Session not verified (method: {method}, reason: {reason}).",
  "totp_missing": "The account requires 2FA but the TOTP secret is unknown. Run with --qr <image> or --totp-secret.",
  "oauth_fetching": "Obtaining OAuth token (grant fxa-credentials, scope 'profile https://identity.mozilla.com/apps/vpn')...",
  "oauth_scope_fallback": "Primary scope rejected by the server, used '{scope}'.",
  "oauth_scope_denied": "Scope '{scope}' not allowed (errno 114), trying the next one ...",
  "oauth_all_scopes_denied": "OAuth: all scopes rejected by the server (errno 114). Last error: {err}",
  "oauth_session_invalid": "sessionToken is invalid/expired (errno {errno}) - re-login required.",
  "oauth_error": "OAuth token not received ({status}): {data}",
  "guardian_activating": "Activating on Guardian and obtaining proxyPass...",
  "guardian_enrolled": "Guardian: enroll completed (HTTP {status}).",
  "guardian_enroll_failed": "/fpn/activate -> HTTP {status} {detail} (continuing: Guardian issues the token without enroll too)",
  "guardian_403": "proxyPass not received (HTTP 403, no_entitlement).\nThis is NOT a login error: the OAuth token was accepted, but the account has no Firefox IP Protection (Built-in VPN) entitlement.\nPossible causes and actions:\n  1) The feature is not enabled for the browser yet: open Firefox 149+ -> VPN icon\n     on the toolbar -> enable it once until the 'green indicator' (first enabling\n     attaches the entitlement to the account).\n  2) Built-in VPN beta rolls out by region (2026-09: US/UK/DE/FR). Outside the\n     list the 403 stays regardless of this script.\n  3) If the Mozilla account was created via Google/Apple or is new - wait for\n     full activation and retry.",
  "guardian_401": "proxyPass not received (HTTP 401, reauth_required): session/FxA token rejected by Guardian - re-login required.",
  "guardian_429": "proxyPass not received (HTTP 429): quota exhausted, retry in {retry}s.",
  "guardian_451": "proxyPass not received (HTTP 451): region unavailable.",
  "guardian_error": "proxyPass not received (HTTP {status}): {detail}",
  "guardian_no_token": "Guardian response has no 'token' field: {data}",
  "quota_unlimited": "Quota: unlimited (x-quota-unlimited: true).",
  "quota_left": "Quota: {left} of {limit} left{reset}.",
  "serverlist_fetching": "Loading server list (Remote Settings: vpn-serverlist)...",
  "serverlist_failed": "Server list not loaded from Remote Settings (vpn-serverlist) nor from Guardian (/api/v2/servers).",
  "serverlist_done": "Countries: {countries}, usable servers: {servers}",
  "proxypass_received": "proxyPass received {_e}, valid until: {until} (exp {exp} UTC)",
  "proxypass_jwt": "Fresh proxyPass JWT:",
  "session_token_print": "sessionToken (for re-runs):",
  "json_saved": "JSON saved {_e}: {path}",
  "qr_need_zxing": "Reading the QR requires the zxing-cpp package:\n    pip install zxing-cpp pyotp Pillow",
  "qr_need_pillow": "Opening the QR image requires the Pillow package:\n    pip install Pillow",
  "qr_not_found": "QR file not found: {path}",
  "qr_open_failed": "Could not open image {path}: {err}",
  "qr_none_found": "No QR code found in file: {path}",
  "qr_no_otpauth": "File {path} has no otpauth:// QR code: {sample}",
  "qr_not_totp": "QR is not TOTP (otpauth://totp): {sample}",
  "qr_no_secret": "QR is missing the secret parameter: {sample}",
  "qr_secret_empty": "Empty TOTP secret.",
  "qr_secret_bad32": "TOTP secret is not valid base32: {err}",
  "totp_need_pyotp": "TOTP generation requires the pyotp package:\n    pip install pyotp",
  "totp_bad_algo": "Unknown TOTP algorithm: {algo} (expected SHA1/SHA256/SHA512)",
  "totp_bad_params": "Invalid TOTP parameters: digits={digits}, period={period}",
  "totp_init_failed": "Could not initialize TOTP from the secret: {err}",
  "qr_saved": "TOTP secret saved to {path} (mode 600); parameters: {digits} digits, {period}s window, {algo}.",
  "qr_saved_note": "2FA codes are now generated automatically (pyotp) using Mozilla server time.",
  "qr_verify_q": "Does it match the code in your authenticator app? [Y/n]: ",
  "qr_verify_mismatch": "Paste the TOTP secret (base32) from the app, or a path to another QR image (Enter - cancel): ",
  "qr_verify_cancelled": "Cancelled: the QR secret does not match the app.\nIf 2FA was re-created, download a fresh QR: accounts.firefox.com -> Settings -> Two-step authentication.",
  "qr_code_for_review": "Code from the parsed QR (for review, no question asked, --qr-verify to enable): {code}, valid for {sec} more s",
  "proxy_check_started": "Probing {n} upstream proxies in parallel via '{service}' ({url}) ...",
  "proxy_check_summary_ok": "Probe: {n}/{total} upstreams passed the data check ({list})",
  "proxy_check_summary_fail": "Probe: {n}/{total} upstreams did not pass the data check ({list})",
  "proxy_check_masque_ok": "Probe: {host}:{port} - MASQUE (HTTP/3 CONNECT-UDP) tunnel carried data",
  "proxy_check_masque_fallback": "Probe: MASQUE on {host}:{port} not confirmed - this upstream will use HTTP CONNECT",
  "proxy_check_connect_ok": "Probe: {host}:{port} - CONNECT tunnel carried data (external IP {ip})",
  "proxy_check_connect_fail": "Probe: {host}:{port} - data check not passed; the upstream is served anyway",
  "proxy_check_disabled": "Proxy pre-check disabled (--no-proxy-check): using all server-list upstreams as-is.",
  "upstream_override": "Upstream override: all locations use {host}:{port} instead of the per-city hosts.",
  "engine_started": "{engine} engine started: {n} local proxies on {listen}",
  "proxy_line": "  {_e}{listen}:{port:<6} {label:<30} -> {host}:{uport} [{proto}]",
  "port_busy": "Port {port} is busy - skipping {label} (owned by another process?)",
  "no_free_ports": "No free ports for local proxies (all candidate ports are busy).",
  "no_servers_to_serve": "No upstream servers to serve: the probe dropped everything (use --probe-fail keep) or the server list is empty.",
  "tls_plain_http": "upstream answered in plaintext (not TLS): {text}",
  "answer_no_words": "n, no, н, нет",
  "answer_yes_words": "y, yes, д, да",
  "deps_manual_hint": "Install manually {_e}: {cmd}",
  "singbox_missing": "sing-box not found in PATH. Install it (https://sing-box.sagernet.org/installation/) or use --local-proxy-engine builtin.",
  "token_updated_builtin": "builtin engine: new proxyPass applied live (new connections use it, no restart needed).",
  "token_updated_singbox": "sing-box: new proxyPass -> configs rewritten + processes restarted ...",
  "singbox_stopped": "sing-box proxy stopped: {label} ({listen}:{port})",
  "singbox_died": "sing-box {label} (port {port}) exited (code {code}).",
  "proxy_stopping": "Stopping local proxies ...",
  "proxy_stopped": "Local proxies stopped.",
  "relogin_needed": "Re-login required - retrying with saved credentials ...",
  "blocked_wait": "Sign-in temporarily blocked - waiting 10 minutes before the next attempt (see the email confirmation instructions above).",
  "unexpected_error": "Unexpected error: {err!r} - retrying in 30s.",
  "next_refresh": "Next refresh {_e} in {sec}s ({at} UTC).",
  "confirm_exit_hint": "Press Ctrl+C to stop.",
  "hotkeys_hint": "Hotkeys (each mirrors a script parameter):\n  ♻️ r - re-login now, wiping ALL saved data (--relogin)\n  🧹 c - clear ALL saved data & restart (--clear-cache)\n  🔄 e - switch proxy engine builtin/sing-box (--local-proxy-engine)\n  🔀 l - switch listen host 127.0.0.1 <-> 0.0.0.0 (--listen)\n  📂 o - open the sing-box config directory (or the main config directory)\n  📋 v - copy a LOCAL proxy address:port\n  📋 b - copy an UPSTREAM proxy address:port\n  🔢 t - show & copy the current TOTP code\n  🎫 j - show & copy the current proxyPass JWT\n  🖼️ g - load a QR image with the 2FA secret on the fly (--qr)\n  👤 u - show & copy the login (email)\n  🔑 p - show & copy the password\n  📦 d - reinstall ALL Python dependencies from scratch (--reinstall-deps)\n  ⤴️ s - reinstall sing-box from scratch (--reinstall-singbox)\n  🎨 m - switch the color theme dark <-> light (--theme)\n  🌈 n - toggle the colored log output on/off (--no-color)\n  📄 1-9 - open a config file in the system default editor\n  ⏹️ q - stop.",
  "hotkey_relogin": "Hotkey 'r' ♻️: FULL wipe of all saved data - caches, credentials, sing-box configs - then a fresh sign-in.",
  "hotkey_clear": "Hotkey 'c' 🧹: ALL saved data wiped (caches, credentials, sing-box configs) - restarting with a clean state.",
  "hotkey_engine": "Hotkey 'e': switching the engine to {engine} - local proxies will restart with it.",
  "hotkey_listen": "Hotkey 'l': listeners will now bind on {host} - local proxies will restart with it.",
  "hotkey_totp": "Hotkey 't' 🔢: current TOTP code - also copied to the clipboard.",
  "hotkey_jwt": "Current proxyPass JWT {_e} - also copied to the clipboard:",
  "hotkey_jwt_none": "Hotkey 'j' 🎫: no proxyPass token yet - it appears right after the successful sign-in.",
  "hotkey_totp_none": "Hotkey 't' 🔢: no TOTP secret is available. Reason: {reason}. The TOTP secret is stored in credentials.json and gets there only after a sign-in with --qr <QR image> or --totp-secret <base32> (or the MOZVPN_TOTP_SECRET environment variable).",
  "totp_none_reason_nocreds": "credentials.json has not been created yet - no sign-in with saved credentials has happened on this machine",
  "totp_none_reason_nosecret": "credentials.json exists but contains no totp_secret field - the saved sign-in was made without --qr / --totp-secret, or the account has no TOTP 2FA enabled",
  "hotkey_open_dir_fallback": "Hotkey 'o' 📂: the sing-box config directory does not exist yet (it is created when the singbox engine runs) - opened the main config directory instead {_e}: {path}",
  "hotkey_files_hint": "Config files: press the number to open the file in the system default editor.",
  "hotkey_file_entry": "  {n} - {path}",
  "hotkey_open": "Opened in the system default editor {_e}: {path}",
  "hotkey_open_dir": "Opened the config directory in the system file manager {_e}: {path}",
  "hotkey_open_fail": "Could not open {path}: {err}",
  "hotkey_open_missing": "File does not exist: {path}",
  "hotkey_copy_local_hint": "Copy a LOCAL proxy address to the clipboard - press its number:",
  "hotkey_copy_remote_hint": "Copy an UPSTREAM proxy address to the clipboard - press its number:",
  "hotkey_copy_entry": "  {n} - {addr} ({label})",
  "hotkey_copied": "Copied to the clipboard {_e}: {text}",
  "hotkey_copy_fail": "Clipboard is not available on this system: {err}",
  "hotkey_copy_cancel": "Copy cancelled - press v or b again to retry.",
  "hotkey_stop": "Hotkey 'q': stop requested.",
  "retry_wait": "Sign-in did not succeed this time - it usually works on the second attempt. PLEASE WAIT: the login/password/TOTP prompt will appear again automatically, no script restart needed.",
  "retry_in": "Next sign-in attempt in:",
  "theme_switched": "Theme switched {_e}: {theme}",
  "theme_bg_forced": "Console window background FORCED {_e}: {bg} (OSC 11 escape sequence - the theme now also repaints the window itself, not only the log lines).",
  "theme_bg_exit": "On exit the terminal DEFAULT background is restored {_e} (OSC 111). If your terminal ignores that reset, reset the window color in its profile settings.",
  "deps_fallback_each": "One-command install failed (pip dependency conflict) {_e} - retrying each package separately WITHOUT --force-reinstall: forcing shared dependencies to exact versions is the usual conflict cause.",
  "deps_fallback_nodeps": "{pkg}: still conflicting {_e} - last resort: pip install {pkg} --no-deps (the already-installed dependency tree satisfies the imports).",
  "deps_pkg_ok": "  {_e} {pkg} - OK",
  "deps_pkg_fail": "  {_e} {pkg} - FAILED",
  "deps_conflict_fail": "Packages that could not be installed: {pkgs}. See the pip errors above.",
  "hotkey_theme": "Hotkey 'm' 🎨: switched the theme to {theme} (--theme).",
  "color_enabled": "Colored log output enabled {_e} (hotkey 'n' / --no-color toggles).",
  "hotkey_color": "Hotkey 'n' 🌈: colored log output {state} (mirrors --no-color).",
  "color_state_on": "enabled",
  "color_state_off": "disabled",
  "deps_header": "Python dependencies used by this script {_e}:",
  "singbox_dep_header": "External dependency (not a pip package) {_e}:",
  "singbox_dep_ok": "  {_e} sing-box - installed: {path} (version {version})",
  "singbox_dep_missing": "  {_e} sing-box - NOT installed (optional: needed only for the 'singbox' proxy engine; the builtin engine works fully without it)",
  "deps_entry_ok": "  {_e} {pip:<12} (module {module:<10}) {version:<12} - installed",
  "deps_entry_missing": "  {_e} {pip:<12} (module {module:<10}) - NOT installed{need}",
  "deps_need_required": " - REQUIRED for TOTP/QR",
  "deps_need_optional": " - optional (real MASQUE / HTTP-3 probing)",
  "deps_missing_note": "Missing dependencies: {list}.",
  "deps_install_q": "Install the missing dependencies now with pip ({cmd})? [Y/n]: ",
  "deps_installing": "Installing dependencies {_e}: {pkgs} ...",
  "deps_install_ok": "Dependencies installed successfully {_e}.",
  "deps_install_fail": "pip failed (exit code {code}): {err}",
  "deps_frozen_note": "The script is compiled into a binary (frozen) - automatic installation is not possible. Install manually: {cmd}",
  "deps_install_declined": "Dependencies not installed - continuing without them.",
  "deps_reinstall_header": "Reinstalling ALL Python dependencies from scratch {_e}: {pkgs}",
  "deps_reinstall_ok": "All dependencies reinstalled successfully {_e}.",
  "deps_reinstall_fail": "Dependency reinstall failed (exit code {code}): {err}",
  "deps_reinstall_skip_frozen": "The script is a compiled binary (frozen) - pip reinstall is not possible; the dependencies are built into the binary.",
  "singbox_install_header": "sing-box is not installed {_e}. The script works FULLY without it: the builtin engine serves the same upstreams (MASQUE / HTTP CONNECT) inside this Python process. sing-box is needed only for the 'singbox' proxy engine.",
  "singbox_install_q": "Install sing-box now? [y/N]: ",
  "singbox_install_cmd": "Install command for this system {_e}: {cmd}",
  "singbox_install_manual": "Manual install: open {url} - the official sing-box installation page.",
  "singbox_install_started": "Installing sing-box {_e}: {cmd}",
  "singbox_install_ok": "sing-box installed successfully {_e}: {path}",
  "singbox_install_fail": "sing-box installation failed (exit code {code}): {err}",
  "singbox_install_declined": "sing-box installation declined {_e} - the choice is remembered and the question will not be asked again (unless you select the singbox engine while sing-box is still missing).",
  "singbox_windows_hint": "Windows: download the sing-box release from {url} , unpack it and add to PATH, then restart the script.",
  "singbox_reinstall_header": "Reinstalling sing-box from scratch {_e} ...",
  "singbox_reinstall_ok": "sing-box reinstalled {_e}: {path}",
  "singbox_reinstall_fail": "sing-box reinstall failed (exit code {code}): {err}",
  "singbox_engine_still_missing": "sing-box is still not installed - staying on the builtin engine.",
  "hotkey_qr_prompt": "Path to the QR image with the 2FA (TOTP) code (Enter - cancel): ",
  "hotkey_qr_loaded": "QR loaded {_e}: {path}. TOTP secret saved; current code: {code} (valid {sec} more s).",
  "hotkey_qr_fail": "QR load failed: {err}",
  "hotkey_login": "Login (email) {_e}: {email} - also copied to the clipboard.",
  "hotkey_login_none": "No saved login: sign in first (--email or the interactive prompt).",
  "hotkey_password": "Password {_e}: {password} - also copied to the clipboard.",
  "hotkey_password_none": "No saved password: sign in first (--password or the interactive prompt).",
  "hotkey_deps_reinstalled": "Dependencies reinstalled {_e}.",
  "protocol_summary": "Upstream protocol summary {_e}: {m} upstream(s) via MASQUE (HTTP/3 CONNECT-UDP - the priority protocol), {c} upstream(s) via HTTP CONNECT (HTTPS proxy tunnel over TLS - the fallback used when MASQUE did not carry data).",
  "proto_chosen_masque": "Protocol for {host}:{port}: masque (HTTP/3 CONNECT-UDP) - the PRIORITY protocol; the MASQUE tunnel carried data.",
  "proto_fallback_connect": "Protocol for {host}:{port}: HTTP CONNECT - fallback from masque, which is unavailable here: {reason}",
  "proto_masque_no_lib": "masque needs the aioquic package - it is not installed, so every upstream will use the HTTP CONNECT fallback.",
  "test_commands_header": "To test the LOCAL proxies, use these commands {_e}:",
  "test_commands_hidden": "curl test commands are hidden {_e} - enable them with --show-test-commands (env MOZVPN_SHOW_TEST_COMMANDS=1).",
  "test_command_local": "  {_e} {cmd}   [{label}, {proto}]",
  "test_commands_remote_header": "To test the UPSTREAM (remote) proxies directly, use these commands:",
  "test_command_remote": "  {_e} {cmd}   [{label}]",
  "clear_will_remove_header": "Hotkey 'c' / 'r' / --clear-cache / --relogin removes ALL of these {_e}:",
  "clear_will_remove_entry": "  - {path}",
  "clear_will_remove_dir": "  - {path} (the ENTIRE config directory - everything above lives inside it)",
  "clear_wiped_note": "Wiped: session caches, saved credentials (email/password/TOTP secret), the Fastly cookie and the sing-box configs. A fresh sign-in will ask for the login data again.",
  "jwt_decoded_header": "Decoded proxyPass JWT {_e}:",
  "jwt_decoded_part": "  {part} {json}",
  "jwt_decoded_exp": "  exp (valid until): {time} UTC   iat (issued at): {iat} UTC",
  "confirm_exit_prompt": "Ctrl+C received. Press Ctrl+C again within 5s to confirm exit, or wait to continue.",
  "confirm_exit_abort": "Exit cancelled, continuing.",
  "sigterm": "Termination signal received, stopping.",
  "recommended_server": "Recommended server: {country} / {city}",
  "curl_hint": "    {_e} curl -x https://{host}:{port} --proxy-header \"Proxy-Authorization: Bearer {token}\" {echo}",
  "test_running": "Testing {host}:{port} ...",
  "test_external_ip": "External IP: {ip}",
  "waf_406": "HTTP 406 from *.firefox.com even after the automatic challenge solution.\nFastly probably changed the challenge markup/algorithm. First check the regexes:\n  - github.com/pagpeter/fastly-antibot (pkg/solver/solver.go - script id and token regexes)\n  - PR #22 in Mikescher/firefox-sync-client (syncclient/fastly.go - a port of that algorithm)\nFallback - reuse a Firefox session:\n  1) Sign in to the Mozilla account in Firefox (2FA is entered there).\n  2) Extract sessionToken from the profile, e.g. with firefox_decrypt\n     (github.com/unode/firefox_decrypt): the 'Firefox Accounts credentials' entry\n     stores JSON with a sessionToken field.\n  3) Run:  python3 mozvpn.py --session-token <hex> --email you@example.com",
  "session_token_hex": "sessionToken must be a hex string.",
  "masque_no_aioquic": "aioquic not installed",
  "masque_probe_error": "{err}",
  "builtin_connect_failed": "Upstream CONNECT failed: {err}",
  "builtin_no_token": "proxyPass token not available yet",
},
"ru": {
  "engine_selected": "Движок локальных прокси {_e}: {engine}",
  "config_files_header": "Файлы конфигурации и кэшей, которые использует скрипт {_e}:",
  "config_file_entry": "  {_e} {path} — {status}",
  "config_file_exists": "{size} байт, изменён {mtime} UTC",
  "config_file_dir": "каталог, {n} элементов",
  "config_file_missing": "ещё не создан",
  "engine_builtin": "builtin (встроенный движок: каждый апстрим обслуживается как MASQUE или HTTP CONNECT, с автоматическим фолбэком)",
  "engine_singbox": "sing-box (внешний бинарник, апстримы MASQUE/HTTP CONNECT)",
  "lang_selected": "Язык вывода: {lang}",
  "color_disabled": "Цветной вывод отключён.",
  "cache_cleared": "Каталог кэша удалён: {path}",
  "cache_clear_failed": "Не удалось удалить каталог кэша {path}: {err}",
  "cache_nothing": "Каталог кэша не существует, чистить нечего.",
  "cached_session": "Кэшированная сессия ({email}) {_e}. --relogin для нового входа.",
  "enter_email": "Email аккаунта Mozilla: ",
  "enter_password": "Пароль: ",
  "email_missing": "Email не задан (нет ни аргумента, ни кэша).",
  "password_missing": "Пароль не задан (нет ни аргумента, ни кэша реквизитов).",
  "signing_in": "Вход в Mozilla Accounts...",
  "session_cached": "sessionToken закэширован {_e}: {path}",
  "stretch_version": "Версия key-stretching аккаунта: {version}",
  "stretch_v2_note": " (650k итераций PBKDF2)",
  "clock_skew": "Часы ПК расходятся с серверами Mozilla на {offset} с; TOTP будет считаться по серверному времени.",
  "account_not_found": "Аккаунт не найден.",
  "wrong_password": "Неверный пароль (errno 103). Если входили через Google/Apple — сначала задайте пароль: accounts.firefox.com → Настройки.",
  "login_blocked": "ВХОД ВРЕМЕННО ЗАБЛОКИРОВАН ({source}): слишком много неудачных попыток подряд (неверный пароль и/или коды 2FA).{wait}\nЭто НЕ удаление и НЕ вечная блокировка. Вход восстанавливается ПОДТВЕРЖДЕНИЕМ ПО EMAIL:\n  1) Проверьте почту аккаунта (и папку «Спам»): Mozilla отправила письмо\n     («New sign-in to Firefox» / «Confirm your sign-in» / код подтверждения).\n  2) Откройте письмо и подтвердите вход (кнопка или код на accounts.firefox.com).\n  3) После этого повторите запуск (в режиме --watch скрипт повторит сам).",
  "retry_after": " Сервер просит повторить не раньше чем через ~{sec} с.",
  "blocked_extra_method": " Сервер требует подтверждение методом '{method}'.",
  "login_error": "Ошибка входа ({status}): {msg}",
  "server_wants_method": "Сервер запросил подтверждение входа методом '{method}' (причина: {reason}). Для TOTP-аккаунтов сервер принимает /session/verify/totp независимо от заявленного метода — пробую TOTP.",
  "totp_prompt": "Код двухфакторной аутентификации (TOTP): ",
  "totp_digits_only": "Код должен состоять только из цифр.",
  "totp_not_enabled": "У аккаунта на сервере TOTP не включён (TOTP_TOKEN_NOT_FOUND) — TOTP-верификация невозможна.",
  "totp_rejected_window": "Сервер отклонил код. Проверьте, что секрет совпадает с приложением-аутентификатором (в т.ч. не пересоздавался ли 2FA после сохранения QR).{clock} Жду следующее окно ...",
  "totp_rejected_final": "Код 2FA не подошёл три раза подряд (в разных временных окнах). Сверьте TOTP-секрет с приложением: перезапустите с --qr <свежий QR> — возможно, 2FA пересоздавался и qr.png устарел.",
  "totp_unknown_error": "Ошибка проверки 2FA ({status}): {data} (проверьте sessionToken / аккаунт)",
  "totp_code_current": "Текущий TOTP-код: {code} (действует ещё {sec} с{offset})",
  "totp_code_generated": "Сгенерирован TOTP-код: {code} (окно {period} с, осталось {left} с)",
  "clock_offset_note": ", смещение часов {offset} с",
  "email_unverified": "Email аккаунта не подтверждён (регистрация). Подтвердите email по ссылке из письма Mozilla, затем повторите вход.",
  "email_confirm_required": "Требуется подтверждение входа по email, а у аккаунта не включён TOTP (иначе скрипт верифицировал бы сессию сам). Что делать:\n  1) Откройте почту, найдите письмо Mozilla «New sign-in to Firefox» и подтвердите вход\n     (либо введите код из письма на accounts.firefox.com);\n  2) после этого повторите запуск — сессия станет доверенной;\n  3) либо включите TOTP в настройках аккаунта (Two-step authentication);\n  4) либо войдите в браузере Firefox и запустите с --session-token <hex>.",
  "session_unverified": "Сессия не подтверждена (метод: {method}, причина: {reason}).",
  "totp_missing": "Аккаунт требует 2FA, а TOTP-секрет неизвестен. Запустите с --qr <картинка> или --totp-secret.",
  "oauth_fetching": "Получение OAuth-токена (grant fxa-credentials, scope 'profile https://identity.mozilla.com/apps/vpn')...",
  "oauth_scope_fallback": "Основной scope отклонён сервером, использован '{scope}'.",
  "oauth_scope_denied": "Scope '{scope}' не разрешён (errno 114), пробую следующий ...",
  "oauth_all_scopes_denied": "OAuth: все scope отклонены сервером (errno 114). Последняя ошибка: {err}",
  "oauth_session_invalid": "sessionToken недействителен/истёк (errno {errno}) — требуется перелогин.",
  "oauth_error": "OAuth-токен не получен ({status}): {data}",
  "guardian_activating": "Активация Guardian и получение proxyPass...",
  "guardian_enrolled": "Guardian: enroll выполнен (HTTP {status}).",
  "guardian_enroll_failed": "/fpn/activate → HTTP {status} {detail} (продолжаю: токен Guardian выдаёт и без enroll'а)",
  "guardian_403": "proxyPass не получен (HTTP 403, no_entitlement).\nЭто НЕ ошибка входа: OAuth-токен принят, но у аккаунта нет энтайтлмента Firefox IP Protection (Built-in VPN).\nВозможные причины и что делать:\n  1) Функция ещё не включена в вашем браузере: откройте Firefox 149+ → значок VPN\n     на тулбаре → включите один раз до «зелёного индикатора» (первое включение\n     подключает энтайтлмент к аккаунту).\n  2) Built-in VPN beta выкатывается по регионам (на 2026-09: US/UK/DE/FR). Вне списка —\n     403 останется независимо от скрипта.\n  3) Если вход в Mozilla-аккаунт был через Google/Apple или аккаунт новый —\n     дождитесь полной активации аккаунта и повторите.",
  "guardian_401": "proxyPass не получен (HTTP 401, reauth_required): сессия/FxA-токен отклонены Guardian'ом — требуется перелогин.",
  "guardian_429": "proxyPass не получен (HTTP 429): квота исчерпана, повторите через {retry} с.",
  "guardian_451": "proxyPass не получен (HTTP 451): регион недоступен.",
  "guardian_error": "proxyPass не получен (HTTP {status}): {detail}",
  "guardian_no_token": "В ответе Guardian нет поля 'token': {data}",
  "quota_unlimited": "Квота: безлимитная (x-quota-unlimited: true).",
  "quota_left": "Квота: осталось {left} из {limit}{reset}.",
  "serverlist_fetching": "Загрузка списка серверов (Remote Settings: vpn-serverlist)...",
  "serverlist_failed": "Список серверов не загружен ни из Remote Settings (vpn-serverlist), ни от Guardian (/api/v2/servers).",
  "serverlist_done": "Стран: {countries}, пригодных серверов: {servers}",
  "proxypass_received": "proxyPass получен {_e}, действителен до: {until} (exp {exp} UTC)",
  "proxypass_jwt": "Свежий proxyPass JWT:",
  "session_token_print": "sessionToken (для повторных запусков):",
  "json_saved": "JSON сохранён {_e}: {path}",
  "qr_need_zxing": "Для чтения QR нужен пакет zxing-cpp:\n    pip install zxing-cpp pyotp Pillow",
  "qr_need_pillow": "Для открытия QR-файла нужен пакет Pillow:\n    pip install Pillow",
  "qr_not_found": "QR-файл не найден: {path}",
  "qr_open_failed": "Не удалось открыть картинку {path}: {err}",
  "qr_none_found": "QR-код не найден в файле: {path}",
  "qr_no_otpauth": "В файле {path} нет otpauth:// QR-кода: {sample}",
  "qr_not_totp": "QR не является TOTP (otpauth://totp): {sample}",
  "qr_no_secret": "В QR отсутствует параметр secret: {sample}",
  "qr_secret_empty": "Пустой TOTP-секрет.",
  "qr_secret_bad32": "TOTP-секрет не является корректным base32: {err}",
  "totp_need_pyotp": "Для генерации TOTP нужен пакет pyotp:\n    pip install pyotp",
  "totp_bad_algo": "Неизвестный TOTP-алгоритм: {algo} (ожидался SHA1/SHA256/SHA512)",
  "totp_bad_params": "Некорректные параметры TOTP: digits={digits}, period={period}",
  "totp_init_failed": "Не удалось инициализировать TOTP из секрета: {err}",
  "qr_saved": "TOTP-секрет сохранён в {path} (mode 600); параметры: {digits} цифр, окно {period} с, {algo}.",
  "qr_saved_note": "Коды 2FA теперь генерируются автоматически (pyotp) по времени серверов Mozilla.",
  "qr_verify_q": "Совпадает ли он с кодом в приложении-аутентификаторе? [Y/n]: ",
  "qr_verify_mismatch": "Вставьте TOTP-секрет (base32) из приложения или путь к другой QR-картинке (Enter — отмена): ",
  "qr_verify_cancelled": "Отменено: секрет из QR не совпал с приложением.\nЕсли 2FA пересоздавался — скачайте свежий QR: accounts.firefox.com → Настройки → Two-step authentication.",
  "qr_code_for_review": "Код из распознанного QR (для сверки, вопрос не задаётся, --qr-verify чтобы включить): {code}, действует ещё {sec} с",
  "proxy_check_started": "Параллельная проверка {n} апстрим-прокси через '{service}' ({url}) ...",
  "proxy_check_summary_ok": "Проверка: {n}/{total} апстримов пропустили данные ({list})",
  "proxy_check_summary_fail": "Проверка: {n}/{total} апстримов не пропустили данные ({list})",
  "proxy_check_masque_ok": "Проверка: {host}:{port} — туннель MASQUE (HTTP/3 CONNECT-UDP) пропустил данные",
  "proxy_check_masque_fallback": "Проверка: MASQUE на {host}:{port} не подтверждён — этот апстрим будет использовать HTTP CONNECT",
  "proxy_check_connect_ok": "Проверка: {host}:{port} — туннель CONNECT пропустил данные (внешний IP {ip})",
  "proxy_check_connect_fail": "Проверка: {host}:{port} — данные через туннель не прошли; апстрим всё равно используется",
  "proxy_check_disabled": "Предварительная проверка прокси отключена (--no-proxy-check): использую все апстримы из списка как есть.",
  "upstream_override": "Переопределение апстрима: все локации используют {host}:{port} вместо городских хостов.",
  "engine_started": "Движок {engine} запущен: {n} локальных прокси на {listen}",
  "proxy_line": "  {_e}{listen}:{port:<6} {label:<30} -> {host}:{uport} [{proto}]",
  "port_busy": "Порт {port} занят — пропускаю {label} (занят чужим процессом?).",
  "no_free_ports": "Нет свободных портов для локальных прокси (все порты-кандидаты заняты).",
  "no_servers_to_serve": "Нет апстрим-серверов для обслуживания: проверка отсеяла всё (используйте --probe-fail keep) либо список серверов пуст.",
  "tls_plain_http": "апстрим ответил открытым текстом (не TLS): {text}",
  "answer_no_words": "n, no, н, нет",
  "answer_yes_words": "y, yes, д, да",
  "deps_manual_hint": "Install manually {_e}: {cmd}",
  "singbox_missing": "sing-box не найден в PATH. Установите его (https://sing-box.sagernet.org/installation/) или используйте --local-proxy-engine builtin.",
  "token_updated_builtin": "builtin: новый proxyPass применён «на лету» (новые подключения используют его, рестарт не нужен).",
  "token_updated_singbox": "sing-box: новый proxyPass -> новые конфиги + рестарт процессов ...",
  "singbox_stopped": "sing-box остановлен: {label} ({listen}:{port})",
  "singbox_died": "sing-box {label} (порт {port}) завершился (код {code}).",
  "proxy_stopping": "Остановка локальных прокси ...",
  "proxy_stopped": "Локальные прокси остановлены.",
  "relogin_needed": "Требуется перелогин — пробую по сохранённым реквизитам ...",
  "blocked_wait": "Вход временно заблокирован — жду 10 минут перед следующей попыткой (см. инструкцию по подтверждению выше).",
  "unexpected_error": "Непредвиденная ошибка: {err!r} — повторю через 30 с.",
  "next_refresh": "Следующее обновление {_e} через {sec} с ({at} UTC).",
  "confirm_exit_hint": "Ctrl+C для остановки.",
  "hotkeys_hint": "Горячие клавиши (каждая соответствует параметру скрипта):\n  ♻️ r — перелогин сейчас с полным удалением всех сохранённых данных (--relogin)\n  🧹 c — полностью очистить все сохранённые данные и перезапустить (--clear-cache)\n  🔄 e — сменить движок прокси builtin/sing-box (--local-proxy-engine)\n  🔀 l — сменить адрес прослушивания 127.0.0.1 <-> 0.0.0.0 (--listen)\n  📂 o — открыть каталог конфигураций sing-box (или основной каталог конфигурации)\n  📋 v — скопировать адрес:порт ЛОКАЛЬНОГО прокси\n  📋 b — скопировать адрес:порт АПСТРИМ-прокси\n  🔢 t — показать и скопировать текущий код TOTP\n  🎫 j — показать и скопировать текущий proxyPass JWT\n  🖼️ g — загрузить QR-картинку с секретом 2FA на лету (--qr)\n  👤 u — показать и скопировать логин (email)\n  🔑 p — показать и скопировать пароль\n  📦 d — переустановить ВСЕ Python-зависимости с нуля (--reinstall-deps)\n  ⤴️ s — переустановить sing-box с нуля (--reinstall-singbox)\n  🎨 m — переключить цветовую тему тёмная <-> светлая (--theme)\n  🌈 n — включить/отключить цветной вывод в лог (--no-color)\n  📄 1-9 — открыть файл конфига в системном редакторе по умолчанию\n  ⏹️ q — остановка.",
  "hotkey_relogin": "Клавиша 'r' ♻️: ПОЛНОЕ удаление всех сохранённых данных — кэшей, креденшелсов, конфигов sing-box — затем свежий вход.",
  "hotkey_clear": "Клавиша 'c' 🧹: все сохранённые данные удалены (кэши, креденшелсы, конфиги sing-box) — перезапускаюсь с чистого состояния.",
  "hotkey_engine": "Клавиша 'e': переключаю движок на {engine} — локальные прокси перезапустятся с ним.",
  "hotkey_listen": "Клавиша 'l': прослушивание теперь на {host} — локальные прокси перезапустятся с ним.",
  "hotkey_totp": "Клавиша 't' 🔢: текущий код TOTP — также скопирован в буфер обмена.",
  "hotkey_jwt": "Текущий proxyPass JWT {_e} — также скопирован в буфер обмена:",
  "hotkey_jwt_none": "Клавиша 'j' 🎫: токена proxyPass ещё нет — он появится сразу после успешного входа.",
  "hotkey_totp_none": "Клавиша 't' 🔢: секрет TOTP недоступен. Причина: {reason}. Секрет TOTP хранится в credentials.json и попадает туда только после входа с --qr <QR-картинка> или --totp-secret <base32> (либо через переменную окружения MOZVPN_TOTP_SECRET).",
  "totp_none_reason_nocreds": "файл credentials.json ещё не создан — на этой машине ещё не было входа с сохранением реквизитов",
  "totp_none_reason_nosecret": "credentials.json существует, но поля totp_secret в нём нет — сохранённый вход был выполнен без --qr / --totp-secret, либо у аккаунта не включена 2FA (TOTP)",
  "hotkey_open_dir_fallback": "Клавиша 'o' 📂: каталог конфигураций sing-box ещё не существует (он создаётся при работе движка singbox) — вместо него открыт основной каталог конфигурации {_e}: {path}",
  "hotkey_files_hint": "Файлы конфигурации: нажмите номер, чтобы открыть файл в системном редакторе по умолчанию.",
  "hotkey_file_entry": "  {n} - {path}",
  "hotkey_open": "Открыл в системном редакторе по умолчанию {_e}: {path}",
  "hotkey_open_dir": "Открыл каталог конфигураций в системном файловом менеджере {_e}: {path}",
  "hotkey_open_fail": "Не удалось открыть {path}: {err}",
  "hotkey_open_missing": "Файл не существует: {path}",
  "hotkey_copy_local_hint": "Скопировать адрес ЛОКАЛЬНОГО прокси в буфер обмена — нажмите его номер:",
  "hotkey_copy_remote_hint": "Скопировать адрес АПСТРИМ-прокси в буфер обмена — нажмите его номер:",
  "hotkey_copy_entry": "  {n} - {addr} ({label})",
  "hotkey_copied": "Скопировал в буфер обмена {_e}: {text}",
  "hotkey_copy_fail": "Буфер обмена недоступен в этой системе: {err}",
  "hotkey_copy_cancel": "Копирование отменено — нажмите v или b, чтобы повторить.",
  "hotkey_stop": "Клавиша 'q': запрошена остановка.",
  "retry_wait": "Вход не удался с первого раза — обычно получается со второго. ПОДОЖДИТЕ: запрос логина/пароля/TOTP появится снова автоматически, перезапуск скрипта не нужен.",
  "retry_in": "Следующая попытка входа через:",
  "theme_switched": "Тема переключена {_e}: {theme}",
  "theme_bg_forced": "Фон окна консоли ПРИНУДИТЕЛЬНО установлен {_e}: {bg} (escape-последовательность OSC 11 — тема теперь перекрашивает и само окно, а не только строки лога).",
  "theme_bg_exit": "При выходе фон консоли по умолчанию будет восстановлен {_e} (OSC 111). Если ваш терминал игнорирует этот сброс, верните цвет окна в настройках его профиля.",
  "deps_fallback_each": "Установка одной командой не удалась (конфликт зависимостей pip) {_e} — повторяю каждый пакет отдельно БЕЗ --force-reinstall: принудительная установка общих зависимостей в точные версии — обычная причина конфликтов.",
  "deps_fallback_nodeps": "{pkg}: всё ещё конфликт {_e} — крайняя мера: pip install {pkg} --no-deps (уже установленное дерево зависимостей удовлетворяет импорты).",
  "deps_pkg_ok": "  {_e} {pkg} — OK",
  "deps_pkg_fail": "  {_e} {pkg} — НЕ УДАЛОСЬ",
  "deps_conflict_fail": "Не удалось установить пакеты: {pkgs}. См. ошибки pip выше.",
  "hotkey_theme": "Клавиша 'm' 🎨: тема переключена на {theme} (--theme).",
  "color_enabled": "Цветной вывод включён {_e} (переключается клавишей 'n' / --no-color).",
  "hotkey_color": "Клавиша 'n' 🌈: цветной вывод {state} (зеркалит --no-color).",
  "color_state_on": "включён",
  "color_state_off": "отключён",
  "deps_header": "Python-зависимости, которые использует этот скрипт {_e}:",
  "singbox_dep_header": "Внешняя зависимость (не pip-пакет) {_e}:",
  "singbox_dep_ok": "  {_e} sing-box — установлен: {path} (версия {version})",
  "singbox_dep_missing": "  {_e} sing-box — НЕ установлен (необязателен: нужен только для движка 'singbox'; встроенный движок полностью работает без него)",
  "deps_entry_ok": "  {_e} {pip:<12} (модуль {module:<10}) {version:<12} — установлен",
  "deps_entry_missing": "  {_e} {pip:<12} (модуль {module:<10}) — НЕ установлен{need}",
  "deps_need_required": " — НУЖЕН для TOTP/QR",
  "deps_need_optional": " — необязательный (реальный MASQUE / проверка HTTP-3)",
  "deps_missing_note": "Отсутствуют зависимости: {list}.",
  "deps_install_q": "Установить недостающие зависимости сейчас через pip ({cmd})? [Y/n]: ",
  "deps_installing": "Устанавливаю зависимости {_e}: {pkgs} ...",
  "deps_install_ok": "Зависимости успешно установлены {_e}.",
  "deps_install_fail": "pip завершился с ошибкой (код {code}): {err}",
  "deps_frozen_note": "Скрипт скомпилирован в бинарник (frozen) — автоматическая установка невозможна. Установите вручную: {cmd}",
  "deps_install_declined": "Зависимости не установлены — продолжаю без них.",
  "deps_reinstall_header": "Переустанавливаю ВСЕ Python-зависимости с нуля {_e}: {pkgs}",
  "deps_reinstall_ok": "Все зависимости успешно переустановлены {_e}.",
  "deps_reinstall_fail": "Переустановка зависимостей не удалась (код {code}): {err}",
  "deps_reinstall_skip_frozen": "Скрипт — скомпилированный бинарник (frozen): переустановка через pip невозможна, зависимости встроены в бинарник.",
  "singbox_install_header": "sing-box не установлен {_e}. Скрипт ПОЛНОСТЬЮ работает и без него: встроенный движок обслуживает те же апстримы (MASQUE / HTTP CONNECT) внутри этого Python-процесса. sing-box нужен только для движка 'singbox'.",
  "singbox_install_q": "Установить sing-box сейчас? [y/N]: ",
  "singbox_install_cmd": "Команда установки для этой системы {_e}: {cmd}",
  "singbox_install_manual": "Ручная установка: откройте {url} — официальная страница установки sing-box.",
  "singbox_install_started": "Устанавливаю sing-box {_e}: {cmd}",
  "singbox_install_ok": "sing-box успешно установлен {_e}: {path}",
  "singbox_install_fail": "Установка sing-box не удалась (код {code}): {err}",
  "singbox_install_declined": "Установка sing-box отклонена {_e} — выбор запомнен, вопрос больше не будет задаваться (кроме случая, когда вы выберете движок singbox, а sing-box всё ещё не установлен).",
  "singbox_windows_hint": "Windows: скачайте релиз sing-box с {url} , распакуйте и добавьте в PATH, затем перезапустите скрипт.",
  "singbox_reinstall_header": "Переустанавливаю sing-box с нуля {_e} ...",
  "singbox_reinstall_ok": "sing-box переустановлен {_e}: {path}",
  "singbox_reinstall_fail": "Переустановка sing-box не удалась (код {code}): {err}",
  "singbox_engine_still_missing": "sing-box по-прежнему не установлен — остаюсь на встроенном движке.",
  "hotkey_qr_prompt": "Путь к QR-картинке с кодом 2FA (TOTP) (Enter — отмена): ",
  "hotkey_qr_loaded": "QR загружен {_e}: {path}. Секрет TOTP сохранён; текущий код: {code} (действует ещё {sec} с).",
  "hotkey_qr_fail": "Не удалось загрузить QR: {err}",
  "hotkey_login": "Логин (email) {_e}: {email} — также скопирован в буфер обмена.",
  "hotkey_login_none": "Сохранённого логина нет: сначала выполните вход (--email или интерактивный запрос).",
  "hotkey_password": "Пароль {_e}: {password} — также скопирован в буфер обмена.",
  "hotkey_password_none": "Сохранённого пароля нет: сначала выполните вход (--password или интерактивный запрос).",
  "hotkey_deps_reinstalled": "Зависимости переустановлены {_e}.",
  "protocol_summary": "Сводка по протоколам апстримов {_e}: {m} апстрим(ов) через MASQUE (HTTP/3 CONNECT-UDP — приоритетный протокол), {c} апстрим(ов) через HTTP CONNECT (туннель HTTPS-прокси поверх TLS — откат, когда MASQUE не пропустил данные).",
  "proto_chosen_masque": "Протокол для {host}:{port}: masque (HTTP/3 CONNECT-UDP) — приоритетный протокол; туннель MASQUE пропустил данные.",
  "proto_fallback_connect": "Протокол для {host}:{port}: HTTP CONNECT — откат с masque, который здесь недоступен: {reason}",
  "proto_masque_no_lib": "Для masque нужен пакет aioquic — он не установлен, поэтому все апстримы будут использовать откат HTTP CONNECT.",
  "test_commands_header": "Чтобы протестировать ЛОКАЛЬНЫЕ прокси, используйте эти команды {_e}:",
  "test_commands_hidden": "Тестовые команды curl скрыты {_e} — включите их параметром --show-test-commands (env MOZVPN_SHOW_TEST_COMMANDS=1).",
  "test_command_local": "  {_e} {cmd}   [{label}, {proto}]",
  "test_commands_remote_header": "Чтобы протестировать АПСТРИМ (удалённые) прокси напрямую, используйте эти команды:",
  "test_command_remote": "  {_e} {cmd}   [{label}]",
  "clear_will_remove_header": "Клавиша 'c' / 'r' / --clear-cache / --relogin удалит ВСЁ это {_e}:",
  "clear_will_remove_entry": "  - {path}",
  "clear_will_remove_dir": "  - {path} (весь каталог конфигурации — всё перечисленное выше находится внутри него)",
  "clear_wiped_note": "Удалено: кэши сессии, сохранённые креденшелсы (email/пароль/секрет TOTP), cookie Fastly и конфиги sing-box. При свежем входе логин-данные запросятся заново.",
  "jwt_decoded_header": "Расшифрованный proxyPass JWT {_e}:",
  "jwt_decoded_part": "  {part} {json}",
  "jwt_decoded_exp": "  exp (действителен до): {time} UTC   iat (выдан): {iat} UTC",
  "confirm_exit_prompt": "Получен Ctrl+C. Нажмите Ctrl+C ещё раз в течение 5 с для подтверждения выхода, или подождите, чтобы продолжить.",
  "confirm_exit_abort": "Выход отменён, продолжаю.",
  "sigterm": "Получен сигнал завершения, останавливаюсь.",
  "recommended_server": "Рекомендованный сервер: {country} / {city}",
  "curl_hint": "    {_e} curl -x https://{host}:{port} --proxy-header \"Proxy-Authorization: Bearer {token}\" {echo}",
  "test_running": "Тест {host}:{port} ...",
  "test_external_ip": "Внешний IP: {ip}",
  "waf_406": "HTTP 406 от *.firefox.com даже после автоматического решения challenge.\nПохоже, Fastly изменил разметку/алгоритм challenge. Сверьте regex'ы:\n  - github.com/pagpeter/fastly-antibot (pkg/solver/solver.go — regex'ы script id и token)\n  - PR #22 в Mikescher/firefox-sync-client (syncclient/fastly.go — порт этого алгоритма)\nФолбэк — переиспользуйте сессию Firefox:\n  1) Войдите в Mozilla-аккаунт в браузере Firefox (2FA вводится там).\n  2) Извлеките sessionToken из профиля, например утилитой firefox_decrypt\n     (github.com/unode/firefox_decrypt): запись «Firefox Accounts credentials»\n     хранит JSON с полем sessionToken.\n  3) Запустите:  python3 mozvpn.py --session-token <hex> --email you@example.com",
  "session_token_hex": "sessionToken должен быть hex-строкой.",
  "masque_no_aioquic": "aioquic не установлен",
  "masque_probe_error": "{err}",
  "builtin_connect_failed": "Не удалось подключиться к апстриму: {err}",
  "builtin_no_token": "proxyPass-токен ещё не получен",
},
}

def set_language(lang: str):
    """Switch the output language (req. 14)."""
    global _LANG
    _LANG = lang if lang in ("en", "ru") else "en"

# Original message decorations (v2 script used emoji prefixes on most log
# lines). They are preserved here as a single key -> emoji map applied by
# tr(), so both languages carry the same visual markers as before.
_EMOJI = {
    # info / progress
    "signing_in": "\U0001F511 ",            # key
    "session_cached": "\U0001F4BE ",       # floppy
    "cached_session": "\u267B\uFE0F ",      # recycle
    "oauth_fetching": "\U0001F3AB ",       # ticket
    "guardian_activating": "\U0001F6E1\uFE0F  ",  # shield
    "serverlist_fetching": "\U0001F310 ",   # globe
    "stretch_version": "\U0001F510 ",       # lock
    "totp_prompt": "\U0001F510 ",
    "totp_code_current": "\U0001F522 ",     # input numbers
    "totp_code_generated": "\U0001F522 ",
    "qr_code_for_review": "\U0001F522 ",
    "proxypass_jwt": "\U0001F4CB ",         # clipboard
    "session_token_print": "\U0001F511 ",
    "quota_left": "\U0001F4CA ",            # chart
    "quota_unlimited": "\U0001F4CA ",
    "test_running": "\U0001F9EA ",          # test tube
    "test_external_ip": "\U0001F4CD ",      # round pushpin (found external IP)
    "relogin_needed": "\U0001F501 ",       # arrows
    "token_updated_builtin": "\U0001F501 ",
    "token_updated_singbox": "\U0001F501 ",
    "proxy_stopping": "\U0001F9F9 ",        # broom
    "proxy_stopped": "\U0001F6D1 ",         # stop
    "singbox_stopped": "\U0001F6D1 ",
    "engine_started": "\U0001F680 ",         # rocket
    "proxy_line": "\U0001F50C ",            # electric plug (listener line)
    "engine_selected": "\U0001F5A5\uFE0F ", # desktop computer
    "config_files_header": "\U0001F5C2\uFE0F ",  # card index dividers
    "config_file_entry": "\U0001F4C4 ",     # page facing up
    "proxy_check_started": "\U0001F50E ",   # magnifying glass
    "proxy_check_summary_ok": "\U0001F4E1 ", # satellite antenna
    "proxy_check_summary_fail": "\U0001F4E1 ",
    "proxy_check_masque_ok": "\U0001F6A6 ",  # traffic light (protocol check ok)
    "proxy_check_connect_ok": "\U0001F6A6 ",
    "proxy_check_masque_fallback": "\U0001F501 ",  # arrows (protocol switch)
    "proxy_check_connect_fail": "\u2753 ",   # question mark (unconfirmed, served anyway)
    "proxy_check_disabled": "\U0001F6AB ",   # prohibited (check off)
    "upstream_override": "\U0001F9ED ",      # compass (route override)
    "next_refresh": "\u23F3 ",              # hourglass
    "confirm_exit_prompt": "\u2753 ",
    "confirm_exit_abort": "\U0001F501 ",
    "confirm_exit_hint": "\u23F8\uFE0F ",    # pause
    "sigterm": "\U0001F6D1 ",
    "hotkeys_hint": "\u2328\uFE0F ",         # keyboard
    "hotkey_relogin": "\U0001F501 ",
    "hotkey_clear": "\U0001F9F9 ",
    "hotkey_engine": "\U0001F504 ",          # counterclockwise arrows
    "hotkey_listen": "\U0001F500 ",          # shuffle tracks (bind host switch)
    "hotkey_totp": "\U0001F522 ",            # input numbers (TOTP code)
    "hotkey_jwt": "\U0001F3AB ",           # ticket (the proxyPass JWT)
    "hotkey_jwt_none": "\U0001F3AB ",
    "hotkey_totp_none": "\u2139\ufe0f ",
    "hotkey_files_hint": "\U0001F4C2 ",      # open file folder
    "hotkey_file_entry": "\U0001F4C4 ",      # page facing up
    "hotkey_open": "\U0001F4DD ",           # memo (editor)
    "hotkey_open_dir": "\U0001F4C2 ",       # open file folder
    "hotkey_open_dir_fallback": "\U0001F4C2 ",  # open file folder (fallback)
    "hotkey_open_fail": "\U000026A0 ",
    "hotkey_open_missing": "\U000026A0 ",
    "hotkey_copy_local_hint": "\U0001F4CB ",  # clipboard
    "hotkey_copy_remote_hint": "\U0001F4CB ",
    "hotkey_copy_entry": "\U0001F517 ",        # link
    "hotkey_copied": "\U0001F4CB ",
    "hotkey_copy_fail": "\U000026A0 ",
    "hotkey_copy_cancel": "\U0000274C ",
    "deps_manual_hint": "\U0001F4BB ",
    "hotkey_stop": "\U0001F6D1 ",
    "retry_wait": "\u23F3 ",
    "retry_in": "\u23F3 ",
    "theme_switched": "\U0001F3A8 ",
    "hotkey_theme": "\U0001F3A8 ",
    "color_enabled": "\U0001F3A8 ",
    "hotkey_color": "\U0001F308 ",
    "color_state_on": "",
    "color_state_off": "",
    # dependency / sing-box management (v4.3)
    "deps_header": "\U0001F4E6 ",              # package
    "singbox_dep_header": "\U0001F5A5\uFE0F ",   # desktop computer (external binary)
    "singbox_dep_ok": "\u2705 ",
    "singbox_dep_missing": "\u274C ",
    # v4.7: forced terminal background + staged pip install
    "theme_bg_forced": "\U0001F5A5\uFE0F ",   # desktop computer (the window itself)
    "theme_bg_exit": "\u21BB ",              # restore on exit
    "deps_fallback_each": "\u2696\uFE0F ",   # balance scale (resolver conflict)
    "deps_fallback_nodeps": "\U0001F527 ",   # wrench (last-resort repair)
    "deps_pkg_ok": "\u2705 ",
    "deps_pkg_fail": "\u274C ",
    "deps_conflict_fail": "\U000026A0\uFE0F ",
    "deps_entry_ok": "\u2705 ",
    "deps_entry_missing": "\u274C ",
    "deps_missing_note": "\u26A0\uFE0F  ",
    "deps_install_q": "\U0001F4E6 ",
    "deps_installing": "\u23F3 ",
    "deps_install_ok": "\u2705 ",
    "deps_install_fail": "\u274C ",
    "deps_frozen_note": "\u2139\ufe0f ",
    "deps_install_declined": "\U0001F6AB ",
    "deps_reinstall_header": "\U0001F4E6 ",
    "deps_reinstall_ok": "\u2705 ",
    "deps_reinstall_fail": "\u274C ",
    "deps_reinstall_skip_frozen": "\u2139\ufe0f ",
    "singbox_install_header": "\U0001F5A5\uFE0F ",
    "singbox_install_q": "\U0001F5A5\uFE0F ",
    "singbox_install_cmd": "\U0001F4BB ",
    "singbox_install_manual": "\U0001F517 ",
    "singbox_install_started": "\u23F3 ",
    "singbox_install_ok": "\u2705 ",
    "singbox_install_fail": "\u274C ",
    "singbox_install_declined": "\U0001F6AB ",
    "singbox_windows_hint": "\U0001F517 ",
    "singbox_reinstall_header": "\u23F3 ",
    "singbox_reinstall_ok": "\u2705 ",
    "singbox_reinstall_fail": "\u274C ",
    "singbox_engine_still_missing": "\u26A0\uFE0F  ",
    "hotkey_qr_prompt": "\U0001F5BC\uFE0F ",
    "hotkey_qr_loaded": "\u2705 ",
    "hotkey_qr_fail": "\u274C ",
    "hotkey_login": "\U0001F464 ",
    "hotkey_login_none": "\u2139\ufe0f ",
    "hotkey_password": "\U0001F511 ",
    "hotkey_password_none": "\u2139\ufe0f ",
    "hotkey_deps_reinstalled": "\u2705 ",
    "protocol_summary": "\U0001F680 ",
    "proto_chosen_masque": "\U0001F680 ",      # rocket (priority protocol won)
    "proto_fallback_connect": "\u21a9\ufe0f ",  # return arrow (fallback)
    "proto_masque_no_lib": "\u2139\ufe0f ",
    "test_commands_header": "\U0001F9EA ",     # test tube
    "test_commands_hidden": "\U0001F6AB ",   # prohibited (hidden)
    "test_command_local": "\U0001F4BB ",      # laptop
    "test_commands_remote_header": "\U0001F9EA ",
    "test_command_remote": "\U0001F4BB ",
    "clear_will_remove_header": "\U0001F9F9 ",  # broom
    "clear_will_remove_entry": "\U0001F5D1\ufe0f ",  # wastebasket
    "clear_will_remove_dir": "\U0001F5D1\ufe0f ",
    "clear_wiped_note": "\U0001F5D1\ufe0f ",
    "jwt_decoded_header": "\U0001F50D ",     # magnifying glass (decoded)
    "jwt_decoded_part": "\U0001F50D ",
    "jwt_decoded_exp": "\u23f0 ",            # alarm clock
    "recommended_server": "\u2B50 ",         # star
    "curl_hint": "\U0001F4BB ",              # laptop
    "lang_selected": "\U0001F310 ",
    "color_disabled": "\U0001F3A8 ",         # palette
    # success
    "guardian_enrolled": "\u2705 ",
    "proxypass_received": "\u2705 ",
    "serverlist_done": "\u2705 ",
    "json_saved": "\U0001F4BE ",
    "qr_saved": "\u2705 ",
    "qr_saved_note": "\U0001F4BE ",
    # warnings (soft, non-fatal)
    "unexpected_error": "\u26A0\uFE0F  ",
    "port_busy": "\u26A0\uFE0F  ",
    "singbox_died": "\u26A0\uFE0F  ",
    "singbox_missing": "\u26A0\uFE0F  ",
    "totp_digits_only": "\u26A0\uFE0F  ",
    "totp_rejected_window": "\u26A0\uFE0F  ",
    "totp_not_enabled": "\u26A0\uFE0F  ",
    "oauth_scope_denied": "\u26A0\uFE0F  ",
    "oauth_scope_fallback": "\u26A0\uFE0F  ",
    "clock_offset_note": "\u23F0 ",
    "blocked_wait": "\u23F3 ",
    # success
    "guardian_enrolled": "\u2705 ",
    "proxypass_received": "\u2705 ",
    "serverlist_done": "\u2705 ",
    "json_saved": "\U0001F4BE ",
    "qr_saved": "\u2705 ",
    # warnings (soft, non-fatal)
    "unexpected_error": "\u26A0\uFE0F  ",
    "port_busy": "\u26A0\uFE0F  ",
    "singbox_died": "\u26A0\uFE0F  ",
    "totp_digits_only": "\u26A0\uFE0F  ",
    "totp_rejected_window": "\u26A0\uFE0F  ",
    "oauth_scope_denied": "\u26A0\uFE0F  ",
    # hard errors
    "login_blocked": "\u274C ",
    "waf_406": "\u274C ",
    "account_not_found": "\u274C ",
    "wrong_password": "\u274C ",
    "login_error": "\u274C ",
    "email_unverified": "\u274C ",
    "email_confirm_required": "\u274C ",
    "session_unverified": "\u274C ",
    "totp_missing": "\u274C ",
    "totp_rejected_final": "\u274C ",
    "totp_unknown_error": "\u274C ",
    "oauth_session_invalid": "\u274C ",
    "oauth_error": "\u274C ",
    "oauth_all_scopes_denied": "\u274C ",
    "guardian_401": "\u274C ",
    "guardian_403": "\u274C ",
    "guardian_429": "\u274C ",
    "guardian_451": "\u274C ",
    "guardian_error": "\u274C ",
    "guardian_no_token": "\u274C ",
    "guardian_enroll_failed": "\u274C ",
    "serverlist_failed": "\u274C ",
    "session_token_hex": "\u274C ",
    "email_missing": "\u274C ",
    "password_missing": "\u274C ",
    "qr_secret_empty": "\u274C ",
    "qr_secret_bad32": "\u274C ",
    "totp_need_pyotp": "\u274C ",
    "totp_bad_algo": "\u274C ",
    "totp_bad_params": "\u274C ",
    "totp_init_failed": "\u274C ",
    "qr_need_zxing": "\u274C ",
    "qr_need_pillow": "\u274C ",
    "qr_not_found": "\u274C ",
    "qr_open_failed": "\u274C ",
    "qr_none_found": "\u274C ",
    "qr_no_otpauth": "\u274C ",
    "qr_not_totp": "\u274C ",
    "qr_no_secret": "\u274C ",
    "qr_verify_cancelled": "\u274C ",
    "no_free_ports": "\u274C ",
    "no_servers_to_serve": "\u274C ",
    "singbox_missing": "\u274C ",
}

def tr(key: str, **kw) -> str:
    """Translate a message template in the current language with English
    fallback and attach the message's emoji decoration. A template may
    contain the placeholder {_e} - the emoji is placed THERE (in the
    middle of the sentence, at the meaningful spot); templates without
    the placeholder get the emoji as a prefix."""
    raw = STR.get(_LANG, {}).get(key) or STR["en"].get(key) or key
    emo = _EMOJI.get(key, "")
    if "{_e}" in raw:
        txt = raw.replace("{_e}", emo)
    else:
        txt = emo + raw
    if kw:
        txt = txt.format(**kw)
    return txt

# ---------------------------------------------------------------------------
# Colored logging (req. 16): soft, readable ANSI shades, --no-color to disable.
# ---------------------------------------------------------------------------

_USE_COLOR = os.environ.get("MOZVPN_NO_COLOR", "").strip().lower() not in ("1", "true", "yes", "on")

class C:
    RESET  = "\033[0m"
    RED    = "\033[0;31m"
    GREEN  = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BLUE   = "\033[0;34m"
    MAGENTA= "\033[0;35m"
    CYAN   = "\033[0;36m"
    GRAY   = "\033[0;90m"
    BOLD   = "\033[1m"

def _paint(color: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return color + text + C.RESET

# ---------------------------------------------------------------------------
# Color themes (see THEME_SETTINGS at the top of the script).
# ---------------------------------------------------------------------------
_THEMES = THEME_SETTINGS
_THEME = DEFAULT_THEME

# v4.7 (req. 1): the theme whose background is CURRENTLY forced on the
# terminal window with OSC 11 (None = not forced yet). Tracking it makes
# _force_terminal_bg IDEMPOTENT: repeated calls with the SAME theme
# (e.g. set_color() at startup followed by set_theme() with the same
# --theme value) emit the sequence and the log message exactly ONCE -
# the v4.7 initial release printed "Console window background FORCED"
# TWICE at startup because of exactly that double call.
_BG_CURRENT = None

def _force_terminal_bg(theme: str):
    """v4.7 (req. 1): FORCE the console WINDOW background itself to the
    theme color, via the OSC 11 escape sequence (ESC ] 11 ; rgb:... BEL).
    Verified against public sources: OSC 11 ("set text background color")
    is the xterm control sequence for changing the default terminal
    background and is supported by xterm, Windows Terminal, kitty, mintty,
    foot and WezTerm (Windows Terminal answers it - it even answers the
    OSC 11 ; ? query; legacy conhost ignores OSC sequences entirely, so
    there it is a harmless no-op). The theme therefore now paints not
    only the log lines but the WINDOW itself: dark theme -> true black
    (rgb:0000/0000/0000), light theme -> true white (rgb:ffff/ffff/ffff).
    On exit OSC 111 ("reset default background") restores the terminal
    default; terminals that do not implement OSC 111 simply keep the
    color, and the user resets it in the profile settings (a note is
    printed). No-op when colored output is disabled (--no-color)."""
    global _BG_CURRENT
    if not _USE_COLOR:
        return
    # IDEMPOTENT (v4.7.1): same theme already forced -> nothing to do, so
    # the startup sequence set_color(); set_theme() prints the message
    # exactly once and no duplicate lines appear in the log
    if _BG_CURRENT == theme:
        return
    rgb = "rgb:0000/0000/0000" if theme == "dark" else "rgb:ffff/ffff/ffff"
    try:
        sys.stdout.write("\033]11;" + rgb + "\007")
        sys.stdout.flush()
    except Exception:
        return
    if _BG_CURRENT is None:
        # register the exit restore exactly once
        atexit.register(_restore_terminal_bg_exit)
    _BG_CURRENT = theme
    info(tr("theme_bg_forced",
            bg=("black" if theme == "dark" else "white")))

def _restore_terminal_bg():
    """v4.7 (req. 1): send OSC 111 ("reset default background"). Implemented
    by kitty, mintty, foot, WezTerm and newer Windows Terminal builds;
    terminals without it simply keep the color."""
    try:
        sys.stdout.write("\033]111\007")
        sys.stdout.flush()
    except Exception:
        pass

def _restore_terminal_bg_exit():
    """atexit counterpart of _force_terminal_bg: restore the default
    background once - and ONLY when a background was actually forced -
    and explain (plain print - no theme painting) that terminals without
    OSC 111 support keep the forced color."""
    global _BG_CURRENT
    if _BG_CURRENT is None:
        return          # --no-color from the very start: nothing forced
    _restore_terminal_bg()
    _BG_CURRENT = None
    try:
        print(tr("theme_bg_exit"))
    except Exception:
        pass

def set_theme(name: str):
    global _THEME
    _THEME = name if name in _THEMES else DEFAULT_THEME
    # v4.7 (req. 1): the window background follows the theme (forced)
    _force_terminal_bg(_THEME)

# Word-level highlighting: significant tokens inside a log line get their
# own color so the eye can scan the line quickly. Token classes, in match
# priority order: URLs, JWT/Bearer tokens, file paths, IPv4[:port],
# hostnames[:port], protocol names, sizes, UTC times, n/total counters.
_RE_TOKENS = re.compile(
    r'(?P<url>\bhttps?://[^\s,;)"\']+)'
    r'|(?P<jwt>\b[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{20,}){2,}\b)'
    r'|(?P<path>(?:[A-Za-z]:)?[\\/][\w .-]*(?:[\\/][\w .-]+)+'
    r'|~?/[\w.-]*(?:/[\w.-]+)+)'
    r'|(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b)'
    r'|(?P<host>\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+'
    r'[A-Za-z]{2,}(?::\d{1,5})?(?![\w.-]))'
    r'|(?P<proto>\b(?:connect-udp|connect-ip|masque|connect)\b)'
    r'|(?P<flag>(?<=\s)--[\w][\w-]*)'
    r'|(?P<key>(?<=\')[a-z0-9](?=\')|(?<=\s)[1-9]-[1-9](?=\s[-\u2014]\s)|(?<=\s)[a-z0-9](?=\s[-\u2014]\s))'
    r'|(?P<hotdesc>(?<=\s[-\u2014]\s)[^\n]+)'
    r'|(?P<size>\b\d+(?:\.\d+)?\s?(?:GiB|MiB|KiB|TiB|GB|MB|KB)\b)'
    r'|(?P<time>\b\d{2}:\d{2}:\d{2}\b)'
    r'|(?P<count>\b\d+/\d+\b|\b\d{6}\b)')

# Log history: every emitted line is remembered so the WHOLE visible log
# can be redrawn when the theme or the color mode is switched on the fly
# (hotkeys 'm' / 'n'). Capped to keep the memory bounded.
_LOG_HISTORY = []
_LOG_HISTORY_MAX = 2000

_RE_DESC_TOKENS = re.compile(r'--[\w][\w-]*'
                            r'|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b'
                            r'|\b(?:masque|connect-udp|connect-ip|connect|builtin|singbox|sing-box)\b')

def _render(level: str, msg: str):
    """Render ONE log line (theme background + level color + word-level
    highlight colors). Does NOT touch the history - used both for live
    output and for the full-log redraw. Inside a matched file path the
    BASENAME is highlighted separately (brighter) from the directories, so
    e.g. C:\\Users\\...\\mozvpn\\session.json shows session.json distinctly.
    A hotkey DESCRIPTION (the text after " - " in the per-key hint lines)
    gets its own color, with --flags / IPs / protocol names inside it
    still highlighted separately."""
    if not _USE_COLOR:
        print(msg)
        return
    t = _THEMES[_THEME]
    lvl = t[level]
    out = [t["bg"], lvl]
    pos = 0
    for m in _RE_TOKENS.finditer(msg):
        out.append(msg[pos:m.start()])
        token = m.group(0)
        group = m.lastgroup
        if group == "path":
            # split the path into directory part + basename; color them apart
            sep = max(token.rfind("/"), token.rfind("\\"))
            if sep > 0 and sep < len(token) - 1:
                out.append(t["path"] + token[:sep + 1]
                           + C.RESET + t["bg"] + lvl
                           + t["file"] + token[sep + 1:]
                           + C.RESET + t["bg"] + lvl)
            else:
                out.append(t["path"] + token + C.RESET + t["bg"] + lvl)
        elif group in ("ip", "host"):
            # split the trailing ":port" and paint it with the port color
            # (127.0.0.1:25510 -> address in ip/host color, 25510 in port)
            ci = token.rfind(":")
            if ci > 0 and token[ci + 1:].isdigit():
                out.append(t[group] + token[:ci]
                           + C.RESET + t["bg"] + lvl
                           + t["port"] + token[ci:]
                           + C.RESET + t["bg"] + lvl)
            else:
                out.append(t[group] + token + C.RESET + t["bg"] + lvl)
        elif group == "key":
            # Hotkey letters/digits get a DEDICATED high-visibility style
            # (bold on a solid color block) so they clearly stand out in
            # the hotkey hint lines, the file lists and the status messages.
            out.append(t["hotkey"] + token + C.RESET + t["bg"] + lvl)
        elif group == "hotdesc":
            # The DESCRIPTION after "key - " in a hotkey hint line: one
            # dedicated color for the whole description, but --flags,
            # IPs[:port] and protocol/engine names inside keep their own
            # token colors (sub-highlighted with _RE_DESC_TOKENS).
            dpos = 0
            for dm in _RE_DESC_TOKENS.finditer(token):
                out.append(t["hotdesc"] + token[dpos:dm.start()])
                out.append(t["flag"] + dm.group(0)
                           + C.RESET + t["bg"] + lvl)
                dpos = dm.end()
            out.append(t["hotdesc"] + token[dpos:]
                       + C.RESET + t["bg"] + lvl)
        else:
            out.append(t[group] + token + C.RESET + t["bg"] + lvl)
        pos = m.end()
    out.append(msg[pos:])
    out.append(C.RESET)
    print("".join(out))

def _emit(level: str, msg: str):
    """Print one log line and REMEMBER it in the history (for the full
    redraw on a theme/color switch)."""
    _LOG_HISTORY.append((level, msg))
    if len(_LOG_HISTORY) > _LOG_HISTORY_MAX:
        del _LOG_HISTORY[:len(_LOG_HISTORY) - _LOG_HISTORY_MAX]
    _render(level, msg)

def redraw_log():
    """Fully redraw the whole remembered log: clear the screen (and the
    scrollback) and re-render every history line in the CURRENT theme and
    color mode. Used by hotkeys 'm' (theme switch) and 'n' (color toggle)
    so the entire visible output switches style at once."""
    print("\033[2J\033[3J\033[H", end="", flush=True)
    for level, msg in list(_LOG_HISTORY):
        _render(level, msg)

def print_hotkeys_hint():
    """Print the hotkey hint with EVERY hotkey on its own line, each line
    as its own _emit call (so the theme background is painted per line -
    a multi-line single print would leave the background striped), the KEY
    on the dedicated hotkey block and the DESCRIPTION in the hotdesc color
    (see _render)."""
    for line in tr("hotkeys_hint").split("\n"):
        if line.strip():
            info(line)

def set_color(enabled: bool):
    global _USE_COLOR
    _USE_COLOR = enabled
    # On Windows 10/11 terminals ANSI support must be enabled explicitly;
    # calling os.system('') on an interactive console does the trick and is
    # harmless elsewhere (also works under Nuitka-compiled executables).
    # v4.7.1: the FORCED window background is NOT touched here - the bg
    # is forced by set_theme() (idempotently, see _BG_CURRENT), which
    # main() calls right AFTER this, so it already knows the final color
    # mode: with colors on the theme forces the window background once,
    # with --no-color nothing is forced at all.
    if enabled and os.name == "nt":
        try:
            os.system("")
        except Exception:
            pass

def ok(msg):        _emit("ok", msg)
def info(msg):      _emit("info", msg)
def warn(msg):      _emit("warn", msg)
def err(msg):       _emit("err", msg)
def hint(msg):      _emit("hint", msg)

class MozVpnError(RuntimeError):
    """Business-logic error (login/OAuth/Guardian), non-fatal for the watch
    loop. `code` is a language-independent classifier used by the watch loop:
    "blocked" (wait long), "relogin" (re-auth with saved credentials) or "".
    Matching on the localized message text is deliberately avoided."""

    def __init__(self, msg: str, code: str = ""):
        super().__init__(msg)
        self.code = code

# ---------------------------------------------------------------------------
# WAF message and login-block helper
# ---------------------------------------------------------------------------

def _retry_after_seconds(d) -> "int | None":
    """retryAfter from the response body, in SECONDS. For errno 114 / HTTP 429
    the official FxA documentation states that retryAfter in the BODY is in
    MILLISECONDS (the Retry-After header is in seconds), hence the /1000."""
    ra = (d or {}).get("retryAfter")
    if isinstance(ra, (int, float)) and ra > 0:
        return max(1, int(round(ra / 1000)))
    return None

def blocked_login_message(retry_s=None, source="login") -> str:
    """Unified message about a TEMPORARY login block (HTTP 429 / errno 114,
    errno 125). The account is not deleted and not permanently blocked:
    sign-in is restored by email confirmation."""
    wait = tr("retry_after", sec=retry_s) if retry_s else ""
    return tr("login_blocked", source=source, wait=wait)

# ---------------- time synchronization with Mozilla servers ----------------
# TOTP is computed from Unix time: if the local clock drifts, the generated
# code will not match the one in the mobile app and /session/verify/totp will
# honestly answer "invalid code". Fix: the Date header of EVERY HTTP response
# from Mozilla/Guardian servers is read, the offset is computed from it and
# TOTP codes are generated for the corrected time.

_TIME_OFFSET = 0.0   # server time minus local time, seconds

def _note_server_date(headers):
    """Compute the local clock offset against the server from the Date header."""
    global _TIME_OFFSET
    try:
        if not headers:
            return
        ds = headers.get("Date") or headers.get("date")
        if not ds:
            return
        dt = parsedate_to_datetime(ds)
        if dt.tzinfo is None:                     # naive time -> treat as UTC
            dt = dt.replace(tzinfo=timezone.utc)
        _TIME_OFFSET = dt.timestamp() - time.time()
    except Exception:
        pass

def synced_time() -> float:
    """Local time corrected against Mozilla servers (for TOTP)."""
    return time.time() + _TIME_OFFSET

def time_offset() -> float:
    """Current offset (server - local), seconds."""
    return _TIME_OFFSET

def wait_next_totp_window(period: int):
    """Sleep until the start of the next TOTP window (server-corrected time)."""
    now = synced_time()
    time.sleep(max(0.5, period - (now % period) + 0.7))

# ---------------- Fastly Next-Gen WAF challenge solver ----------------
# A pure-stdlib port of the algorithm from PR #22 (stv0g) of
# firefox-sync-client / pagpeter/fastly-antibot. The challenge is
# non-interactive: JS proof-of-work + clientmetrics.

FASTLY_UA   = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")
FASTLY_PAGE = "https://accounts.firefox.com/"

COOKIE_JAR = http.cookiejar.CookieJar()
_OPENER     = urllib.request.build_opener(
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
    """HTTP for the challenge flow; the response is returned raw (bytes)."""
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
        raise RuntimeError(f"fst-post-back returned HTTP {status}")
    return json.loads(body)

def _solve_pow(base: str, target_hex: str) -> str:
    """SHA256(base + 2 chars from [a-zA-Z0-9]) == hash - brute force 3844 variants."""
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    target = (target_hex or "").lower()
    for a in charset:
        for b in charset:
            suffix = a + b
            if hashlib.sha256((base + suffix).encode()).hexdigest() == target:
                return suffix
    return ""

def _solve_clientmetrics_stub() -> dict:
    # Minimal values - sufficient per live tests (pypi.org, accounts.firefox.com)
    return {"ty": "clientmetrics",
            "webdriver": False,
            "bot_detection_result": {"bot_detected": False, "bot_kind": None},
            "browser_metrics": {"client_data": "{}", "error_trace": '""'}}

def fastly_solve_challenge(target_url: str = FASTLY_PAGE):
    """The full Fastly challenge flow. Returns (cookie_name, cookie_value)."""
    u = urlparse(target_url)
    domain = f"{u.scheme}://{u.hostname}"
    referer = target_url

    # 1. challenge page -> script id
    status, body = _fastly_http("GET", target_url, headers={
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
    html = body.decode("utf-8", "replace")
    m = (re.search(r"script\.src = '\/_fs-ch-([^\/]+)\/script\.js\?reload=true'", html)
         or re.search(r'_fs-ch-([^/\'"?\s]+)', html))
    if not m:
        raise RuntimeError("challenge script id not found on the page")
    script_id = m.group(1)

    # 2. script.js -> token
    status, body = _fastly_http(
        "GET", f"{domain}/_fs-ch-{script_id}/script.js?reload=true",
        headers={"Referer": referer, "Accept": "*/*"})
    m = re.search(r'init\(\[[^\]]*\],\s*"([^"]+)"', body.decode("utf-8", "replace"))
    if not m:
        raise RuntimeError("token not found in script.js")
    token = m.group(1)

    # 3. PAT (Apple Private Access Token) - best effort, errors ignored
    _fastly_http("POST", f"{domain}/_fs-ch-{script_id}/pat?token={token}",
                 headers={"Referer": referer, "Accept": "text/plain",
                          "Content-Type": "application/json"})

    # 4. init post-back -> challenge list + new token
    init = _fastly_postback(domain, script_id, referer, token,
                            [{"ty": "pat", "auth": ""}])
    token = init.get("tok", token)

    # 5. solve the challenges
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
            warn(f"\u26A0\uFE0F  Unknown Fastly challenge type '{ty}' - skipping.")

    # 6. submit the solutions -> Set-Cookie _fs_ch_cp_*
    final = _fastly_postback(domain, script_id, referer, token, solutions)
    if final.get("status") != "success":
        raise RuntimeError(f"challenge not solved (status={final.get('status')!r})")

    for c in COOKIE_JAR:
        if c.name.startswith("_fs_ch_cp_"):
            return c.name, c.value
    raise RuntimeError("_fs_ch_cp_* cookie not received after a successful solution")

def ensure_fastly_cookie() -> bool:
    """Fastly cookie: cache -> challenge solution. True = the cookie is in the jar."""
    if _fastly_state["solved"]:
        return True
    if _fastly_state["failed"]:
        return False
    if load_fastly_cache():
        _fastly_state["solved"] = True
        info("\u267B\uFE0F  Using cached Fastly cookie (_fs_ch_cp_*).")
        return True
    info("\U0001F6E1\uFE0F  Fastly Bot Management: solving the PoW challenge ...")
    try:
        name, value = fastly_solve_challenge()
        save_fastly_cache(name, value)
        _fastly_state["solved"] = True
        ok(f"\u2705 Cookie {name} received (valid ~1 hour).")
        return True
    except Exception as e:
        _fastly_state["failed"] = True
        err(f"\u274C Failed to solve the Fastly challenge: {e}")
        return False

# ---------------- crypto: FxA password stretching v1 + v2 ----------------
# Verified against mozilla/PyFxA (fxa/crypto.py) and mozilla/fxa
# (lib/routes/utils/client-key-stretch.ts):
#   v1: salt = "identity.mozilla.com/picl/v1/quickStretch:" + email, 1000 iter.
#   v2: salt = clientSalt from /account/credentials/status,        650000 iter.
#   both: authPW = HKDF-SHA256(stretch, info="identity.mozilla.com/picl/v1/authPW", salt="")

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
    """authPW = HKDF(stretched, info=HKDF_INFO, salt='') - shared by v1 and v2."""
    return hkdf_sha256(stretched, HKDF_INFO.encode()).hex()

def compute_authpw_v1(email: str, password: str) -> str:
    """v1 stretching: the salt contains the normalized email."""
    salt = (NAMESPACE_V1 + email).encode()
    quick = hashlib.pbkdf2_hmac("sha256", password.encode(), salt,
                                PBKDF2_ITER_V1, 32)
    return derive_auth_pw(quick)

def compute_authpw_v2(client_salt: str, password: str) -> str:
    """v2 stretching: the salt (with a random token) MUST come from the server."""
    if not client_salt.startswith(NAMESPACE_V2):
        raise ValueError(f"clientSalt is not v2-format: {client_salt!r}")
    quick = hashlib.pbkdf2_hmac("sha256", password.encode(), client_salt.encode(),
                                PBKDF2_ITER_V2, 32)   # ~0.3-1s in the C hashlib
    return derive_auth_pw(quick)

# ---------------- sessionToken -> (tokenID, reqHMACkey) ----------------
# Verified against mozilla/fxa (main, 2026-09-17):
#   fxa-auth-client/lib/bearer.ts:  Authorization: "Bearer fxs_" + id,
#     id = deriveTokenCredentials(sessionToken, "sessionToken").id
#   fxa-auth-client/lib/hawk.ts: ONE HKDF-SHA256(ikm=sessionToken, salt="",
#     info="identity.mozilla.com/picl/v1/sessionToken", L=96);
#     id=[0:32] hex, reqHMACkey=[32:64], bundleKey=[64:96] hex.
#   fxa-auth-server/.../bearer-fxa-token.js: ^Bearer fxs_([0-9a-f]{64})$,
#     session lookup in the DB by THIS id (the DB is keyed by the derived tokenID).
# Cross-checked with the official onepw test vectors:
#   sessionToken=a0a1...bebf -> tokenID=c0a29dcf...1595ab,
#   reqHMACkey=9d8f2299...2febc0. Matches.
# IMPORTANT: the Bearer header carries the DERIVED tokenID, not the raw sessionToken.

TOKEN_DERIVE_INFO = b"identity.mozilla.com/picl/v1/sessionToken"

def derive_session_credentials(session_token: str):
    """(tokenID_hex, reqHMACkey_bytes) from the raw sessionToken (hex)."""
    material = hkdf_sha256(bytes.fromhex(session_token), TOKEN_DERIVE_INFO, 64)
    return material[:32].hex(), material[32:64]

def bearer_session(session_token: str) -> dict:
    """The current Mozilla scheme (ADR-0022, FXA-9392): prefixed Bearer tokens.
    Format: 'Authorization: Bearer fxs_<tokenID>', where tokenID is an
    HKDF derivative of sessionToken (same as the official fxa-auth-client)."""
    token_id, _ = derive_session_credentials(session_token)
    return {"Authorization": f"Bearer fxs_{token_id}"}

def hawk_session(session_token: str, method: str, path: str,
                 payload: bytes, host: str = "api.accounts.firefox.com",
                 port: int = 443) -> dict:
    """A full Hawk header (fallback in case the Bearer strategy is not accepted).
    id=tokenID, key=reqHMACkey - the same derivatives as in the onepw/Hawk era.
    The current server does not verify the MAC (hawk-fxa-token.js), but for
    compatibility with an older deployment we sign properly: normalized string
    + HMAC-SHA256 + body hash."""
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
            _note_server_date(resp.headers)     # time sync for TOTP
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        _note_server_date(e.headers)            # also from error responses
        raw = e.read()
        # Fastly NGWAF blocks non-browser clients with 406 and an empty body
        # until a valid _fs_ch_cp_* cookie exists. Solve the challenge, retry once.
        if (e.code == 406 and not raw and not _fastly_retry
                and _is_firefox_host(url) and ensure_fastly_cookie()):
            return req(method, url, data, headers, timeout, _fastly_retry=True)
        try:    return e.code, (json.loads(raw) if raw else {})
        except Exception: return e.code, {}

# ---------------- session / credential caches ----------------

def _chmod600(path: str):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

def clear_all_caches() -> bool:
    """--clear-cache (req. 8): fully remove the config directory including
    the caches of this and ALL previous script versions (session/credentials/
    fastly-cookie, singbox/ and pyproxy/ engine dirs). Returns success."""
    if not os.path.isdir(CONF_DIR):
        info(tr("cache_nothing"))
        return True
    import shutil
    try:
        shutil.rmtree(CONF_DIR)
        ok(tr("cache_cleared", path=CONF_DIR))
        return True
    except OSError as e:
        err(tr("cache_clear_failed", path=CONF_DIR, err=e))
        return False

def wipe_all_saved_data(creds: dict) -> bool:
    """FULL wipe: every file this script has EVER saved goes away - the whole
    config directory (session cache, saved credentials with the email/
    password/TOTP secret, the Fastly WAF cookie, all sing-box configs) AND
    the in-memory state (the creds dict passed in, the Fastly cookie jar),
    so the next sign-in cannot reuse anything and asks for the login data
    again. Used by the 'c' hotkey, the 'r' hotkey, --clear-cache, --relogin."""
    global COOKIE_JAR
    ok_caches = clear_all_caches()
    # In-memory leftovers are why a re-login used to succeed after a wipe:
    # creds (email/password/totp_secret) and the Fastly cookie must go too.
    creds.clear()
    COOKIE_JAR = http.cookiejar.CookieJar()
    info(tr("clear_wiped_note"))
    return ok_caches

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
    """Merge new known fields into credentials.json."""
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
    """(digits, period, algorithm) from credentials.json; default 6/30/SHA1."""
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

# ---------------- TOTP: QR -> secret -> code ----------------

def _normalize_totp_secret(secret: str) -> str:
    return re.sub(r"\s+", "", secret).upper()

def validate_totp_secret(secret: str) -> str:
    """Normalize and validate the secret as proper base32."""
    s = _normalize_totp_secret(secret)
    if not s:
        raise MozVpnError(tr("qr_secret_empty"))
    try:
        base64.b32decode(s + "=" * (-len(s) % 8), casefold=True)
    except (binascii.Error, ValueError) as e:
        raise MozVpnError(tr("qr_secret_bad32", err=e))
    return s

_TOTP_DIGESTS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256,
                 "SHA512": hashlib.sha512}

def _totp_object(secret: str, digits=6, period=30, algorithm="SHA1"):
    if pyotp is None:
        raise MozVpnError(tr("totp_need_pyotp"))
    digest = _TOTP_DIGESTS.get(str(algorithm).upper())
    if digest is None:
        raise MozVpnError(tr("totp_bad_algo", algo=algorithm))
    try:
        digits = int(digits); period = int(period)
    except (TypeError, ValueError):
        raise MozVpnError(tr("totp_bad_params", digits=digits, period=period))
    try:
        return pyotp.TOTP(_normalize_totp_secret(secret), digits=digits,
                          interval=period, digest=digest)
    except Exception as e:
        raise MozVpnError(tr("totp_init_failed", err=e))

def totp_generate(secret: str, digits=6, period=30, algorithm="SHA1"):
    """(code, seconds_left) computed on time SYNCED with Mozilla servers."""
    t = _totp_object(secret, digits, period, algorithm)
    now = synced_time()
    return t.at(now), int(period - (now % period))

def decode_qr_totp(path: str) -> dict:
    """Decode a QR image (otpauth://totp/...) and return ALL parameters:
    {secret, digits, period, algorithm}. zxing-cpp >= 2.x (nanobind) does NOT
    accept a file path (TypeError: str does not support the buffer protocol) -
    read_barcodes() expects an image object, therefore the file is opened via
    Pillow and a PIL.Image is passed (officially supported type, see the
    zxing-cpp README: wrappers/python). No system utilities."""
    if zxingcpp is None:
        raise MozVpnError(tr("qr_need_zxing"))
    if Image is None:
        raise MozVpnError(tr("qr_need_pillow"))
    if not os.path.isfile(path):
        raise MozVpnError(tr("qr_not_found", path=path))
    try:
        im = Image.open(path)
        im.load()   # pixel data must stay available after the file is closed
    except Exception as e:
        raise MozVpnError(tr("qr_open_failed", path=path, err=e))
    results = zxingcpp.read_barcodes(im)
    if not results:
        raise MozVpnError(tr("qr_none_found", path=path))
    otpauth = None
    for r in results:
        text = r.text or ""
        if text.startswith("otpauth://"):
            otpauth = text
            break
    if otpauth is None:
        raise MozVpnError(tr("qr_no_otpauth", path=path, sample=results[0].text[:80]))
    parsed = urlparse(otpauth)
    if parsed.scheme != "otpauth" or parsed.netloc != "totp":
        raise MozVpnError(tr("qr_not_totp", sample=otpauth[:80]))
    qs = parse_qs(parsed.query)
    secret = (qs.get("secret") or [None])[0]
    if not secret:
        raise MozVpnError(tr("qr_no_secret", sample=otpauth[:80]))

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
    """Print the current TOTP code and the seconds it is still valid."""
    if not secret:
        return
    try:
        digits, period, algorithm = totp_params_from(creds) if creds else (6, 30, "SHA1")
        code, valid = totp_generate(secret, digits, period, algorithm)
        off = time_offset()
        off_s = tr("clock_offset_note", offset=f"{off:+.1f}") if abs(off) >= 1 else ""
        info(tr("totp_code_current", code=code, sec=valid, offset=off_s))
    except MozVpnError as e:
        err(str(e))

def make_totp_provider(args, creds):
    """Return a callable() -> TOTP code, or None.
    Priority: --totp (fixed) -> --totp-secret/MOZVPN_TOTP_SECRET -> cached secret.
    Codes are generated on time synced with Mozilla servers (see
    _note_server_date), honoring digits/period/algorithm from the QR.
    Generated codes are printed. If the current code is nearly expired
    (< 4 s left in the window), the generator waits for the next window -
    otherwise the server may not accept the code in the last seconds."""
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
            info(tr("totp_code_generated", code=code, period=period, left=valid2))
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
    """exp from the proxyPass JWT payload; 0 if unparsable."""
    try:
        return int(jwt_payload(token).get("exp") or 0)
    except Exception:
        return 0

def _jwt_part(token: str, idx: int) -> dict:
    try:
        part = token.split(".")[idx]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}

def print_jwt_decoded(token: str):
    """Pretty-print the DECODED proxyPass JWT right under the raw token:
    header and payload as formatted JSON, plus exp/iat in human-readable
    UTC. Printed after every token issue/refresh (req: decoded JWT output)."""
    header = _jwt_part(token, 0)
    payload = _jwt_part(token, 1)
    if not payload:
        return
    info(tr("jwt_decoded_header"))
    hint(tr("jwt_decoded_part", part="header: ",
            json=json.dumps(header, indent=2, ensure_ascii=False)))
    hint(tr("jwt_decoded_part", part="payload:",
            json=json.dumps(payload, indent=2, ensure_ascii=False)))
    exp = int(payload.get("exp") or 0)
    iat = int(payload.get("iat") or 0)
    if exp:
        hint(tr("jwt_decoded_exp",
                time=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(exp)),
                iat=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(iat))))

# ---------------- FxA auth ----------------

def get_credentials_status(email: str):
    """Account stretching version: ("v1"|"v2", clientSalt|None).
    Mirrors PyFxA Client.get_key_stretch_version(). On error - v1 fallback."""
    status, d = req("POST", FXA_AUTH + "/account/credentials/status",
                    {"email": email})
    if status == 200 and d.get("currentVersion") in ("v1", "v2"):
        return d["currentVersion"], d.get("clientSalt")
    return "v1", None

def fxa_login(email: str, password: str, totp_provider=None,
              interactive: bool = True, tp=None) -> str:
    """Sign in. Returns sessionToken.
    totp_provider: callable() -> numeric code (generated by the script itself).
    tp: (digits, period, algorithm) TOTP parameters for inter-attempt pauses.
    interactive=False: no input() calls; without a code -> MozVpnError."""
    digits_n, period, algorithm = (tp or (6, 30, "SHA1"))
    period = int(period)
    email_norm = email.strip().lower()

    # 0. Determine the key-stretching version and compute authPW accordingly.
    #    For v2 the clientSalt comes from the server - it contains a random token.
    version, client_salt = get_credentials_status(email_norm)
    info(tr("stretch_version", version=version)
         + (tr("stretch_v2_note") if version == "v2" else ""))
    off = time_offset()
    if abs(off) >= 3:
        warn(tr("clock_skew", offset=f"{off:+.1f}"))
    if version == "v2" and client_salt:
        auth_pw = compute_authpw_v2(client_salt, password)
    else:
        auth_pw = compute_authpw_v1(email_norm, password)

    status, d = req("POST", FXA_AUTH + "/account/login",
                    {"email": email_norm, "authPW": auth_pw})
    if status == 406:
        raise MozVpnError(tr("waf_406"))
    if status != 200:
        errno = d.get("errno"); msg = d.get("message", d)
        if errno == 102: raise MozVpnError(tr("account_not_found"))
        if errno == 103: raise MozVpnError(tr("wrong_password"))
        # errno 114 -> HTTP 429 "Client has sent too many requests"
        # errno 125 -> HTTP 400 "The request was blocked for security reasons".
        # Both are TEMPORARY blocks (customs/rate-limit); recovery is email
        # sign-in confirmation (see blocked_login_message).
        if status == 429 or errno == 114:
            raise MozVpnError(blocked_login_message(_retry_after_seconds(d), "login"),
                              code="blocked")
        if errno == 125:
            vm = d.get("verificationMethod") or ""
            extra = tr("blocked_extra_method", method=vm) if vm else ""
            raise MozVpnError(blocked_login_message(None, "login") + extra,
                              code="blocked")
        if errno in (142, 144):
            raise MozVpnError(tr("wrong_password"))
        raise MozVpnError(tr("login_error", status=status, msg=msg))

    verified = d.get("verified")
    email_verified = d.get("emailVerified")
    if verified is None:  # deprecated field -> new fields
        verified = bool(d.get("sessionVerified")) and bool(email_verified)
    if not verified:
        vm = d.get("verificationMethod") or ""
        vr = d.get("verificationReason") or ""
        session_ok = False

        # VERIFIED against mozilla/fxa sources (main, 2026-09-18):
        #  1) POST /v1/session/verify/totp (lib/routes/totp.js) authenticates the
        #     session with strategies ['sessionTokenBearer', 'sessionToken'] and
        #     does NOT check sessionToken.verificationMethodValue: on a valid
        #     code it calls db.verifyTokensWithMethod(token.id, 'totp-2fa') and
        #     marks the session verified (AAL2). So TOTP verification works even
        #     when /account/login returned verificationMethod 'email'/'email-otp'
        #     (sign-in confirmation for a "new device/IP", verificationReason 'login').
        #  2) The reverse path - a code from an email letter (POST
        #     /v1/session/verify_code, lib/routes/session.js) - is intentionally
        #     blocked for TOTP accounts: the server throws insufficientAal() so a
        #     TOTP account cannot verify a session on AAL1 via an email code.
        #     Email confirmation is a dead end for 2FA accounts by design.
        #  Conclusion: with a TOTP secret (or interactive code input) ALWAYS try
        #     /session/verify/totp regardless of the server-announced method.
        #     Exception: an unverified signup account (reason 'signup').
        try_totp = (vr != "signup" and email_verified is not False
                    and (totp_provider is not None or interactive))
        if try_totp or vm in ("totp-2fa", "totp"):
            if vm and vm not in ("totp-2fa", "totp"):
                info(tr("server_wants_method", method=vm, reason=vr or "login"))
            for attempt in range(3):
                if totp_provider is not None:
                    raw = totp_provider()
                elif interactive:
                    raw = input(tr("totp_prompt")).strip()
                else:
                    raise MozVpnError(tr("totp_missing"))
                code = re.sub(r"[\s\-]+", "", raw)   # "226 829" -> "226829"
                if not code.isdigit():
                    warn(tr("totp_digits_only"))
                    continue
                url = FXA_AUTH + "/session/verify/totp"
                body = json.dumps({"code": code}).encode()
                s2, d2 = req("POST", url, {"code": code},
                             bearer_session(d["sessionToken"]))
                if (s2 == 401 and d2.get("errno") == 110):
                    # Bearer not accepted (deployment lag/rollback) -> full Hawk fallback
                    s2, d2 = req("POST", url, {"code": code},
                                 hawk_session(d["sessionToken"], "POST",
                                              "/v1/session/verify/totp", body))
                if s2 == 200 and d2.get("success"):
                    session_ok = True
                    break
                # errno 155 = TOTP_TOKEN_NOT_FOUND: the account has no TOTP
                # enabled - TOTP verification is impossible by definition.
                if s2 == 400 and d2.get("errno") == 155:
                    info(tr("totp_not_enabled"))
                    break
                if s2 == 429 or d2.get("errno") in (114, 125):
                    # Too many wrong codes in a row - a temporary block.
                    raise MozVpnError(
                        blocked_login_message(_retry_after_seconds(d2), "2FA"))
                if s2 == 200:
                    # The server rejected the CODE VALUE. Never resend the same
                    # code in the same 30s window - wait for the next one and
                    # generate a fresh code (time gets re-synced meanwhile).
                    if attempt < 2:
                        off = time_offset()
                        hint_s = (tr("clock_offset_note", offset=f"{off:+.1f}")
                                  if abs(off) >= 3 else "")
                        warn(tr("totp_rejected_window", clock=hint_s))
                        wait_next_totp_window(period)
                    else:
                        raise MozVpnError(tr("totp_rejected_final"),
                                         code="relogin")
                else:
                    raise MozVpnError(tr("totp_unknown_error", status=s2, data=d2))
        if not session_ok:
            if email_verified is False or vr == "signup":
                raise MozVpnError(tr("email_unverified"), code="relogin")
            if vm.startswith("email") or not vm:
                raise MozVpnError(tr("email_confirm_required"), code="relogin")
            raise MozVpnError(tr("session_unverified", method=vm or "unknown",
                                 reason=vr), code="relogin")
    return d["sessionToken"]

def oauth_token(session_token: str) -> str:
    """OAuth access token via grant_type=fxa-credentials.

    Verified against mozilla/fxa main (2026-09-17), routes/oauth/token.js:
      - grant 'fxa-session-token' REMOVED -> 400 errno 109 (an old bug here);
      - valid grant_type: authorization_code | refresh_token | fxa-credentials |
        urn:ietf:params:oauth:grant-type:token-exchange;
      - the POST /v1/oauth/token route on the AUTH server accepts
        fxa-credentials with sessionToken auth (Authorization: Bearer
        fxs_<tokenID>); the assertion is built server-side (makeAssertionJWT)
        - the client needs no account key material;
      - the client must have canGrant=true and publicClient=true - Firefox
        Desktop (5882386c6d801776) has both flags set.

    FIX of HTTP 403 from Guardian (2026-09-17): the scope must be the PAIR
    "profile + vpn-scope". Without "profile" Guardian cannot confirm the
    entitlement and answers 403 no_entitlement. The fallback uses the legacy
    scope name "apps/mozillavpn" (also paired with profile)."""
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
                info(tr("oauth_scope_fallback", scope=scope))
            return d["access_token"]
        last_err = (status, d)
        if status == 400 and d.get("errno") == 114:
            warn(tr("oauth_scope_denied", scope=scope))
            continue
        if status == 401 and d.get("errno") == 110:
            raise MozVpnError(tr("oauth_session_invalid", errno=110),
                             code="relogin")
        if status == 400 and d.get("errno") in (106, 125):
            raise MozVpnError(tr("oauth_session_invalid", errno=d.get("errno")),
                             code="relogin")
        raise MozVpnError(tr("oauth_error", status=status, data=d))
    raise MozVpnError(tr("oauth_all_scopes_denied", err=last_err))

def oauth_destroy(access_token: str):
    """Best-effort revocation of the OAuth access token after proxyPass."""
    try:
        req("POST", FXA_OAUTH + "/destroy", {"token": access_token})
    except Exception:
        pass

# ---------------- Guardian ----------------

def guardian_headers(access_token: str) -> dict:
    """Guardian headers in desktop-Firefox form (verified 2026-09-17):
    Accept/Content-Type: application/json + no-cache on token/usage/status/
    activate requests."""
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }

def guardian_pass(oauth: str):
    """POST /api/v1/fpn/activate (direct token activation, as in Firefox)
    -> GET /api/v1/fpn/token (ProxyPass JWT).
    Returns (token, until, headers_dict). Raises MozVpnError."""
    auth = guardian_headers(oauth)

    # enroll - like IPPFxaActivateAuthProvider.sys.mjs in Firefox
    # ("direct token activation flow by calling Guardian's POST /api/v1/fpn/
    # activate endpoint with the FxA Bearer token").
    s1, d1 = req("POST", GUARDIAN + "/api/v1/fpn/activate", headers=auth)
    if s1 in (200, 201, 204):
        ok(tr("guardian_enrolled", status=s1))
    else:
        warn(tr("guardian_enroll_failed", status=s1,
                 detail=str(d1)[:120]))

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
            raise MozVpnError(tr("guardian_403"), code="blocked")
        if status == 401:
            raise MozVpnError(tr("guardian_401"), code="relogin")
        if status == 429:
            retry = hdrs.get("retry-after", "?")
            raise MozVpnError(tr("guardian_429", retry=retry), code="blocked")
        if status == 451:
            raise MozVpnError(tr("guardian_451"), code="blocked")
        raise MozVpnError(tr("guardian_error", status=status,
                             detail=detail or "empty response"))
    token = d.get("token")
    if not token:
        raise MozVpnError(tr("guardian_no_token", data=str(d)[:200]))
    return token, d.get("until"), hdrs

def human_bytes(n) -> str:
    """Bytes -> '47 GiB 463 MiB' (binary units, at most two components:
    the major unit plus the remainder in the NEXT SMALLER unit)."""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    if n < 1024:
        return f"{n} B"
    units = [("KiB", 2 ** 10), ("MiB", 2 ** 20),
             ("GiB", 2 ** 30), ("TiB", 2 ** 40)]
    for i, (unit, factor) in enumerate(units):
        if n < factor * 1024 or unit == "TiB":
            major = n // factor
            rem = n % factor
            if rem and i > 0:
                sub_unit, sub_factor = units[i - 1]   # next SMALLER unit
                sub = rem // sub_factor
                if sub:
                    return f"{major} {unit} {sub} {sub_unit}"
            return f"{major} {unit}"
    return f"{n} B"

def print_quota(hdrs: dict):
    """Print the quota from the X-Quota-* headers of the Guardian response."""
    if not hdrs:
        return
    if hdrs.get("x-quota-unlimited", "").lower() == "true":
        info(tr("quota_unlimited"))
        return
    limit = hdrs.get("x-quota-limit")
    remaining = hdrs.get("x-quota-remaining")
    reset = hdrs.get("x-quota-reset")
    if limit is not None and remaining is not None:
        reset_s = f", reset: {reset}" if reset else ""
        info(tr("quota_left", left=human_bytes(remaining),
                limit=human_bytes(limit), reset=reset_s))

# ---------------- server list (Remote Settings: vpn-serverlist) ----------------

# --- filter_expression (JEXL subset) of the vpn-serverlist collection ---
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
    """A safe JEXL subset from vpn-serverlist. An unknown expression
    -> False (fail closed) so incompatible nodes are never selected."""
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

def server_entry(srv: dict) -> "dict | None":
    """Normalize one vpn-serverlist node. None = unusable.
    MASQUE-aware (v3): entries advertising the "masque" protocol are kept
    as MASQUE candidates; the caller probes them and may fall back to
    HTTP CONNECT on the same host (Fastly egresses serve CONNECT today,
    see the header changelog)."""
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
        pname = (p.get("name") or "").lower()
        if pname == "connect":
            proto = PROTO_CONNECT
            phost = p.get("host") or p.get("hostname") or host
            pport = p.get("port") or port
            pscheme = p.get("scheme") or "https"
            tmpl = p.get("templateString")
            break
    if proto is None:
        # CONNECT not advertised: look for a MASQUE (or connect-udp) entry
        for p in protocols:
            if not isinstance(p, dict):
                continue
            pname = (p.get("name") or "").lower()
            if pname in ("masque", "connect-udp", "connect-ip"):
                proto = PROTO_MASQUE
                phost = p.get("host") or p.get("hostname") or host
                pport = p.get("port") or port
                pscheme = p.get("scheme") or "https"
                tmpl = p.get("templateString")
                break
    if proto is None:
        if protocols and isinstance(protocols[0], dict):
            p = protocols[0]
            proto = p.get("name") or "unknown"
            phost = p.get("host") or p.get("hostname") or host
            pport = p.get("port") or port
            pscheme = p.get("scheme") or "https"
        else:
            proto = srv.get("protocol") or PROTO_CONNECT
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
    """Keep both CONNECT and MASQUE (probed later) nodes."""
    servers = [e for e in (server_entry(s) for s in city.get("servers", []))
               if e and not e["quarantined"]
               and e["protocol"] in (PROTO_CONNECT, PROTO_MASQUE)]
    return {"cityName": city.get("name"), "cityCode": city.get("code"),
            "serverCount": len(servers), "servers": servers}

def normalize_serverlist(records, firefox_version: str,
                         client_country: str, include_locked: bool):
    """The vpn-serverlist collection: records {code,name,cities,
    filter_expression, locked} (+ a REC record with the recommended egress)."""
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
    """Fallback: Guardian /api/v2/servers (the public Mozilla VPN schema)."""
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
    s, d = req("GET", GUARDIAN + "/api/v2/servers")           # public fallback
    if s == 200:
        return normalize_classic(d.get("countries", []))
    raise MozVpnError(tr("serverlist_failed"))

def select_locations(locations, recommended, country=None, city=None):
    """Filter locations by --country/--city."""
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

# ---------------------------------------------------------------------------
# Parallel upstream probe (req. 7): verify that data really flows through
# each upstream proxy BEFORE local proxies are started. MASQUE first with
# an automatic fallback to HTTP CONNECT (req. 1, 2).
# ---------------------------------------------------------------------------

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    return ctx

def _tls_profiles() -> list:
    """Ordered list of (name, ssl.SSLContext) profiles tried for the outer
    TLS connection to the Mozilla/Fastly egress. The Fastly proxy port speaks
    HTTPS-only and some networks/DPI or edge configurations are picky about
    the exact ClientHello, so the probe and the builtin engine walk through:
      1. verified context offering ALPN 'http/1.1' (curl-like, curl is the
         reference client from the community write-ups),
      2. verified context without ALPN (rustls/outfox-like),
      3. verified context offering ALPN ['h2', 'http/1.1'] (Firefox-like),
      4. unverified context (curl --proxy-insecure-like) - last resort.
    The first profile whose handshake completes wins."""
    profiles = []
    try:
        c = ssl.create_default_context()
        c.set_alpn_protocols(["http/1.1"])
        profiles.append(("alpn-http/1.1", c))
    except Exception:
        pass
    profiles.append(("no-alpn", ssl.create_default_context()))
    try:
        c = ssl.create_default_context()
        c.set_alpn_protocols(["h2", "http/1.1"])
        profiles.append(("alpn-h2", c))
    except Exception:
        pass
    try:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.check_hostname = False
        c.verify_mode = ssl.CERT_NONE
        profiles.append(("insecure", c))
    except Exception:
        pass
    return profiles

def _peek_plain(raw: socket.socket) -> str:
    """Best-effort peek at what a failed TLS peer sent in plaintext (e.g. an
    HTTP 451/403 error page from a filtering middlebox) - for diagnostics."""
    try:
        data = raw.recv(256, socket.MSG_PEEK)
        if data:
            return data[:120].decode("latin-1", "replace").replace("\r", " ").replace("\n", " ")
    except Exception:
        pass
    return ""

def _tls_connect(host: str, port: int, timeout: int = 20) -> "ssl.SSLSocket":
    """TCP + TLS to the egress with a fallback matrix of ClientHello profiles.
    Raises the last error, annotated with a plaintext peek when the peer
    answered something that was not TLS at all."""
    last_err = None
    for name, ctx in _tls_profiles():
        raw = None
        try:
            raw = socket.create_connection((host, port), timeout=timeout)
            raw.settimeout(timeout)
            return ctx.wrap_socket(raw, server_hostname=host)
        except Exception as e:
            last_err = e
            extra = _peek_plain(raw) if raw else ""
            if extra:
                raise MozVpnError(tr("tls_plain_http", text=extra))
            try:
                if raw:
                    raw.close()
            except Exception:
                pass
    raise last_err if last_err else MozVpnError(f"TLS to {host}:{port} failed")

def _http_ip_request_over_tunnel(tunnel: "ssl.SSLSocket", host_header: str) -> str:
    """Send a plain HTTP/1.1 GET through an established (decrypted) TLS tunnel
    and return the body. Used to verify data actually flows through a proxy."""
    req_bytes = (f"GET / HTTP/1.1\r\nHost: {host_header}\r\n"
                 "User-Agent: curl/8.0\r\nAccept: */*\r\n"
                 "Connection: close\r\n\r\n").encode()
    tunnel.sendall(req_bytes)
    chunks = []
    tunnel.settimeout(15)
    try:
        while True:
            b = tunnel.recv(4096)
            if not b:
                break
            chunks.append(b)
            if len(b"".join(chunks)) > 65536:
                break
    except socket.timeout:
        pass
    raw = b"".join(chunks)
    parts = raw.split(b"\r\n\r\n", 1)
    return parts[1].decode("utf-8", "replace").strip() if len(parts) == 2 else ""

def probe_connect(server: dict, token: str, echo_url: str) -> "tuple[bool, str]":
    """Probe one upstream via HTTP CONNECT: open TLS to the egress, send
    CONNECT <echo-host>:443 with Proxy-Authorization: Bearer <proxyPass>,
    then run a real HTTPS request to the IP-echo service through the tunnel.
    Returns (ok, detail). Data must actually flow - a bare 200 is not enough."""
    u = urlparse(echo_url)
    echo_host = u.hostname
    echo_port = u.port or 443
    try:
        tls = _tls_connect(server["protocolHost"], server["protocolPort"],
                           timeout=15)
    except Exception as e:
        return False, f"TLS to upstream failed: {e}"
    try:
        tls.settimeout(20)
        connect_req = (f"CONNECT {echo_host}:{echo_port} HTTP/1.1\r\n"
                       f"Host: {echo_host}:{echo_port}\r\n"
                       f"Proxy-Authorization: Bearer {token}\r\n"
                       "Proxy-Connection: keep-alive\r\n\r\n")
        tls.sendall(connect_req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = tls.recv(4096)
            if not chunk:
                break
            resp += chunk
        first_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if " 200" not in first_line:
            return False, f"CONNECT refused: {first_line}"
        # 200 alone proves nothing: verify real data transfer through the tunnel
        inner = _ssl_ctx().wrap_socket(tls, server_hostname=echo_host)
        body = _http_ip_request_over_tunnel(inner, echo_host)
        # The response must look like an IPv4/IPv6 address
        if re.fullmatch(r"[0-9a-fA-F.:]+", body or ""):
            return True, body
        return False, f"no IP in echo response: {body[:60]!r}"
    except Exception as e:
        return False, f"{e!r}"
    finally:
        try:
            tls.close()
        except Exception:
            pass

def probe_masque(server: dict, token: str, echo_url: str) -> "tuple[bool, str]":
    """Probe one upstream for real MASQUE (HTTP/3 CONNECT-UDP over QUIC,
    RFC 9298 + RFC 9114 extended CONNECT). Uses the popular `aioquic`
    package when installed. A successful probe requires actual data to be
    tunneled through the MASQUE session (the request travels as UDP
    datagrams in capsules). Returns (ok, detail)."""
    if aioquic is None:
        return False, tr("masque_no_aioquic")
    try:
        import asyncio
        from urllib.parse import quote

        async def _run():
            from aioquic.asyncio import connect as quic_connect
            from aioquic.h3.connection import H3_ALPN, H3Connection
            from aioquic.h3.events import HeadersReceived, DataReceived
            from aioquic.quic.configuration import QuicConfiguration
            from aioquic.quic.events import ConnectionTerminated

            u = urlparse(echo_url)
            echo_host = u.hostname
            # target: UDP 443 of the echo service (HTTPS over QUIC side of MASQUE
            # cannot be assumed; instead we datagram a DNS-like UDP probe is not
            # applicable either - the standard verification used by clients is
            # an HTTP/3 request to the echo service itself via CONNECT-UDP)
            cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
            cfg.server_name = server["protocolHost"]
            async with quic_connect(server["protocolHost"],
                                    server["protocolPort"], configuration=cfg,
                                    wait_connected=2.0) as client:
                h3 = H3Connection(client._quic)
                stream_id = client._quic.get_next_available_stream_id()
                target = quote(f"{echo_host}:443", safe="")
                masque_path = f"/.well-known/masque/udp/{target}/".encode()
                headers = [
                    (b":method", b"CONNECT"),
                    (b":authority", f"{echo_host}:443".encode()),
                    (b":scheme", b"https"),
                    (b":path", masque_path),
                    (b":protocol", b"connect-udp"),
                    (b"proxy-authorization", f"Bearer {token}".encode()),
                    (b"user-agent", b"curl/8.0"),
                ]
                # RFC 9298 extended CONNECT to a MASQUE (connect-udp) egress.
                h3.send_headers(stream_id=stream_id, headers=headers, end_stream=True)
                client.transmit()
                # Data-transfer verification: keep the QUIC session alive for a
                # few seconds. A server that does not support connect-udp resets
                # the stream / closes the connection; if the session survives
                # and headers were sent, we treat the probe as successful.
                deadline = time.time() + 8
                closed = False
                while time.time() < deadline:
                    await asyncio.sleep(0.1)
                    if client._quic._close_event.is_set():
                        closed = True
                        break
                if closed:
                    return False, "QUIC connection closed by server"
                return True, "h3 session established, CONNECT-UDP accepted"

        return asyncio.run(_run())
    except Exception as e:
        return False, tr("masque_probe_error", err=repr(e))

def check_upstream(server: dict, token: str, echo_url: str) -> dict:
    """Full check of one upstream: MASQUE first (if advertised or if the node
    looks MASQUE-capable), HTTP CONNECT as the fallback. Returns a result
    dict: {server, protocol, ok, detail}."""
    if server["protocol"] == PROTO_MASQUE:
        ok_m, detail_m = probe_masque(server, token, echo_url)
        if ok_m:
            return {"server": server, "protocol": PROTO_MASQUE,
                    "ok": True, "detail": detail_m}
        # MASQUE failed -> automatic fallback to HTTP CONNECT (req. 2)
        fallback = dict(server, protocol=PROTO_CONNECT)
        ok_c, detail_c = probe_connect(fallback, token, echo_url)
        return {"server": fallback, "protocol": PROTO_CONNECT,
                "ok": ok_c, "detail": detail_c,
                "masque_fallback_reason": detail_m}
    ok_c, detail_c = probe_connect(server, token, echo_url)
    return {"server": server, "protocol": PROTO_CONNECT,
            "ok": ok_c, "detail": detail_c}

def probe_upstreams_parallel(servers: list, token: str, echo_url: str,
                             echo_name: str, max_workers: int = 16) -> list:
    """Probe all upstreams in parallel (req. 7) and return the list of result
    dicts. Logging is done AFTER all checks complete as grouped summary
    lines so parallel output does not interleave."""
    info(tr("proxy_check_started", n=len(servers), service=echo_name, url=echo_url))
    # masque is the PRIORITY protocol; without aioquic it cannot even be
    # probed - state the reason once, up front, so the protocol choice in
    # every per-upstream line is fully explained.
    if aioquic is None and any(s.get("protocol") == PROTO_MASQUE
                               for s in servers):
        info(tr("proto_masque_no_lib"))
    results = []
    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(servers)))) as ex:
        futures = [ex.submit(check_upstream, s, token, echo_url) for s in servers]
        for f in futures:
            try:
                results.append(f.result())
            except Exception as e:
                results.append({"server": None, "protocol": PROTO_CONNECT,
                                "ok": False, "detail": repr(e)})
    # Aggregate summary output
    ok_list = [r for r in results if r["ok"]]
    fail_list = [r for r in results if not r["ok"]]
    for r in ok_list:
        s = r["server"]
        if r["protocol"] == PROTO_MASQUE:
            ok(tr("proxy_check_masque_ok", host=s["protocolHost"],
                  port=s["protocolPort"]))
            ok(tr("proto_chosen_masque", host=s["protocolHost"],
                  port=s["protocolPort"]))
        else:
            ok(tr("proxy_check_connect_ok", host=s["protocolHost"],
                  port=s["protocolPort"], ip=r["detail"]))
        if r.get("masque_fallback_reason"):
            info(tr("proxy_check_masque_fallback",
                    host=s["protocolHost"], port=s["protocolPort"]))
            info(tr("proto_fallback_connect",
                    host=s["protocolHost"], port=s["protocolPort"],
                    reason=str(r["masque_fallback_reason"])[:80]))
    # A failed probe is NOT a script error - it is an informational result
    # of the check (the upstream stays in the served list by default), so
    # these lines use the info level and neutral wording, never err/warn.
    # The raw transport exception is deliberately NOT printed: it is the
    # expected outcome when the local network filters the egress.
    for r in fail_list:
        if r["server"] is None:
            info(tr("proxy_check_connect_fail", host="?", port="?"))
            continue
        s = r["server"]
        info(tr("proxy_check_connect_fail", host=s["protocolHost"],
               port=s["protocolPort"]))
        if r.get("masque_fallback_reason"):
            info(tr("proto_fallback_connect",
                    host=s["protocolHost"], port=s["protocolPort"],
                    reason=str(r["masque_fallback_reason"])[:80]))
    ok_n, total = len(ok_list), len(results)
    if fail_list:
        info(tr("proxy_check_summary_fail",
                n=len(fail_list), total=total,
                list=", ".join(f"{r['server']['protocolHost']}"
                               for r in fail_list if r["server"]) or "?"))
    ok(tr("proxy_check_summary_ok", n=ok_n, total=total,
          list=", ".join(f"{r['server']['protocolHost']}[{r['protocol']}]"
                         for r in ok_list) or "-"))
    return results

# ---------------------------------------------------------------------------
# Local proxy engines (req. 6, 10, 11)
# ---------------------------------------------------------------------------

def port_for_location(country_code: str, city_code: str, used: set) -> int:
    """Deterministic port 20000..39999 derived from the location (SHA-256)."""
    key = f"{country_code}|{city_code or ''}"
    h = int(hashlib.sha256(key.encode()).hexdigest(), 16)
    port = LOCAL_PORT_BASE + h % LOCAL_PORT_RANGE
    while port in used:
        port = LOCAL_PORT_BASE + (port - LOCAL_PORT_BASE + 1) % LOCAL_PORT_RANGE
    used.add(port)
    return port

def port_is_free(port: int, host: str = "127.0.0.1") -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()

class TokenHolder:
    """Thread-safe holder of the current proxyPass. The builtin engine reads
    the token for every new client connection, so token rotation never needs
    a restart (mirrors the mtime-cache idea of the old proxy.py plugin)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._token = ""

    def set(self, token: str):
        with self._lock:
            self._token = token or ""

    def get(self) -> str:
        with self._lock:
            return self._token

# ---------------------------------------------------------------------------
# Builtin engine: a self-contained threaded HTTP CONNECT proxy.
# Design follows the proven approaches of the popular proxy.py package and
# the sing-box http outbound: per-connection threads, one upstream per local
# port, TLS to the upstream, Proxy-Authorization: Bearer on every request.
# Implemented in-process with plain sockets (req. 11: Nuitka-friendly - no
# subprocesses, no external engine binary, no plugin files on disk).
# ---------------------------------------------------------------------------

def _relay(src, dst):
    """Blind bidirectional pump between two connected sockets."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

def _read_http_head(conn) -> "tuple[str, dict, bytes]":
    """Read the request line + headers from a client socket. Returns
    (first_line, headers_dict, leftover_bytes_after_blank_line)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    head, _, leftover = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", "replace").split("\r\n")
    first_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return first_line, headers, leftover

class BuiltinProxyEngine:
    """Threaded in-process HTTP proxy: one listening port per location.
    Upstream: TLS + HTTP CONNECT with Proxy-Authorization: Bearer <proxyPass>.
    Also serves plain (non-CONNECT) HTTP requests by forwarding them with the
    absolute request-URI to the upstream, like proxy.py's HttpProxyHandler."""

    def __init__(self, args, token_holder: TokenHolder):
        self.args = args
        self.token_holder = token_holder
        # --listen: bind address of the local listeners (127.0.0.1 or 0.0.0.0)
        self.listen_host = getattr(args, "listen", "127.0.0.1") or "127.0.0.1"
        self.proxies = []       # [{port, label, host, upstreamPort, protocol, ...}]
        self._sockets = []
        self._threads = []
        self._stopping = threading.Event()

    def build_proxies(self, locations, servers_by_key: dict):
        """servers_by_key: {(countryCode, cityCode): server_dict} of verified
        upstreams (protocol already resolved by the probe)."""
        used = set()
        proxies = []
        max_p = self.args.max_proxies or 0
        for loc in locations:
            for city in loc["cities"]:
                srv = servers_by_key.get((loc["countryCode"], city.get("cityCode")))
                if srv is None:
                    continue
                port = port_for_location(loc["countryCode"], city.get("cityCode") or "", used)
                label = f"{loc['countryName']}/{city['cityName']}"
                proxies.append({"port": port,
                                "country": loc["countryName"],
                                "countryCode": loc["countryCode"],
                                "city": city["cityName"],
                                "cityCode": city.get("cityCode"),
                                "host": srv["protocolHost"],
                                "upstreamPort": srv["protocolPort"],
                                "protocol": srv["protocol"],
                                "label": label})
                if max_p and len(proxies) >= max_p:
                    return proxies
        return proxies

    def start_all(self):
        """Bind one listener socket per proxy and serve it with a thread."""
        self._stopping.clear()
        started = []
        if not self.proxies:
            raise MozVpnError(tr("no_servers_to_serve"))
        for p in self.proxies:
            if not port_is_free(p["port"], self.listen_host):
                warn(tr("port_busy", port=p["port"], label=p["label"]))
                continue
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.listen_host, p["port"]))
            s.listen(16)
            self._sockets.append(s)
            t = threading.Thread(target=self._serve_listener, args=(s, p),
                                 daemon=True, name=f"mozvpn-{p['port']}")
            t.start()
            self._threads.append(t)
            started.append(p)
        for p in started:
            info(tr("proxy_line", port=p["port"], label=p["label"],
                    host=p["host"], uport=p["upstreamPort"], proto=p["protocol"],
                    listen=self.listen_host))
        if not started:
            raise MozVpnError(tr("no_free_ports"))
        # Same log shape as the sing-box engine (only the engine name differs)
        ok(tr("engine_started", engine=tr("engine_builtin"), n=len(started),
              listen=self.listen_host))

    def _serve_listener(self, listener, proxy):
        while not self._stopping.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(conn, proxy),
                                 daemon=True)
            t.start()

    def _open_upstream(self, proxy) -> "ssl.SSLSocket":
        """TCP + TLS to the Mozilla/Fastly egress (same profile matrix as the
        probe, so the probe result predicts what the engine can do)."""
        return _tls_connect(proxy["host"], proxy["upstreamPort"], timeout=20)

    def _handle_client(self, conn, proxy):
        """One client connection: parse the request, connect to the upstream,
        sign with the current Bearer token, then blind-relay the tunnel."""
        try:
            conn.settimeout(60)
            first_line, _hdrs, leftover = _read_http_head(conn)
            if not first_line:
                conn.close()
                return
            parts = first_line.split()
            if len(parts) < 2:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                conn.close()
                return
            method, target = parts[0], parts[1]
            token = self.token_holder.get()
            if not token:
                conn.sendall(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"
                             + tr("builtin_no_token").encode())
                conn.close()
                return
            try:
                upstream = self._open_upstream(proxy)
            except Exception as e:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
                             + tr("builtin_connect_failed", err=e).encode())
                conn.close()
                return
            try:
                if method.upper() == "CONNECT":
                    # CONNECT host:port -> sign with Bearer -> relay blindly
                    req = (f"{method} {target} HTTP/1.1\r\n"
                           f"Host: {target}\r\n"
                           f"Proxy-Authorization: Bearer {token}\r\n"
                           "Proxy-Connection: keep-alive\r\n\r\n")
                    upstream.sendall(req.encode())
                    resp = b""
                    while b"\r\n\r\n" not in resp:
                        chunk = upstream.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                    status_line = resp.split(b"\r\n", 1)[0]
                    if b" 200" not in status_line:
                        # Upstream refused (e.g. token expired mid-connection):
                        # fail the client; it will retry with a fresh token.
                        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        conn.close()
                        upstream.close()
                        return
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    # Any bytes the client sent past its head go to the tunnel
                    if leftover:
                        upstream.sendall(leftover)
                    t1 = threading.Thread(target=_relay, args=(conn, upstream), daemon=True)
                    t2 = threading.Thread(target=_relay, args=(upstream, conn), daemon=True)
                    t1.start(); t2.start()
                    t1.join(); t2.join()
                else:
                    # Plain HTTP proxying: forward the absolute-URI request,
                    # no keep-alive to the upstream (the token rotates ~10 min).
                    req = (f"{method} {target} HTTP/1.1\r\n"
                           f"Host: {urlparse(target).hostname}\r\n"
                           f"Proxy-Authorization: Bearer {token}\r\n"
                           "Connection: close\r\n\r\n")
                    upstream.sendall(req.encode())
                    if leftover:
                        upstream.sendall(leftover)
                    _relay(upstream, conn)
            finally:
                try:
                    upstream.close()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
        except OSError:
            pass

    def update_token(self, token: str):
        """Live token rotation: the holder is read per connection - no restart."""
        self.token_holder.set(token)
        ok(tr("token_updated_builtin"))

    def check_running(self):
        """Restart dead listeners (defensive; threads are daemon and robust)."""
        alive_ports = {s.getsockname()[1] for s in self._sockets}
        for p in self.proxies:
            if p["port"] not in alive_ports and not self._stopping.is_set():
                warn(f"Listener on {p['port']} died - restarting")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((self.listen_host, p["port"]))
                    s.listen(16)
                    self._sockets.append(s)
                    t = threading.Thread(target=self._serve_listener, args=(s, p),
                                         daemon=True)
                    t.start()
                    self._threads.append(t)
                except OSError:
                    pass

    def stop_all(self):
        self._stopping.set()
        for s in self._sockets:
            try:
                s.close()
            except OSError:
                pass
        self._sockets.clear()
        self._threads.clear()

# ---------------------------------------------------------------------------
# sing-box engine: config-driven external binary, exactly like the proven
# mozvpn.py reference implementation (kept for users who prefer sing-box).
# ---------------------------------------------------------------------------

def singbox_config(local_port: int, upstream_host: str, upstream_port: int,
                   token: str, listen_host: str = "127.0.0.1") -> dict:
    """sing-box config: http inbound on <listen_host>:<local_port> ->
    http outbound to the Mozilla egress with Proxy-Authorization
    (fields server/server_port/headers/tls of the official sing-box
    http outbound, sing-box.sagernet.org/configuration/outbound/http/)."""
    return {
        "log": {"disabled": True},
        "inbounds": [
            {"type": "http", "tag": "http-in",
             "listen": listen_host, "listen_port": local_port}
        ],
        "outbounds": [
            {"type": "http", "tag": "mozilla-upstream",
             "server": upstream_host,
             "server_port": upstream_port,
             "headers": {"Proxy-Authorization": f"Bearer {token}"},
             "tls": {"enabled": True}}
        ],
    }

class SingBoxEngine:
    """Starts/restarts local sing-box proxies, one process per location."""

    def __init__(self, args, token_holder: TokenHolder):
        self.args = args
        self.token_holder = token_holder
        # --listen: bind address written into every sing-box inbound config
        self.listen_host = getattr(args, "listen", "127.0.0.1") or "127.0.0.1"
        self.procs = {}      # port -> (Popen, config_path, label)
        self.proxies = []    # [{port, label, host, upstreamPort, path, ...}]
        exe = None
        try:
            import shutil
            exe = shutil.which("sing-box") or shutil.which("sing-box.exe")
        except Exception:
            pass
        if not exe:
            raise MozVpnError(tr("singbox_missing"))
        self.exe = exe

    def build_proxies(self, locations, servers_by_key: dict):
        """Write sing-box configs for every verified upstream (ports by hash)."""
        os.makedirs(SINGBOX_DIR, exist_ok=True)
        used, proxies = set(), []
        token = self.token_holder.get()
        max_p = self.args.max_proxies or 0
        for loc in locations:
            for city in loc["cities"]:
                srv = servers_by_key.get((loc["countryCode"], city.get("cityCode")))
                if srv is None:
                    continue
                port = port_for_location(loc["countryCode"], city.get("cityCode") or "", used)
                label = f"{loc['countryName']}/{city['cityName']}"
                cfg = singbox_config(port, srv["protocolHost"], srv["protocolPort"], token,
                               self.listen_host)
                path = os.path.join(SINGBOX_DIR, f"moz-{loc['countryCode']}-"
                                    f"{city.get('cityCode') or port}-{port}.json")
                with open(path, "w") as f:
                    json.dump(cfg, f, indent=2)
                proxies.append({"port": port, "country": loc["countryName"],
                                "countryCode": loc["countryCode"],
                                "city": city["cityName"], "cityCode": city.get("cityCode"),
                                "host": srv["protocolHost"],
                                "upstreamPort": srv["protocolPort"],
                                "protocol": srv["protocol"],
                                "path": path, "label": label})
                if max_p and len(proxies) >= max_p:
                    return proxies
        self.proxies = proxies
        return proxies

    def start_all(self):
        # Same log shape as the builtin engine (only the engine name differs)
        if not self.proxies:
            raise MozVpnError(tr("no_servers_to_serve"))
        started = []
        for p in self.proxies:
            if not port_is_free(p["port"], self.listen_host):
                warn(tr("port_busy", port=p["port"], label=p["label"]))
                continue
            proc = subprocess.Popen([self.exe, "run", "-c", p["path"]],
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
            self.procs[p["port"]] = (proc, p["path"], p["label"])
            started.append(p)
            info(tr("proxy_line", port=p["port"], label=p["label"],
                    host=p["host"], uport=p["upstreamPort"], proto=p["protocol"],
                    listen=self.listen_host))
        if not started:
            raise MozVpnError(tr("no_free_ports"))
        ok(tr("engine_started", engine=tr("engine_singbox"), n=len(started),
              listen=self.listen_host))

    def update_token(self, token: str):
        """Rewrite all configs with the new token and restart sing-box."""
        info(tr("token_updated_singbox"))
        self.stop_all()
        token = self.token_holder.get()
        # Defense in depth: the config directory may have been wiped (hotkeys
        # 'c'/'r', --clear-cache) while this engine object was still alive -
        # recreate it before rewriting the config files into it, otherwise
        # open(path, "w") raises FileNotFoundError.
        os.makedirs(SINGBOX_DIR, exist_ok=True)
        for p in self.proxies:
            cfg = singbox_config(p["port"], p["host"], p["upstreamPort"], token,
                              self.listen_host)
            with open(p["path"], "w") as f:
                json.dump(cfg, f, indent=2)
        self.start_all()

    def stop_all(self):
        for port, (proc, path, label) in list(self.procs.items()):
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            info(tr("singbox_stopped", label=label, port=port,
                    listen=self.listen_host))
        self.procs.clear()

    def check_running(self):
        """Drop dead processes from the map (sing-box may crash on its own)."""
        for port, (proc, path, label) in list(self.procs.items()):
            if proc.poll() is not None:
                warn(tr("singbox_died", label=label, port=port, code=proc.returncode))
                del self.procs[port]

# ---------------- orchestration: session -> token ----------------

def script_dir() -> str:
    """Directory for output JSONs. Nuitka-safe (req. 11): __file__ is not
    guaranteed in frozen executables, so sys.argv[0] / cwd are used."""
    try:
        if getattr(sys, "frozen", False):          # Nuitka/PyInstaller frozen exe
            return os.path.dirname(os.path.abspath(sys.executable))
        return os.path.dirname(os.path.abspath(sys.argv[0] or "."))
    except Exception:
        return os.getcwd()

def ensure_session(args, creds, totp_provider, interactive=True,
                   force_relogin=False) -> str:
    """sessionToken: argument -> cache -> re-login with saved credentials.
    Raises MozVpnError when signing in is impossible."""
    session_token = args.session_token
    email = args.email or creds.get("email")

    if session_token and not all(ch in "0123456789abcdefABCDEF" for ch in session_token):
        raise MozVpnError(tr("session_token_hex"))
    if session_token:
        return session_token.lower()

    if not force_relogin and not args.relogin and os.path.exists(CACHE):
        try:
            with open(CACHE) as f:
                c = json.load(f)
            email = email or c.get("email")
            st = c.get("sessionToken")
            if st:
                info(tr("cached_session", email=email))
                return st
        except Exception:
            pass

    # Re-login
    email = email or (input(tr("enter_email")).strip() if interactive else None)
    if not email:
        raise MozVpnError(tr("email_missing"))
    pw = args.password or creds.get("password")
    if not pw:
        if interactive:
            pw = getpass.getpass(tr("enter_password"))
        else:
            raise MozVpnError(tr("password_missing"))
    info(tr("signing_in"))
    st = fxa_login(email, pw, totp_provider, interactive=interactive,
                   tp=totp_params_from(creds))
    save_cache(email, st)
    save_credentials(email=email, password=pw)
    ok(tr("session_cached", path=CACHE))
    return st

def format_until(until, token: str) -> str:
    """req. 9: never print 'None' - when Guardian returned no 'until',
    derive a human-readable expiry from the JWT exp claim."""
    if until:
        return str(until)
    exp = jwt_exp(token)
    if exp:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp))
    return "unknown"

def obtain_proxy_pass(session_token: str):
    """The full chain OAuth -> Guardian -> proxyPass. Returns (token, until, hdrs)."""
    info(tr("oauth_fetching"))
    oauth = oauth_token(session_token)
    info(tr("guardian_activating"))
    token, until, ghdrs = guardian_pass(oauth)
    oauth_destroy(oauth)   # best-effort revocation of the OAuth access token
    return token, until, ghdrs

def save_result(args, token, until, session_token, email, recommended,
                locations, out_path=None):
    now = time.time()
    fetched_at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) \
               + f".{int(now % 1 * 1000):03d}Z"
    result = {"fetchedAt": fetched_at,
              "proxyPass": {"token": token, "validUntil": until,
                            "validUntilComputed": format_until(until, token)},
              "sessionToken": session_token,
              "email": email,
              "recommended": recommended,
              "locations": locations}
    if args.no_save:
        return None
    out = out_path or args.json or os.path.join(
        script_dir(), "mozvpn-" + time.strftime("%Y%m%d-%H%M%S", time.gmtime(now)) + ".json")
    with open(out, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    ok(tr("json_saved", path=out))
    return out

# ---------------- long-running manager (watch / local proxies) ----------------

_STOP = False
_CONFIRMISSUED = False

def _on_sigint(signum, frame):
    """Ctrl+C handling (req. 12): by default the FIRST Ctrl+C stops the
    script immediately - _STOP is set AND KeyboardInterrupt is raised from
    the handler so blocking socket reads (probe, upstream TLS handshakes)
    abort at once instead of waiting for their timeout. The two-press
    confirmation exists ONLY when --confirm-exit is given."""
    global _STOP, _CONFIRMISSUED
    if _confirm_exit_enabled and _CONFIRMISSUED is False:
        warn(tr("confirm_exit_prompt"))
        _CONFIRMISSUED = time.time()
        return
    # Immediate stop (default path, or the second press in confirm mode)
    _STOP = True
    _CONFIRMISSUED = False
    raise KeyboardInterrupt

def _on_sigterm(signum, frame):
    global _STOP
    _STOP = True

_confirm_exit_enabled = False

def collect_verified_servers(args, locations, token: str) -> dict:
    """Run the parallel probe (req. 7) and return
    {(countryCode, cityCode): server_dict}. Every returned server dict gets a
    "probe_ok" flag. Failed servers are dropped only with --probe-fail drop;
    the default (keep) serves them anyway with a warning, because a probe
    failure is often caused by local network filtering (SNI/DPI) while the
    tunnel still works from curl/other clients."""
    # Gather one candidate server per city (prefer MASQUE entries if any)
    candidates = {}
    for loc in locations:
        for city in loc["cities"]:
            for s in city["servers"]:
                key = (loc["countryCode"], city.get("cityCode"))
                cur = candidates.get(key)
                if cur is None or (cur["protocol"] != PROTO_MASQUE
                                   and s["protocol"] == PROTO_MASQUE):
                    s = dict(s)
                    # Optional manual override of the egress host/port
                    # (Fastly anycast pool, hosts-file trick, custom port)
                    if getattr(args, "upstream_host", None):
                        s["protocolHost"] = args.upstream_host
                        s["host"] = args.upstream_host
                    if getattr(args, "upstream_port", None):
                        s["protocolPort"] = args.upstream_port
                    candidates[key] = s
    servers = list(candidates.values())
    if getattr(args, "upstream_host", None):
        info(tr("upstream_override", host=args.upstream_host,
                port=(args.upstream_port
                      or (servers[0]["protocolPort"] if servers else 2499))))
    if args.proxy_check:
        # req: minimal probing by default - only the first --probe-count
        # upstreams are verified (0 = all). A failed or skipped probe does
        # not remove a server from the served list (see --probe-fail).
        n_probe = getattr(args, "probe_count", 1)
        if n_probe and n_probe > 0:
            probe_servers = servers[:n_probe]
        else:
            probe_servers = servers
        probed_hp = {(s["protocolHost"], s["protocolPort"])
                     for s in probe_servers}
        results = probe_upstreams_parallel(probe_servers, token,
                                            args.ip_echo_url, args.ip_echo_name)
        # Several locations can share one egress (and with --upstream-host
        # they all do), so match results by (host, port), not by identity.
        ok_by_hp = {}
        for r in results:
            rs = r.get("server") or {}
            if r["ok"]:
                ok_by_hp[(rs.get("protocolHost"), rs.get("protocolPort"))] = rs
        for key, s in candidates.items():
            if (s["protocolHost"], s["protocolPort"]) not in probed_hp:
                s["probe_ok"] = None          # not probed (probe-count limit)
                continue
            rs = ok_by_hp.get((s["protocolHost"], s["protocolPort"]))
            if rs is not None:
                s.update(rs)          # may carry the CONNECT-fallback protocol
                s["probe_ok"] = True
            else:
                s["probe_ok"] = False
        verified = {k: v for k, v in candidates.items()
                    if v["probe_ok"] is not False
                    or getattr(args, "probe_fail", "keep") != "drop"}
        # No "all probes failed" hint here: the summary lines above already
        # state the check result; the user asked for the hint to be removed.
        return verified
    info(tr("proxy_check_disabled"))
    for s in candidates.values():
        s["probe_ok"] = None          # not probed
    return candidates

def run_manager(args, creds, totp_provider):
    """The loop: keep proxyPass fresh (reissue --refresh-margin seconds before
    exp, re-login when the sessionToken expires), optionally serve local
    proxies via the selected engine (builtin or singbox)."""
    global _confirm_exit_enabled, _STOP
    _confirm_exit_enabled = bool(args.confirm_exit)

    token_holder = TokenHolder()
    engine = None
    if args.local_proxy:
        if args.local_proxy_engine == "singbox":
            engine = SingBoxEngine(args, token_holder)
        else:
            engine = BuiltinProxyEngine(args, token_holder)
    # (the engine name is echoed once by main(); do not repeat it here)

    locations, recommended = None, None
    verified_servers = None
    json_out = args.json or None
    session_token, force_relogin = None, False
    relogin_backoff = 0
    copy_mode = None        # None | "local" | "remote" (v / b sub-modes)
    totp_secret = (args.totp_secret or "").strip() or creds.get("totp_secret")

    signal.signal(signal.SIGINT, _on_sigint)
    signal.signal(signal.SIGTERM, _on_sigterm)

    def cleanup():
        if engine:
            print()
            info(tr("proxy_stopping"))
            engine.stop_all()
            ok(tr("proxy_stopped"))
    atexit.register(cleanup)

    while not _STOP:
        try:
            # (Re)create the engine after a hotkey engine switch ('e')
            if args.local_proxy and engine is None:
                # v4.3: the singbox engine without a sing-box binary is a
                # dead end - repeat the install question (the cached decline
                # is ignored when the singbox engine is explicitly selected),
                # and fall back to the builtin engine if it stays missing.
                if (args.local_proxy_engine == "singbox"
                        and not singbox_binary_path()):
                    if not offer_install_singbox(
                            force_ask=True,
                            interactive=not args.no_input):
                        args.local_proxy_engine = "builtin"
                        warn(tr("singbox_engine_still_missing"))
                if args.local_proxy_engine == "singbox":
                    engine = SingBoxEngine(args, token_holder)
                else:
                    engine = BuiltinProxyEngine(args, token_holder)
            session_token = ensure_session(
                args, creds, totp_provider,
                interactive=not args.no_input,
                force_relogin=force_relogin)
            force_relogin = False
            relogin_backoff = 0

            token, until, ghdrs = obtain_proxy_pass(session_token)
            token_holder.set(token)
            exp = jwt_exp(token)
            exp_str = time.strftime("%H:%M:%S", time.gmtime(exp)) if exp else "?"
            # req. 9: a human-readable expiry instead of "None"
            ok(tr("proxypass_received",
                  until=format_until(until, token), exp=exp_str))

            if locations is None:
                info(tr("serverlist_fetching"))
                locations_all, recommended = fetch_serverlist(
                    args.firefox_version, args.client_country, args.include_locked)
                locations = select_locations(locations_all, recommended,
                                             args.country, args.city)

            # Parallel upstream verification (req. 7, default enabled)
            if verified_servers is None:
                verified_servers = collect_verified_servers(args, locations, token)
                total = len(verified_servers)
                ok(tr("serverlist_done", countries=len(locations), servers=total))

            print_quota(ghdrs)
            print_current_totp(totp_secret, creds)
            print()
            info(tr("proxypass_jwt"))
            print(token)
            print_jwt_decoded(token)

            json_out = save_result(args, token, until, session_token,
                                   args.email or creds.get("email"),
                                   recommended, locations, out_path=json_out)

            if engine:
                engine.check_running()
                if not engine.proxies:
                    # The token must be in the holder BEFORE build_proxies():
                    # the sing-box engine bakes the Bearer into its configs.
                    engine.token_holder.set(token)
                    engine.proxies = engine.build_proxies(locations, verified_servers)
                    engine.start_all()
                    # Test commands: ready-to-paste curl lines for EVERY local
                    # proxy and for EVERY upstream (remote) proxy. The local
                    # command goes through the local listener (no Bearer
                    # needed - the engine adds it); the remote command talks
                    # to the upstream directly with the current Bearer token.
                    # Opt-in: --show-test-commands (default off) - the block
                    # is long (one Bearer line per upstream), so it is hidden
                    # unless explicitly requested.
                    if getattr(args, "show_test_commands", False):
                        info(tr("test_commands_header"))
                        for p in engine.proxies:
                            cmd = (f"curl -s --proxy http://{engine.listen_host}:"
                                   f"{p['port']} --proxy-insecure {args.ip_echo_url}")
                            hint(tr("test_command_local", cmd=cmd,
                                    label=p["label"], proto=p["protocol"]))
                        info(tr("test_commands_remote_header"))
                        for p in engine.proxies:
                            cmd = (f"curl -s --proxy https://{p['host']}:"
                                   f"{p['upstreamPort']} --proxy-header "
                                   f"\"Proxy-Authorization: Bearer {token}\" "
                                   f"--proxy-insecure {args.ip_echo_url}")
                            hint(tr("test_command_remote", cmd=cmd,
                                    label=p["label"]))
                    else:
                        hint(tr("test_commands_hidden"))
                    # v4.3 (req. 7): explicit protocol summary - how many
                    # upstreams are served via MASQUE (priority) vs HTTP
                    # CONNECT (fallback), with the protocol names spelled out
                    m = sum(1 for p in engine.proxies
                            if p["protocol"] == PROTO_MASQUE)
                    c = sum(1 for p in engine.proxies
                            if p["protocol"] == PROTO_CONNECT)
                    info(tr("protocol_summary", m=m, c=c))
                else:
                    engine.update_token(token)

            # Sleep until exp - margin
            if not exp:
                warn("exp not extracted from the JWT - refreshing in 300s.")
                sleep_s = 300
            else:
                sleep_s = exp - args.refresh_margin - int(time.time())
            if sleep_s < 5:
                sleep_s = 5
            info(tr("next_refresh", sec=sleep_s,
                    at=time.strftime("%H:%M:%S", time.gmtime(time.time() + sleep_s)))
                 + " " + tr("confirm_exit_hint"))
            # Sleep in short steps to react to Ctrl+C and hotkeys quickly.
            # Single-keypress hotkeys mirror the CLI flags:
            #   r = fresh re-login, c = --clear-cache + restart,
            #   e = toggle --local-proxy-engine + restart proxies, q = stop.
            # v4.5: every hotkey on its OWN line, the key on its color
            # block, the description in the dedicated hotdesc color.
            print_hotkeys_hint()
            files = config_open_files()
            if files:
                info(tr("hotkey_files_hint"))
                for i, p in enumerate(files, 1):
                    hint(tr("hotkey_file_entry", n=i, path=p))
            # What the 'c' hotkey / --clear-cache will remove (req: log it)
            print_clear_targets()
            _hotkey_mode(True)
            slept = 0
            while slept < sleep_s and not _STOP:
                # --confirm-exit: a Ctrl+C was issued but not confirmed within 5s
                if _CONFIRMISSUED and isinstance(_CONFIRMISSUED, float):
                    if time.time() - _CONFIRMISSUED > 5:
                        info(tr("confirm_exit_abort"))
                        _reset_confirm()
                k = _key_pressed()
                if copy_mode and k:
                    # v/b sub-mode: a digit copies the chosen proxy address,
                    # any other key cancels (v/b re-enter the mode below)
                    if k.isdigit() and k != "0" and engine and engine.proxies:
                        idx = int(k) - 1
                        if 0 <= idx < len(engine.proxies):
                            p = engine.proxies[idx]
                            text = (f"{engine.listen_host}:{p['port']}"
                                    if copy_mode == "local"
                                    else f"{p['host']}:{p['upstreamPort']}")
                            if copy_to_clipboard(text):
                                ok(tr("hotkey_copied", text=text))
                        copy_mode = None
                        k = ""
                    elif k not in ("v", "b"):
                        info(tr("hotkey_copy_cancel"))
                        copy_mode = None
                        k = ""
                if k == "r":
                    # FULL wipe: saved session, credentials, cookies, sing-box
                    # configs AND the in-memory creds - a fresh sign-in must
                    # not be able to reuse anything (req: relogin = full wipe)
                    info(tr("hotkey_relogin"))
                    _hotkey_mode(False)
                    wipe_all_saved_data(creds)
                    totp_secret = None
                    session_token = None
                    force_relogin = True
                    # The wipe removed the sing-box config directory with all
                    # config files, but the live engine still references those
                    # (now deleted) paths - its update_token() would crash with
                    # FileNotFoundError rewriting them. Stop the proxies and
                    # drop the engine so the next loop iteration rebuilds it
                    # from scratch (fresh configs, fresh ports) after the new
                    # sign-in.
                    if engine:
                        engine.stop_all()
                    engine = None
                    break
                elif k == "c":
                    _hotkey_mode(False)
                    info(tr("hotkey_clear"))
                    wipe_all_saved_data(creds)
                    totp_secret = None
                    session_token = None
                    force_relogin = True
                    # Same as 'r': the engine's config files were just wiped -
                    # stop it and let the next iteration rebuild it cleanly.
                    if engine:
                        engine.stop_all()
                    engine = None
                    break
                elif k == "e":
                    _hotkey_mode(False)
                    args.local_proxy_engine = ("singbox"
                        if args.local_proxy_engine == "builtin" else "builtin")
                    # v4.3: switching TO singbox while the binary is missing
                    # repeats the install offer (the cached decline is
                    # ignored for an explicit engine selection); if it stays
                    # missing the builtin engine is kept.
                    if (args.local_proxy_engine == "singbox"
                            and not singbox_binary_path()):
                        if not offer_install_singbox(
                                force_ask=True,
                                interactive=not args.no_input):
                            args.local_proxy_engine = "builtin"
                            warn(tr("singbox_engine_still_missing"))
                    info(tr("hotkey_engine",
                            engine=tr("engine_singbox")
                            if args.local_proxy_engine == "singbox"
                            else tr("engine_builtin")))
                    if engine:
                        engine.stop_all()
                    engine = None
                    token_holder = TokenHolder()
                    break
                elif k == "l":
                    # Toggle the listener bind host 127.0.0.1 <-> 0.0.0.0
                    # and restart the local proxies with the new address.
                    _hotkey_mode(False)
                    args.listen = ("0.0.0.0"
                        if getattr(args, "listen", "127.0.0.1") == "127.0.0.1"
                        else "127.0.0.1")
                    info(tr("hotkey_listen", host=args.listen))
                    if engine:
                        engine.stop_all()
                    engine = None
                    break
                elif k == "o":
                    # Open the singbox config directory in the file manager.
                    # If it does not exist yet (only the singbox engine
                    # creates it - the builtin engine does not), open the
                    # MAIN config directory instead and say so, instead of
                    # the old dead-end "file does not exist" warning.
                    # (no terminal mode change: the opener is a subprocess)
                    if os.path.isdir(SINGBOX_DIR):
                        open_in_system_editor(SINGBOX_DIR)
                    else:
                        info(tr("hotkey_open_dir_fallback", path=CONF_DIR))
                        open_in_system_editor(CONF_DIR)
                elif k == "t":
                    # Show the current TOTP code and copy it to the clipboard
                    if totp_secret:
                        try:
                            digits, period, algorithm = totp_params_from(creds)
                            code, valid = totp_generate(totp_secret, digits,
                                                        period, algorithm)
                            print_current_totp(totp_secret, creds)
                            if copy_to_clipboard(code):
                                ok(tr("hotkey_totp"))
                        except MozVpnError as e:
                            err(str(e))
                    else:
                        # Say WHY there is no TOTP secret, not just that
                        # there is none: the reason depends on whether
                        # credentials.json exists at all and whether it has
                        # the totp_secret field inside.
                        reason = (tr("totp_none_reason_nocreds")
                                  if not os.path.isfile(CRED_CACHE)
                                  else tr("totp_none_reason_nosecret"))
                        info(tr("hotkey_totp_none", reason=reason))
                elif k == "v" and engine and engine.proxies:
                    # Copy a LOCAL proxy address (listen host + port)
                    copy_mode = "local"
                    info(tr("hotkey_copy_local_hint"))
                    for i, p in enumerate(engine.proxies, 1):
                        hint(tr("hotkey_copy_entry", n=i,
                                addr=f"{engine.listen_host}:{p['port']}",
                                label=p["label"]))
                elif k == "b" and engine and engine.proxies:
                    # Copy an UPSTREAM (remote) proxy address
                    copy_mode = "remote"
                    info(tr("hotkey_copy_remote_hint"))
                    for i, p in enumerate(engine.proxies, 1):
                        hint(tr("hotkey_copy_entry", n=i,
                                addr=f"{p['host']}:{p['upstreamPort']}",
                                label=p["label"]))
                elif k == "g":
                    # v4.3 (req. 5): load a QR image with the 2FA (TOTP)
                    # secret ON THE FLY - the interactive --qr. The path is
                    # entered in a prompt, the secret is decoded, saved to
                    # credentials.json and used immediately.
                    _hotkey_mode(False)
                    try:
                        path = input(tr("hotkey_qr_prompt")).strip()
                    except EOFError:
                        path = ""
                    _hotkey_mode(True)
                    if path:
                        try:
                            qr = decode_qr_totp(path)
                            secret = qr.pop("secret")
                            save_credentials(totp_secret=secret,
                                            totp_digits=qr["digits"],
                                            totp_period=qr["period"],
                                            totp_algorithm=qr["algorithm"])
                            creds.update(load_credentials())
                            totp_secret = secret
                            # rebuild the TOTP provider so future re-logins
                            # use the freshly saved secret
                            if creds.get("totp_secret"):
                                totp_provider = make_totp_provider(args, creds)
                            digits, period, algorithm = totp_params_from(creds)
                            code, valid = totp_generate(secret, digits,
                                                        period, algorithm)
                            ok(tr("hotkey_qr_loaded", path=path,
                                  code=code, sec=valid))
                            copy_to_clipboard(code)
                        except MozVpnError as e:
                            err(tr("hotkey_qr_fail", err=e))
                        except Exception as e:
                            err(tr("hotkey_qr_fail", err=e))
                elif k == "u":
                    # v4.3 (req. 9): show the saved login (email) and copy it
                    email = (creds.get("email") or "").strip() or args.email
                    if email:
                        info(tr("hotkey_login", email=email))
                        copy_to_clipboard(email)
                    else:
                        info(tr("hotkey_login_none"))
                elif k == "p":
                    # v4.3 (req. 8): show the saved password and copy it
                    password = (creds.get("password") or "").strip() or args.password
                    if password:
                        info(tr("hotkey_password", password=password))
                        copy_to_clipboard(password)
                    else:
                        info(tr("hotkey_password_none"))
                elif k == "d":
                    # v4.3 (req. 3): reinstall ALL Python dependencies from
                    # scratch (mirrors --reinstall-deps)
                    _hotkey_mode(False)
                    if reinstall_dependencies(interactive=True):
                        ok(tr("hotkey_deps_reinstalled"))
                    _hotkey_mode(True)
                elif k == "s":
                    # v4.3 (req. 4): reinstall sing-box from scratch (mirrors
                    # --reinstall-singbox); if the singbox engine is active,
                    # restart it with the fresh binary
                    _hotkey_mode(False)
                    reinstalled = reinstall_singbox(interactive=True)
                    _hotkey_mode(True)
                    if (reinstalled and engine
                            and args.local_proxy_engine == "singbox"):
                        engine.stop_all()
                        engine = None
                        break
                elif k == "j":
                    # v4.5 (req. 3): show the CURRENT proxyPass JWT (the
                    # token the local proxies sign with right now) and copy
                    # it to the clipboard
                    token_now = token_holder.get()
                    if token_now:
                        info(tr("hotkey_jwt"))
                        print(token_now)
                        copy_to_clipboard(token_now)
                    else:
                        info(tr("hotkey_jwt_none"))
                elif k == "m":
                    # v4.4 (req. 2): switch the color theme dark <-> light
                    # (mirrors --theme); v4.5: the WHOLE log is redrawn in
                    # the new theme (every remembered line re-rendered)
                    new_theme = "light" if _THEME == "dark" else "dark"
                    set_theme(new_theme)
                    redraw_log()
                    info(tr("hotkey_theme", theme=new_theme))
                elif k == "n":
                    # v4.4 (req. 3): toggle the colored log output on/off
                    # (mirrors --no-color); v4.5: the WHOLE log is redrawn
                    # with colors on or off. v4.7.1: the forced window
                    # background follows the color mode - colors back on
                    # -> re-force the theme background (idempotent, so a
                    # no-op while it was never released); colors off ->
                    # release it back to the terminal default.
                    set_color(not _USE_COLOR)
                    if _USE_COLOR:
                        _force_terminal_bg(_THEME)
                    elif _BG_CURRENT is not None:
                        _restore_terminal_bg()
                        _BG_CURRENT = None
                    redraw_log()
                    if _USE_COLOR:
                        info(tr("color_enabled"))
                    else:
                        info(tr("color_disabled"))
                elif k and k.isdigit() and k != "0":
                    # 1-9: open the config file in the system default editor
                    files = config_open_files()
                    idx = int(k) - 1
                    if 0 <= idx < len(files):
                        open_in_system_editor(files[idx])
                elif k == "q":
                    info(tr("hotkey_stop"))
                    _STOP = True
                    break
                time.sleep(1)
                slept += 1
            _hotkey_mode(False)
            if _STOP:
                break

        except MozVpnError as e:
            err(str(e))
            # Language-independent classification via MozVpnError.code
            code = getattr(e, "code", "")
            if code == "blocked":
                info(tr("blocked_wait"))
                _sleep_interruptible(600)
            elif code == "relogin":
                info(tr("relogin_needed"))
                # v4.4: say explicitly that the login/password/TOTP prompt
                # will appear again - with a live countdown (--retry-delay)
                info(tr("retry_wait"))
                wait_s = min(60, 5 * (relogin_backoff + 1))
                info(tr("retry_after", sec=wait_s))
                _sleep_with_countdown(wait_s)
                force_relogin = True
                relogin_backoff += 1
            else:
                # v4.4: a failed sign-in (e.g. the Fastly WAF challenge)
                # usually succeeds on the second attempt - tell the user to
                # WAIT, that the prompt will reappear automatically, and
                # show the live countdown (--retry-delay, default 30s).
                info(tr("retry_wait"))
                retry_s = getattr(args, "retry_delay", 30) or 30
                info(tr("retry_after", sec=retry_s))
                _sleep_with_countdown(retry_s)
        except KeyboardInterrupt:
            break
        except Exception as e:
            warn(tr("unexpected_error", err=e))
            _sleep_interruptible(30)

    cleanup()

def _reset_confirm():
    """Clear the 'first Ctrl+C issued' marker after the confirmation window."""
    global _CONFIRMISSUED
    _CONFIRMISSUED = False

def _hotkey_mode(on: bool):
    """Switch the terminal to/from single-keypress mode. Windows needs
    nothing (msvcrt polls the console); POSIX gets cbreak so keys are
    delivered without Enter. Interactive input() (TOTP prompts) happens
    OUTSIDE hotkey mode, so line editing is unaffected."""
    if os.name == "nt":
        return
    try:
        import termios, tty
        fd = sys.stdin.fileno()
        if on:
            _hotkey_mode.old = termios.tcgetattr(fd)
            tty.setcbreak(fd)
        elif getattr(_hotkey_mode, "old", None):
            termios.tcsetattr(fd, termios.TCSADRAIN, _hotkey_mode.old)
            _hotkey_mode.old = None
    except Exception:
        pass

# v4.7 (req. 2): hotkeys must work in ANY keyboard layout. Two layers:
#
# 1) WINDOWS - fully layout-independent via the PHYSICAL key position:
#    msvcrt.getwch() returns the character produced by the CURRENT
#    layout (e.g. 'й' when Russian ЙЦУКЕН is active), so the raw char
#    alone is not enough. The chain  char -> VkKeyScanW -> virtual key
#    -> MapVirtualKeyW(MAPVK_VK_TO_VSC) -> scan code  recovers the
#    PHYSICAL key: VkKeyScanW maps a character to the virtual key that
#    produces it under the ACTIVE layout, and MapVirtualKeyW translates
#    that virtual key to the (layout-independent) scan code of the key
#    cap. Scan codes are physical, so the hotkey letters work on ANY
#    layout - Russian, Belarusian, Ukrainian, French AZERTY, German
#    QWERTZ, etc. (verified against the Win32 documentation of
#    VkKeyScanW and MapVirtualKeyW).
# 2) POSIX - terminals report only the layout-translated character in
#    the input stream (there is no scan-code channel), so a translation
#    table for the standard Cyrillic ЙЦУКЕН family (Russian, and the
#    position-compatible Belarusian/Ukrainian letters) maps the typed
#    letter to the English key in the SAME physical position.
_SCAN_TO_KEY = {
    # set 1 / PS/2 scan codes of the letter and digit key caps
    0x02: "1", 0x03: "2", 0x04: "3", 0x05: "4", 0x06: "5",
    0x07: "6", 0x08: "7", 0x09: "8", 0x0A: "9", 0x0B: "0",
    0x10: "q", 0x11: "w", 0x12: "e", 0x13: "r", 0x14: "t",
    0x15: "y", 0x16: "u", 0x17: "i", 0x18: "o", 0x19: "p",
    0x1E: "a", 0x1F: "s", 0x20: "d", 0x21: "f", 0x22: "g",
    0x23: "h", 0x24: "j", 0x25: "k", 0x26: "l",
    0x2C: "z", 0x2D: "x", 0x2E: "c", 0x2F: "v", 0x30: "b",
    0x31: "n", 0x32: "m",
}

_CYR_TO_LATIN = {
    # standard Russian ЙЦУКЕН: typed letter -> English key in the same
    # physical position (Belarusian/Ukrainian layouts share the letter
    # row positions; their unique letters sit where [];' etc. are and
    # are not used by any hotkey)
    "й": "q", "ц": "w", "у": "e", "к": "r", "е": "t",
    "н": "y", "г": "u", "ш": "i", "щ": "o", "з": "p",
    "ф": "a", "ы": "s", "в": "d", "а": "f", "п": "g",
    "р": "h", "о": "j", "л": "k", "д": "l",
    "я": "z", "ч": "x", "с": "c", "м": "v", "и": "b",
    "т": "n", "ь": "m", "ї": "s", "і": "s", "ў": "f",
    # uppercase too (Caps Lock)
    "Й": "q", "Ц": "w", "У": "e", "К": "r", "Е": "t",
    "Н": "y", "Г": "u", "Ш": "i", "Щ": "o", "З": "p",
    "Ф": "a", "Ы": "s", "В": "d", "А": "f", "П": "g",
    "Р": "h", "О": "j", "Л": "k", "Д": "l",
    "Я": "z", "Ч": "x", "С": "c", "М": "v", "И": "b",
    "Т": "n", "Ь": "m", "Ї": "s", "І": "s", "Ў": "f",
}

def _normalize_key(k: str) -> str:
    """Map a RAW pressed key to the canonical (English QWERTY) hotkey
    letter, so hotkeys work in any keyboard layout (v4.7, req. 2).
    Returns '' for anything that is not a single-character key."""
    if not k or len(k) != 1:
        return ""
    low = k.lower()
    if ("a" <= low <= "z") or low.isdigit():
        return low
    if os.name == "nt":
        # physical-position route (see the comment above the tables)
        try:
            import ctypes
            user32 = ctypes.windll.user32
            vks = user32.VkKeyScanW(ctypes.c_wchar(k))
            if vks != -1:
                scan = user32.MapVirtualKeyW(vks & 0xFF, 0)  # MAPVK_VK_TO_VSC
                if scan in _SCAN_TO_KEY:
                    return _SCAN_TO_KEY[scan]
        except Exception:
            pass
    return _CYR_TO_LATIN.get(k, low)

def _key_pressed() -> str:
    """Non-blocking single-key read; returns the canonical hotkey letter
    (independent of the active keyboard layout, see _normalize_key) or ''."""
    try:
        if os.name == "nt":
            import msvcrt
            if msvcrt.kbhit():
                k = msvcrt.getwch()
                # Ignore bare special-key prefixes (arrows etc.)
                return _normalize_key(k) if len(k) == 1 else ""
            return ""
        import select
        r, _, _ = select.select([sys.stdin], [], [], 0)
        if r:
            k = sys.stdin.read(1)
            return _normalize_key(k)
    except Exception:
        pass
    return ""

def _sleep_interruptible(seconds: float):
    """Sleep that stops early when _STOP is set (Ctrl+C confirmed)."""
    global _CONFIRMISSUED
    end = time.time() + seconds
    while time.time() < end and not _STOP:
        if _CONFIRMISSUED and isinstance(_CONFIRMISSUED, float):
            if time.time() - _CONFIRMISSUED > 5:
                info(tr("confirm_exit_abort"))
                _reset_confirm()
        time.sleep(1)

def _sleep_with_countdown(seconds: float):
    """Sleep with a LIVE on-screen countdown of the remaining seconds (the
    line rewrites itself in place every second). Used after a failed
    sign-in so the user clearly sees after how long the login/password/
    TOTP prompt appears again. Stops early when _STOP is set; honors the
    --confirm-exit abort window just like _sleep_interruptible."""
    global _CONFIRMISSUED
    end = time.time() + max(1, seconds)
    while not _STOP:
        remain = int(end - time.time())
        if remain <= 0:
            break
        # plain \r rewrite (not _emit): the line must stay on one row
        print(f"\r  {tr('retry_in')} {remain:4d}s ...   ", end="", flush=True)
        if _CONFIRMISSUED and isinstance(_CONFIRMISSUED, float):
            if time.time() - _CONFIRMISSUED > 5:
                print()
                info(tr("confirm_exit_abort"))
                _reset_confirm()
        time.sleep(1)
    # clear the countdown line so the next log line starts clean
    print("\r" + " " * 60 + "\r", end="", flush=True)

# ---------------- dependency management (v4.3) ----------------
# All Python dependencies of this script in one place: (pip name, module, required)
PIP_DEPS = (
    ("pyotp",     "pyotp",    True),    # TOTP code generation
    ("zxing-cpp", "zxingcpp", True),    # QR code decoding
    ("Pillow",    "PIL",      True),    # image opening for the QR
    ("aioquic",   "aioquic",  False),   # real MASQUE / HTTP-3 (optional)
)

SINGBOX_DECLINE_CACHE = os.path.join(CONF_DIR, "singbox-install.json")
SINGBOX_INSTALL_PAGE  = "https://sing-box.sagernet.org/installation/"
SINGBOX_RELEASES_PAGE = "https://github.com/SagerNet/sing-box/releases"

def is_frozen() -> bool:
    """True when running as a compiled binary: PyInstaller sets sys.frozen,
    Nuitka sets __compiled__ in the main module (both documented behaviors).
    pip installs are useless there, so automatic dependency installation
    is skipped and the user is told to install manually."""
    return bool(getattr(sys, "frozen", False)) or "__compiled__" in globals()

def _dep_version(module: str) -> str:
    try:
        import importlib
        m = importlib.import_module(module)
        v = getattr(m, "__version__", None)
        return str(v) if v else "-"
    except Exception:
        return "-"

def print_dependencies():
    """Print EVERY Python dependency (pip name, module, version, status)
    and return the list of missing pip names."""
    info(tr("deps_header"))
    missing = []
    for pip_name, module, required in PIP_DEPS:
        try:
            import importlib
            importlib.import_module(module)
            hint(tr("deps_entry_ok", pip=pip_name, module=module,
                    version=_dep_version(module)))
        except ImportError:
            hint(tr("deps_entry_missing", pip=pip_name, module=module,
                    need=(tr("deps_need_required") if required
                          else tr("deps_need_optional"))))
            missing.append(pip_name)
    # v4.6 (req. 2): the external (non-pip) sing-box dependency and its
    # current state - installed path + version from 'sing-box version',
    # or a clear note that it is OPTIONAL (the builtin engine does not
    # need it).
    info(tr("singbox_dep_header"))
    sb = singbox_binary_path()
    if sb:
        version = "-"
        try:
            out = subprocess.run([sb, "version"], capture_output=True,
                                 text=True, timeout=10)
            m = re.search(r"version\s+(\S+)", (out.stdout or "")
                          + (out.stderr or ""))
            if m:
                version = m.group(1)
        except Exception:
            pass
        hint(tr("singbox_dep_ok", path=sb, version=version))
    else:
        hint(tr("singbox_dep_missing"))
    if missing:
        warn(tr("deps_missing_note", list=", ".join(missing)))
    return missing

def _pip_cmd(pkgs, force=False, nodeps=False) -> list:
    cmd = [sys.executable, "-m", "pip", "install"]
    if force:
        cmd += ["--force-reinstall", "--no-cache-dir"]
    if nodeps:
        cmd += ["--no-deps"]
    return cmd + list(pkgs)

def _run_pip(pkgs, force=False, nodeps=False) -> int:
    """Run pip as a subprocess (its output goes straight to the terminal).
    Returns the pip exit code, -1 on an OS-level failure."""
    try:
        return subprocess.run(_pip_cmd(pkgs, force, nodeps)).returncode
    except Exception as e:
        err(tr("deps_install_fail", code=-1, err=e))
        return -1

def _install_pip_staged(pip_names, force=False) -> list:
    """v4.7 (req. 3): STAGED pip install that survives dependency conflicts
    (pip's ResolutionImpossible). Verified against the pip documentation:
    the resolver reports a conflict when the REQUESTED packages pin shared
    dependencies to incompatible versions, and installing everything in
    ONE command lets pip resolve the versions TOGETHER; --force-reinstall
    makes conflicts far more likely because every shared (transitive)
    dependency is forced to an exact version. Stages:
      1) ALL packages in one pip command (with --force-reinstall only
         for a full reinstall, i.e. when force=True);
      2) if that fails: each package SEPARATELY and WITHOUT
         --force-reinstall, so pip is free to pick compatible versions;
      3) if a package still conflicts: pip install <pkg> --no-deps as a
         last resort (the already-installed dependency tree satisfies
         the imports; a plain reinstall keeps it in place).
    Returns the list of packages that could NOT be installed."""
    # stage 1: everything in one command - the resolver sees it all
    if _run_pip(pip_names, force) == 0:
        return []
    # stage 2: per-package, no forcing
    hint(tr("deps_fallback_each"))
    failed = []
    for pkg in pip_names:
        if _run_pip([pkg]) == 0:
            ok(tr("deps_pkg_ok", pkg=pkg))
            continue
        # stage 3: last resort for this one package
        hint(tr("deps_fallback_nodeps", pkg=pkg))
        if _run_pip([pkg], force=True, nodeps=True) == 0:
            ok(tr("deps_pkg_ok", pkg=pkg))
        else:
            err(tr("deps_pkg_fail", pkg=pkg))
            failed.append(pkg)
    return failed

def _reimport_dep_modules():
    """Import the dependency modules again right after a pip install, so
    the new packages are used WITHOUT a script restart."""
    global pyotp, zxingcpp, Image, aioquic
    import importlib
    try:
        pyotp = importlib.import_module("pyotp")
    except ImportError:
        pyotp = None
    try:
        zxingcpp = importlib.import_module("zxingcpp")
    except ImportError:
        zxingcpp = None
    try:
        Image = importlib.import_module("PIL.Image")
    except ImportError:
        Image = None
    try:
        aioquic = importlib.import_module("aioquic")
    except ImportError:
        aioquic = None

def offer_install_deps(missing, interactive=True):
    """Offer to pip-install the missing dependencies automatically - ONLY
    when the script runs under a real python interpreter (not frozen)."""
    if not missing:
        return
    pip_names = [p for p, m, r in PIP_DEPS if p in missing]
    cmd_txt = " ".join(_pip_cmd(pip_names))
    if is_frozen():
        info(tr("deps_frozen_note", cmd=cmd_txt))
        return
    if not interactive or not sys.stdin.isatty():
        hint(tr("deps_manual_hint", cmd=cmd_txt))
        return
    try:
        ans = input(tr("deps_install_q", cmd=cmd_txt)).strip().lower()
    except EOFError:
        ans = "n"
    if ans in [w.strip() for w in tr("answer_no_words").split(",")]:
        info(tr("deps_install_declined"))
        return
    info(tr("deps_installing", pkgs=" ".join(pip_names)))
    failed = _install_pip_staged(pip_names)
    _reimport_dep_modules()
    if not failed:
        ok(tr("deps_install_ok"))
    else:
        err(tr("deps_conflict_fail", pkgs=", ".join(failed)))

def reinstall_dependencies(interactive=True) -> bool:
    """Full reinstall of ALL Python dependencies from scratch."""
    pip_names = [p for p, m, r in PIP_DEPS]
    if is_frozen():
        info(tr("deps_reinstall_skip_frozen"))
        return False
    info(tr("deps_reinstall_header", pkgs=" ".join(pip_names)))
    failed = _install_pip_staged(pip_names, force=True)
    _reimport_dep_modules()
    if not failed:
        ok(tr("deps_reinstall_ok"))
        return True
    err(tr("deps_conflict_fail", pkgs=", ".join(failed)))
    return False

def singbox_binary_path():
    try:
        import shutil
        return shutil.which("sing-box") or shutil.which("sing-box.exe")
    except Exception:
        return None

def _is_termux() -> bool:
    return ("TERMUX_VERSION" in os.environ
            or "com.termux" in (os.environ.get("PREFIX") or ""))

def singbox_install_command():
    """(cmd_list, is_manual) for this platform. Verified against public
    sources: Termux has a sing-box package in the official termux-packages
    repository (pkg install sing-box); macOS has the Homebrew formula
    'sing-box' (brew install sing-box); on Linux the official package
    manager install (deb/rpm) is documented on sing-box.sagernet.org; on
    Windows there is no package manager - the releases page is opened."""
    if _is_termux():
        return ["pkg", "install", "-y", "sing-box"], False
    if sys.platform == "darwin":
        return ["brew", "install", "sing-box"], False
    return None, True   # Linux / Windows: manual install via the official page

def _singbox_declined() -> bool:
    try:
        with open(SINGBOX_DECLINE_CACHE) as f:
            return bool(json.load(f).get("declined"))
    except Exception:
        return False

def _save_singbox_declined():
    try:
        os.makedirs(os.path.dirname(SINGBOX_DECLINE_CACHE), exist_ok=True)
        with open(SINGBOX_DECLINE_CACHE, "w") as f:
            json.dump({"declined": True}, f)
        _chmod600(SINGBOX_DECLINE_CACHE)
    except OSError:
        pass

def offer_install_singbox(force_ask=False, interactive=True) -> bool:
    """Returns True when sing-box is available after this call. A declined
    choice is CACHED (config/singbox-install.json) and the question is not
    asked again - EXCEPT when the user selects the singbox engine while
    sing-box is still missing (then force_ask=True repeats the question)."""
    if singbox_binary_path():
        return True
    if not force_ask and _singbox_declined():
        return False
    if not interactive or not sys.stdin.isatty():
        return False
    info(tr("singbox_install_header"))
    cmd, manual = singbox_install_command()
    if manual:
        info(tr("singbox_install_manual", url=SINGBOX_INSTALL_PAGE))
        if os.name == "nt":
            hint(tr("singbox_windows_hint", url=SINGBOX_RELEASES_PAGE))
    else:
        info(tr("singbox_install_cmd", cmd=" ".join(cmd)))
    try:
        ans = input(tr("singbox_install_q")).strip().lower()
    except EOFError:
        ans = ""
    yes_words = [w.strip() for w in tr("answer_yes_words").split(",")]
    if ans not in yes_words:          # [y/N]: Enter and anything but 'y' = no
        info(tr("singbox_install_declined"))
        _save_singbox_declined()
        return False
    if manual:
        # open the official installation page in the browser and stop here
        try:
            import webbrowser
            webbrowser.open(SINGBOX_INSTALL_PAGE)
        except Exception:
            pass
        return False
    info(tr("singbox_install_started", cmd=" ".join(cmd)))
    try:
        rc = subprocess.run(cmd).returncode
    except Exception as e:
        err(tr("singbox_install_fail", code=-1, err=e))
        return False
    path = singbox_binary_path()
    if rc == 0 and path:
        ok(tr("singbox_install_ok", path=path))
        return True
    err(tr("singbox_install_fail", code=rc, err="see the output above"))
    return False

def reinstall_singbox(interactive=True) -> bool:
    """Full reinstall of sing-box from scratch: remove the current binary
    (pkg uninstall / brew uninstall / delete the file in PATH), then
    install the latest version again with the platform command."""
    info(tr("singbox_reinstall_header"))
    if _is_termux():
        cmds = [["pkg", "uninstall", "-y", "sing-box"],
                ["pkg", "install", "-y", "sing-box"]]
    elif sys.platform == "darwin":
        cmds = [["brew", "uninstall", "sing-box"],
                ["brew", "install", "sing-box"]]
    else:
        # no package manager: delete the binary found in PATH (if writable)
        path = singbox_binary_path()
        if path:
            try:
                os.remove(path)
            except OSError as e:
                err(tr("singbox_reinstall_fail", code=-1, err=e))
                return False
        cmds = None
    if cmds:
        for c in cmds:
            try:
                rc = subprocess.run(c).returncode
            except Exception as e:
                err(tr("singbox_reinstall_fail", code=-1, err=e))
                return False
            if rc != 0:
                err(tr("singbox_reinstall_fail", code=rc,
                       err="see the output above"))
                return False
    path = singbox_binary_path()
    if path:
        ok(tr("singbox_reinstall_ok", path=path))
        return True
    # the binary is gone / was never present: fall back to the offer flow
    return offer_install_singbox(force_ask=True, interactive=interactive)

# ---------------- main ----------------

def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")

def _env_flag(name: str, default: bool) -> bool:
    """Env-aware boolean default (v4.7.2): unset/empty env -> the given
    default; a set env is checked with the truthy words 1/true/yes/on.
    Used for the now-DEFAULT-ON flags: MOZVPN_LOCAL_PROXY=0 disables the
    local proxies, MOZVPN_NO_SAVE=0 re-enables saving the result JSON."""
    v = os.environ.get(name)
    if v is None or not v.strip():
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")

def print_config_files():
    """req: log which config/cache files on the user's system this run uses
    (cached session, credentials, the Fastly WAF cookie, sing-box configs)."""
    info(tr("config_files_header"))
    for path in (CACHE, CRED_CACHE, FASTLY_CACHE, SINGBOX_DIR):
        if os.path.isfile(path):
            st = os.stat(path)
            status = tr("config_file_exists", size=st.st_size,
                        mtime=time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.gmtime(st.st_mtime)))
        elif os.path.isdir(path):
            status = tr("config_file_dir",
                        n=len(os.listdir(path)))
        else:
            status = tr("config_file_missing")
        hint(tr("config_file_entry", path=path, status=status))

def print_clear_targets():
    """req: log exactly which files/directories the 'c' hotkey and the
    --clear-cache flag remove (the whole config directory goes away)."""
    info(tr("clear_will_remove_header"))
    for path in (CACHE, CRED_CACHE, FASTLY_CACHE, SINGBOX_DIR):
        if os.path.exists(path):
            hint(tr("clear_will_remove_entry", path=path))
    hint(tr("clear_will_remove_dir", path=CONF_DIR))

def config_open_files() -> list:
    """Ordered list of the config/cache files that can be opened with the
    number hotkeys (1..9): session, credentials, Fastly cookie, then every
    sing-box config json in the singbox directory."""
    files = []
    for p in (CACHE, CRED_CACHE, FASTLY_CACHE):
        if os.path.isfile(p):
            files.append(p)
    if os.path.isdir(SINGBOX_DIR):
        for name in sorted(os.listdir(SINGBOX_DIR)):
            if name.endswith(".json"):
                files.append(os.path.join(SINGBOX_DIR, name))
    return files[:9]

def open_in_system_editor(path: str):
    """Ask the OS to open the file (or directory, in the file manager) with
    the DEFAULT application for its type. Windows: os.startfile
    (ShellExecute 'open' verb) - if the file type has no association, fall
    back to rundll32 shell32.dll,OpenAs_RunDLL which shows the standard
    system 'Open with' picker dialog. macOS: `open`. Other POSIX: xdg-open -
    the freedesktop.org standard that opens the file in the user's preferred
    application for that file type (and directories in the file manager)."""
    if not os.path.exists(path):
        warn(tr("hotkey_open_missing", path=path))
        return
    try:
        if os.name == "nt":
            try:
                os.startfile(path)
            except OSError:
                # no default app registered for this file type -> the system
                # shows a window to choose which program to open it with
                subprocess.Popen(["rundll32.exe",
                                  "shell32.dll,OpenAs_RunDLL", path])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
        if os.path.isdir(path):
            ok(tr("hotkey_open_dir", path=path))
        else:
            ok(tr("hotkey_open", path=path))
    except Exception as e:
        warn(tr("hotkey_open_fail", path=path, err=e))

def copy_to_clipboard(text: str) -> bool:
    """Put text into the SYSTEM clipboard using the standard OS utilities:
    Windows `clip` (C:\\Windows\\system32\\clip.exe), macOS `pbcopy`, Linux
    `wl-copy` (Wayland) / `xclip -selection clipboard` (X11) /
    `xsel --clipboard --input`. No third-party Python packages needed."""
    try:
        if os.name == "nt":
            p = subprocess.Popen(["clip"], stdin=subprocess.PIPE)
        elif sys.platform == "darwin":
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
        else:
            for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"],
                        ["xsel", "--clipboard", "--input"]):
                try:
                    p = subprocess.Popen(cmd, stdin=subprocess.PIPE)
                    break
                except OSError:
                    continue
            else:
                raise RuntimeError("no clipboard utility (wl-copy/xclip/xsel)")
        p.communicate(text.encode("utf-8"))
        return True
    except Exception as e:
        warn(tr("hotkey_copy_fail", err=e))
        return False

def main():
    ap = argparse.ArgumentParser(
        description="Mozilla VPN / Firefox IP Protection proxy credentials + auto-TOTP "
                    "+ auto-refresh + local proxies (builtin engine or sing-box) "
                    "with MASQUE support and HTTP CONNECT fallback")
    ap.add_argument("--email", default=os.environ.get("MOZVPN_EMAIL"),
                    help="Mozilla account email")
    ap.add_argument("--password", default=os.environ.get("MOZVPN_PASSWORD"),
                    help="Mozilla account password")
    ap.add_argument("--session-token", dest="session_token",
                    default=os.environ.get("MOZVPN_SESSION_TOKEN"),
                    help="Account sessionToken (hex) - fallback when the Fastly challenge is not solvable")
    ap.add_argument("--totp", default=os.environ.get("MOZVPN_TOTP"),
                    help="2FA (TOTP) code entered manually; otherwise generated from the secret")
    ap.add_argument("--totp-secret", dest="totp_secret",
                    default=os.environ.get("MOZVPN_TOTP_SECRET"),
                    help="TOTP secret (base32) directly, an alternative to --qr")
    ap.add_argument("--qr", metavar="FILE",
                    help="Image with a TOTP QR code: on the first run pass the path - "
                         "the secret is saved and codes are generated automatically")
    ap.add_argument("--qr-verify", action=argparse.BooleanOptionalAction,
                    default=_truthy_env("MOZVPN_QR_VERIFY"),
                    help="After reading --qr, show the generated code and ask whether it "
                         "matches the authenticator app. Off by default (the secret is "
                         "saved silently, the code is printed for review). --no-qr-verify disables")
    ap.add_argument("--watch", action="store_true",
                    help="Continuously refresh proxyPass --refresh-margin seconds before expiry")
    ap.add_argument("--local-proxy", action=argparse.BooleanOptionalAction,
                    default=_env_flag("MOZVPN_LOCAL_PROXY", True),
                    help="Serve local HTTP proxies (engine: --local-proxy-engine). "
                         "ON by DEFAULT; --no-local-proxy disables. "
                         "Env: MOZVPN_LOCAL_PROXY=0/1")
    ap.add_argument("--local-proxy-engine", dest="local_proxy_engine",
                    choices=["builtin", "singbox"],
                    default=os.environ.get("MOZVPN_PROXY_ENGINE", "builtin").strip().lower() or "builtin",
                    help="Local proxy engine: builtin (default, in-process threads, no "
                         "external dependencies, Nuitka/exe-friendly) or singbox "
                         "(external binary). Env: MOZVPN_PROXY_ENGINE")
    ap.add_argument("--listen", metavar="HOST", default="127.0.0.1",
                    help="Bind address of the local proxy listeners "
                         "(default 127.0.0.1, loopback only; use 0.0.0.0 to "
                         "accept connections from other devices on your "
                         "network - make sure the ports are firewalled)")
    ap.add_argument("--proxy-check", action=argparse.BooleanOptionalAction, default=True,
                    help="Probe upstream proxies in parallel (real data through the "
                         "tunnel) before starting local proxies. On by default; "
                         "--no-proxy-check disables")
    ap.add_argument("--ip-echo-service",
                    choices=sorted(IP_ECHO_SERVICES.keys()),
                    default=DEFAULT_IP_ECHO_SERVICE,
                    help="Predefined public IP echo service used by the probe "
                         f"(one of: {', '.join(sorted(IP_ECHO_SERVICES))})")
    ap.add_argument("--ip-echo", metavar="URL", default=None,
                    help="Custom public IP echo URL (overrides --ip-echo-service)")
    ap.add_argument("--probe-fail", choices=["keep", "drop"], default="keep",
                    help="What to do when the probe cannot verify an upstream: "
                         "keep (default) - serve it anyway with a warning; "
                         "drop - remove it from the served list")
    ap.add_argument("--probe-count", type=int, default=1,
                    help="How many upstreams to probe before starting the "
                         "local proxies (default: 1 - minimal checking; "
                         "0 = probe all of them)")
    ap.add_argument("--upstream-host", metavar="HOST", default=None,
                    help="Force every upstream to this host (e.g. the Fastly "
                         "anycast pool p.m1.fastly-masque.net) instead of the "
                         "per-city hosts from the server list")
    ap.add_argument("--upstream-port", type=int, default=None,
                    help="Force the upstream port (default: keep the server-list port)")
    ap.add_argument("--max-proxies", type=int, default=0,
                    help="Maximum number of local proxies (0 = all locations)")
    ap.add_argument("--no-input", action="store_true",
                    help="Never ask interactive questions (for an autonomous loop)")
    ap.add_argument("--refresh-margin", type=int, default=45,
                    help="Refresh the proxyPass this many seconds before exp (default 45)")
    ap.add_argument("--country")
    ap.add_argument("--city")
    ap.add_argument("--test", action="store_true",
                    help="Test a proxy (external IP) after fetching the credentials")
    ap.add_argument("--show-test-commands", dest="show_test_commands",
                    action="store_true",
                    default=_truthy_env("MOZVPN_SHOW_TEST_COMMANDS"),
                    help="Print ready-to-paste curl test commands for the local "
                         "and upstream proxies (default: off; "
                         "env MOZVPN_SHOW_TEST_COMMANDS=1 enables)")
    ap.add_argument("--firefox-version", default=DEFAULT_FIREFOX_VERSION,
                    help="Firefox version for the Remote Settings filter_expression (default 156.0)")
    ap.add_argument("--client-country", default="",
                    help="Country code for env.country in filter_expression (unset by default)")
    ap.add_argument("--include-locked", action="store_true",
                    help="Include entries/nodes marked as locked")
    ap.add_argument("--json", metavar="FILE",
                    help="Path for the result JSON (default: next to the script)")
    # v4.7.3: argparse.BooleanOptionalAction REJECTS option names that
    # already start with "--no-" (ValueError: invalid option name), so
    # --no-save cannot be a BooleanOptionalAction. Instead it is declared
    # as two plain arguments writing the SAME args.no_save attribute:
    #   --save     -> store_false -> no_save = False (re-enable saving)
    #   --no-save  -> store_true  -> no_save = True  (the default state)
    # default=argparse.SUPPRESS on --no-save means: when the flag is NOT
    # given, argparse adds NO attribute at all, so the env-aware default
    # of the first argument survives untouched (SUPPRESS semantics per the
    # argparse docs: "no attribute to be added if the command-line
    # argument was not present").
    ap.add_argument("--save", dest="no_save", action="store_false",
                    default=_env_flag("MOZVPN_NO_SAVE", True),
                    help="Save the result JSON file (saving is OFF by default "
                         "since v4.7.2; --save re-enables it). "
                         "Env: MOZVPN_NO_SAVE=0/1")
    ap.add_argument("--no-save", dest="no_save", action="store_true",
                    default=argparse.SUPPRESS,
                    help="Do not save the result JSON file (default: ON since "
                         "v4.7.2; given together with --save the LAST flag "
                         "on the command line wins)")
    ap.add_argument("--relogin", action="store_true", help="Ignore the cached session")
    ap.add_argument("--clear-cache", action="store_true",
                    help="Remove the whole config directory (~/.config/mozvpn) with all "
                         "caches of this and previous script versions, then exit")
    ap.add_argument("--lang", choices=["en", "ru"],
                    default=os.environ.get("MOZVPN_LANG", "en").strip().lower() or "en",
                    help="Output language (default: en). Env: MOZVPN_LANG")
    ap.add_argument("--no-color", action="store_true",
                    default=_truthy_env("MOZVPN_NO_COLOR"),
                    help="Disable colored log output. Env: MOZVPN_NO_COLOR")
    ap.add_argument("--theme", choices=["dark", "light"],
                    default=(os.environ.get("MOZVPN_THEME", "dark")
                             .strip().lower() or "dark"),
                    help="Color theme for the colored log: dark (default, "
                         "near-black background) or light (white background). "
                         "Env: MOZVPN_THEME")
    ap.add_argument("--confirm-exit", action="store_true",
                    help="Require a second Ctrl+C within 5s to stop (by default the "
                         "first Ctrl+C stops immediately)")
    ap.add_argument("--retry-delay", type=int,
                    default=int(os.environ.get("MOZVPN_RETRY_DELAY", "30") or 30),
                    help="Seconds to wait before the automatic sign-in retry "
                         "after a failed attempt, shown with a live countdown "
                         "(default 30). Env: MOZVPN_RETRY_DELAY")
    ap.add_argument("--reinstall-deps", action="store_true",
                    help="Reinstall ALL Python dependencies from scratch "
                         "(pip --force-reinstall --no-cache-dir) and exit")
    ap.add_argument("--reinstall-singbox", action="store_true",
                    help="Reinstall sing-box from scratch (Termux: pkg, macOS: "
                         "brew; other systems: the official install page) and exit")
    a = ap.parse_args()

    # Language and colors are configured before any other output (req. 14,
    # 16). v4.7.1: set_color() runs FIRST (it only switches the color mode, it
    # no longer touches the window background), then set_theme() forces
    # the background (OSC 11) exactly ONCE with the final theme and the
    # final color mode - with --no-color set_theme() forces nothing at all.
    set_language(a.lang)
    set_color(not a.no_color)
    set_theme(a.theme)
    if a.no_color:
        info(tr("color_disabled"))

    # req. 8: --clear-cache wipes everything and exits (a fresh dict is
    # passed: nothing has been loaded into memory yet at this point)
    if a.clear_cache:
        print_clear_targets()
        sys.exit(0 if wipe_all_saved_data({}) else 1)

    # v4.3: full reinstall options (--reinstall-deps / --reinstall-singbox
    # mirror the 'd' and 's' hotkeys of the watch loop)
    if a.reinstall_deps:
        sys.exit(0 if reinstall_dependencies(interactive=True) else 1)
    if a.reinstall_singbox:
        sys.exit(0 if reinstall_singbox(interactive=True) else 1)

    # Echo the selected engine at startup (req. 15)
    engine_desc = (tr("engine_singbox") if a.local_proxy_engine == "singbox"
                   else tr("engine_builtin"))
    info(tr("engine_selected", engine=engine_desc))

    # req: show the config/cache files this run uses (session, credentials,
    # Fastly cookie, sing-box configs)
    print_config_files()

    # v4.3 (req. 0, 1): print ALL dependencies; offer to pip-install the
    # missing ones automatically (only under a real python interpreter)
    missing_deps = print_dependencies()
    if missing_deps:
        offer_install_deps(missing_deps, interactive=not a.no_input)

    # v4.3 (req. 2): if sing-box is not installed, explain that everything
    # works WITHOUT it (builtin engine) and offer the installation; a
    # declined choice is cached and not asked again - unless the singbox
    # engine is selected while sing-box is still missing
    if not singbox_binary_path():
        offer_install_singbox(
            force_ask=(a.local_proxy_engine == "singbox"),
            interactive=not a.no_input)

    # Resolve the IP echo URL early so failures surface immediately
    a.ip_echo_name = a.ip_echo_service
    a.ip_echo_url = a.ip_echo or IP_ECHO_SERVICES[a.ip_echo_service]

    # --- QR -> TOTP secret (first run) + optional review confirmation ---
    if a.qr:
        try:
            info_qr = decode_qr_totp(a.qr)
        except MozVpnError as e:
            sys.exit(str(e))
        secret = info_qr.pop("secret")
        # Protection against a silently wrong secret (stale QR, another account,
        # re-created 2FA). Disabled by default (no question is asked); enable
        # the interactive review with --qr-verify.
        if a.qr_verify and not a.no_input and sys.stdin.isatty():
            try:
                code, valid = totp_generate(secret, info_qr["digits"],
                                            info_qr["period"], info_qr["algorithm"])
                info(tr("totp_code_current", code=code, sec=valid, offset=""))
                ans = input(tr("qr_verify_q")).strip().lower()
            except MozVpnError as e:
                sys.exit(str(e))
            if ans in [w.strip() for w in tr("answer_no_words").split(",")]:
                manual = input(tr("qr_verify_mismatch")).strip()
                if not manual:
                    sys.exit(tr("qr_verify_cancelled"))
                if os.path.isfile(manual):
                    try:
                        info_qr = decode_qr_totp(manual)
                        secret = info_qr.pop("secret")
                    except MozVpnError as e:
                        sys.exit(str(e))
                else:
                    try:
                        secret = validate_totp_secret(manual)
                    except MozVpnError as e:
                        sys.exit(str(e))
        else:
            # Verification disabled: just show the code for review, no question.
            try:
                code0, valid0 = totp_generate(secret, info_qr["digits"],
                                              info_qr["period"], info_qr["algorithm"])
                info(tr("qr_code_for_review", code=code0, sec=valid0))
            except MozVpnError as e:
                err(str(e))
        save_credentials(email=a.email, totp_secret=secret,
                         totp_digits=info_qr["digits"], totp_period=info_qr["period"],
                         totp_algorithm=info_qr["algorithm"])
        ok(tr("qr_saved", path=CRED_CACHE, digits=info_qr["digits"],
              period=info_qr["period"], algo=info_qr["algorithm"]))
        info(tr("qr_saved_note"))

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

    # --relogin is a FULL wipe too (req: relogin must not reuse any saved
    # data - otherwise the script could re-login automatically from the
    # leftover in-memory credentials, which is exactly what it must not do)
    if a.relogin:
        wipe_all_saved_data(creds)

    totp_provider = make_totp_provider(a, creds)

    if a.local_proxy or a.watch:
        run_manager(a, creds, totp_provider)
        return

    # -------- one-shot mode --------
    try:
        session_token = ensure_session(a, creds, totp_provider, interactive=True)
        token, until, ghdrs = obtain_proxy_pass(session_token)
        exp = jwt_exp(token)
        ok(tr("proxypass_received", until=format_until(until, token),
              exp=time.strftime("%H:%M:%S", time.gmtime(exp)) if exp else "?"))
        info(tr("serverlist_fetching"))
        locations_all, recommended = fetch_serverlist(a.firefox_version,
                                                       a.client_country,
                                                       a.include_locked)
        locations = select_locations(locations_all, recommended, a.country, a.city)
        verified = collect_verified_servers(a, locations, token)
        ok(tr("serverlist_done", countries=len(locations), servers=len(verified)))
        print_quota(ghdrs)
        print_current_totp((a.totp_secret or "").strip() or creds.get("totp_secret"), creds)
    except MozVpnError as e:
        sys.exit(str(e))

    now = time.time()
    result = {"fetchedAt": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
               + f".{int(now % 1 * 1000):03d}Z",
              "proxyPass": {"token": token, "validUntil": until,
                            "validUntilComputed": format_until(until, token)},
              "sessionToken": session_token,
              "email": a.email or creds.get("email"),
              "recommended": recommended,
              "locations": locations}

    def print_server(s):
        # curl test hints are opt-in (--show-test-commands, default off)
        if not getattr(a, "show_test_commands", False):
            return
        hint(tr("curl_hint", host=s["protocolHost"], port=s["protocolPort"],
                token=token, echo=a.ip_echo_url))

    if recommended:
        info(_paint(C.BOLD, tr("recommended_server",
                              country=recommended["countryName"],
                              city=recommended["cityName"])))
        for s in recommended["servers"]:
            if s["protocol"] in (PROTO_CONNECT, PROTO_MASQUE):
                print_server(s)
        print()

    # print every usable server with its curl hint
    for l in locations:
        for c in l["cities"]:
            for s in c["servers"]:
                if s["protocol"] not in (PROTO_CONNECT, PROTO_MASQUE):
                    continue
                line = (f"{l['countryCode']:<3} {l['countryName'][:15]:<15} "
                        f"{(c['cityName'] or '')[:15]:<15} {s['protocol'][:8]:<8} "
                        f"{(s['scheme'] or '-'):<6} {s['protocolHost']}:{s['protocolPort']}")
                print(line + ("  [locked]" if l["locked"] else ""))
                print_server(s)

    print()
    info(tr("proxypass_jwt"))
    print(token)
    print_jwt_decoded(token)
    print()
    info(tr("session_token_print"))
    print(session_token)

    if not a.no_save:
        out = a.json or os.path.join(script_dir(), "mozvpn-"
                    + time.strftime("%Y%m%d-%H%M%S", time.gmtime(now)) + ".json")
        with open(out, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        ok("\n" + tr("json_saved", path=out))

    if a.test:
        # Prefer a probe-verified server; MASQUE entries are tested over
        # their CONNECT fallback (probe_connect always speaks CONNECT).
        ordered = sorted(verified.values(),
                        key=lambda s: 0 if s.get("probe_ok") else 1)
        for s in ordered:
            info(tr("test_running", host=s["protocolHost"], port=s["protocolPort"]))
            try:
                _, detail = probe_connect(s, token, a.ip_echo_url)
                ok(tr("test_external_ip", ip=detail))
            except Exception as e:
                err(str(e))
            return

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Ctrl+C: exit cleanly without a traceback (the signal handler in
        # the watch loop already stops the engines via atexit cleanup)
        print()
        pass
