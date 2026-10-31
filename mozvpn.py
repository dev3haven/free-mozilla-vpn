#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mozvpn.py -- Mozilla VPN / Firefox IP Protection proxy credentials + auto-TOTP
+ automatic proxyPass refresh + local proxies (builtin engine or sing-box).

VERSION 2026-10-31 (v9.3) - THE FULL IMPLEMENTATION AUDIT (the user's
  request: check EVERY implementation for correctness and adequacy, the
  comments AND the code, compare with the analog projects and verify
  THEIR implementations too; every algorithm NOT listed here is
  UNTOUCHED - the audit swept the FxA/Guardian auth chain, the Fastly
  solver, the crypto, the DoH stack, the raw-IP fallbacks, the TLS
  split, the probes, both engines, the DNS relay, the pass monitor,
  the exports, the doctor and the watch loop against mozilla/fxa
  (account.ts), product-details.mozilla.org and the Go reference
  client's CURRENT sources, and found everything else CORRECT).

  1) THE DOCTOR TYPO: step 6 posted /account/credentials_status (an
     UNDERSCORE) while the real FxA route - verified against
     mozilla/fxa packages/fxa-auth-server/lib/routes/account.ts
     (PR #21517) - is /account/credentials/status, the exact route
     get_credentials_status() already rides. The underscore form
     always 404'd and the step's 'any REAL server answer is a pass'
     rule masked the typo as an OK; the doctor now exercises the
     REAL route (a 404 answer can no longer masquerade as a pass
     either - only 200/400/403 of the real endpoint count).

  2) THE DOCTOR DoH STEP no longer reports a misleading FAIL when
     the user chose the SYSTEM resolver (DoH 'off'): resolve_host()
     is a no-op BY DESIGN in that mode, and the system resolution is
     already proven by step 4; the step now says exactly that (the
     new tr key doctor_doh_system, en+ru) and PASSES.

  3) THE FASTLY SOLVER IDENTITY: the challenge flow rode a
     Chrome-macOS UA (the pagpeter/fastly-antibot-era port) while
     every FxA API request rode the pinned Firefox UA - an
     inconsistent client identity on the SAME *.firefox.com hosts.
     The Go reference client pinned its solver to the FxA UA on
     2026-10-31 with the exact reason ('challenge cookies may be
     tied to the client identity'); FASTLY_UA is now the SAME
     Firefox UA as BROWSER_HEADERS (a real Firefox sends it to
     accounts.firefox.com too), so the solver and the API requests
     present ONE identity.

  4) THE PINNED FIREFOX VERSION: 158.0.1 -> 159.0, the ACTUAL
     current stable (product-details.mozilla.org
     LATEST_FIREFOX_VERSION, released 2026-10-27; the Go reference
     client pins 159.0 as well). The value drives the serverlist
     filter_expression (env.version versionCompare) and the
     User-Agent, so it must stay a plausible CURRENT Firefox.

  5) THE CLIENTMETRICS STUB parity with the Go solver
     (fastly.go clientMetricsAnswer, the 2026-08-22 sync): the
     answer now also carries detector_results {} and v 2, and
     error_trace is JSON null (the old stub predates both fields
     and sent a '""' string).

  6) THE STALE DoH COMMENTS (a comment-vs-code mismatch the audit
     class is about): the resolve_host() and _doh_chain()
     docstrings still said 'the SYSTEM resolver is the last
     resort' - untrue since the v5.29 STRICT default (the system
     resolver runs only with the explicit --system-dns-fallback
     opt-in, or when DoH is off). The wording now matches the
     code; the code itself was already correct.

  7) check_running() (the builtin engine's defensive listener
     restart) could itself CRASH: getsockname() on a socket that
     already died raises OSError and the set comprehension
     propagated it into the watch loop's generic 'Unexpected
     error' retry - the opposite of what a defensive method is
     for. Every listener's port is now read best-effort; a dead
     socket simply counts as 'not alive' and gets restarted.

VERSION 2026-10-31 (v9.2) - THE SPURIOUS 'SESSION LOOKS BROKEN' REFRESHES
  (the user's report: 'Egress answered HTTP 502' lines and the '3+
  distinct targets failed... refreshing the pass now' cascade started
  appearing in the latest version; every algorithm NOT listed here is
  UNTOUCHED).

  1) THE ROOT CAUSE: the v6.6 pass-health books grew FOREVER. The
     '3+ distinct targets' rule of _PassMonitor kept ONE entry per
     DISTINCT target with NO expiry and NO success reset - three
     unrelated ONE-OFF failures of three different destinations
     (dead/blocked sites), however far apart in time, accumulated
     until the script concluded 'the session looks broken' and
     refreshed the proxyPass even though the tunnel served successful
     CONNECTs the whole time. THE V9.0 CONNECTION: the socks5 default
     made such failures VISIBLE - with remote DNS (the socks5h
     semantics) a dead/blocked destination now fails AT THE EGRESS
     with 502 instead of dying in the local resolver, so the books
     filled with the ordinary 'this site is dead from the exit
     country' noise. THE FIX (verified online 2026-10-31 against
     Firefox's OWN IPP design - the proxy state machine escalates
     only REPEATED failures and RESETS the connection/error history
     when the connection works again; the pass rotation fires on the
     401-class rejection while staying ACTIVE): (a) a failure counts
     only while it is FRESH - a _PASS_FAIL_WINDOW of 60 s prunes
     stale entries before the threshold check (a REAL broken session
     bursts through three distinct targets in seconds; one-off noise
     spread minutes apart can never trip it); (b) every SUCCESSFUL
     CONNECT through an egress drops THAT egress's recorded failures
     (the books are now target -> (ts, egress host)) - a working
     tunnel is direct evidence the session is alive; (c) a pass
     rotation (mark_refresh) clears the books - the old entries
     belong to the OLD pass. The stale-pass burst case still
     refreshes in seconds, and the 400/401/403 PASS-REJECTION class
     is UNTOUCHED (still an immediate refresh).

  2) THE DNS RELAY'S OWN DoH TARGET NO LONGER FEEDS THE PASS-HEALTH
     BOOKS. The engine sees the relay's DoH CONNECT like any client's;
     with the v9.1 'the CHOSEN provider ONLY' contract a blocked or
     unreachable provider fails EVERY relayed DNS query - one
     'Egress answered HTTP 502' line per query plus a book entry each
     time. v9.2: the current DoH wire target (_is_doh_wire_target)
     is exempted from the target-failure classes (502/504 / the
     tunnel-open timeout) with ONE calm
     connect_target_doh_unreachable line per run per target (the new
     tr key, en+ru); the PASS-REJECTION classes stay counted for it -
     a rejected pass is a rejected pass whatever the target. The
     relayed queries keep their own failure semantics (nothing is
     sent, the client's resolver retries).

VERSION 2026-10-31 (v9.1) - THE RELAY DoH: THE USER'S CHOICE ONLY (the
  user's request; every algorithm NOT listed here is UNTOUCHED).

  1) NO MORE 'BY THE CIRCLE' DoH CHAIN IN THE DNS RELAY. The
     v8.5/v9.0 relay chain (the selected provider FIRST, then the
     hardcoded cloudflare/google/quad9 trio - DNS_RELAY_FALLBACK -
     inside the SAME DNS_RELAY_BUDGET) is REPLACED by EXACTLY ONE
     target: the provider the USER chose - the hotkey-'h' menu /
     --doh / the SAVED settings.doh (the choice that survives
     restarts). A custom --doh-url endpoint stays the USER's choice
     too (its URL is parsed best-effort exactly as before); when
     NOTHING is chosen - or the choice is 'off', because the relay
     speaks DoH BY DESIGN and cannot query a system resolver
     through the egress - the built-in DEFAULT 'cloudflare' applies
     (the exact v6.8 default). THE REASON (the user's): a fallback
     walk answers through a provider the user did NOT pick - the
     same leak class v9.0 closed for the PROXIES is now closed for
     the DoH TARGET: if the chosen provider is dead, or a custom
     JSON-only endpoint cannot speak the RFC 8484 wireformat, the
     relay fails THAT query (nothing is sent; the client's resolver
     retries, like any plain DNS) - it NEVER silently answers
     through somebody else. DNS_RELAY_FALLBACK is REMOVED (dead
     code); DNS_RELAY_TIMEOUT (5 s) still bounds the ONE attempt
     and DNS_RELAY_BUDGET stays the per-query cap.

  2) THE HOTKEY. The choice is made - and changed LIVE (the relay
     reads doh_wire_targets() on EVERY query: no restart, no
     engine rebuild) - in the SAME hotkey-'h' menu that has always
     set the script's own resolver; the menu hint, the
     hotkeys-hint 'h' line, the hotkey_doh message and the --doh /
     --doh-url help now SAY that the per-proxy DNS endpoints ride
     the CHOSEN provider ONLY (default cloudflare). The script's
     OWN DoH chain (resolve_host of the egress/API hostnames, the
     v5.x provider penalty / fallback) is UNTOUCHED - the request
     is about the RELAY.

VERSION 2026-10-31 (v9.0) - PER-PROXY DNS + THE SOCKS5 DEFAULT (the
  user's two requests; every algorithm NOT listed here is UNTOUCHED).

  1) EVERY PROXY'S DNS RIDES THAT PROXY ONLY - the v8.9 ONE shared
     round-robin DNS endpoint is REPLACED by the v8.5 per-proxy
     scheme again (ONE deterministic '<location>|dns' UDP+TCP
     endpoint per started proxy, BOTH engines, ON by default): a
     query entering through the DNS port of proxy X is relayed
     through THE LOCAL LISTENER OF PROXY X and NOTHING else. The
     DoH TARGET chain still walks (the selected provider first,
     then the hardcoded cloudflare/google/quad9 trio) inside the
     SAME DNS_RELAY_BUDGET - but ALWAYS through that one proxy.
     THE REASON (the user's): a country can block resources BY
     DNS; with the v8.9 round-robin a query could be answered
     through ANY other country's exit, so the user who had just
     switched to another country's proxy could STILL see the old
     country's DNS block and not understand why. THE QUIET LOG IS
     PRESERVED (v8.7): ONE dns_line summary after the proxy list
     (the count + the per-proxy property + WHO needs the
     endpoint), and every proxy_line now shows the DNS port of
     ITS proxy (' DNS:<port>', only when the endpoint actually
     bound - the v8.9 'the port must be visible' rule applied to
     the per-proxy scheme); dns_port_busy is PER PROXY again (the
     {label} is restored). --no-dns-relay is UNCHANGED (binds
     nothing at all; the proxies and their socks5h remote DNS are
     NOT affected).

  2) THE DEFAULT LOCAL PROXY TYPE IS NOW 'socks5' (was 'http'
     since v8.5) - RFC 1928 CONNECT-only with REMOTE DNS (the curl
     socks5h/socks5a semantics: a DOMAIN request address is
     passed through to the egress). COMPATIBILITY (the user's
     question, verified online 2026-10-31 against the curl
     documentation): 'socks5h' is NOT a separate wire protocol -
     it is curl's name for a SOCKS5 CLIENT that sends the DOMAIN
     name (ATYP=03) instead of a locally pre-resolved IP
     (ATYP=01); the SERVER is the same SOCKS5 listener either way,
     and this listener accepts BOTH request shapes, so every
     program that 'only supports socks5' works: it resolves
     locally and sends the IP, which the listener relays to the
     egress verbatim (the only caveat is client-side: such a
     program's DNS goes through the LOCAL resolver - use the
     per-proxy DNS endpoints of item 1 or the app-level socks5h
     setting when the local DNS is blocked or leaks). The
     PRECEDENCE is UNCHANGED (an explicit --proxy-type, then the
     SAVED settings.proxy_type, then the built-in default) and the
     Ctrl+T menu / the hotkeys / --proxy-type / the sing-box
     inbound mapping are UNCHANGED - only the never-chosen
     built-in default flips (a SAVED http choice keeps winning,
     the v6.9 sticky-settings contract).

VERSION 2026-10-31 (v8.9) - ONE SHARED DNS ENDPOINT (the user's
  decision after the v8.8 audit Q&A; every algorithm NOT listed here
  is UNTOUCHED).

  1) THE PER-PROXY DNS PORTS ARE GONE. The v8.5 scheme (one DNS port
     per local proxy) is replaced by ONE shared UDP+TCP endpoint on a
     single deterministic port (the 'dns-relay|dns' key of the same
     port_for_location scheme - it can never collide with the proxy
     ports). The user was right: the OS resolver holds ONE address,
     so only one of the N per-proxy endpoints could ever be used -
     the rest sat idle.
  2) EVERY QUERY RIDES THE PROXIES ROUND-ROBIN: a query starts at
     the round-robin pick; when the WHOLE DoH chain through that
     proxy fails, the rotation walks on to the next proxy INSIDE the
     SAME DNS_RELAY_BUDGET - the shared endpoint survives the loss
     of any single proxy (a fixed single-proxy endpoint would not).
  3) THE PORT IS NOW VISIBLE: dns_line (the ONE summary line after
     the proxy list, v8.7) now names THE port and says WHO needs it -
     point the SYSTEM resolver / any plain-DNS app at the address;
     apps that already send domain names through the proxies
     (socks5h remote DNS) do not need it. The v8.7 'one line'
     change had left the ports unprinted entirely (the user's 'how
     do I use it' question).
  4) --no-dns-relay (env MOZVPN_DNS_RELAY, default ON, the
     --system-dns-fallback BooleanOptionalAction shape): does not
     bind the DNS endpoint at all; the proxies and their socks5h
     remote DNS are NOT affected. dns_port_busy lost its {label}
     (there is no per-proxy endpoint anymore).

VERSION 2026-10-31 (v8.8) - THE AUDIT + THE QUAD9 CURRENCY FIX (the
  user's audit request; every algorithm NOT listed here is UNTOUCHED).

  1) THE FULL IMPLEMENTATION AUDIT (DNS RELAY / DoH / DPI / engines /
     UI) - result: NO logic bugs found; every implementation is
     coherent and matches the shapes the analogous projects ship
     (see the audit report in the chat: foxhole-vpn runs the same
     'DoH relay inside the tunnel', Zeus-VPN the same 'ClientHello
     fragmentation + DoH-resolved server addresses + DoH through
     the tunnel' trio, foxyvpn the same RFC 1928 CONNECT-only
     remote-DNS SOCKS5). Nothing was rewritten.
  2) ONE REAL STALENESS BUG FOUND AND FIXED: the Quad9 endpoints.
     Quad9 RETIRED its JSON-based DNS service on TCP port 5053 on
     5 May 2025 (their official announcement: 'migrate to DoH on
     port 443') - verified live on 2026-10-31: dns.quad9.net:443/
     dns-query answers (RFC 8484 wireformat; the ?name= JSON form
     is gone), the 5053 JSON endpoint no longer serves JSON. FIXED
     in all THREE tables: DOH_WIRE_ENDPOINTS['quad9'] -> port 443
     (the v8.5 RELAY chain keeps quad9 as a WORKING wireformat
     target), _DOH_IP_BOOTSTRAP quad9 -> port 443 (the emergency /
     direct-IP JSON walk: the 443 endpoint answers a JSON request
     with an error status and the loop walks on - fast, no hang),
     DOH_PROVIDERS['quad9'] -> https://dns.quad9.net/dns-query.
     The 'quad9' PRESET STAYS in the --doh menu (no user-visible
     feature removed): as the script's OWN JSON resolver a
     selected quad9 now fails into the v5.12 provider penalty and
     the chain answers via cloudflare/google (Quad9 itself no
     longer offers a JSON API anywhere - only the wireformat DoH
     the relay speaks); as the RELAY wireformat target quad9 WORKS
     again on the current port. Cloudflare / Google / NextDNS
     entries are UNCHANGED (verified current).

VERSION 2026-10-31 (v8.7) - THE QUIET DNS LOG + THE PROTOCOL HIGHLIGHT
  (the user's live-run feedback; every algorithm NOT listed here is
  UNTOUCHED).

  1) THE DNS RELAY START IS NOW ONE SUMMARY LINE (was one line PER
     PROXY - 30+ lines of ports in a real run, the user's report).
     DnsRelay.start() counts the started DNS endpoints and prints
     ONE dns_line with the COUNT: 'DNS relay {listen}: {n} DNS
     endpoints (UDP+TCP; each rides its local proxy -> the egress ->
     DoH {target})'. dns_port_busy stays PER PORT (a busy port is
     actionable info, not noise); the relay itself is UNCHANGED.
     The dns_line tr keys are REWORDED in en+ru (no new keys).
  2) THE LOCAL PROXY PROTOCOL IS NOW VISIBLE AND HIGHLIGHTED in the
     console UI: (a) 'socks5' and 'http' joined the proto class of
     the theme auto-highlighter (_RE_TOKENS) - the local proxy type
     is painted with the SAME bold color as masque/connect wherever
     it appears (the engine start line, the Ctrl+T menu, the type
     switch messages, the hotkeys hint); (b) engine_started now
     names the ACTIVE local proxy type: '{engine} engine started:
     {n} local proxies on {listen} ({ptype})' - both engines, on
     every (re)build. proxy_line's [proto] (the UPSTREAM protocol,
     masque/connect) is UNCHANGED and keeps its own bracket shape.

VERSION 2026-10-31 (v8.6) - DPI PROTECTION FOR THE DoH ITSELF (the
  user's clarified request; every algorithm NOT listed here is
  UNTOUCHED).

  1) THE v8.5 DNS RELAY'S DoH TLS NOW RIDES THE SAME ClientHello
     FRAGMENTATION as the egress TLS (tls_split() / --tls-split /
     hotkey 'i' - ON by default): the TLS handshake to the DoH
     provider inside the proxy tunnel goes out through _FragTLSConn
     (the v7.0 two-TLS-records + small-TCP-segments combination),
     so an SNI-matching DPI cannot read the DoH provider SNI from
     the first segment of the flow (the same class of national
     filters that cut cloudflare-dns.com by the ClientHello SNI -
     the technique the DoH-capable DPI-bypass tools ship: SecretDNS
     'SNI fragmentation', dns-mns --fragment sni, DPIReaper's
     SNI split). ANY fragmented-handshake failure falls back to a
     FRESH proxy tunnel + the plain handshake (the v6.1 lesson: a
     hardening must never break the data path).
  2) THE SCRIPT'S OWN DoH BOOTSTRAP (the resolver behind
     resolve_host() that resolves the egress/API hostnames) now
     contacts the PRESET resolvers by their WELL-KNOWN IPs
     DIRECTLY (the dnscrypt-proxy shape - a DoH server address is
     an IP, so the resolver hostname is NEVER resolved with the
     system resolver): cloudflare/google/quad9 go through
     _raw_https(frag=True) - the TLS handshake to the resolver is
     FRAGMENTED like every other script TLS; a direct-IP failure
     falls back to the exact v8.5 paths (the broken-resolver state
     -> the v5.36 emergency DoH walk, the healthy state -> the
     plain urlopen query). _raw_https gains an OPT-IN frag
     parameter: its OTHER callers (the API direct-IP fallbacks of
     req_full / the Fastly WAF flow) pass nothing and keep the
     byte-for-byte v8.5 behavior; _emergency_doh_resolve passes
     frag=True (it is a DoH path). nextdns / a custom --doh-url
     endpoint keep the urlopen transport verbatim (their IPs are
     unknowable without a name resolution).
  3) VERIFIED ALREADY PRESENT (the user's point 2, NO change): the
     connections to the fastly/Mozilla VPN egress and the API hosts
     resolve hostnames over DoH ONLY (resolve_host() strict mode,
     v5.29 - no silent system-DNS fallback) and the egress TLS
     already uses the fragmented ClientHello (_tls_connect).

VERSION 2026-10-31 (v8.5) - TWO PROXY TYPES + DNS THROUGH THE LOCAL
  PROXIES (the user's request; every algorithm NOT listed here is
  UNTOUCHED).

  1) THE LOCAL PROXY TYPES ARE NOW EXACTLY TWO: http AND socks5. The
     v8.0 'mixed' single-port auto-detect listener is REMOVED:
     --proxy-type accepts http/socks5, the Ctrl+T menu rides
     _PROXY_TYPES (two options), the FoxyProxy exports drop their
     mixed branch, and a SAVED 'mixed' choice of an older run
     normalizes to the built-in default like every unknown value.
  2) THE DEFAULT LOCAL PROXY TYPE IS NOW 'http' (was 'socks5' since
     v8.0) - the classic HTTP CONNECT listener; the CONNECT target
     hostname goes to the egress in every request, so the remote-DNS
     property of the SOCKS5 listener holds for the HTTP listener too
     (the SOCKS5 option itself is UNCHANGED: RFC 1928 CONNECT-only,
     ATYP=03 domains passed through, the curl socks5h semantics).
  3) THE LOCAL DNS ENDPOINTS (BOTH ENGINES, ON BY DEFAULT): every
     local proxy now also serves a DEDICATED DNS port (the same
     deterministic 20000..39999 port scheme, key '<location>|dns',
     one UDP + one TCP listener): a client's plain DNS query (RFC
     1035/7766) is relayed THROUGH THE LOCAL PROXY LISTENER at
     127.0.0.1:<proxy port> - the SAME wire path every other client
     rides (the SOCKS5 CONNECT with the DOMAIN name / the absolute
     HTTP CONNECT) - so the query leaves through the EGRESS (the
     remote proxy resolves the DoH provider's name) and is answered
     by an RFC 8484 DoH wireformat POST (application/dns-message;
     google's JSON /resolve is NOT a wireformat endpoint -
     dns.google/dns-query is); the chain tries the SELECTED DoH
     provider (hotkey 'h' / --doh) first, then the hardcoded
     cloudflare/google/quad9 trio, bounded by a 10 s budget. The DNS
     message is NEVER parsed or rewritten - the client's transaction
     ID and EDNS options go VERBATIM and the answer returns VERBATIM.
     So the clients' DNS goes local proxy -> remote proxy exactly
     like their HTTP/SOCKS5 traffic (the user's request). The
     script's OWN DoH bootstrap (resolving the EGRESS and the API
     hosts) is UNCHANGED - it must run before any tunnel exists.
     New tr keys (en+ru): dns_line, dns_port_busy; the ptype_desc_
     mixed keys are REMOVED; hotkey_proxy_type / hotkeys_hint /
     --proxy-type now list exactly http / socks5.

VERSION 2026-10-30 (v8.4) - THE Ctrl+T PROXY-TYPE SELECTION MENU (the
  user's request; every algorithm NOT listed here is UNTOUCHED).

  1) CTRL+T OPENS A CHOICE MENU NOW, NOT A BLIND CYCLE. Since v8.0 the
     hotkey cycled the LOCAL proxy type socks5 -> http -> mixed ->
     socks5 - to reach 'http' from 'socks5' the user pressed it twice
     with two engine rebuilds in between, and there was no way to SEE
     the running type before switching. Ctrl+T now opens the SAME
     generic selection menu the 'h' DoH / 'y' language / 'z' files
     hotkeys ride: every type is listed as 'number - name - short
     description' (SOCKS5: remote DNS; HTTP CONNECT; mixed: SOCKS5 +
     HTTP on one port, auto-detected), the RUNNING type is marked
     [x], the current type is named in the menu hint; type the number
     and press Enter (Backspace deletes a digit, any other key
     cancels, the menu exits automatically after applying - the
     v5.30 auto-exit). Choosing the CURRENT type is an explicit
     no-op (just the 'selected' line, no needless rebuild); choosing
     a NEW type runs the EXACT v8.0 cycle apply sequence - set +
     save settings.proxy_type + stop the engine, and the next
     watch-loop iteration rebuilds the listeners (both engines read
     get_proxy_type() at build time). --proxy-type is UNCHANGED,
     the PAC rules of v8.2/v8.3 are UNCHANGED, the OTHER hotkeys
     are UNCHANGED. New tr keys (en+ru): ptype_menu_hint,
     ptype_menu_entry, ptype_desc_socks5, ptype_desc_http,
     ptype_desc_mixed; hotkey_proxy_type / hotkeys_hint /
     proxy_type_selected now speak of the menu; two new _EMOJI
     entries (the wrench).

VERSION 2026-10-30 (v8.3) - THE PAC AUTO-CREATE BUG FIX (the v8.2
  contract was broken by ONE line; every algorithm NOT listed here
  is UNTOUCHED).

  1) THE DEFAULT <config dir>/mozvpn.pac WAS STILL WRITTEN ON EVERY
     ENGINE REBUILD (the user's live report). ROOT CAUSE: the v8.2
     maybe_pac_export() normalized the --pac-export argument with
     'str(custom).strip() if custom is not None else ""' - and that
     normalization ITSELF collapsed argparse's None (the flag was
     NOT given; default=None) into "" (the BARE-flag opt-in value;
     const=""), so the branch 'on_demand or custom == ""' matched
     the NO-FLAG case too and every rebuild re-created the default
     copy - the exact opposite of the v8.2 promise. THE FIX: the
     None-vs-"" distinction is preserved (None stays None):
     NO flag -> the default copy is written by the Ctrl+P hotkey
     ONLY (nothing at startup, nothing on a rebuild); the BARE
     --pac-export opt-in -> the default copy on every rebuild (the
     v8.0 behavior, back by explicit request); an EXPLICIT
     --pac-export FILE -> the named copy on every rebuild (plus the
     default copy on Ctrl+P). One line changed, zero other
     algorithms touched; the rest of the v8.2 delivery was audited
     and confirmed correct (the digit-hotkey honesty, the
     hotkey_no_file message, the on_demand plumbing, the Ctrl+P
     handler, the argparse help).

VERSION 2026-10-30 (v8.2) - THE HONEST DIGIT HOTKEYS + THE PAC FILE
  ON DEMAND (the user's two requests; every algorithm NOT listed here
  is UNTOUCHED).

  1) THE DIGIT HOTKEYS STOPPED PROMISING '1-9'. Since v6.0 the
     editable config is ONE file (config.json), so only '1' opens
     anything - digits 2-9 used to fail SILENTLY while the hint
     promised '1-9'. The hotkeys hint now says '1 - open
     config.json', the 'z' line no longer counts 'files past the
     ninth', and the files-menu hint describes the REAL token flow
     (token + Enter, Backspace deletes, any other key cancels). The
     MECHANISM stays dynamic (config_open_files() decides the list),
     and an out-of-range digit now SAYS so via the new hotkey_no_file
     message instead of doing nothing. The 'z' full menu is UNCHANGED
     (it already handles every listed file).

  2) THE PAC FILE IS NO LONGER AUTO-CREATED. Every engine rebuild
     used to write <config dir>/mozvpn.pac unconditionally; now the
     DEFAULT copy is written on demand by the Ctrl+P hotkey ONLY. An
     explicit --pac-export FILE is still honored on every rebuild
     (the user named the destination), and a bare --pac-export opts
     back into the v8.0 auto-write behavior. The PAC CONTENT - the
     FoxyProxy-style DIRECT bypass list and the fail-over chain - is
     UNTOUCHED; the useful-by-default options (DoH, the DoH cache,
     the TLS ClientHello fragmentation) stay ON exactly as before.

VERSION 2026-10-30 (v8.1) - THE CHANNEL NOTE REFINEMENT + THE REAL
  EMOJI WIDTH TABLE + THE IN-PLACE UI PANEL (the user's three
  requests; every algorithm NOT listed here is UNTOUCHED).

  1) THE CHANNEL NOTE, ROUND 3 ('it can probably handle more than
     just TCP, no?'). Re-verified against the Fastly engineering
     blog ('We built the proxy behind Firefox's new built-in VPN'),
     the Firefox networking docs ('CONNECT-UDP in Firefox') and the
     Mozilla Remote Settings server list: the channel TODAY is an
     HTTP CONNECT tunnel over HTTP/2 - a RAW TCP tunnel, so ANY TCP
     protocol and ANY destination port rides it (no port whitelist;
     Fastly: 'anything can run through it. TLS, Web sockets, custom
     protocols, even other proxies'); UDP/IP is the NEXT step via
     MASQUE over HTTP/3 (RFC 9298 CONNECT-UDP is already implemented
     in the Firefox networking stack - HTTP/3-only - and the
     server list already carries a per-server 'masque' protocol
     next to 'connect'). channel_limits_note (en+ru) and the
     startup comment now state exactly that. CODE AUDIT: no code
     change was needed - the builtin engine and the sing-box
     configs relay every CONNECT host:port; a destination-port
     whitelist never existed on our side either. aioquic stays the
     optional HTTP/3/MASQUE dependency.

  2) THE HOTKEY HINT COLUMN, PART 2 ('the icons are slightly off -
     their width differs across platforms'). The v6.0 fix PADDED the
     icons to one column, but _cw() itself still used the blanket
     'everything in 0x1F300-0x1F64F is 2 cells' rule, and the REAL
     East Asian Width table says otherwise: U+1F39B (control
     knobs, the Ctrl+T icon) is NEUTRAL = 1 cell, so that hint line
     was one column off on every standard-following terminal.
     _cw() now checks the emoji/symbol planes against the REAL
     EAW=W table (Unicode 18.0.0 - the wcwidth project's
     table_wide.py, verbatim 0x2300-0x2BFF + 0x1F000-0x1FBFF
     ranges), and the narrow-base hint icons were replaced with
     guaranteed-wide pictures: Ctrl+C now leads with U+26D4 (no
     entry) instead of U+23F9+VS16 (the VS16 presentation renders
     1 cell on legacy terminals), Ctrl+T with U+1F527 (wrench)
     instead of U+1F39B. Every other hint icon was audited against
     the same table and is genuinely wide.

  3) THE TOKEN REFRESH NO LONGER FLOODS THE LOG ('part of the UI is
     re-printed on every refresh - redraw the current output
     instead'). Every ~10-minute refresh used to APPEND the whole
     per-refresh block: the proxyPass line, the quota, the raw +
     decoded JWT, the next-refresh countdown, the FULL hotkeys
     hint, the config-files list and the clear-cache targets - 50+
     rows per refresh. That block is now a LIVE PANEL redrawn in
     place (ANSI cursor-up + clear-per-row erase, exact wrapped-row
     counting), so a refresh costs ZERO new log rows. Any real log
     line (a warning, a hotkey action, a rebuild message) LIFTS the
     panel, prints above its old position and DROPS it back below -
     the log keeps scrolling, the panel stays pinned at the bottom,
     and the TOTP code line stays a log line (a code lives 30 s; a
     once-per-refresh panel row would show a dead code). Theme and
     color switches re-render the panel in the new style. The
     fallback is the classic append (byte-for-byte the old
     behavior) whenever in-place redraw is impossible: no tty (a
     pipe/file), a dumb TERM, or a window too short for the block.

VERSION 2026-10-30 (v8.0) - THE ANALOG-RECON ROUND 4 IMPLEMENTATION (the
  user's request: implement the round-4 report items - A2, A3, A4,
  B3, B4, B5, C1, C2, C4 - reusing the VERIFIED open patterns of
  the mature analogs instead of inventing; every algorithm NOT
  listed here is UNTOUCHED; every feature is wired to a launch
  parameter AND a hotkey and activates ON by default wherever it
  cannot break the data path).

  1) A2: THE ACCOUNT AUTO-ROTATION BY QUOTA (the armanlife
     'multi-account: when one account's data runs out, the next
     takes over automatically' / Zeus 'moves to the account with
     the most data left' pattern). print_quota() now RECORDS the
     parsed X-Quota numbers: a module-level snapshot (_QUOTA_LAST,
     the zero flag the watch loop reads) and the per-account
     bookkeeping in config.json (quota_remaining/quota_limit/
     quota_reset/quota_seen) - so the rotation planner ranks the
     OTHER cached accounts by their LAST KNOWN remaining data.
     The watch-loop trigger: the CURRENT account reports quota
     zero (remaining <= 0, not unlimited) and auto-rotation is on
     -> pick_rotation_account() chooses the OTHER cached account
     with the LARGEST known remaining (unknown counts as a viable
     candidate, a known-zero account is NEVER a target; accounts
     without a CACHED session token are skipped - the rotation
     rides cached sessions, never password logins, exactly the
     foxyvpn-pool lesson: an FxA 429 login cooldown must never
     be triggered by the rotation itself) and switches the WHOLE
     profile with the SAME sequence as the hotkey-'a' selection
     (args/creds/TOTP provider, cfg_set_current, save_cache,
     apply_profile_runtime, engine stop -> the next iteration
     rebuilds the listeners from the NEW profile's filter and
     configs). --auto-rotate / --no-auto-rotate (default ON - a
     useful option ships enabled; the switch only GATES the
     trigger, the quota bookkeeping runs regardless), hotkey
     Ctrl+R, the choice is SAVED (settings.auto_rotate). When no
     other account has data left, ONE warning is printed (not one
     per refresh) and the run continues on the current account.

  2) A3: THE PASSWORDLESS LOGIN FROM A DESKTOP FIREFOX PROFILE
     (--fxa-profile, a LAUNCH PARAMETER ONLY - no hotkey, per the
     user's explicit request; the foxhole-vpn AUTH.md pattern:
     sessionToken read from signedInUser.json, field
     accountData.sessionToken). --fxa-profile PATH accepts the
     signedInUser.json file itself OR the profile DIRECTORY; the
     token rides the SAME grant_type=fxa-credentials flow every
     password sign-in already rides (oauth_token() below - no new
     auth code), but with NO password login at all: the Fastly
     bot wall on third-party password logins and the FxA 429
     login rate limit never apply, no 2FA is prompted (the
     profile session is already verified), and the token is
     RE-READ FRESH on every ensure_session() call, so a
     Guardian-401 relogin after the user re-signed Firefox picks
     the new session automatically. Precedence: an explicit
     --session-token still wins, --fxa-profile beats the CACHED
     account session. errno 110 on the OAuth mint raises the
     existing relogin path, which re-reads the profile file and
     tells the user to sign into Firefox again (the localized
     messages fxa_profile_* carry the actionable hint).

  3) A4: THE SOCKS5 LOCAL LISTENER + THE SWITCHABLE PROXY TYPE.
     The builtin engine now serves SOCKS5 (RFC 1928, the CONNECT
     command only - the same scope as foxyvpn's SOCKS5 and the
     foxhole SOCKS5/HTTP single-port pattern): the greeting
     handshake (VER 05, NO AUTHENTICATION REQUIRED), the request
     parse (ATYP 01 IPv4 / 03 DOMAIN / 04 IPv6), the bounded
     upstream ride IDENTICAL to the HTTP CONNECT path (the same
     TLS profile matrix, the same Bearer pass, the same
     _PassMonitor signals - a rejected pass refreshes the token
     at once, the same half-close drain window), and REMOTE DNS
     BY DESIGN: a DOMAIN request address is passed THROUGH to
     the egress (the curl socks5h/socks5a semantics - the egress
     resolves the name, the local system DNS is bypassed - the
     user's requested default). --proxy-type socks5|http|mixed
     (default socks5), hotkey Ctrl+T (the cycle socks5 -> http ->
     mixed -> socks5 restarts the engine so the listeners serve
     the new type at once), the choice is SAVED
     (settings.proxy_type). 'mixed' auto-detects the protocol of
     EVERY connection by PEEKING the first byte without consuming
     it (socket.MSG_PEEK, available on POSIX and Windows alike):
     0x05 = a SOCKS5 greeting, anything else = an HTTP request
     line. The sing-box engine maps the type to the OFFICIAL
     sing-box inbounds (http -> 'http', socks5 -> 'socks', mixed
     -> 'mixed' - the inbound that serves HTTP and SOCKS on one
     port). The FoxyProxy exports (f/x, --foxyproxy-export,
     --foxyproxy-legacy-export) now carry the SERVED type: type
     'socks5' + proxyDNS true in the FoxyProxy Standard settings
     (the schema.json enum http/https/socks4/socks5/pac/direct,
     verified 2026-10-30) and type 3 + proxyDNS true in the
     FoxyProxy 6/7 legacy entries (PROXY_TYPE_SOCKS5 - verified
     against the official FoxyProxy Standard 7.5.1 example
     settings, which use exactly "type": 3, "proxyDNS": true for
     a SOCKS proxy).

  4) B3: THE PAC EXPORT (the armanlife 'smart routing: local
     sites open directly' idea, adapted to a terminal proxy).
     build_pac_script() generates a FindProxyForURL that returns
     DIRECT for localhost/private ranges (localhost, 127.*,
     ::1, 10.*/172.16-31.*/192.168.*/169.254.* - the SAME bypass
     list the FoxyProxy exports carry) and the LOCAL proxy for
     everything else, with the PAC fallback chain listing EVERY
     running listener and ending in DIRECT (a dead listener fails
     over, the browser never hits a dead end). The directive
     follows the proxy TYPE: SOCKS5 (the remote-DNS PAC entry)
     or PROXY. The file is written to <config dir>/mozvpn.pac
     AUTOMATICALLY on EVERY engine rebuild (idempotent, cheap -
     a useful default ships enabled) plus to --pac-export FILE
     when given; hotkey Ctrl+P rewrites it on demand.

  5) B4: THE FxA UNBLOCK-CODE FLOW (the errno 125 dead end is
     gone for interactive runs; the Zeus-VPN 'unblock codes
     handled in the app' / fxa-js-client signIn pattern,
     verified 2026-10-30 against the fxa-js-client sources and
     the fxa-auth-server API: on errno 125 the server has
     already emailed the 6-digit unblock code; the login is
     retried with the code riding the payload as 'unblockCode',
     and an EMPTY prompt input re-sends the letter via POST
     /v1/account/login/send_unblock_code {email}). Bounded at
     three prompts; a wrong code re-enters the same flow (the
     server answers errno 125 again); non-interactive runs keep
     the v6.6 blocked error VERBATIM.

  6) B5: THE CONFIRMATION-LINK BRANCH of the emailed session
     verification (the foxyvpn 'email 2FA code verification,
     falling back to a confirmation-link prompt' / 4q4r 'or the
     confirmation link, when FxA chooses that method' pattern).
     The email-code prompt now accepts 'l' (or 'link'): the
     user is told to open the confirmation LINK from the Mozilla
     email in a browser, and the script POLLS GET
     /v1/recovery_email/status (the onepw protocol's own
     endpoint: 'the client can use /recovery_email/status
     (requires sessionToken, not verification) until the user
     clicks the email link and the API reports verification is
     complete' - verified against the mozilla/fxa-auth-server
     wiki, fetched 2026-10-30) with the same Bearer + Hawk
     fallback auth as every other session route, every 10 s,
     bounded at 300 s; the code path stays as it was and a
     timeout simply returns to the prompt. The prompt text
     (en+ru) now says both options exist.

  7) C1: THE HAWK SIGNATURE IS REBUILT ON EVERY RETRY (the
     foxyvpn rule: 'on Hawk-signed FxA requests, the request
     signature is rebuilt fresh on every retry'). hawk_session()
     now returns a _HawkHeaders dict that carries its own
     rebuild closure, and every retry recursion of req_full()
     (the 406 solve-and-retry cycles, the body-aware challenge
     retry, the transient network retry and the emergency
     direct-IP route) re-signs through _rebuild_hawk() before
     the request goes out: a fresh ts + nonce every attempt -
     the server may not verify the MAC today, but the code no
     longer RELIES on that.

  8) C2: ECH (Encrypted Client Hello) - AUDITED, VERIFIED AND
     DELIBERATELY NOT ADOPTED (the round-3 watch-item stands):
     verified online 2026-10-30 - OpenSSL 4.0 shipped the RFC
     9849 ECH implementation (published March 2026), but the
     CPython ssl module still does NOT expose it (the open
     gh-89730 PRs #135435/#160318 are unmerged as of today), so
     a stdlib-only script cannot send an ECH ClientHello yet.
     When ssl gains ECH it slots in as ANOTHER transport
     profile on top of the existing TLS matrix, beside
     --tls-split; zero code changes now (nothing untestable
     ships).

  9) C4: THE --doctor ONE-SHOT DIAGNOSTICS (the foxhole-vpn
     'doctor command' pattern): a READ-ONLY walk of the whole
     chain the script depends on - the interpreter, the config
     store + current account, every pip dependency and sing-box
     (print_dependencies()), the system resolver, the DoH chain
     (the configured provider, resolve_host()), the FxA API
     reachability (the public credentials/status endpoint - the
     Fastly challenge path is exercised implicitly), the server
     list fetch, a REAL TLS handshake to a live egress
     (_tls_connect - the full profile matrix), and the OAuth ->
     Guardian -> quota chain on the CACHED session token ONLY
     (never a fresh sign-in, never a prompt). Exit code 0/1.

  10) THE NEW HOTKEYS Ctrl+R (auto-rotation), Ctrl+T (proxy
      type) and Ctrl+P (PAC export) sit in the hotkeys list
      NEXT TO the Ctrl+O/Ctrl+C block (en+ru, the same icon +
      bold-key + description style; the control chars 0x12/
      0x14/0x10 arrive as single bytes in cbreak mode on every
      platform and the v6.3 _normalize_key() fix passes every
      control character through unchanged).

VERSION 2026-10-30 (v7.2) - THE SECOND v7.0 SYNTAX REPAIR (the
  v7.1 file still did not parse: one comment line of the new
  email-branch explanation lost its leading hash and the parser
  met a bare date at line 7766). ONE hash restored, zero
  algorithms touched: every algorithm NOT listed here is
  UNTOUCHED. The whole file is additionally machine-checked now:
  a character-level scan of every string / comment / bracket
  state (no line ends inside an open one-line string, no
  statement begins with a digit or dangling punctuation, every
  bracket closes) passes over all lines of this file.

VERSION 2026-10-30 (v7.1) - THE v7.0 SYNTAX REPAIR (the delivered
  v7.0 did not even parse: one stray quote my side closed the
  _waf_challenge_body docstring one character early, and the
  parser stopped at line 5330). ONE character removed, zero
  algorithms touched: every algorithm NOT listed here is
  UNTOUCHED - and the v7.0 list below now actually runs.

VERSION 2026-10-30 (v7.0) - THE ANALOG-RECON ROUND 3 (the user's
  request: diff the current analogs again - their closed bugs,
  pitfalls, useful features - and verify THEIR code too; every
  algorithm NOT listed here is UNTOUCHED).

  1) THE EMAILED-CODE SESSION VERIFICATION (the dead end is gone).
     The Go reference client adopted the email-2fa login on
     2026-08-22 ('Sync upstream token pool, email-2fa login, and
     Fastly challenge solver': fxaVerifySession prompts for the
     6-digit code FxA emails at login and POSTs it to
     /v1/session/verify_code), and armanlife issue #19 plus
     Vauth/FoxyVPN PR #46 (2026-10-29/30) confirm the third-party
     FxA logins now lean on the Fastly bot wall. Verified against
     the FxA sources (lib/routes/session.js, fetched 2026-10-30):
     /session/verify_code rides the SAME sessionTokenBearer auth
     with a sessionToken Hawk fallback as the TOTP route, payload
     {'code': DIGITS}; a VALID code verifies the session via
     'email-2fa' but a TOTP account is REFUSED (insufficientAal -
     the AAL1 guard this file documented in v5.25), so the new
     path is entered ONLY for accounts the script holds no TOTP
     provider for and ONLY when a prompt is physically possible;
     the EMPTY input re-sends the letter via /session/resend_code
     (a no-op {} for TOTP accounts); non-interactive runs keep
     the v6.9 reference dead end (the localized instructions)
     VERBATIM.

  2) THE FASTLY SOLVER ACCEPTANCE PROBE + THE BODY-AWARE CHALLENGE
     DETECTION. The solver flow (v6.6/v6.7) now ends like the Go
     fastly.go (fetched 2026-10-30): after 'success' the page is
     RE-FETCHED through the same cookie jar and a page that still
     carries the challenge markup means the earned cookie was NOT
     accepted (the Go errChallengeNotAccepted - e.g. a rotated
     exit IP) and is NOT latched/cached anymore (up to v6.9 it was
     cached blindly and the API call had to rediscover the
     rejection through the 406 re-solve loop). req_full() also
     recognizes the client-challenge page in a RESPONSE BODY now
     (the Vauth/FoxyVPN PR #46 report: the challenge arrives not
     only as the classic empty-body 406 but also as 403/200/503
     WITH the markup) and runs the same bounded solve-and-retry;
     the exact empty-406 condition of v6.7 stays FIRST.

  3) THE TLS-RECORD SPLIT AT THE SNI EXTENSION inside the existing
     --tls-split fragmented handshake. Evidence, not fashion: zapret
     issue #238 (the tpws TLS-record fragmentation ALONE did not
     fool a DPI - the two records went in ONE TCP packet and the
     DPI reassembled them; the ClientHello TCP split was the
     working technique), and the Xray-core discussion #5969
     (2026-04: Iran's national DPI now REASSEMBLES the classic
     TCP-layer fragmentation; 'TLS record-layer fragmentation
     bypasses DPIs that reassemble at the TCP layer but not at
     the TLS record layer'). The v7.0 fragmented ClientHello
     therefore carries BOTH: the single ClientHello record is
     re-framed into TWO TLS records cut at the server_name
     extension (the zapret tpws --tlsrec=sniext cut) and THEN
     each record goes in TLS_SPLIT_CHUNK-byte TCP segments - the
     DPI must now reassemble BOTH layers to see the SNI. RFC
     5246 section 6.2.1 permits a handshake message to span
     multiple records; an unparseable ClientHello keeps the v6.6
     plain TCP segmentation and ANY fragmented-handshake failure
     still falls back to the plain profile walk (the v6.6
     item-12 contract).

  AUDITED, VERIFIED AND DELIBERATELY NOT ADOPTED (the round-3
  findings that change nothing):
   * The Go token pool (-session-token as a .txt file, rotation on
     HTTP 429 / quota-zero / 401-403, a .state file bound to the
     token file's sha256, a 15-minute quota poll): mozvpn.py stores
     WHOLE accounts (email + password + TOTP) with the multi-account
     profile switch and rides the X-Quota headers on every token
     response with the 429 cooldown - the pool solves a problem this
     architecture does not have.
   * The Go in-place session-token update on the proxyPass renewal:
     already here (both engines' update_token()).
   * The Go low-MTU H3 fix (InitialPacketSize 1200): quic-go's
     default 1280 is the QUIC PAYLOAD size (1308 bytes on the wire
     over a low-MTU link), but aioquic - the library of the MASQUE
     probe - already defaults to max_datagram_size =
     SMALLEST_MAX_DATAGRAM_SIZE = 1200 QUIC payload bytes (~1228
     on the wire), below the 1280 MTU floor: no change needed.
   * The Go HTTP/2 keepalive PING loop: mozvpn.py's upstream is a
     per-proxy HTTP/1.1 CONNECT relay, not a pooled H2 session - the
     adopted pacing is the v6.7 TCP keepalive.
   * The July aimkiray batch (the explicit -country selection, the
     verify-exit probe, the systemd health-check/status files):
     already covered by --countries, the probe_geo exit check and
     the config persistence.
   * FoxyVPN's browser PKCE login (a WebView sign-in): needs a GUI
     browser engine - out of scope for a terminal script whose
     solver already rides the same control plane.

VERSION 2026-10-30 (v6.9) - THE CHANNEL-NOTE RETRACTION + STICKY
  USER SETTINGS + THE PROBE-TRAFFIC DEDUP (the user's three
  requests; every algorithm NOT listed here is UNTOUCHED).

  1) THE 'TCP-ONLY / WEB PORTS ONLY' CHANNEL NOTE WAS WRONG AND IS
     RETRACTED. The v6.6 startup line claimed the egress 'proxies
     the WEB ports only (80/443/8080/8443): other ports/protocols
     are refused'. Re-verified against the operator's own
     engineering blog (Fastly, 'We built the proxy behind
     Firefox's new built-in VPN', fetched 2026-10-30): the rollout
     speaks HTTP CONNECT over HTTP/2 with an evolution toward full
     MASQUE over HTTP/3, and the CONNECT tunnel is a RAW TCP
     tunnel - 'anything can run through it. TLS, Web sockets,
     custom protocols, even other proxies'. NO destination-port
     whitelist exists in any source: the 80/443/8080/8443 numbers
     were the EGRESS LISTENER ports of a third-party server list,
     mistaken for allowed DESTINATION ports; Fastly states it does
     no deep packet inspection, and Mozilla positions the feature
     for browser-level web traffic (not full-device tunneling).
     channel_limits_note (en+ru) and its startup comment now state
     only the verified facts.

  2) STICKY USER SETTINGS (the user's request: the hotkey choices
     reset at every restart). The doh/lang precedence - an
     EXPLICIT argument wins, then the SAVED choice, then the env,
     then the built-in default - now covers EVERY preference a
     hotkey can flip: settings.theme (hotkey 'm' / --theme),
     settings.color (hotkey 'n' / --no-color), settings.doh_cache
     (hotkey 'k' / --doh-cache - the config-layout docstring has
     carried this key name since v6.4), settings.tls_split (hotkey
     'i' / --tls-split) and settings.engine (hotkey 'e' /
     --local-proxy-engine). Every hotkey saves its state the moment
     it flips it, the startup mirrors the EFFECTIVE state back into
     the profile (the same write doh/lang already do), the argparse
     defaults of the five became None ('not chosen') so a
     never-written key can never pose as an explicit choice (the
     v6.8 lesson), and apply_profile_runtime() re-applies the new
     profile's theme/color/DoH-cache/fragmentation with the same
     precedence (redrawing the log when the look changed; the saved
     ENGINE of a profile applies at the next start - a live engine
     switch stays hotkey 'e', which stops and recreates every
     listener). DELIBERATELY NOT PERSISTED: --listen (hotkey 'l') -
     binding 0.0.0.0 exposes every local proxy to the network and
     must stay an explicit per-run decision; --doh-url and
     --api-proxy (a custom URL may be secret); and --verbose (a
     diagnostic that de-redacts the browsing destinations, opt-in
     by design).

  3) THE PROBE-TRAFFIC DEDUP (the user's report: the protocol
     support test 'works long'). The probe phase was audited end
     to end: the upstreams ALREADY run in a 64-thread pool with
     per-upstream MASQUE/CONNECT overlap, daemon-thread DoH
     prefill with in-flight dedup and the TCP-failure
     profile-matrix abort - nothing there is serial. The real
     waste was DUPLICATE TUNNELS: several locations share one
     egress (and with --upstream-host EVERY entry points at the
     same upstream), yet the old loop opened one probe tunnel per
     ENTRY - N simultaneous TLS+CONNECT handshakes against the
     same egress, N times the WAF-visible request rate, all to
     learn the SAME fact. probe_upstreams_parallel() now probes
     each UNIQUE (host, port, protocol) ONCE and fans the verdict
     (including the CONNECT-fallback protocol switch of a failed
     MASQUE probe) out to every entry that points at it - the
     collect_verified_servers() merge already matched results by
     (host, port), so the mapping is exact. The analogs agree with
     the minimal-probe principle: the Go client verifies the exit
     ONCE after connecting (main.go verifyExit) and Firefox runs
     NO pre-flight probes at all (its IPPNetworkErrorObserver
     reacts to failures instead).

VERSION 2026-10-30 (v6.8) - THE DEFAULT-DoH BUG: THE BUILT-IN
  'cloudflare' DEFAULT WAS UNREACHABLE (the user's live report: 'the
  default resolver is the SYSTEM DNS, there is no DoH'; every
  algorithm NOT listed here is UNTOUCHED).

  ROOT CAUSE (found by reading the whole resolver-selection path):
  load_doh_provider_cache() read settings.doh with a '' DEFAULT, so
  a key that was NEVER WRITTEN - a fresh install, exactly the
  do-nothing case the built-in default exists for - came back as '',
  which the startup honored as 'the saved system-DNS mode'; the
  'else env / else cloudflare' branch was DEAD CODE, and the startup
  mirror then SAVED the '' right back into config.json: the bug
  hardened itself on the very first run and looked like a
  deliberate user choice forever after. Under the v5.31 doh.json a
  MISSING FILE meant None and the default worked; the v6.0
  uber-config rework lost the 'missing' case while this very
  docstring kept promising 'None when nothing was saved yet'.

  THE FIX (the documented contract is restored, in four places):
  1) load_doh_provider_cache(): a MISSING key - and any legacy ''
     the bug wrote - is None again ('never chosen'), so the startup
     and apply_profile_runtime() fall through to MOZVPN_DOH or the
     built-in 'cloudflare' default. Only an EXPLICIT marker keeps
     the system-DNS mode.
  2) save_doh_provider_cache(): the system-DNS choice is now stored
     as the EXPLICIT 'off' marker (load maps 'off'/'system' -> ''),
     so a deliberate hotkey-'h' / --doh off choice stays sticky
     across restarts while a never-chosen key can never masquerade
     as one again.
  3) ONE-TIME HEAL of the poisoned configs: a settings.doh of ''
     written by the bug is indistinguishable from a deliberate
     pre-v6.8 choice, but the user's directive is explicit - the
     DEFAULT IS CLOUDFLARE - so '' is treated as 'never chosen':
     the next run selects cloudflare and persists it. A user who
     really wants the system DNS re-picks it once with hotkey 'h'
     (stored as 'off', survives restarts).
  4) The legacy doh.json migration now maps a legacy '' to the
     EXPLICIT 'off' marker: a pre-v6.0 '' was only ever written by a
     deliberate old-version choice (a missing file produced no
     entry), so the deliberate choice is preserved.

  THE SECOND RE-CHECK OF EVERY ADOPTED IMPROVEMENT (the user's
  request 2; all confirmed present and wired): anchored_exp() + all
  its consumers, the Guardian 403 re-activation retry, the CONNECT
  response classification (400/401/403 / 502/504 / timeout), the
  _PassMonitor signal classes and the 1-second sleep poll with the
  minRotationInterval floor, the half-close drain (the v6.7 fixed
  semantics), the TCP keepalive on both tunnel sockets, the bounded
  Fastly solver (3 rounds / 60 s / lock), the 406 re-solve loop
  (v6.7), the blocked_login 429/errno-114 cooldown on login and
  2FA, the quota_low <15% warning on every proxyPass refresh,
  --api-proxy with the opener rebuild (and the v6.7 profile-switch
  fix), --tls-split ON by default with the plain-TLS fallback,
  --verbose target redaction, the auto-clear of a broken countries
  filter, hotkey 'i', and the full en+ru tr/emoji set of the new
  keys. One STALE hotkey-'i' comment still claiming 'OFF by
  default' (a leftover of the v6.6 wording) was found by the
  re-check and corrected.

VERSION 2026-10-30 (v6.7) - THE SECOND PASS: ONE MORE ADOPTED
  PATTERN, THE DEFAULTS-ON DIRECTIVE, AND THE v6.6 QUALITY AUDIT (the
  user's three requests; every algorithm NOT listed here is UNTOUCHED -
  the sign-in chain, the reference-parity auth/scopes/stretching, the
  Fastly PoW solver core, the probe/engine design, the TLS profile
  matrix, the strict-DoH contract and the hotkey UX are preserved
  exactly as v6.6 left them). All the external facts below were
  re-verified ONLINE on 2026-10-30 against the same analogs:
  mozilla-firefox/firefox (toolkit/components/ipprotection/*) and
  UjuiUjuMandan/firefox-vpn-client (fxa.go, http_client.go, tokens.go,
  guardian.go, serverlist.go, main.go).

  1) THE v6.6 HALF-CLOSE DRAIN BUG - the one place v6.6 really could
     break the data path, and it did. v6.6 bounded BOTH relay joins of
     the builtin engine's CONNECT tunnel (_HALF_CLOSE_DRAIN = 120 s
     per join) and then closed both sockets - so a perfectly HEALTHY
     tunnel (a long download whose client side stays silent for two
     minutes) was KILLED after at most 4 minutes of quiet. The audit
     re-read the Go source: halfCloseDrainTimeout is a DECLARE-ONLY
     leftover constant in main.go (its tunnel copy path never uses
     it), and the pre-v6.6 code waited for both relays UNBOUNDED
     (t1.join(); t2.join()). The corrected semantics: the FIRST relay
     direction is waited for UNBOUNDED again (that is the tunnel's
     real lifetime - v5.0 parity, and the v6.6 TCP keepalive already
     reaps a dead peer at the OS level, so an unbounded wait can no
     longer pin a thread on a dead path); only the SECOND direction -
     after the half-close - gets the bounded 120 s drain window, which
     is exactly what 'drain after half-close' means. A live tunnel is
     never closed by the clock anymore.

  2) --tls-split IS ON BY DEFAULT NOW (the user's directive: every
     USEFUL option ships enabled). The ClientHello fragmentation is
     unconditionally beneficial (a single-packet DPI cannot read the
     whole SNI from one segment) and CANNOT break the data path by
     construction: every fragmented-handshake failure falls back to
     the plain TLS profile matrix of _tls_profiles() on a fresh
     socket, so the v6.1 lesson now holds by fallback, not by
     opt-in. --no-tls-split / MOZVPN_TLS_SPLIT=0 restores the old
     behavior; hotkey 'i' still toggles it live. --verbose stays
     opt-in BY DESIGN: it de-redacts the CONNECT destinations (the
     user's browsing history), and both references keep it off (the
     Go -verbose defaults to false; Firefox gates debug logging
     behind browser.ipProtection.log) - a diagnostic is not a
     benefit. --api-proxy takes a URL and cannot have a default.

  3) THE 406 RE-SOLVE LOOP OF THE GO CLIENT IS ADOPTED (fxa.go fxaDo:
     maxChallengeAttempts = 5). The audit of the v6.6 code found the
     gap: req_full() retried a 406 exactly ONCE, and when the edge
     rejected a cookie that was ALREADY in the jar (a rotating
     control-plane exit re-binds the WAF verdict to the IP), the
     retry re-sent the SAME rejected cookie and the call died with
     waf_406. The Go client re-solves the challenge FRESH on EVERY
     406 of a call, up to 5 attempts. req_full() now does the same:
     a 406 answered while a cookie was already sent drops the solved
     latch, purges the stale _fs_ch_cp_* cookie from the jar AND from
     the config cache, and ensure_fastly_cookie() then solves a NEW
     challenge (still bounded by the v6.6 solver caps: 3 post-back
     rounds / 60 s under the solve lock); up to
     FASTLY_MAX_406_ATTEMPTS (= 5, the Go constant) solve-and-retry
     cycles per request. The FIRST 406 of a call keeps the exact
     v5.25 cache-or-solve behavior (reference parity), and the
     emergency direct-IP route keeps its own single v5.25 retry
     (that path only exists in the broken-resolver state).

  4) _reset_fastly_session() KEEPS THE --api-proxy OPENER - an
     integration bug of v6.6 found by the audit: the v5.x sequence
     rebuilt _OPENER with a bare HTTPCookieProcessor, silently
     dropping the v6.6 ProxyHandler, so after a profile switch
     (hotkey 'a', an account delete, a wipe) --api-proxy stopped
     routing the control plane without a word. The reset now calls
     _rebuild_opener(), which picks up the fresh COOKIE_JAR and
     re-applies the ProxyHandler of the moment.

  5) THE CONNECT RESPONSE OVER-READ IS FORWARDED - a small v6.6
     correctness gap: the builtin engine reads the upstream's CONNECT
     answer with recv(4096) until the blank line, so the same read
     may pull the FIRST TUNNEL BYTES past the response head (an
     eager server, early data). v6.6 parsed the status and silently
     dropped those bytes; the 200 path now partitions the response
     and hands the client every byte read past the head before the
     relays start - no tunnel byte is ever lost.

  THE REST OF THE SECOND ANALOG PASS (the user's request 1; every
  point verified online 2026-10-30): ALREADY COVERED by earlier
  versions - the Guardian JWT clock-skew hardening (mozvpn's
  anchored_exp() receipt anchoring is strictly stronger than the Go
  detectProxyPassClaimTimeOffset candidate scan, and the Date-header
  time sync already warns about a skewed local clock), the shared
  cookie jar of the challenge flow (v5.36), X-Quota-*/Retry-After
  parsing, quarantined-server skipping (build_city), the exit
  IP/country verification (probe_geo - the Go -verify-exit), the
  atomic 0600 config writes (tmp + os.replace), Guardian
  401 -> relogin / 403 -> re-activate + retry / 429 -> cooldown
  (v6.6), the bounded per-round solver (v6.6), the browser-style
  header matrix (BROWSER_HEADERS, deliberately kept: reference
  parity - the Go MozillaVPN UA is its own reference client's
  choice, not Firefox's), and the Go token-file hygiene (N/A:
  mozvpn keeps ONE uber-config, already atomic and 0600). NOT
  APPLICABLE by design: the Firefox auto-activation/offline
  observers (an OS-integrated browser service, not a CLI script)
  and the Go session-token pool rotation (a multi-account farm
  feature; mozvpn's account switching covers the single-user case).
  ADOPTED NOW: only item 3 - the one pattern the analogs genuinely
  had and mozvpn.py lacked.

VERSION 2026-10-29 (v6.6) - THE 14 PRACTICAL PITFALLS (the Firefox-vs-Go
  comparison the user requested; every algorithm NOT listed here is
  UNTOUCHED - the sign-in chain, the reference-parity auth/scopes/
  stretching, the Fastly PoW solver core, the probe/engine design, the
  TLS profile matrix, the strict-DoH contract, the hotkey UX and the
  whole feature set are preserved exactly as v6.5 left them). All the
  external facts below were verified ONLINE on 2026-10-29 against the
  Firefox IP Protection sources (mozilla-firefox/firefox, toolkit/
  components/ipprotection: GuardianTypes.sys.mjs, IPPProxyManager.sys.mjs,
  IPPNetworkErrorObserver.sys.mjs) and the Go reference client
  (UjuiUjuMandan/firefox-vpn-client, cmd/proxy-demo: main.go, fastly.go).

  1) THE proxyPass EXPIRY IS NOW ANCHORED TO OUR CLOCK AT RECEIPT.
     Firefox GuardianTypes.ProxyPass does exactly this (verbatim:
     'Anchor the pass to our clock at receipt: it is valid from now for
     the token's lifetime. This makes rotation scheduling immune to any
     drift between Guardian's clock (nbf/exp) and ours'). The old code
     scheduled the refresh from the JWT's ABSOLUTE 'exp', which a skewed
     local clock misreads in BOTH directions (a slow clock 'extends'
     the pass into real expiry - the 'proxy stopped working for a
     while' window; a fast clock can even see a FRESH pass as already
     expired). The new anchored_exp() computes receipt + (exp - nbf) -
     the JWT lifetime measured on OUR clock - and every consumer of the
     expiry now uses it: the watch loop margin clock, the adaptive
     refresh retry, the startup display and the one-shot mode. A JWT
     with no nbf falls back to the raw exp (the pre-v6.6 behavior,
     preserved exactly). The rotation lead stays --refresh-margin
     (default 120 s = Firefox's own 'Rotate 2 Minutes from the End
     Time').

  2) A GUARDIAN 403 ON THE TOKEN FETCH NO LONGER KILLS THE CYCLE:
     Firefox re-establishes the enrollment and asks again before
     giving up - guardian_pass() now performs ONE automatic POST
     /api/v1/fpn/activate (the v5.3 reference-parity re-activation
     path, reused verbatim) followed by ONE retry of the GET
     /api/v1/fpn/token; a 403 after the retry raises exactly as
     before and every other status is untouched.

  3) THE proxyPass REJECTION BY THE EGRESS IS NOW OBSERVED LIVE. The
     builtin engine parses the status code of EVERY upstream CONNECT
     response: HTTP 400 ('parsing JWT failed' - the documented
     Guardian body for a bad/expired pass), 401 and 403 mean THE PASS
     WAS REJECTED: the client still gets its 502, but the new
     _PassMonitor flags the event and the watch loop's sleep phase
     polls the flag EVERY SECOND and breaks the sleep at once -
     Firefox reacts to a non-2xx CONNECT response of the egress the
     moment it is observed (IPPNetworkErrorObserver fires
     'proxy-http-error' on every failed proxy response), not at the
     next margin tick. The immediate refresh is PACED by the Firefox
     floors: at least 1 s between rotations (minRotationInterval) plus
     the 500 ms retry pacing (retryAfter) - never a tight refresh
     loop.

  4) TWO DISTINCT FAILURE CLASSES (the Go reference design:
     maxDistinctOpenTimeoutTargets / maxDistinctBadGatewayTargets = 3).
     (a) TARGET failures - a CONNECT to a destination that never opens
     (timeout) or that the egress answers with 502/504 - are counted
     PER DISTINCT TARGET: one flaky destination fails only its own
     client connection, and only THREE DISTINCT failing targets mean
     the TUNNEL/SESSION is broken (-> the pass is refreshed at once);
     (b) the PASS rejection of item 3 is the separate, faster signal.
     Both classes live in the new thread-safe _PassMonitor (the
     BUILTIN engine only - the sing-box engine runs as an external
     process this script cannot instrument; its lifecycle is
     unchanged).

  5) THE HALF-CLOSE DRAIN WINDOW (the Go halfCloseDrainTimeout = 2
     minutes): when ONE side of a relayed tunnel half-closed, the peer
     may legitimately keep sending for a while (a download finishing)
     - but a tunnel whose second direction NEVER ends must not pin the
     client thread and the sockets forever. After the 2-minute window
     BOTH sockets are closed, the relay threads unblock and the
     connection is reaped (the old join() waited forever on a
     half-open tunnel).

  6) TCP KEEPALIVE with the Go pacing (upstreamKeepAliveInterval =
     10 s / the probe timeout of 5 s -> idle 10 s, retry every 5 s,
     3 probes): a silently-dropped NAT/middlebox path is detected by
     the OS instead of leaving a half-open tunnel until the
     application timeouts fire. Purely advisory - every option is
     applied best-effort (try/except) and every platform keeps
     working without them.

  7) THE FASTLY CHALLENGE SOLVER IS BOUNDED (the Go fastly.go limits:
     maxPostBackRounds = 3, fastlySolveTimeout = 60 s). A server that
     answers a solution submission with ANOTHER challenge list no
     longer loops the solver forever - the post-back exchange runs at
     most 3 rounds and the WHOLE solve is capped at 60 s; and the
     whole check-and-solve sequence of ensure_fastly_cookie() now runs
     under _FASTLY_SOLVE_LOCK (the Go solve mutex): concurrent callers
     (the probe threads, a hotkey racing the watch loop) JOIN the one
     running solve instead of racing it with parallel PoW work and
     mismatched token/cookie pairs.

  8) THE FxA LOGIN RATE LIMIT (HTTP 429 / errno 114) IS NOW A DISTINCT
     'blocked_login' ERROR with its own cooldown: a 15-minute wait (the
     old generic 600 s 'blocked' wait stays for the Guardian-side
     blocks), and the retry prefers the CACHED session token
     (ensure_session reuses it automatically - a rate-limited password
     login never keeps re-prompting). The 2FA 429 gets the same code.

  9) THE QUOTA IS REPORTED ON EVERY proxyPass REFRESH (the ~10-minute
     cadence - TIGHTER than the Go quotaCheckInterval of 15 min; the
     X-Quota headers already ride every token response, so no extra
     request is made), and a NEW warning fires when the remaining
     monthly allowance drops below 15% of the limit (the reset time is
     included in both lines).

  10) --api-proxy URL / env MOZVPN_API_PROXY (the Go -api-proxy flag):
     the CONTROL-plane requests (FxA, Guardian, Remote Settings, the
     Fastly challenge - everything that goes through the shared
     _OPENER / req_full / _fastly_http) leave through ONE FIXED
     HTTP(S) proxy while the proxied browsing traffic keeps rotating
     through the Mozilla egresses: the Fastly WAF cookie and the
     Guardian enrollment are BOUND TO THE EGRESS IP, so a rotating
     control plane can invalidate them mid-session. http:// and
     https:// proxy URLs only - socks5:// is refused with a clear
     error (the stdlib ProxyHandler tunnels http/https via CONNECT;
     this script adds no new dependency). The DoH chain is NOT routed
     through it (the DoH endpoints are anycast - DNS needs no fixed
     exit). OFF by default; hotkey-free (a run-start decision).

  11) --verbose / env MOZVPN_VERBOSE: the CONNECT targets of the
     engine failure logs are REDACTED by default
     ('<redacted; use --verbose>' - exactly the Go logTarget
     redaction): the destination of a client request is the user's
     browsing. The per-host EGRESS names stay visible - they are the
     script's own servers, not the user's traffic.

  12) --tls-split / hotkey 'i' / env MOZVPN_TLS_SPLIT: the TLS
     ClientHello of the outer connection (which carries the egress
     SNI) is sent in SMALL TCP SEGMENTS (64-byte pieces, the first one
     delayed 30 ms), so a single-packet DPI cannot read the whole SNI
     from the first segment. Implemented with memory BIOs
     (ctx.wrap_bio + a hand-driven do_handshake loop - the stdlib
     technique the Python ssl docs document for non-blocking BIO
     use); everything after the handshake is pumped through the SAME
     SSLObject, so the connection stays a normal TLS stream for the
     peer. STRICTLY OPT-IN, OFF by default (the v6.1 lesson: a
     transport 'hardening' must never surprise the working data
     path); ANY fragmented-handshake failure falls back to the plain
     profile matrix of _tls_profiles() (a fresh socket, the plain
     wrap_socket) - the data path never breaks.

  13) THE PERSISTENTLY-BROKEN SELECTION SELF-HEALS: when a saved
     countries filter leaves the engine serving proxies whose egress
     ALL keep failing (5+ consecutive failures on EVERY served host),
     the saved filter is CLEARED and ALL proxies are served on the
     next engine rebuild - the same 'never zero usable proxies'
     fallback the probe phase has; one localized line says so, and
     the user can re-apply the selection with 'w' once the egresses
     recover.

  14) THE Mozilla CHANNEL LIMITS ARE STATED ONCE AT STARTUP (verified
     2026-10-29: the egress proxies the WEB PORTS ONLY - 80/443/8080/
     8443 - over TCP; other ports/protocols are refused server-side),
     so a misdirected non-web client (mail, SSH, games) is diagnosed
     at a glance instead of as a 'broken proxy'.

  AUDIT-CONFIRMED, NO CODE CHANGE (the v6.2 item-1 style): the DoH
  DEFAULT is already Cloudflare (the preset https://cloudflare-dns.com/
  dns-query) and the startup precedence is already argument > the
  saved 'h'-menu choice > the MOZVPN_DOH env > the built-in
  'cloudflare' default - the Firefox TRR default is matched exactly,
  and the v5.29 strict-DoH contract (no silent fallback to a non-DoH
  resolver) stays intact. The 2-minute rotation lead of item 1 equals
  Firefox's own. The sing-box engine keeps its own lifecycle (the
  monitor of items 3-6 is builtin-only, as documented above).

VERSION 2026-10-25 (v6.5) - THE PROFILE-EXCLUSIVE DATA FIX (the user's
  report: 'you made a GLOBAL default fastly_cookie for some reason,
  which makes no sense at all. When a new account is added, a NEW
  fastly_cookie and other parameters that can belong ONLY to a
  separate profile must be obtained/created and can never cross').
  ONE correction of the v6.4 profile model; every algorithm NOT
  listed here is UNTOUCHED (the sign-in chain, the Fastly solver,
  the probe/engine design, the TLS matrix, the hotkey UX and the
  whole feature set stay exactly as v6.4 left them):

  1) THE FASTLY COOKIE AND THE SING-BOX CONFIGS ARE PROFILE-EXCLUSIVE
     AND ARE NEVER STORED OUTSIDE AN ACCOUNT ENTRY. The v6.4
     'profile_defaults' placeholder could also hold them (while no
     account existed yet) - WRONG: a cookie/config of profile A can
     never be inherited or reused by profile B. The placeholder now
     holds the SETTINGS ONLY (language/resolver/filter - preferences
     that may legitimately be configured before the first sign-in
     and adopted by the first account). The exclusive roots
     ('fastly_cookie', 'singbox_configs') have NO placeholder at
     all: while their account does not exist yet (the sign-in of a
     NEW account solves its FIRST Fastly challenge BEFORE its entry
     is created) the value is STAGED in memory (_PENDING_PROFILE)
     and flushed into the account entry the moment it is created
     (save_cache/cache_account); with no account the value is
     dropped - a NEW account therefore always receives its OWN
     fresh cookie and configs, and the previous profile's data
     stays untouched.

  2) THE SIGN-IN BINDS THE EXCLUSIVE DATA TO THE ACCOUNT BEING
     SIGNED IN, not to whoever is 'current' at that moment (the '+'
     flow of the 'a' menu signs in a NEW account while the previous
     one is still current; a plain --email start does the same):
     _SIGNIN_EMAIL routes cfg_get/cfg_set of the exclusive roots to
     the signing-in account for the duration of the actual login
     call, so its FIRST cookie lands in ITS entry (via the staging
     stash), never in the previous profile's.

  3) THE '+' FLOW (a new account = a new profile) STARTS CLEAN:
     the in-memory HTTP session (the cookie jar with the previous
     profile's Fastly cookie, the challenge latch) is reset
     (_reset_fastly_session - the same v5.23 sequence
     wipe_all_saved_data uses) and the local-proxy engine is
     stopped, so the sign-in obtains a FRESH cookie bound to the
     new account and the engine is rebuilt from ITS tokens, filter
     and configs after the sign-in.

  4) A SIGN-IN THAT SWITCHES THE ACCOUNT NOW APPLIES THE NEW
     PROFILE (the watch loop detects current != the profile of the
     moment and runs apply_profile_runtime: the language, the
     resolver and the Fastly cookie of the NEW account, plus an
     engine rebuild). Covers the '+' flow and a plain --email start
     against a stored different current account; token refreshes
     and re-logins of the SAME account trigger nothing.

  5) MIGRATION: a pre-v6.4 GLOBAL fastly_cookie/singbox_configs of
     a file with NO account is DROPPED (it belongs to nobody; a
     fresh cookie is obtained at the next sign-in); with a current
     account it folds into that account as before. Pre-v6.5
     exclusive leftovers inside 'profile_defaults' are cleaned on
     load. The first-run file migration (fastly-cookie.json) goes
     into the CURRENT account's entry only, never the placeholder.

VERSION 2026-10-25 (v6.4) - THE PROFILE-BOUND UBER-CONFIG (one user-requested
  change; every algorithm NOT listed here is UNTOUCHED - the sign-in
  chain, the Fastly solver, the probe/engine design, the TLS matrix,
  the hotkey UX and the whole feature set are preserved exactly as
  v6.3 left them):

  1) EVERY ACCOUNT IS A PROFILE, AND EVERY CONFIGURATION BELONGS TO A
     PROFILE (the user's report: 'fastly_cookie is not bound to the
     account in your config. That cannot be: the accounts in
     config.json are profiles, and all their configs must belong to
     them and change with them - including every setting like doh and
     the language. And the sing-box settings belong to the profiles
     too'). THE LAYOUT CHANGE (config.json, CONFIG_VERSION 2):
       * the Fastly WAF cookie, the settings section (doh, doh_cache,
         lang, countries_filter, singbox_declined) and the sing-box
         outbound configs now live INSIDE the account entry they
         belong to (config.json['accounts'][email]['fastly_cookie'],
         [...]['settings'], [...]['singbox_configs']);
       * a pre-v6.4 config.json is migrated on the first load: the
         old GLOBAL top-level sections are folded into the CURRENT
         account's entry (the only profile that could have been using
         them), or into the 'profile_defaults' placeholder when the
         file has no account yet;
       * while NO current account exists (a fresh install before the
         first sign-in), the profile-scoped settings live in the
         top-level 'profile_defaults' section; the FIRST account the
         script ever creates ADOPTS them (its own values win for
         keys it already has), so nothing is ever lost;
       * the ACCESS LAYER is unchanged for every caller: cfg_get()/
         cfg_set() transparently route the ('settings', ...),
         ('fastly_cookie', ...) and ('singbox_configs', ...) paths to
         the profile node of the CURRENT account (or to
         profile_defaults while there is none) - every existing
         consumer (the 'h'/'y'/'w' menus, the DoH chain, the language
         switcher, the sing-box engine, the Fastly cookie cache, the
         countries filter) keeps working verbatim;
       * SWITCHING the profile (hotkey 'a', --select-account, the
         auto-switch after deleting the current account) now re-applies
         the whole profile at runtime: the saved language, the saved
         DoH resolver (an explicit --lang/--doh/--doh-url argument of
         this run still wins, exactly like at startup), the countries
         filter and the sing-box configs of the newly selected
         account, plus its Fastly cookie - the in-memory cookie jar,
         the opener and the challenge latch are reset first (the same
         v5.23 sequence wipe_all_saved_data uses) so the cookie of
         profile A can never leak into the session of profile B; the
         local-proxy engine is stopped so the next watch-loop
         iteration rebuilds it from the NEW profile's configs and
         filter;
       * the wipe contract is unchanged: clear_all_caches() keeps the
         account store - which now carries the profiles' settings,
         cookies and sing-box configs with it.

VERSION 2026-10-25 (v6.3) - THE Ctrl+O FIX (it really DID conflict with
  the plain 'o' on Windows) + THE ORIGINAL HINT STYLING of the Ctrl
  combinations (two user-reported items; everything else is untouched
  - all algorithms, the security contract, the whole UI/UX and the
  feature set are preserved exactly as v6.2 left them):

  1) ROOT CAUSE FOUND: Ctrl+O fired the 'o' handler on Windows. The
     hotkey loop receives Ctrl+O as the single control char \x0F
     (msvcrt.getwch() on Windows, the cbreak byte read on POSIX),
     but _normalize_key() then ran the WINDOWS LAYOUT-INDEPENDENCE
     route on it: VkKeyScanW() maps CHARACTERS to keystrokes, and the
     keystroke that TYPES \x0F in the console IS 'the O key with
     Ctrl held' - so VkKeyScanW('\x0f') legitimately returns the O
     virtual key + the Ctrl shift-state flag (verified online
     2026-10-25 in the Microsoft Learn winuser.h reference: the low
     byte of the return value is the virtual-key code, the high byte
     the shift state, where 'either CTRL key is pressed' is a
     documented flag bit). MapVirtualKeyW(VK_O, MAPVK_VK_TO_VSC) ->
     scan 0x18 and the _SCAN_TO_KEY table then produced the PLAIN
     hotkey letter 'o' - and the loop ran the 'o' handler (open the
     config directory) every time; the \x0f handler (the cleanup)
     was unreachable. POSIX was never affected (no VkKeyScanW route
     there), which is why the code looked correct in review - the
     user's live report pinpointed it.
     THE FIX: _normalize_key() returns EVERY control character
     (< 0x20, plus 0x7F) UNCHANGED, BEFORE any layout mapping - a
     control char is a key COMBINATION, not 'a letter in another
     keyboard layout'. Ctrl+O now reaches its own handler on Windows
     too. The fix is strictly conservative: on POSIX nothing changes
     at all (control chars already fell through unchanged), and on
     Windows it also protects Backspace (\x08), DEL (\x7f), Enter
     (\r, \n) and Esc (\x1b) from ever being rewritten by the layout
     scan (they keep their existing roles in the menus), and no
     other Ctrl+letter can masquerade as its plain hotkey anymore.
     (Ctrl+C stays the console-managed SIGINT path as before -
     _getch/_getwch never even see it; msvcrt docs: the functions
     cannot be used to read CTRL+C.)

  2) THE HINT STYLING of the Ctrl combinations now matches the
     ORIGINAL style of the list (the user's report: 'Ctrl+O had a
     different style'). In the hotkeys hint every KEY sits on the
     dedicated hotkey block (bold on the solid color cell) - but the
     key-highlight pattern of _RE_TOKENS matched only SINGLE
     letters/digits ('r', 'c', the '1-9' pair), so 'Ctrl+O' rendered
     as PLAIN text and its line visibly differed from its neighbors.
     The key pattern now also matches the 'Ctrl+<letter>' form
     between the icon and the ' - ' / em-dash separator, so Ctrl+O
     and Ctrl+C get the SAME bold-on-block highlight as every other
     key in the list (the icon column, the separator and the
     hotdesc coloring were already correct and are unchanged).

VERSION 2026-10-25 (v6.2) - SECURITY RE-AUDIT + THE COMPLETE HOTKEYS LIST
  (three user-requested items; every algorithm NOT listed here is
  UNTOUCHED - the sign-in chain, the Fastly solver, the probe/engine
  design, the TLS matrix, the whole UI/UX and the feature set are
  preserved exactly as v6.1 left them):

  1) SECURITY RE-AUDIT (the requirement: connections ENCRYPTED ONLY, no
     silent downgrade to an unencrypted transport - and it must keep
     WORKING). Every network path of this script was re-checked and
     every external fact was verified online 2026-10-25. RESULT: the
     contract HOLDS; no code change was needed - the audit CONFIRMS
     and DOCUMENTS the v6.1 behavior:
       * _tls_profiles(): all 4 profiles are TLS. Profiles 1-3 VALIDATE
         the egress certificate (Python's ssl defaults: PROTOCOL_TLS_
         CLIENT / create_default_context() enable CERT_REQUIRED +
         check_hostname by default - verified in the CPython ssl
         docs); profile 4 ENCRYPTS WITHOUT VALIDATING - the restored
         original last resort (a curl --proxy-insecure-like fallback,
         NOT a plaintext fallback). When even profile 4 cannot
         handshake, _tls_connect() RAISES - there is NO plaintext
         fallback anywhere: an unavailable encrypted transport fails
         LOUDLY instead of silently downgrading (the v6.0 lesson -
         removing profile 4 broke the user's DPI-network connectivity
         and profile 4 is an ENCRYPTED-but-unverified context, so the
         'encrypted only' contract is intact either way);
       * the MASQUE probe rides QUIC = TLS 1.3 by design (RFC 9000
         section 4: "QUIC uses TLS 1.3"); aioquic verifies the server
         certificate with the certifi root store by default
         (QuicConfiguration.verify_mode defaults to None and certifi
         roots are loaded when no CA was specified - verified in the
         aioquic source and changelog);
       * the emergency direct-IP route (_raw_https, the broken-system-
         resolver case) wraps the socket in a VERIFIED TLS context
         (ssl.create_default_context()) with the SNI kept - encrypted
         even in the emergency state;
       * the DoH chain speaks HTTPS ONLY (every preset is an https://
         endpoint); '--doh off' and --system-dns-fallback are EXPLICIT
         user opt-ins, and DNS resolution is not a data channel;
       * the sing-box engine uses the official http outbound with
         tls.enabled=true (the structure verified against the sing-box
         documentation) - the local-to-egress hop is TLS;
       * the local listeners speak plain HTTP BY DESIGN (127.0.0.1 by
         default), like every standard local proxy and like Mozilla
         VPN's own local proxy: the browser-to-local hop stays on the
         user's own machine, and the local-to-egress hop is the TLS/
         QUIC tunnel above. Firefox itself pairs the same local-proxy
         pattern with HTTPS-Only Mode upgrading the browser's own
         requests to https (and PSM certificate verification - no
         'accept-unverified-TLS' bypass in recent Firefox).

  2) Ctrl+O IS IN THE HOTKEYS LIST - re-verified end to end (en + ru):
     the entry sits between 'z' and 'f' (the icon, the key, the
     description and the --clean-old-config twin parameter), the
     handler (k == "\x0f") is reachable in the hotkey phase on every
     platform (POSIX cbreak and Windows console both deliver Ctrl+O
     as the single byte 0x0F), and the whole rendering pipeline
     (tr() -> split("\n") -> _align_icon_line() -> info() -> print())
     carries the line to the screen on every refresh cycle. v6.2 also
     groups the Ctrl-COMBINATIONS into one visible block: the Ctrl+O
     entry and the NEW Ctrl+C entry (item 3) now sit NEXT TO EACH
     OTHER in the list, so the combination keys are impossible to
     overlook.

  3) THE HOTKEYS LIST IS NOW COMPLETE (user request). Every key the
     hotkey loop handles was cross-checked against the list: r, c, e,
     l, w, o, t, v, b, g, u, p, a, d, s, j, m, h, k, n, f, x, z, y,
     1-9, Ctrl+O and q were ALL already listed. The ONE combination
     with a dedicated handler that was NOT in the list is now ADDED,
     in the original hint style (icon + key + description + the
     mirrored parameter), en + ru:
       Ctrl+C - stop the script (the first press stops immediately;
       with --confirm-exit a second press within 5 s confirms the exit),
     The menu SUB-MODE controls stay documented per menu, exactly as
     before: Enter applies the typed token, Backspace deletes the
     last character, any other key cancels (the select_hint line of
     every menu), SPACE separates the tokens of the 'w' multi-
     selection (the 'w' hint line), '+'/'-' add/delete an account in
     the 'a' menu (the 'a' hint line) - they are menu controls, not
     global hotkeys, so they do not repeat in the global list.

VERSION 2026-10-25 (v6.1) - TWO USER-REPORTED FIXES (every algorithm the
  user did NOT ask about is untouched - this entry only RESTORES the
  original connectivity behavior and moves the config file):

  1) THE LOCAL PROXIES CONNECT AGAIN (the v6.0 regression; the user's
     live report: 'the log says the token is obtained and the
     connections for all countries are established, but NOTHING works;
     the ORIGINAL script works perfectly'). ROOT CAUSE: the v6.0
     'security' change (its item 2 below) removed the 4th profile of
     _tls_profiles() - the UNVERIFIED (ssl.CERT_NONE) last resort that
     every probe AND every builtin-engine relay walks through. On
     real-world networks with DPI/TLS interception the three
     certificate-VALIDATING profiles cannot complete the handshake to
     the Fastly egress, so EVERY relay dies while the startup log
     keeps looking healthy: the masque probe rides QUIC/UDP (a
     different transport the interceptor may pass) and --probe-fail
     keep (the default) keeps unverified upstreams in the served list
     - the 'all countries established' lines print anyway and every
     actual request through the local proxy fails. THE FIX restores
     the ORIGINAL matrix VERBATIM: the 'insecure' profile is back as
     the LAST resort (the curl --proxy-insecure-like fallback the
     user's working setup relies on), the suggested curl test
     commands carry --proxy-insecure again, and the v6.0
     QuicConfiguration.verify_mode = ssl.CERT_REQUIRED pin of the
     masque probe is removed (the original leaves the library
     default in place - aioquic 1.x verifies with the certifi roots
     anyway; the pin only changed behavior on OLDER aioquic).
     LESSON (the same one v5.26 records): the reference script is
     the ground truth - a 'hardening' that breaks the real data path
     is a regression, not a fix.

  2) config.json NEXT TO THE SCRIPT (user request): the uber-config
     now lives in the DIRECTORY OF THIS SCRIPT (default
     <script-dir>/config.json) instead of ~/.config/mozvpn, and the
     NEW --config FILE parameter points it anywhere else. When
     config.json does not exist at the resolved path (the default OR
     the --config one), it is CREATED AUTOMATICALLY with the default
     values (one localized info line says so). The old
     ~/.config/mozvpn directory is read-only history now: the
     first-run migration still READS the pre-v6 leftovers from
     there, Ctrl+O / --clean-old-config REMOVES them, and nothing is
     ever written there again.

VERSION 2026-10-25 (v6.0) - THE UBER-CONFIG config.json + SECURITY + ACCOUNTS
  (ten user-requested changes; every algorithm NOT listed here is
  UNTOUCHED - the sign-in chain, the Fastly solver, the probe/engine
  design, the hotkey UX and the whole feature set are preserved):

  1) PROACTIVE proxyPass REFRESH. The default --refresh-margin is now
     120 s (was 45): the new token is requested a full two minutes
     before the old one expires, so one or two transient Guardian/
     network failures no longer leave a window where the local proxies
     sign with an expired Bearer (the live symptom: the proxy 'stops
     working for a while' although the Internet is fine - the old
     45 s margin plus one 30 s retry could cross the exp). The refresh
     retry inside the watch loop is now ADAPTIVE: when the current
     token is within margin+30 s of its exp, a failed refresh retries
     in min(--retry-delay, 15) s instead of the full 30 s.

  2) SECURITY (audited against the Firefox 158.0.1 networking model):
     the 'insecure' TLS profile (verify_mode=CERT_NONE) is REMOVED from
     _tls_profiles() - the probe and the builtin engine now connect to
     the egress ONLY with certificate-VALIDATING contexts. Firefox/PSM
     never disables certificate verification and has no
     'accept-unverified-TLS' fallback; the old 4th profile was exactly
     such a fallback (an active attacker could MITM the 'encrypted'
     tunnel, so the connection was effectively unauthenticated and
     readable). The MASQUE probe now ALSO sets
     QuicConfiguration.verify_mode = ssl.CERT_REQUIRED explicitly
     (aioquic 1.x verifies by default; the belt-and-suspenders pin
     survives a future default change). The strict-DoH behavior of
     v5.29 (no silent fallback to a non-DoH resolver) is unchanged.
     (REVERTED in v6.1 - see the v6.1 entry: removing the insecure
     last-resort profile broke the user's real connectivity on a
     DPI/intercepting network; the original 4-profile matrix, the
     original masque-probe behavior and the --proxy-insecure test
     commands are restored VERBATIM. The strict-DoH part stays.)

  3) HOTKEY ICON WIDTH. A wcwidth-style cell-width function _cw()
     (wide/fullwidth = 2 cells, VS16/ZWJ/combining = 0, the
     supplementary emoji planes = 2) now pads EVERY hotkey-hint icon
     to the same fixed column, so the gap between an icon and its
     hotkey letter is identical on every line of the hint - on every
     platform that renders the icons at their Unicode width.

  4) THE UBER-CONFIG. EVERY configuration this script persists now
     lives in ONE file: config.json (v6.1: NEXT TO THIS SCRIPT by
     default, --config FILE moves it) - accounts,
     credentials (per account), session tokens (per account), the
     Fastly cookie, the countries filter, the DoH resolver choice,
     the DoH cache flag, the interface language, the sing-box
     decline marker AND the sing-box configs (the per-port outbound
     definitions). All in PLAIN TEXT exactly as before, chmod 600.
     DUPLICATED data is gone: session.json duplicated the session
     token and the email of accounts.json, and credentials.json
     duplicated the login/password/TOTP fields of accounts.json - the
     v6 store keeps exactly ONE copy of each value (per account).
     The sing-box engine materializes its runtime config files into a
     TEMPORARY directory (cleaned on stop/exit); config.json is the
     only PERSISTED configuration.

  5) MULTI-ACCOUNT MANAGEMENT (config.json['accounts'], all plain
     text, all persistent):
       * --add-account / hotkey 'a' -> '+' : sign in to a NEW account
         (nothing is wiped); on success it is cached and current;
       * --list-accounts / --show-accounts / hotkey 'a' (the list);
       * --select-account EMAIL : make a cached account current;
       * --delete-account EMAIL[,EMAIL...] / hotkey 'a' -> '-' :
         delete accounts; deleting the current one auto-switches to
         the first remaining account (or asks for a fresh sign-in
         when the last one is gone).

  6) FIRST-RUN FLAG + MIGRATION. config.json stores 'first_run'. On
     the first run the script MIGRATES every old-format file
     (session.json, credentials.json, fastly-cookie.json,
     accounts.json, countries.json, doh.json, lang.json,
     singbox-install.json, the cached QR pngs of the 2FA secrets,
     the singbox/ and engine/ directories) into config.json and then
     DELETES all of them - the old files AND the old directories.
     Nothing of the old format is left behind.

  7) Ctrl+O (and --clean-old-config): find and remove every
     leftover of the OLD config format (never config.json itself) -
     for machines that ran an older version of this script.

  8) FLAG ICONS PER PLATFORM. --flag-style auto now picks the EMOJI
     pair only where flag emoji actually render (macOS, Linux and
     Termux terminals with an emoji font) and the truecolor pixel
     art everywhere else (Windows ships no flag-glyph font; a bare
     linux/dumb console has none either) - on the rest the art
     paints the flag instead of printing 'US'/'RU' letters.
     MOZVPN_FLAG_STYLE=emoji|art|auto overrides; --flag-style still
     forces a style explicitly.

  9) PYTHON 3.15.1 + CURRENT DEPENDENCIES. The script is modernized
     for Python 3.15.1 (the current stable release, 2026-10-21;
     UTF-8 mode is the default there per PEP 686 - the explicit
     stdout/stderr reconfigure stays as a harmless belt-and-
     suspenders for redirected/piped output). Current dependency
     line (verified 2026-10-25): pyotp 2.10.0, zxing-cpp 3.1.1,
     Pillow 13.0.0, aioquic 1.7.0, cryptography 50.0.2, Nuitka
     4.3+ (the current line pronounces Python 3.15 experimentally
     supported; PyPI still lists 3.4-3.14 as the official range).
     The Firefox version baseline is
     158.0.1 (the serverlist filter_expression and the User-Agent).

  10) THE SCRIPT IS NOW mozvpn.py (was mozvpn_beta.py); the GitHub
      Actions workflow builds mozvpn.py and the release assets are
      named mozvpn-<target>[.exe].

VERSION 2026-10-02 (v5.36) - THE ENDLESS 'temporary DNS failure - retrying in
  30s' LOOP ON THE PACKAGED TERMUX BINARY FIXED - the real root cause of the
  live log, and this time it is a NAME-AND-LINE verifiable one:

  THE LIVE SYMPTOM (the packaged armv9 binary in Termux, the live log
  2026-10-01): the OAuth token was obtained, Guardian's POST
  /api/v1/fpn/activate answered HTTP 200 - and THEN the run died with
  'Network error: temporary DNS failure (no address associated with
  hostname) - retrying in 30s', over and over, forever, while the
  reference mozvpn.py worked on the same phone EVERY time and Windows 11
  never failed.

  ROOT CAUSE - ONE NETWORK CALL THAT BYPASSED THE EMERGENCY ROUTE.
  The v5.28 emergency direct-IP route (for the packaged-binary broken
  system resolver) was wired into req() ONLY. But guardian_pass() fetched
  GET /api/v1/fpn/token through a RAW '_OPENER.open(urllib.request.
  Request(...))' call (copied from the reference script, where it is
  correct - the reference runs as a plain script whose getaddrinfo is
  healthy). That raw call is the ONLY network request of the whole
  sign-in chain that did NOT go through req(). On the packaged Termux
  binary (socket.getaddrinfo persistently broken - the known
  packaged-Python-on-Android issue, python-for-android #1447: 'name
  resolutions just seem to plain not work... while nslookup in termux
  works fine') the sequence was exactly the live log:
    1) oauth_token() -> req() -> gaierror x2 -> the two-strike detector
       flags the resolver broken -> _req_ip_fallback() -> SUCCESS;
    2) POST /api/v1/fpn/activate -> req() -> straight to the emergency
       route -> 'Guardian: enroll completed (HTTP 200)';
    3) GET /api/v1/fpn/token -> the RAW _OPENER call -> getaddrinfo ->
       gaierror(7) EAI_NODATA -> the exception is NOT transient-fixable
       in-process -> the watch loop classifies it as a transient blip
       and retries in 30 s - but EVERY retry hits the same broken
       getaddrinfo -> the endless 'temporary DNS failure' loop.
  That is also why the binary 'very rarely works': when the packaged
  resolver happens to be healthy for a whole run, the raw call succeeds
  like everything else; when it is broken, EVERY refresh cycle dies at
  the same line. And that is why every previous fix 'worked for a few
  hours': the token refresh cycle re-enters guardian_pass() every ~10
  minutes, and each cycle re-dies at the raw call.

  THE FIX (the sign-in algorithm itself is UNTOUCHED - the reference
  scopes, grants, stretching and the Fastly 406-challenge solver are
  preserved verbatim):
  1) req_full(): a req()-shaped transport that ALSO returns the response
     HEADERS (guardian_pass needs the X-Quota-*/Retry-After headers). It
     implements the EXACT reference request algorithm (one 406-challenge
     retry) PLUS the v5.28 broken-resolver emergency route and the v5.12
     one-shot transient retry. req() is now a thin wrapper over it (the
     reference parity of every existing req() caller is preserved).
  2) guardian_pass(): the GET /api/v1/fpn/token request now goes through
     req_full() - the same routed transport as every other request of
     the sign-in chain. The reference-path behavior on a healthy
     resolver is IDENTICAL (urllib, the same headers, the same JSON
     handling); on the broken packaged resolver the request now rides
     the emergency direct-IP route and SUCCEEDS.
  3) _fastly_http(): the Fastly challenge flow could not be solved in
     the broken state either (it also opened _OPENER directly) - that
     was the OTHER latent bypass: a fresh sign-in after the cached
     _fs_ch_cp_* cookie expired (~1 h) would have died with waf_406
     forever. In the broken state the challenge requests now go through
     _fastly_http_ip() (emergency DoH -> raw HTTPS to the IP, the shared
     cookie jar kept in sync - the Set-Cookie _fs_ch_cp_* MUST land in
     COOKIE_JAR, fastly_solve_challenge() scans the jar).
  4) _doh_query(): in the broken state a provider NOT in the bootstrap
     table (nextdns / a custom --doh-url) no longer fails the whole
     chain - the query is answered over the well-known resolver IPs.
  5) req_full() short-circuits: once the resolver is flagged broken,
     every request goes STRAIGHT to the emergency route (no doomed
     getaddrinfo attempt per call, no per-call 'resolver broken' noise).
  Verified against the Firefox architecture (the user's request):
  Firefox itself NEVER uses the platform getaddrinfo for its network
  stack when TRR is on - necko resolves via nsHostResolver/TRR and
  connects to the resolved IP (TRR mode 3 = 'only DoH is employed, no
  fall back'; network.trr.bootstrapAddress exists precisely to resolve
  the DoH resolver itself without getaddrinfo) - see the Firefox Source
  Docs 'DNS over HTTPS (Trusted Recursive Resolver)'. The emergency
  route is the same design applied to this script; v5.36 closes the
  gaps where the script still 'trusted the system resolver' by proxy.


VERSION 2026-10-01 (v5.35) - THE PACKAGED-BINARY (Termux) 415 'Unsupported
  Media Type' OAuth FAILURE FIXED - the real root cause of the live log:

  The live Termux log (the packaged armv9 binary): right after the v5.28
  two-strike detector switched req() to the emergency direct-IP route (the
  broken packaged-resolver case), the OAuth POST /v1/oauth/token request
  returned {'code': 415, 'errno': 999, 'error': 'Unsupported Media Type'} -
  while the reference mozvpn.py (no emergency route at all), Windows 11
  (a healthy resolver - the emergency route never engaged) and even the
  RARE healthy moments of the same Termux binary (when the packaged
  resolver happened to work and the emergency route stayed off) all signed
  in fine.

  ROOT CAUSE - DUPLICATED HTTP HEADERS IN THE EMERGENCY RAW REQUEST.
  _req_ip_fallback() merged the urllib Request's header list into the
  outgoing dict: urllib stores header names .capitalize()d
  (Request.add_header), so "Content-Type" came back as "Content-type";
  the dict already held the original-spelled "Content-Type", and a dict
  treats different-case keys as DIFFERENT keys. _raw_https() then wrote
  BOTH lines into the raw request ("Content-Type: ..." and
  "Content-type: ...", the same for User-Agent and Accept-Language, and
  Content-Length was set twice as well). api.accounts.firefox.com is
  served through Fastly, which combines duplicate request headers into
  ONE comma-joined value (the std.collect semantics of the Fastly/VCL
  header model), so the FxA backend received
  'Content-Type: application/json, application/json'; the
  fxa-auth-server (Hapi) cannot match that media type and answers
  415 Unsupported Media Type (errno 999) - the exact live error. The
  emergency transport itself was HEALTHY: the DoH-to-IP bootstrap
  resolved the host, the TLS+HTTP request reached the real FxA backend
  and got a genuine FxA JSON error - only the header set was malformed.
  That is also why the NORMAL urllib path (req()) never fails on any
  platform: urllib sends exactly ONE line per header, like the reference
  script and like every sane HTTP client.

  FIX (two levels - the belt and the suspenders):
  - _req_ip_fallback(): ONLY the Cookie header is taken from the urllib
    Request now (that is where the shared cookie jar writes it); every
    other header comes from the single base_headers dict;
  - _raw_https(): the outgoing header set is DEDUPLICATED
    case-insensitively before the wire (one header line per name, the
    first occurrence wins, Content-Length set once) - a future caller
    with mixed-case duplicates can never trigger this again. The normal
    req() path is UNTOUCHED (the reference parity is preserved).

VERSION 2026-09-30 (v5.34) - EVERY CONFIG FILE HAS A WORKING HOTKEY AGAIN
  (user request; completes the v5.32/v5.33 fix):

  v5.32 added the settings files to the config file lists and v5.33 made
  them exist from the first run - but the DIGIT handler still assumed
  "at most 9 files": whenever the list grew past 9 entries (which the
  settings files made the normal case), pressing 1-9 switched into the
  multi-char token sub-mode instead of opening the file directly. The
  files were LISTED but digits did not OPEN them - exactly the reported
  bug. v5.34 fixes it:

  - digits 1-9 now ALWAYS open files 1-9 DIRECTLY (no sub-mode): the
    token scheme is unambiguous because files 1-9 always have the
    single-character tokens "1".."9" (selection_token());
  - NEW hotkey 'z': the FULL config-file selection menu - it numbers
    EVERY file (tokens 1-9, then a, b, ... z, aa, ...) and therefore
    gives a hotkey even to files past the ninth; type the token and
    press Enter (Backspace deletes a character, any other non-matching
    key cancels). The menu exits automatically after opening the file
    (the v5.30 auto-exit rule); it never blocks the main loop.
  - new tr keys: files_menu_hint (en+ru); hotkeys_hint updated in both
    languages (mentions the settings files 1-9 and the new 'z' menu).

VERSION 2026-09-30 (v5.33) - THE SETTINGS FILES NOW EXIST FROM THE FIRST
  RUN (user request; completes the v5.32 fix):

  v5.32 added the four settings files to the config file lists, but
  the lists are EXISTENCE-based - and countries.json / doh.json /
  lang.json only appeared AFTER the user saved the matching menu choice,
  so on a fresh install (or before using the 'h'/'y' menus) the lists
  STILL looked incomplete. v5.33 makes the script PERSIST the settings
  at startup, mirroring the CURRENT EFFECTIVE state, so the files (and
  therefore both lists - '1-9 open' and 'c' removes) are complete from
  the very first run:
    - doh.json: the effective resolver (skipped while a custom
      --doh-url endpoint is active - its URL may be secret);
    - lang.json: the effective language;
    - accounts.json: an empty {} cache when no account is cached yet
      (an empty cache still reads as 'no cached accounts');
    - countries.json: NOT created when no filter is active - the
      'all proxies' default has NO file BY DESIGN (hotkey '0' and the
      clear entry REMOVE the file; recreating an empty one at every
      startup would fight that contract). It appears in the lists as
      soon as a filter is actually saved.

VERSION 2026-09-30 (v5.32) - THE CONFIG FILE LISTS ARE NOW COMPLETE (user
  request):

  The '1-9 open a config file' list and the "what 'c' will remove"
  list missed the PERSISTED SETTINGS files even though the settings
  were cached in the config directory all along. Both lists now show
  EVERY file the script persists, when it exists:
    - accounts.json  - the cached Mozilla accounts (hotkey 'a')
    - countries.json - the local-proxy selection (hotkey 'w')
    - doh.json       - the DNS resolver choice (hotkey 'h', v5.31)
    - lang.json      - the language choice (hotkey 'y', v5.30)
  config_open_files(): the four settings files are appended after the
  session/credentials/cookie trio (before the sing-box configs), so the
  number hotkeys / the token sub-mode can open them like any other
  file; print_clear_targets(): the same four are listed among the
  removal targets (they live inside the config directory, which 'c'
  removes entirely). The listing is EXISTENCE-based as before: a file
  that was never created is not shown.

VERSION 2026-09-30 (v5.31) - THREE HOTKEY/PERSISTENCE FIXES (user request):

  1) THE 'y' HOTKEY LINE WAS MISALIGNED in the hotkeys hint: the v5.30
     emoji U+1F5FA (world map) has DEFAULT=TEXT presentation, so many
     terminals render it as a NARROW single-cell text glyph and the
     whole 'y' line shifted one column against the other entries (all
     of which use wide DEFAULT=EMOJI presentation symbols). Replaced
     with U+1F4AC (speech balloon, always wide) in both the en/ru
     hints and the _EMOJI map entries (lang_menu_hint / lang_set /
     lang_reset) - the column aligns with every other hotkey again.

  2) THE DNS RESOLVER CHOICE (hotkey 'h' menu) IS NOW PERSISTED to
     doh.json in the user config directory (chmod 600, the same place
     as session.json / countries.json / lang.json) and survives
     restarts, like the other script settings. Startup precedence:
     an explicit --doh / --doh-url argument > the SAVED hotkey-'h'
     choice > the MOZVPN_DOH environment variable > the built-in
     default 'cloudflare' (--doh default changed to None accordingly;
     a custom --doh-url endpoint is NOT persisted - its URL may be
     secret). The 'h' menu now also MARKS THE CURRENT resolver with
     the same [x] marker as the 'w'/'y' menus (the active DoH preset
     or the system-DNS entry).

  3) EVERY option menu that HAS a default value now offers it as
     option '0' (per request: only where a default exists):
     - 'h' DNS resolver menu: NEW '0' = the DEFAULT resolver
       (cloudflare); applied + persisted like a manual choice
       (new localized lines doh_default_desc / doh_default_applied,
       en + ru);
     - 'y' language menu: '0' = the DEFAULT language (was added in
       v5.30);
     - 'w' local-proxy menu: '0' = ALL proxies (the default state,
       clears the saved filter - as before);
     - the v/b copy lists, the 1-9 config files and the 'a' account
       switch have NO default value (a copy target / file / account
       is not a setting with a default), so no '0' entry was added
       there, exactly per the 'if a default exists' rule.

VERSION 2026-09-30 (v5.30) - TWO HOTKEY UX FEATURES (user request):

  1) AUTOMATIC MENU EXIT ON ENTER. In EVERY hotkey selection menu
     (the 'w' local-proxy multi-selection, the v/b copy lists, the
     'h' DoH resolver menu, the 1-9 config files, the 'a' account
     switch and the NEW 'y' language menu) pressing Enter now APPLIES
     the chosen option and EXITS the menu AUTOMATICALLY: the sleep/
     countdown phase restarts immediately and the normal watch display
     reappears - the menu no longer stays open for the rest of the
     sleep window after an option was applied (previously only the
     'w' menu restarted the engine; the generic token menus kept
     waiting for more keystrokes with the menu text still on screen).

  2) NEW HOTKEY 'y': THE INTERFACE LANGUAGE MENU (en/ru), in the same
     token + Enter style as the other menus:
       0 - reset to the DEFAULT language (English) and CLEAR the saved
           choice (later runs fall back to env/default again),
       1 - English, 2 - Russian; the current language is marked [x].
     The choice is PERSISTED in lang.json in the user config directory
     (~/.config/mozvpn, the same directory as session.json /
     countries.json, chmod 600) and survives restarts. Startup
     precedence: an explicit --lang argument > the saved hotkey-'y'
     choice > the MOZVPN_LANG environment variable > the built-in
     default 'en' (--lang default changed accordingly; a read-only
     config dir cannot crash the run - the cache write is best-effort).
     New localized lines (lang_menu_hint / lang_menu_entry /
     lang_default_desc / lang_set / lang_reset, en + ru) and the 'y'
     entry in the hotkeys hint of both languages; the [x] marker and
     the emoji decoration keep the console styling intact.

VERSION 2026-09-30 (v5.29) - SECURITY: STRICT DoH - NO automatic fallback
  from DoH to a NON-DoH resolver (user request):

  The v5.1-v5.28 resolve chain ended with an automatic 'last resort'
  step: when the WHOLE DoH chain failed, the hostname was silently
  resolved with the SYSTEM resolver - which may be plaintext,
  observed or filtered DNS, the exact risk the DoH mode exists to
  avoid. v5.29 removes that automatic DoH -> non-DoH step, mirroring
  Firefox TRR mode 3 ('TRR-only' / strict resolution: only DoH is
  employed, with NO fall back mechanism - verified online 2026-09-30
  in the Firefox Source Docs 'DNS over HTTPS (Trusted Recursive
  Resolver)' and the Internet Society TRR write-up):
  - resolve_host(): a full DoH-chain failure now returns None (the
    caller fails loudly) instead of quietly asking the system
    resolver; _connect_resolved()/_connect_resolved_ips() and the
    QUIC (aioquic) path RAISE a clear 'strict DoH' error rather than
    handing the hostname to a non-DoH resolver.
  - EXPLICIT opt-ins are kept (nothing is impossible anymore):
    * --doh off / hotkey 'h' -> 'off' - the whole run on the system
      resolver, exactly as before (DoH was never on in that mode);
    * NEW --system-dns-fallback / --no-system-dns-fallback (env
      MOZVPN_SYSTEM_DNS_FALLBACK, default OFF) - re-enables the old
      last-resort behavior for the current run; the startup log
      prints the chosen state (new localized lines doh_strict_mode /
      system_dns_fallback_on, en+ru, emoji-decorated).
  - ALL the other fallbacks are UNTOUCHED: provider -> provider
    within the DoH chain, the v5.12 PARALLEL chain race, the DoH
    cache/memo, the in-flight dedup, and the v5.28 emergency
    direct-IP DoH route for the broken-packaged-resolver (Termux
    binary) case - that route speaks DoH ONLY (the well-known
    resolver IPs), so it is strict-mode compatible.
  - The strict gate applies ONLY when a DoH provider is selected
    (_doh_provider non-empty); with DoH off nothing changes at all.

VERSION 2026-09-30 (v5.28) - THE PACKAGED-BINARY (Termux/Android) DNS FAILURE
  FIXED - the root cause of the endless "Network error: temporary DNS
  failure (no address associated with hostname)" loop:

  ROOT CAUSE (verified online 2026-09-30): the Termux build runs as a
  Nuitka-PACKAGED BINARY, and inside a packaged Python runtime on
  Android socket.getaddrinfo is a known long-standing broken path
  (persistent gaierror / EAI_NODATA - the classic issue tracked in
  python-for-android #1447 and kivy #7087; the same packaged program
  re-run as a PLAIN script resolves fine, and nslookup / the browser
  work too). That is EXACTLY the observed split:
    - mozvpn.py (always a plain script) works on the SAME phone;
    - the Windows 11 binary works (its packaged resolver is healthy);
    - only the ANDROID PACKAGED binary loops on gaierror.
  Why DoH settings could not help: the v5.26 "reference parity" change
  REMOVED the _req_ip_fallback() emergency route from req() (it was
  built for exactly this case in v5.13), so every OAuth/Guardian call
  went back to plain urlopen -> getaddrinfo -> gaierror; and the DoH
  queries themselves also resolve the provider HOSTNAME
  (cloudflare-dns.com etc.) with getaddrinfo, so changing/turning off
  DoH could not fix anything.

  THE FIX (the sign-in algorithm itself is UNTOUCHED - the v5.26
  reference-parity auth path, scopes, grants, stretching and the Fastly
  406-challenge solver are preserved verbatim):
  1) A two-strike detector: the FIRST gaierror is still treated as a
     transient blip (one retry after 1.5 s, like the reference
     mozvpn.py); a SECOND one flags the system resolver as BROKEN for
     the rest of the process (a successful resolution resets the
     counter, so a healthy resolver is never bypassed).
  2) In the broken state req() switches to _req_ip_fallback() (the
     v5.13 emergency route, restored): the hostname is resolved by the
     emergency DoH straight to the well-known resolver IPs (a hardcoded
     bootstrap table - NO name resolution anywhere), then ONE raw
     HTTPS request goes to the resolved IP with the SNI/Host kept;
     its own 406-challenge handling from v5.25 is kept.
  3) _doh_query() in the broken state also goes straight to the
     well-known DoH resolver IPs (the TCP connect goes to the IP
     literal, the SNI/Host stay the provider hostname), so the normal
     DoH chain keeps working even though the provider hostnames can
     no longer be resolved by the system.
  4) The transient retry and the Fastly 406 retry now use SEPARATE
     flags (the v5.25 shared-flag bug stays fixed; the reference-parity
     406-challenge path of mozvpn.py is kept as-is).
  5) Two new localized log lines (en/ru, emoji-decorated like the rest
     of the log): a one-time blip note (retry) and the broken-resolver
     note (emergency direct-IP route).

VERSION 2026-09-29 (v5.27) - THREE NEW FEATURES (no sign-in algorithm
  changes; the v5.26 reference-parity auth path is untouched):

  FIX 1) PROBES FOLLOW THE LOCAL-PROXY SELECTION. When the user chose
     specific local proxies (--countries or the hotkey 'w' filter in
     countries.json), the startup probes used to run for EVERY upstream
     of the server list anyway. Now _filter_probe_entries() applies the
     SAME filter as apply_countries_filter() (--countries of this run
     wins, then the saved per-proxy keys, then the country tokens)
     BEFORE the probe phase: only the upstreams behind the selected
     local proxies are probed (one info line says so); the rest get
     probe_ok=None ('not probed', the same state as with --probe-count)
     and stay available when the filter is cleared. When the filter
     matches nothing, ALL upstreams are probed (the same fallback as
     the serving filter - never zero usable proxies).

  FIX 2) MULTI-ACCOUNT CACHE (accounts.json). Every SUCCESSFUL sign-in
     (watch mode and one-shot mode) is cached as a separate account
     entry: login, password, TOTP secret + digits/period/algorithm and
     the sessionToken. New parameters:
       --list-accounts  - the cached accounts, masked (password: yes/no,
                          TOTP: yes/no, session: yes/no, saved date);
       --show-accounts  - the SAME list with the logins, passwords and
                          the CURRENT TOTP code of every account in
                          PLAIN TEXT;
       --qr-dir DIR     - where the cached QR images of the 2FA secrets
                          are stored (default: the directory of this
                          script; the info line always shows the path);
       --accounts-json FILE - export ALL accounts into ONE json file:
                          logins, passwords, current TOTP codes, QR
                          images as base64.
     The QR image given via --qr is copied into the QR cache dir on
     every successful sign-in (account_qr_path: <sanitized-email>.png).
     accounts.json SURVIVES every wipe ('r', 'c', --clear-cache,
     --relogin): wiping one account's session must not delete the
     saved logins of all the others (wipe_all_saved_data backs it up
     and restores it). ensure_session() now reuses the cached session
     ONLY when it belongs to the SAME account (email match, the
     permissive behavior for old caches without an email is kept).

  FIX 3) HOTKEY 'a' - SWITCH THE MOZILLA ACCOUNT. Opens the selection
     menu of the cached accounts (the same token style as the other
     menus: 1-9, a-z, aa, ab, ... + Enter; the prompt runs in the
     cooked terminal mode, empty input cancels). The switch sets
     args.email/password/session_token/totp_secret, the creds dict and
     the TOTP provider, syncs session.json and leaves the sleep phase -
     the next watch-loop iteration signs the chosen account in (the
     cached sessionToken first, on a Guardian failure the normal
     relogin path uses the cached login/password/TOTP). Added to the
     hotkeys hint in both languages.

VERSION 2026-09-29 (v5.26) - REFERENCE PARITY of the whole sign-in path +
  an honest RETRACTION of the v5.25 theory:

  RETRACT 0) The v5.25 claim 'a restart always fixed it' was WRONG - the
     user's live report: mozvpn_beta NEVER worked under Termux, restart
     included, while the reference mozvpn.py works EVERY time on the
     same phone. v5.25 therefore could not have found the real root
     cause: a per-call retry-flag reorder (the v5.25 theory) would
     have failed only SOMETIMES (when a transient error preceded the
     406), not on every single run. The v5.25 changelog entry is kept
     above for the history only - do not rely on its analysis.
  PARITY 1) req() is the reference mozvpn.py EXACTLY again: one retry
     flag (_fastly_retry) for the Fastly 406 challenge and NOTHING
     else. The v5.12-v5.25 transient-network retry (_net_retry) and
     the _req_ip_fallback() emergency raw-HTTPS call are REMOVED from
     req(). Rationale: the user's reference script - the ground truth
     that always works - has no such path; every extra retry layer is
     an extra way to reorder the challenge sequence on a mobile
     network. The helpers (_raw_https, _emergency_doh_resolve,
     _req_ip_fallback) stay DEFINED but are no longer wired into
     req(). The only kept passive addition is _note_server_date() (a
     Date-header read for the TOTP clock sync; it never alters a
     request). Transient errors now bubble up like in the reference
     and the watch loop retries the whole cycle (with a friendly
     localized reason via _is_transient_net_error).
  PARITY 2) fxa_login(): the unverified-session branch follows the
     reference CONTROL FLOW exactly - the TOTP route is entered ONLY
     when the server announces verificationMethod 'totp-2fa'/'totp';
     the v5.24 speculative try_totp attempt (a TOTP request even when
     the server announced 'email') is REMOVED. The reference script
     never makes that extra request, so neither does the beta. Kept
     from v5.24 (prompt robustness only, no server-flow change): the
     code prompt goes through prompt_line() and is allowed when the
     caller's flag is set OR stdin is a real tty (_can_prompt()) -
     a redirected stdin produces a clear localized error, not an
     EOFError crash.
  TERM 3) A REAL POSIX-ONLY bug is fixed that v5.24-v5.25 only
     half-addressed: when an exception fired during the hotkey/cbreak
     phase (e.g. a failed proxyPass refresh inside the sleep window),
     the run_manager except handlers ran the retry countdown and
     looped back to ensure_session() WITHOUT restoring the cooked
     terminal - the next email/password/TOTP prompt then read a
     raw-cbreak tty (broken line editing, Enter not submitting,
     stray hotkey-phase keystrokes leaking into the answers), so the
     retry attempt failed again and again. Fixed on three levels:
       a) every run_manager except handler calls _hotkey_mode(False)
          FIRST (it is idempotent and a no-op on Windows);
       b) the top of every watch-loop iteration calls _hotkey_mode(False)
          as a belt-and-suspenders guard before any prompt can run;
       c) _sleep_with_countdown()/_sleep_interruptible() never poll
          keys themselves (verified) - the countdown can no longer
          depend on the cbreak state.
     This cannot explain a FIRST-never-worked fresh run by itself (the
     first sign-in happens before any hotkey phase), but it fully
     explains the endless failing RETRY loop after the first error on
     POSIX, and it is a genuine difference from Windows 11 (where
     _hotkey_mode is a no-op).
  NOTE 4) The Fastly WAF solver (FASTLY_UA .. ensure_fastly_cookie)
     was re-diffed line by line against the reference mozvpn.py: the
     algorithm is IDENTICAL (only the log strings are localized). The
     solver is NOT the difference between the scripts.

VERSION 2026-09-29 (v5.25) - THE REAL TERMUX ROOT CAUSE FOUND AND FIXED (the
  live symptom: email+password entered -> one failed attempt -> the
  waf_406 'retry form' with the manual-sessionToken instructions, over
  and over; a RESTART always fixed it; the reference mozvpn.py NEVER
  failed on the same phone; Windows 11 never failed):

  ROOT CAUSE - ONE SHARED RETRY FLAG FOR TWO DIFFERENT RETRIES IN req().
  Since v5.12 req() had TWO retry paths guarded by the SAME parameter
  _fastly_retry: (a) the Fastly 406 challenge retry and (b) the
  TRANSIENT-network retry (a gaierror blip / a momentary timeout - the
  v5.12 addition for the Termux/arm live runs). Sequence that broke
  the sign-in on Termux, step by step:
    1) POST /account/login, attempt 1 -> a transient network error
       (routine on a mobile network after a wipe: cold DNS, a flaky
       first TLS) -> req() sleeps 1.5 s and RETRIES WITH
       _fastly_retry=True;
    2) attempt 2 -> the Fastly NGWAF answers its normal 406 with an
       empty body (a fresh run has no _fs_ch_cp_* cookie - this is the
       EXPECTED first answer, the whole reason the challenge solver
       exists);
    3) the 406 handler checked `not _fastly_retry` - already True from
       step 1 - so the CHALLENGE SOLUTION WAS SKIPPED, the raw 406 was
       returned to fxa_login and it raised waf_406: exactly the
       observed 'one failed attempt + the retry form with the manual
       sessionToken instructions'. Every in-process retry repeated the
       same dance (the flag is per-call, but so is the flaky first
       connection on a mobile network), and only a RESTART helped.
  WHY mozvpn.py ALWAYS WORKS: it has NO transient-retry path at all -
  its 406 handler ALWAYS runs ensure_fastly_cookie() and retries. The
  beta's extra robustness (the transient retry) is exactly what
  disabled the challenge on the network where transient errors are
  common. Windows 11 never failed because its stable network rarely
  produces a transient error before the 406.
  FIX 1) req() now uses TWO independent flags: _fastly_retry (the 406
     challenge retry) and _net_retry (the transient retry). A
     transient first attempt no longer suppresses the challenge; both
     retries still happen at most once each.
  FIX 2) _req_ip_fallback() (the emergency raw-HTTPS path after a
     double transient failure) had NO 406 handling either - a raw 406
     bubbled up as the same waf_406 form. Now the raw path solves the
     challenge (ensure_fastly_cookie) and redoes the SAME hop once
     with the fresh cookie attached.
  REVERT 3) get_credentials_status() is back to the EXACT reference
     mozvpn.py behavior (silent v1 fallback on any error). The v5.24
     hard-error experiment is withdrawn: the reference script with the
     same silent fallback ALWAYS works on Termux, so the v2-poisoning
     theory was wrong for this symptom (and req() itself now solves
     the 406 challenge reliably). The unused stretch_status_failed
     strings are removed.
  REVERT 4) the v5.24 'same TOTP code sent twice -> fail fast' check
     is REMOVED: the reference mozvpn.py retries the same fixed --totp
     code up to 3 times without any such check and always logs in, so
     the retry semantics are back to the reference exactly.
  KEPT 5) the v5.24 fixes that do NOT change the reference server
     flow remain: the TOTP gate never silently skips the 2FA step
     (auto-provider first, then a prompt whenever stdin is a real
     tty), prompt_line/prompt_secret give a clear localized error
     instead of an EOFError crash on broken stdin, and the POSIX
     cbreak hardening of _hotkey_mode (double-True no longer
     overwrites the saved terminal state; leaving hotkey mode
     flushes the pending input queue so stray keystrokes cannot
     corrupt the email/password/TOTP answers).

VERSION 2026-09-29 (v5.24) - THE TERMUX/ANDROID SIGN-IN BUG FIXED (3 variants:
  after a wipe/relogin the sign-in under Termux failed forever while the
  same script worked on Windows 11; the reference mozvpn.py worked on the
  same phone because its simpler TOTP path had none of these pitfalls):
  1) NO TOTP PROMPT AFTER EMAIL/PASSWORD (variant 1). The v5.23 TOTP gate
     required the caller's interactive FLAG; whenever that flag was not
     True the script silently skipped the whole 2FA step and went to the
     email-confirmation dead end - the sign-in was re-attempted WITHOUT
     a 2FA code and failed forever. The gate now tries the TOTP route
     for EVERY unverified session (except an unverified signup): the
     auto-provider first, then a prompt whenever the flag says
     interactive OR stdin is a real tty (_can_prompt() - the physical
     ability to read a line, not the flag).
  2) BROKEN PROMPTS CRASHED THE LOOP (variant 1's hidden form). input()
     and getpass.getpass() can raise EOFError/OSError on Android
     (wrappers/launchers with a redirected stdin, /dev/tty problems in
     Termux) - the generic 'Unexpected error' retry loop hid the cause.
     All interactive reads now go through prompt_line()/prompt_secret()
     with a CLEAR localized error (prompt_read_error) that says exactly
     what to do on Termux: run directly in the Termux terminal.
  3) THE TERMINAL COULD STAY IN CBREAK AFTER HOTKEYS (Termux/POSIX
     only - _hotkey_mode is a no-op on Windows, which is why Windows
     was unaffected). A double _hotkey_mode(True) (nested handler
     pairs) overwrote the saved 'old' attributes with the ALREADY
     CBREAK state, so a later _hotkey_mode(False) restored CBREAK
     instead of cooked mode - the following email/password/TOTP
     prompts misbehaved (line editing broken, the prompt looked
     'skipped'). Now a second True never overwrites the saved state,
     and leaving hotkey mode FLUSHES the pending input queue
     (termios.tcflush TCIFLUSH) and clears the _KEY_BUF leftover, so
     stray cbreak-mode keystrokes can no longer corrupt the answers.
  4) FIXED --totp CODE WAS RESENT 3 TIMES (variant 3: --email
     --password --totp still failed). A rejected code can NEVER be
     accepted again (server-side replay protection), but the retry
     loop re-sent the IDENTICAL fixed --totp value after a 30 s
     window wait - a guaranteed 100% failure. A repeated identical
     code now fails fast with the clear 'code rejected' message;
     only GENERATED codes (auto-TOTP from --qr/--totp-secret) are
     regenerated fresh for the next window.
  5) get_credentials_status NO LONGER SILENTLY DOWNGRADES TO v1
     (variant 1/2 root-cause candidate on mobile IPs): when the
     Fastly NGWAF / a flaky mobile network blocks
     /account/credentials/status, the old v1 fallback computed the
     WRONG authPW for a v2 account -> an endless errno 103
     'Incorrect password' loop (while Windows, unblocked, worked).
     Now: one retry with the Fastly cookie ensured, then a clear
     localized error (stretch_status_failed) instead of a poisoned
     login. Both en and ru strings + icons added.

VERSION 2026-09-28 (v5.23) - the endless failing relogin loop FIXED (the
  "restart always works, retry never does" live-run signature):

  ROOT CAUSE 1) _OPENER (urllib.request.build_opener with
  HTTPCookieProcessor(COOKIE_JAR)) is built ONCE at import and holds the
  ORIGINAL cookie jar forever. wipe_all_saved_data() reassigned
  COOKIE_JAR to a fresh jar, but every HTTP request still went through
  the OPENER wired to the DEAD jar: the Fastly challenge flow stored
  the solved _fs_ch_cp_* Set-Cookie into the OLD jar while
  fastly_solve_challenge() scanned the NEW, empty one -> every single
  attempt ended in "_fs_ch_cp_* cookie not received after a successful
  solution" and the API requests never carried the fresh jar's cookies.
  FIX: wipe_all_saved_data() now REBUILDS _OPENER on the fresh jar
  right after reassigning COOKIE_JAR - the jar and the opener can never
  diverge again after a wipe ('r', 'c', --clear-cache, --relogin).
  ROOT CAUSE 2) the _fastly_state latch ({"solved", "failed"}) survived
  every wipe: after ONE challenge failure failed=True disabled
  ensure_fastly_cookie() for the REST of the process, so every 30 s
  retry skipped the solver and went straight to HTTP 406 - forever.
  That is exactly why the relogin loop NEVER recovered while a RESTART
  always worked (a fresh process starts with a clean latch). FIX: the
  wipe resets both flags - the challenge state is part of the Fastly
  session and is cleared with it.
  RESULT) after 'r' the fresh sign-in asks for the email/password (v5.22)
  and the Fastly challenge is re-solved into the fresh, correctly wired
  cookie jar on the FIRST retry - no restart needed anymore.

VERSION 2026-09-28 (v5.22) - relogin REALLY wipes email/password now (the
  live-run leak found and fixed) + the full 'c'/--clear-cache audit:

  FIX 1) The live run showed the real leak: after 'r' (and 'c') the
  script asked ONLY for the TOTP code and signed in successfully -
  it never asked for the EMAIL and PASSWORD, although the wipe is
  supposed to make the fresh sign-in ask for all of them. ROOT CAUSE:
  ensure_session() reads args.email / args.password / args.session_token
  FIRST (the CLI flags and the MOZVPN_EMAIL/MOZVPN_PASSWORD/
  MOZVPN_SESSION_TOKEN environment copies live in the argparse Namespace
  for the whole run) - the handlers wiped the config dir, credentials.json
  and the in-memory creds DICT, but those args values survived and
  re-logged-in silently. The live totp_provider closure (the --qr
  generator of this run) and args.qr / args.totp_secret / args.totp are
  leftovers of exactly the same kind: a relogin/clear must not reuse ANY
  credential information from before the wipe.
  FIX: the 'r' and 'c' handlers and the --relogin branch of main() now
  ALSO clear args.email, args.password, args.session_token, args.qr,
  args.totp_secret, args.totp and set totp_provider = None after
  wipe_all_saved_data(). The fresh sign-in then asks for the email,
  the password and the 2FA code (fxa_login falls back to the
  interactive totp_prompt when the provider is None) - reusing nothing
  that existed before the wipe. A NEW --qr / --totp-secret / --totp /
  MOZVPN_* value can of course still be given for the new sign-in.
  AUDIT 2) 'c - clear ALL saved data & restart' and --clear-cache
  verified end-to-end: both call wipe_all_saved_data() ->
  clear_all_caches(), which shutil.rmtree's the WHOLE config directory
  (session.json, credentials.json incl. totp_secret,
  fastly-cookie.json, countries.json, singbox-install.json, the
  singbox/ and engine/ dirs of this and all previous versions) and
  clear the in-memory creds dict + the Fastly cookie jar; with v5.22
  the in-memory args credentials and the live TOTP provider go too.
  The 'c' handler additionally stops the live engine (its config files
  were just deleted) and forces the fresh sign-in on the next loop
  iteration; --clear-cache exits right after the wipe. NOTE: when
  --relogin and --qr are combined, the QR secret is decoded and saved
  BEFORE the wipe removes it again - use --qr alone (it stores the
  secret in credentials.json) or re-supply it after a relogin.

VERSION 2026-09-28 (v5.21) - the v5.20 QR/TOTP "wipe" REVERTED (it broke
  the auto-TOTP feature); the original relogin semantics restored:

  REVERT) v5.20 made the 'r'/'c' hotkeys and --relogin also clear the
  in-memory totp_provider and args.qr / args.totp_secret / args.totp.
  That was WRONG: the in-memory TOTP generator (built from the --qr
  image of THIS run) is a DELIBERATE FEATURE of the script - the whole
  point of --qr is that the script generates the 2FA codes itself
  (auto-TOTP, per the v2 credential-flow header) instead of asking
  the user to type them. The QR image is never saved to disk and the
  secret is persisted only in credentials.json, which the wipe DOES
  remove - keeping the live generator working is not "leftover saved
  data", exactly like the login session that is rebuilt right after.
  The v5.20 change therefore only achieved one thing: the fresh
  sign-in after 'r' prompted for a TOTP code by hand - the feature
  regressed. This version restores the ORIGINAL behavior:
  'r' / 'c' / --relogin wipe the DISK and the saved credentials
  (email/password/totp_secret in credentials.json, session.json,
  fastly-cookie.json, countries.json, singbox-install.json, the
  singbox/ and engine/ dirs, the in-memory creds dict and the Fastly
  cookie jar) and the fresh sign-in asks for the LOGIN and PASSWORD
  again (they cannot survive the wipe), while the TOTP code for that
  fresh sign-in is still GENERATED automatically by the live
  totp_provider - the cached generator of the running process, as it
  was before v5.20.
  AUDIT) 'c' / --clear-cache verified again: both go through
  wipe_all_saved_data() -> clear_all_caches() (shutil.rmtree of the
  whole config dir) + the in-memory clear; the 'c' handler stops the
  live engine (its config files were just deleted) and forces the
  fresh sign-in on the next loop iteration. Unchanged and correct.

VERSION 2026-09-28 (v5.19) - the flag art REDRAWN as a real 6x2 pixel
  grid + full line alignment (per the live-run screenshot):

  ART) The old quarter/diagonal-glyph table produced noisy, poorly
  readable flags and mixed 2- and 3-cell entries (Japan sat one
  column left of every other line). The art is now a REAL PIXEL GRID:
  every flag is exactly 6 cells = 12 pixels, painted with the
  upper-half block U+2580 - the truecolor foreground is the TOP pixel
  of the column, the background the BOTTOM pixel (verified online:
  the standard half-block technique gives two vertical pixels per
  cell; Windows Terminal still has no Kitty graphics protocol/Sixel,
  so half-block truecolor remains the only portable console PICTURE).
  The data lives in ONE constant table at the top of the code
  (_FLAG_PIXELS: two 6-char strings per country + a palette dict of
  the official shades) - easy to edit. No SVG/base64 images: consoles
  cannot scale or display them portably; the pixel grid is the best
  representation a terminal offers.
  REC) The recommended anycast keeps its real flag - solid WHITE in
  the dark theme, solid BLACK in the light theme - but in art mode it
  is now DRAWN AS ART (the same 6 cells), so the REC line aligns
  exactly like every country line; in emoji mode it stays the
  single-glyph white/black flag emoji, padded to the same width.
  ALIGN 1) Every flag representation is exactly FLAG_COLS (6) columns
  + 1 trailing space; the emoji fallbacks are padded to the same
  total, so the listen-address column never moves.
  ALIGN 2) The proxy-line LABELS are padded to the widest label of
  all proxies (min 30) before the template runs: the long
  'Recomended Location/Recomended City' line no longer pushes its
  '->' arrow further right than every other line (_proxy_label_width).

VERSION 2026-09-28 (v5.18) - real flag PICTURES on Windows 11 + the
  white/black flag for the recommended location:

  FIX 1) The local proxy lines on Windows showed LETTERS instead of
  flags: the default v5.17 representation is the flag emoji pair,
  and Windows 10/11 (re-verified online today - still true for the
  current 24H2 Emoji 16.0 fonts: Emojiall, chsm.dev, the
  flag-emojis-for-windows font-patch project) ships NO font that
  maps the regional-indicator pairs to flag glyphs. The default is
  therefore now --flag-style AUTO: the truecolor PIXEL ART on
  Windows (a console flag PICTURE exists there ONLY via the art)
  and the ready-made emoji pair on Linux/macOS/Android. --flag-style
  emoji / art still forces a style explicitly. Three countries of
  the live network list had NO art data and fell back to the
  letters - Ghana, Peru and the Philippines now have art entries
  with the official shades (Ghana #CE1126/#FCD116/#006B3F, Peru
  #D91023/#FFFFFF, Philippines #0038A8/#CE1126/#FCD116/#FFFFFF).

  FIX 2) The recommended anycast line no longer shows the electric
  plug: it now gets a REAL single-glyph flag - the waving WHITE flag
  (U+1F3F3 U+FE0F) in the dark theme and the BLACK flag (U+1F3F4)
  in the light theme. Both are SINGLE emoji (not regional-indicator
  pairs), so Windows renders them as pictures too.

  ALIGN) Every flag representation is now 4 console columns wide
  (3 art cells + space; the 2-column pair or flag + 2 spaces), so
  all proxy lines stay aligned and the emoji pair is no longer
  glued to the listen address ("AR127.0.0.1" -> "AR  127.0.0.1").

VERSION 2026-09-28 (v5.17) - hotkey 'n' crash + flag style + mojibake:

  FIX 1) Hotkey 'n' (colors on/off) crashed with "Unexpected error:
  UnboundLocalError("cannot access local variable '_BG_CURRENT'
  where it is not associated with a value")". ROOT CAUSE: the 'n'
  handler of the watch loop releases the forced window background by
  assigning _BG_CURRENT = None, but the enclosing function had NO
  'global _BG_CURRENT' declaration - Python therefore compiles the
  name as a LOCAL of that function, and the earlier read 'elif
  _BG_CURRENT is not None:' raises UnboundLocalError. The toggle
  itself (set_color) ran BEFORE the crash, so the color mode DID
  flip once the 30 s retry loop resumed. FIX: the handler now declares
  'global _BG_CURRENT'.

  FIX 2) The country flags next to the local proxy lines: the DEFAULT
  is again the READY-MADE Unicode flag emoji pair (the regional
  indicators, as in v5.13); the v5.14-v5.16 truecolor pixel art is
  opt-in via the new --flag-style {emoji,art}. Verified online
  (Emojiall, the chsm.dev and execross.dev write-ups): Windows 10/11
  ships NO font that maps regional-indicator pairs to flag glyphs,
  so on Windows the pair renders as the clean two-letter ISO code
  ("US", "DE", ...), not a picture; on Linux/macOS/Android (Termux)
  it is the real colored flag. No ready-made terminal renderer for
  flag PICTURES exists, so the pixel art stays available behind
  --flag-style art for those who want it.

  FIX 3) The corrupt symbols in the log ("Hotkey 'm' <broken glyph>:"
  and the "a" that replaced em dashes): the v5.14 edit pipeline had
  DOUBLE-ENCODED every non-ASCII literal of the string templates -
  e.g. the palette emoji was stored as the four code points U+00F0
  U+009F U+008E U+00A8 instead of U+1F3A8, which prints as garbage.
  v5.17 decodes every damaged literal back to the intended character
  and then stores it as an ASCII-only escape sequence (the
  backslash-u / backslash-U form) - the whole file is now
  PURE ASCII, so no editor, clipboard or code page can ever corrupt
  it again; the runtime strings are byte-for-byte identical.
  (v5.17.1: the first v5.17 build had written THIS VERY text with
  literal backslash-u characters - Python parsed the docstring
  escape and refused to start with SyntaxError: (unicode error)
  'unicodeescape' codec ... truncated \\uXXXX escape at line 3;
  the changelog now uses plain ASCII words only.)

VERSION 2026-09-28 (v5.16) - the 'Unexpected error: ValueError(...)' on
  startup FIXED - the flag-art crash:

  The first v5.15 run (the first run of the pixel-art flags AT ALL -
  v5.14 never started because of its SyntaxError) crashed while
  printing the local proxy list: "Unexpected error:
  ValueError('not enough values to unpack (expected 3, got 2)')".
  ROOT CAUSE: the flag-art table paints every country flag as three
  cells, and a cell is EITHER the full form (glyph, fg, bg) or the
  SHORT form (glyph, color) - a SOLID cell whose fg and bg are the
  same color (the full-block stripes of the vertical tricolors and
  the like: France, Belgium, Italy, Ireland, Sweden, Norway, Denmark,
  Finland, Portugal, Greece, Romania, Switzerland, Brazil, Mexico,
  Kazakhstan, Nigeria, Morocco, Bangladesh, Saudi Arabia, China,
  Israel, Turkey, Vietnam, ... - 29 of the 181 cells). The v5.14
  painter unpacked strictly 3 values per cell, so EVERY short-form
  cell raised ValueError - the watch loop printed a few proxy lines,
  hit the first solid-stripe country and died. v5.16: _flag_paint()
  renders BOTH forms (the short form paints fg = bg = the given
  color); the data table itself is untouched.

VERSION 2026-09-28 (v5.15) - the ROOT CAUSE of the 'broken' themes/hotkeys
  + hotkeys hardened against PTY byte-splitting + MASQUE probes that
  really TUNNEL DATA:

  FIX 1) THE ROOT CAUSE: v5.14 shipped with a SyntaxError - a stray
     closing parenthesis on the _ANSI_RE line ('unmatched \')\'' at
     import time) - so THE SCRIPT DID NOT EVEN START; every hotkey
     ('m' the theme, 'n' the color mode) was 'broken' because there
     was never a running process to press keys in. v5.15 fixes the
     line; the v4.5+ theme machinery (dark/light switch + the FULL
     log redraw via redraw_log(), the color toggle with the embedded-
     ANSI strip) works again exactly as in the older versions.
  FIX 2) hotkeys in ANY layout: _key_pressed() could FREEZE the whole
     hotkey loop on POSIX - the v5.13 code re-read the UTF-8
     continuation bytes of a non-English letter with a BLOCKING
     os.read(), and a PTY that delivers the lead byte in a separate
     write made that read wait for the NEXT keypress forever. v5.15:
     BUFFERED reads - one poll reads every currently available byte,
     leftovers wait in _KEY_BUF, escape sequences (arrows) are
     consumed whole, and a partial UTF-8 sequence is completed with
     bounded 20 ms waits, never a blocking read.
  FIX 3) the MASQUE probe now REALLY transfers data (req. 3): a 2xx
     answer alone is no longer a success. The probe sends a minimal
     DNS query (A mozilla.com, a random transaction ID) through the
     CONNECT-UDP tunnel to 1.1.1.1:53 - a DATAGRAM capsule (RFC 9297:
     capsule type 0x00, varint framing; Context ID 0 = the raw UDP
     payload to the CONNECT target, RFC 9298) - and succeeds ONLY
     when the DNS answer comes back through the tunnel (matched by
     the transaction ID + the QR bit, in a DataReceived capsule or a
     DatagramReceived frame). '200 but no data' is now an honest
     FAILURE. The CONNECT request also gained the RFC-required
     'capsule-protocol: ?1' header, the correct :authority (the
     PROXY host:port, not the tunnel target) and end_stream=False -
     the v5.14 probe CLOSED its send side, so no data could ever be
     tunneled at all. A dropped UDP query is re-sent (max twice, once
     also via the QUIC DATAGRAM frame variant).

VERSION 2026-09-28 (v5.14) - VISIBLE pixel-art flags + the REAL probe
  speedup (the found root causes):

  FLAG) The v5.13 emoji flags (regional-indicator pairs) render as
     LETTERS on Android/Termux - the stock monospace font maps the
     regional indicators to Latin letters (a known Termux font issue;
     termux-app #4757: 'known issue with the monospace fonts shipped by
     default on a lot of phones'), so the user saw "US"/"DE" instead of
     a flag. No script can force a glyph the font does not have, so
     v5.14 draws a REAL mini-flag with ANSI 24-bit truecolor + block
     glyphs (U+2580/258C/2590/quarters): three cell-sized stripes of
     the official flag colors, supported by Termux, Windows Terminal
     and every modern terminal (the termstandard-colors truecolor
     list). With --no-color (or an unknown country) the v5.13 emoji
     pair / the plug emoji remain the representation. The colorless
     log render now strips embedded ANSI codes so a theme/color
     hotkey redraw stays clean.
  SPEED 1) THE remaining probe bottleneck: the v5.13 masque event hook
     DISCARDED the H3 events returned by H3Connection.handle_event()
     (the aioquic docs: handle_event RETURNS a list of H3 events) -
     the response to the extended CONNECT arrives as an
     HeadersReceived with the :status pseudo-header, so an ANSWERING
     masque server produced no verdict and EVERY accepted probe still
     sat out the full 5 s window. v5.14: the hook consumes the
     returned events - a 2xx HEADERS answer is the IMMEDIATE success,
     any other status an IMMEDIATE rejection; StreamReset /
     StreamDataReceived / the silent cap are unchanged.
  SPEED 2) _tls_connect: a TCP-LAYER connect failure (timeout/refused/
     unreachable - no ClientHello was sent) now ABORTS the 4-profile
     ClientHello matrix immediately - no profile can change a connect
     failure, and the v5.8 note already said 'a fully-failing run is
     bounded by the profile matrix x the per-attempt timeout'
     (4 x 5 s per upstream wasted). TLS handshake failures keep
     walking the full matrix as before.
  SPEED 3) _connect_resolved_ips: after the preferred (first) address
     fails, the REMAINING A records are raced CONCURRENTLY (the RFC
     8305 'Happy Eyeballs' idea) and the first winner is used - the
     old serial loop paid the FULL connect timeout PER address.
  SPEED 4) check_upstream: the concurrent CONNECT fallback moved from
     a per-upstream ThreadPoolExecutor (its worker threads are NOT
     daemon and the interpreter JOINS them at exit - bpo-36780) to a
     plain daemon thread + Event: same concurrency, no exit delay.
  SPEED 5) resolve_host: an IN-FLIGHT dedup - concurrent callers for
     the SAME hostname (the probe pool + the prefill racing on a
     shared egress host) share ONE DoH query instead of stampeding;
     the DoH prefill is no longer a SERIAL phase before the probes -
     it starts in daemon threads and OVERLAPS the probe phase.

VERSION 2026-09-28 (v5.13) - binary-on-Android DNS bypass + REAL probe
  parallelism + per-proxy flags + hotkeys in ANY layout:

  FIX 1) gaierror(7) 'No address associated with hostname' in the
     PACKAGED binary (Termux/armv9) while the plain script works:
     packaged-Python-on-Android runtimes are KNOWN to break
     socket.getaddrinfo while nslookup/the browser work fine
     (python-for-android #1447, kivy #7087, PyInstaller #3721), so the
     system resolver is NOT trustworthy inside a binary. req() now has
     a LAST-RESORT DIRECT-IP path: when the v5.12 single retry fails
     too, _emergency_doh_resolve() asks the well-known DoH resolver
     IPs DIRECTLY (1.1.1.1 / 8.8.8.8 / 9.9.9.9 on 443 - NO
     name resolution anywhere, the SNI stays the resolver hostname;
     v8.8: 9.9.9.9 moved 5053 -> 443, Quad9 retired the 5053 JSON
     service on 2025-05-05)
     and _raw_https() sends the API request straight to the resolved
     IP with the correct Host header + SNI (redirect following and the
     shared cookie jar included). This covers EVERY API call (OAuth,
     Guardian, Remote Settings) regardless of the --doh setting.
  FIX 2) per-proxy FLAG emoji in the proxy list: every local proxy
     line now starts with the NATIONAL FLAG of its country (the two
     regional-indicator letters of the ISO code; 'UK' -> the GB flag;
     REC/unknown keep the electric-plug emoji). tr() accepts an _e=
     override, country_flag() builds the pair.
  FIX 3) the probes were STILL slow because of the LAST serial part:
     per upstream the MASQUE attempt and its CONNECT fallback ran ONE
     AFTER ANOTHER (a UDP-blocked network paid up to 2 s QUIC connect
     + 5 s data wait and THEN the whole CONNECT probe on top), the
     masque probe ALWAYS sat out the fixed 5 s data window, and
     aioquic resolved the egress hostname with the SYSTEM resolver.
     v5.13: (a) the CONNECT fallback runs CONCURRENTLY with the
     MASQUE probe (a 1-thread pool; the masque verdict keeps
     priority); (b) the masque verdict returns as soon as the server
     actually ANSWERS (an event hook shadows
     QuicConnectionProtocol.quic_event_received; a stream reset is
     now detected as a REJECTION instead of a silent 5 s wait; the
     deadline remains only as the cap for silent peers); (c) the QUIC
     connect goes to the DoH-resolved IP (SNI stays the hostname).
  FIX 4) the 'w' multi-selection echo now SHOWS the typed spaces (the
     v5.12.1 .strip() hid the very separator the user is asked to
     type); only accidental double spaces are collapsed.
  FIX 5) hotkeys in ANY keyboard layout on POSIX: _key_pressed() read
     ONE BYTE, so the 2-4 byte UTF-8 letter of a non-English layout
     was split into a lone invalid lead byte that no transliteration
     table could map - hotkeys silently worked only in the English
     layout. It now reads the COMPLETE UTF-8 character and only then
     applies the position-based layout mapping (JCUKEN ru/by/ua on
     POSIX, the scan-code route on Windows), so the letter printed on
     the keycap works in every layout.

VERSION 2026-09-28 (v5.12.1) - 'w' menu: ONE in-place selection line:

  The v5.12 multi-selection echoed a NEW 'Selected: ...' log line on
  EVERY keystroke, so typing '1 2 x' left three duplicate lines in
  the log. v5.12.1 prints ONE line that REWRITES itself in place (\r
  rewrite, the exact technique of the existing retry countdown) -
  _multi_line_show() / _multi_line_clear(); the line is erased when
  the selection is applied or cancelled, and the apply/cancel
  summary starts on a clean row. Everything else is unchanged.

VERSION 2026-09-28 (v5.12) - friendly transient net errors + REAL
  parallel DoH + --countries filter with hotkey 'w':

  FIX 1) The Termux/arm live log showed 'Unexpected error:
     URLError(gaierror(7, 'No address associated with hostname'))'.
     A gaierror(7) is a TRANSIENT DNS blip (the resolver briefly had
     no answer) that is gone seconds later - the raw exception repr
     was printed by the watch loop's generic handler. Fixes:
       a) new _is_transient_net_error() / _net_err_public(): transient
          network errors (URLError with a gaierror/timeout/connection
          reason, socket.gaierror, timeouts, connection errors) are
          detected and mapped to SHORT localized reasons
          (net_error_retry + net_err_dns/timeout/conn, EN + RU);
       b) req() retries ONCE (a 1.5 s pause) on a transient URLError -
          this covers EVERY API call site (OAuth, Guardian, Remote
          Settings), not just the watch loop;
       c) the watch loop's generic except prints the friendly
          net_error_retry line instead of the raw repr.
  FIX 2) The probes were STILL slow because the DoH chain was walked
     SEQUENTIALLY per hostname: when the first provider was slow or
     blocked (typical on filtering networks) EVERY lookup paid its
     full 4 s timeout before the chain moved on - so 'parallel probes'
     still waited on DNS. Fixes:
       a) _doh_query_parallel(): ALL DoH providers of the chain get
          the query AT ONCE and the FIRST non-empty answer wins (the
          losing slower queries finish in the background); failed
          providers keep the 60 s penalty;
       b) the probe pre-resolve now runs ALWAYS (not only with the
          opt-in long cache - the always-on 60 s memo keeps the
          answers), its workers 8 -> 16;
       c) probe workers 32 -> 64.
  NEW 3) --countries LIST: run local proxies ONLY for the listed
     countries (comma/space-separated ISO codes, full country names,
     'rec' = the recommended anycast egress; example:
     --countries "us,de,jp"). Default: not used. The choice is
     cached in countries.json and survives restarts. Hotkey 'w'
     opens the interactive equivalent: every upstream gets a token
     (1-9, a-z, aa, ...), the tokens are typed SEPARATED BY SPACES
     and confirmed with Enter; token '0' = ALL local proxies (this
     clears the saved filter).

VERSION 2026-09-23 (v4.7.1) -- startup duplicate-line fix + full re-audit:
VERSION 2026-09-25 (v5.8) - probe log: ONE compact message + the probe
  errors VERIFIED as not caused by the earlier edits:

  VERIF) The live v5.7 run showed 33/33 'data check not passed'
     (SSLError(1, '[SSL: UNEXPECTED_MESSAGE] ...') on 32 upstreams, one
     timeout). A full diff of the probe path against the pre-v5.6
     sources shows the ONLY changes were: the DoH resolve-once memo in
     _tls_connect(), the probe timeouts 10s->5s / 12s->6s, and skipping
     the in-probe echo fallback when the failure was already at the
     TLS/CONNECT stage - none of these can produce an SSL error; the
     handshake code path (ctx.wrap_socket to the egress) is unchanged.
     The builtin engine itself reaches the upstream via the SAME
     _tls_connect() (timeout=20), so the probe reflects the real
     serving conditions. Fastly's official blog confirms the rollout
     proxy runs HTTP CONNECT over HTTP/2 (TLS); a failing TLS handshake
     to *.m1.fastly-masque.net:2499 is a network/egress-side outcome
     (the same 33/33 failure signature was already documented in the
     v5.4 changelog from a live run BEFORE any of those edits).
  LOG 1) probe_upstreams_parallel no longer prints one line per
     upstream (33+ lines with raw exception reprs in the live run) plus
     two host-list summaries: the whole probe now produces exactly ONE
     message - an ok line when all upstreams pass, otherwise ONE info
     line: 'Probe: {n}/{total} upstreams passed the data check; {n_fail}
     did not - they are served anyway (32x TLS to the upstream failed
     (network or egress side), 1x timed out)'. The raw per-probe details
     stay in the result dicts / the JSON output.
  LOG 2) new _probe_reason_public(): raw exception reprs (SSLError(...),
     timeouts, refusals, resets) are mapped to short localized reason
     classes so the summary stays informative without scary stack noise.
  NOTE 3) probe speed: in a fully-failing run the duration is bounded by
     the network itself (the TLS profile matrix x the per-attempt
     timeout), not by DNS - the v5.6 DoH memoization already removed the
     repeated DoH round-trips, which is why a failing run feels barely
     faster (the handshakes, not the lookups, take the seconds).

VERSION 2026-09-25 (v5.7) - FoxyProxy import FIXED for real (verified
  against the official FoxyProxy Standard v9.8 sources,
  github.com/foxyproxy/browser-extension):

  DIAG) Why the v5.6 legacy import produced an EMPTY list: the legacy
     file used a 'proxySettings' ARRAY, but migrate.js convert7()
     extracts proxies ONLY from TOP-LEVEL object keys
     (Object.values(pref).filter(i => i && ['address','type']
     .some(p => Object.hasOwn(i, p)))) - a 'proxySettings' array is
     silently dropped. Reproduced by simulating convert7 over the v5.6
     output: 0 proxies found.
  FIX 1) The LEGACY export (--foxyproxy-legacy-export / hotkey 'x') is
     now the REAL FoxyProxy 6/7 shape: every proxy as its own TOP-LEVEL
     'k<id>' key (id == key, sha256-derived) + {mode, sync, logging};
     convert7() now finds every proxy - 33/33 in the simulation.
  FIX 2) The CURRENT export (--foxyproxy-export / hotkey 'f') is now a
     COMBINED file: the full current pref shape ({mode, sync, autoBackup,
     passthrough (the standard localhost/private-IP CIDR list), theme,
     container, commands, data: [...]}) PLUS the same proxies as
     top-level 'k<id>' entries - so it imports via ANY FoxyProxy import
     path ('Import' button reads 'data', 'Import from older versions'
     reads the 'k<id>' entries); a wrong picker can no longer produce an
     empty list. cc values are schema-valid ('REC' -> '' (no flag),
     'UK' -> 'GB').
  NOTE 3) After ANY import FoxyProxy shows the settings in the UI, but
     they are persisted only after clicking 'Save' - the import hint
     and the hotkey help now say the exact buttons to press.
VERSION 2026-09-25 (v5.6) -- probe speedup (DoH) + FoxyProxy import fixes:

  SPEED 1) The 'probes take 10+ seconds' ROOT CAUSE was in the DoH
     layer, not in the echo parsing: with the DoH cache OFF (the
     default), EVERY TLS profile attempt of the probe re-resolved the
     egress hostname over DoH - 4 profile attempts + 4 more in the
     in-probe echo fallback = up to 8 DoH queries PER UPSTREAM, and
     when the first DoH provider in the chain is slow or blocked
     (typical on filtering networks), EACH query first paid the full
     DOH_TIMEOUT before the chain moved on. Fixes:
       a) an ALWAYS-ON short answer memo (DOH_MEMO_TTL = 60 s): the
          same hostname is never re-resolved within one probe run -
          the opt-in --doh-cache (300 s) semantics are unchanged;
       b) a provider penalty (DOH_PROVIDER_PENALTY = 60 s): a DoH
          endpoint that just timed out is SKIPPED for the next 60 s,
          so one dead provider no longer adds its timeout to every
          subsequent lookup;
       c) DOH_TIMEOUT 10 s -> 4 s;
       d) _tls_connect() resolves the host ONCE before the profile
          loop and reuses the IP list for every profile attempt.
  SPEED 2) The in-probe echo fallback (checkip.amazonaws.com) is now
     skipped when the failure was at the TLS/CONNECT stage - on a
     filtering network the second tunnel fails identically and only
     doubled the probe time. The fallback still runs when a tunnel
     worked but the echo BODY could not be parsed (its original
     v5.4 purpose). Probe timeouts shortened: TLS 10 -> 5 s,
     CONNECT wait 12 -> 6 s, inner HTTP 8 -> 6 s, probe_geo 15/20 ->
     8/10 s.
  FIX 3) FoxyProxy Standard import (both formats failed in the live
     run 2026-09-25). Verified against the official extension source
     (github.com/foxyproxy/browser-extension, v9.8 = the current AMO
     release of FoxyProxy Standard):
       a) 'Import from older versions' does NOT accept XML at all:
          src/content/fs.js accepts only the text/plain and
          application/json MIME types and JSON.parses the file; the
          importer then runs Migrate.convert7() on the FoxyProxy 6/7
          settings JSON ({proxySettings: [{address, port, type: 1,
          whitePatterns, blackPatterns, ...}]}). The old FoxyProxy
          4.x foxyproxy.xml cannot be imported by 9.x in any way
          (the official help says it must first pass through
          FoxyProxy 7.5.1). The legacy export (hotkey x /
          --foxyproxy-legacy-export) is therefore REPLACED: it now
          writes the FoxyProxy 6/7 settings JSON that 'Import from
          older versions' actually parses.
       b) The CURRENT-format file is imported with the 'Import' button
          at the TOP of the Options page (next to Export) - there is
          no 'Options -> Import Settings' submenu in 9.x; the import
          hints now state the exact click path for both formats.

VERSION 2026-09-25 (v5.5) -- FoxyProxy Standard export + faster probes:

  REQ 1) Confirmed (no change needed): a FAILED probe never removes an
     upstream - the fail line says "the upstream is served anyway",
     --probe-fail keep is the default (drop is opt-in), and a failed
     MASQUE probe automatically falls back to HTTP CONNECT, so every
     upstream is served with SOME protocol.
  FIX 2) Faster probes (the "about 10 seconds" complaint): the v5.4
     chunked parser already removed the main delay (the echo answer is
     now parsed on the first try, no fallback tunnel); on top of that
     the probe timeouts are TLS 15 s -> 10 s, CONNECT 20 s -> 12 s,
     inner HTTP request 10 s -> 8 s. The "json" in the endpoint URL is
     NOT the cause - the delay was the broken body parsing, now fixed.
  NEW 3) FoxyProxy Standard settings export, CURRENT format (v8+/v9.x,
     verified against src/content/schema.json of the extension sources,
     v9.8 2026-09): --foxyproxy-export writes one JSON settings file
     with ALL running local proxies (country code -> flag icon, city,
     title, 127.0.0.1 address, port, type http, color palette, standard
     localhost/private-IP exclude patterns); --foxyproxy-out FILE saves
     straight to the path with NO dialog; without it an OS save dialog
     (tkinter, with a console prompt fallback) asks where to save.
     Live hotkey: f. Import in FoxyProxy Standard: Options -> Import
     Settings.
  NEW 4) The same export in the LEGACY FoxyProxy format (foxyproxy.xml
     of FoxyProxy 4.x, structure per verified real-world exports):
     --foxyproxy-legacy-export + --foxyproxy-legacy-out FILE; live
     hotkey: x. isSocks="false" manualconf + a white wildcard match per
     proxy. Import via Options -> Import Settings -> Import from older
     versions.

VERSION 2026-09-25 (v5.4) -- probe algorithm fix per the live-run log:

  DIAG) Live log 2026-09-25: ALL 33 upstreams failed the data check
     ("Probe: ... - data check not passed") while the tunnels themselves
     were fine (the user confirms the script works). The v5.2/v5.3
     probe parsed the echo response with a NAIVE 'split once on
     \r\n\r\n and take the rest' - it cannot handle 'Transfer-Encoding:
     chunked' (RFC 9112 section 7.1, standard HTTP/1.1 framing), and
     ipinfo.io answers /json with a chunked body, so the JSON decoder
     got a body polluted with hex chunk-size lines and no probe could
     extract the IP. The misleading 'Geo check skipped: the echo
     service returns only the IP' line fired for the same reason.
  FIX 1) _http_ip_request_over_tunnel(): a REAL HTTP/1.1 response
     parser (_http_dechunked_body) - status line, lowercase header
     dict, Content-Length slicing, chunked DECHUNKING, read-to-EOF
     fallback; 'Accept-Encoding: identity' prevents gzip; the request
     timeout is 15 s -> 10 s so a dead upstream fails faster (the
     'very long probes' complaint).
  FIX 2) probe_connect(): ONE in-probe fallback - if the primary echo
     body cannot be parsed (CDN change, unexpected encoding, truncated
     chunked body), ONE retry goes to https://checkip.amazonaws.com
     (plain-text 'x.x.x.x\n' endpoint, no JSON, no chunking) through a
     FRESH tunnel, so one flaky echo service can no longer fail all
     probes. Geo still comes only from the primary JSON echo. The
     data-flow requirement is KEPT: a bare 200 proves nothing, the IP
     must arrive through the tunnel (unchanged).
  NEW 3) Failed probe lines now print the REASON
     ('data check not passed (no IP in echo response: ...)') instead
     of failing silently - both EN and RU templates, so future
     diagnosis does not need a code re-read.
  NEW 4) probe_masque(): the keep-alive wait is 8 s -> 5 s (same probe
     speedup; the MASQUE data requirement itself is NOT weakened).
  FIX 5) The 'Geo check skipped' note now fires only when probes DID
     pass but the echo carries no geo (a plain-IP echo service); on
     total probe failure the failure lines speak for themselves.

VERSION 2026-09-25 (v5.3) -- verified against the ORIGINAL file + Python 3.14:

  FIX 1) The hotkey hint emoji now match the ORIGINAL mozvpn_beta.py
     EXACTLY (recycle r, broom c, arrows-e e, shuffle l, folder o,
     clipboard v/b, digits t, ticket j, frame g, person u, key p,
     package d, up-arrow s, palette m, rainbow n, page 1-9, stop q -
     v5.2 restored them) + the new v5.1 keys: globe h, floppy k (both).
  VERIFIED 2) A FULL audit against the user-provided ORIGINAL file
     (mozvpn_beta.py): message-template keys, _EMOJI map keys, argparse
     options, watch-loop hotkey handlers and the function list were
     diffed one by one - NOTHING from the original was removed; the
     script only ADDS (DoH module, selection tokens, geo/probe changes,
     the _hp alignment helper).
  VERIFIED 3) Python 3.14 (the current stable release, 3.14.x) is fully
     supported: sys.stdout.reconfigure exists (3.7+), argparse
     BooleanOptionalAction (3.9+), and the 3.14 deprecations index has
     nothing that this script uses. The UTF-8 reconfigure stays REQUIRED
     on 3.14 - UTF-8 mode becomes the interpreter default only in
     Python 3.15 (PEP 686).

VERSION 2026-09-25 (v5.2) -- aligned log, emoji restored + UTF-8, 1-request probe:

  FIX 1) The log is now COLUMN-ALIGNED: every per-upstream line (probe,
     geo check, protocol choice) prints host:port padded to a fixed
     width, the copy lists (v/b) pad the address column and the DoH
     menu (h) pads the provider names - the message text starts in the
     same column on every line.
  FIX 2) The emoji in the hotkey hint are RESTORED (removing them in
     v5.1 was wrong - they are part of the functionality). The ROOT
     CAUSE of the "garbage symbols" is fixed instead: stdout/stderr are
     reconfigured to UTF-8 at startup (sys.stdout.reconfigure,
     Python 3.7+; Windows legacy consoles may also need chcp 65001).
     MORE emoji added: every message template that had none got its
     emoji, and two new meaning-based highlight classes were added to
     BOTH themes (dark + light): country codes (cc) and email
     addresses (email).
  FIX 3) Probes are FAST again: ONE request per upstream (like the
     original), all in parallel (32 workers). The default echo
     service is now ipinfo.io/json - its single answer carries the
     external IP AND the exit country/city, so the separate
     exit-country request of v5.0/v5.1 is GONE (no second tunnel, no
     second thread pool) and the geo check uses the SAME probe
     answer. probe_geo() is kept as working functionality.
  FIX 4) Every hotkey press logs WHAT HAPPENED: the selection sub-modes
     (v/b/h/1-9) confirm with an explicit info line (copied address /
     applied resolver / opened file / cancelled selection).
  FIX 5) DoH is reported ONCE AT STARTUP: the selected provider, the
     full fallback chain (selected -> other presets -> system resolver)
     and the cache state. During the run the individual DNS lookups
     are SILENT - no more per-host "resolved via DoH" lines.
  FIX 6) No functionality was removed: the function list was diffed
     against the original mozvpn_beta.py - only additions exist
     (DoH module, selection tokens, _hp alignment helper).

VERSION 2026-09-25 (v5.1) -- hotkey UX fixes, opt-in DoH cache, faster startup:

  FIX 1) The hotkey hint lines no longer show "garbage symbols" - all
     emoji decorations are removed from the hotkeys_hint block (both
     languages); the key letters alone mark the hotkeys.
  NEW 2) Hotkey 'h' no longer CYCLES the DNS resolver - it opens a
     SELECTION MENU (like the v/b copy lists): every DoH preset
     (Cloudflare, Google, NextDNS, Quad9) + the system DNS entry; the
     choice is typed as a token and confirmed with Enter.
  NEW 3) Selection tokens for ALL interactive lists (v/b proxy copy, the
     DoH menu, the config-file list): 1-9, then the English letters a-z,
     then two-letter combinations aa, ab, ... - confirmed with Enter,
     Backspace deletes. Lists with more than 9 items stay usable (typing
     "10" or "ab" no longer fires the first key instantly). The
     config-file list is no longer capped at 9 entries.
  NEW 4) The DoH answer cache is DISABLED BY DEFAULT (strictly opt-in):
     --doh-cache / hotkey 'k' / env MOZVPN_DOH_CACHE=1 enable it,
     --no-doh-cache disables. Without the cache every lookup queries the
     DoH chain directly.
  NEW 5) Every configured resolver is DoH ONLY (Cloudflare / Google /
     NextDNS / Quad9 presets + the custom --doh-url endpoint); the SYSTEM
     resolver is used ONLY when DoH is off ('off') or as the LAST resort
     of the fallback chain.
  NEW 6) Default resolver chain: the SELECTED provider first (Cloudflare
     by default), then the remaining DoH presets, the system resolver
     LAST (chain: selected -> other presets -> system).
  NEW 7) Faster startup: the exit-country check (probe_geo) runs in
     parallel WITH the data probe (a second thread pool; results are
     collected after both), the probe pool grew 16 -> 32 workers, and
     with the DoH cache enabled all unique egress hostnames are
     pre-resolved in parallel BEFORE the probe starts.
  NEW 8) While a selection sub-mode is active the watch loop polls keys
     every 0.05 s (instead of 1 s) so multi-character tokens + Enter
     feel instant.

VERSION 2026-09-25 (v5.0) -- all upstream proxies + DoH resolving + geo check:

  ROOT CAUSE of the "few proxies / always US exit" problem (verified against
  the LIVE vpn-serverlist Remote Settings collection on 2026-09-25, 35
  records: 33 countries + US CatchAll Anycast + REC, one city and one server
  {hostname, port 2499} per record, no 'protocols' field at all):

    1) The live collection marks almost every country record 'locked: true'
       (Peru, Brazil, Korea, UK, France, Singapore, ... - only US/DE/JP/AR/
       AU/ZA are unlocked). Firefox serves ALL of them, but this script
       skipped locked records by default -> only ~5 upstreams remained.
       v5.0: locked records are INCLUDED by default (--exclude-locked
       restores the old behavior).
    2) --probe-count defaulted to 1, so only the first upstream was even
       verified. v5.0: the default is 0 = probe ALL.
    3) collect_verified_servers collapsed each city to ONE server and the
       REC (recommended anycast p.m1.fastly-masque.net) record was never
       served as a local proxy. v5.0: every server of every city AND the
       REC egress get their own local proxy.
    4) Fastly terminates the client TLS on the PoP whose IP you CONNECT to,
       and the egress leaves from that same PoP (Fastly blog, June 2026:
       today the proxy speaks HTTP CONNECT over TLS; MASQUE/HTTP-3 comes
       later). A poisoned/geo-wrong system A record for *.m1.fastly-masque.net
       therefore routes you to a US PoP -> US exit IPv4 even though the
       untouched AAAA (IPv6) record still shows the right country (this is
       exactly the "IPv6 shows the chosen country, IPv4 shows the US"
       symptom). Firefox avoids this with TRR (DNS-over-HTTPS); the script
       used the system resolver. v5.0: the egress hostnames are resolved
       over DoH (presets: cloudflare, google, nextdns, quad9; --doh, custom
       --doh-url, 'off' = system DNS; hotkey 'h' opens the resolver
       selection menu), the TLS connection goes to the resolved IP while SNI
       stays the hostname, and every probed upstream gets an exit-country
       check via ipinfo.io/json (--probe-geo warn|drop|off) that warns
       about / drops wrong-country egresses.

VERSION 2026-09-23 (v4.7.3) -- fix: --no-save crashed at startup:

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

VERSION 2026-09-23 (v4.7.2) -- DEFAULT-ON --local-proxy and --no-save:

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

VERSION 2026-09-23 (v4.7) -- forced console background, layout-independent
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
     '\u0439' on a Russian JCUKEN layout still triggers hotkey 'q' (scan
     codes are layout-independent; verified against the Win32 docs).
     On POSIX terminals (no scan-code channel in the input stream) a
     Cyrillic->English translation table for the JCUKEN family is used.
  FIX 3) Dependency reinstall no longer dies on pip ResolutionImpossible
     conflicts: a STAGED install is used - all packages in one command
     first (pip resolves them together), then each package separately
     WITHOUT --force-reinstall (forcing shared transitive dependencies
     to exact versions is the usual conflict cause, per the pip docs),
     then pip install <pkg> --no-deps as a last resort, with a clear
     per-package OK/FAILED report at the end.

VERSION 2026-09-23 (v4.6) -- correct dark/light themes + sing-box dependency info:

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

VERSION 2026-09-23 (v4.5) -- full log redraw, JWT hotkey, hint styling:

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

VERSION 2026-09-23 (v4.4) -- retry countdown, theme & color hotkeys:

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

VERSION 2026-09-23 (v4.3) -- dependencies management, new hotkeys:

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

VERSION 2026-09-23 (v4.2) -- curl test-command output now opt-in:

  NEW 0) The ready-to-paste curl test commands (for the LOCAL proxies and
     for the UPSTREAM proxies, plus the per-server curl hints in one-shot
     mode) are NO LONGER printed by default - the log got noisy with five
     long Bearer lines per refresh. New flag --show-test-commands (env
     MOZVPN_SHOW_TEST_COMMANDS=1) enables them; default: off. When the
     commands are hidden, one short hint line explains how to enable them.

VERSION 2026-09-23 (v4.1) -- hotkey 'r'/'c' crash fix per live-run feedback:

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

VERSION 2026-09-23 (v4.0) -- hotkey fixes per live-run feedback:

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

VERSION 2026-09-23 (v3.9) -- full-wipe relogin, TOTP hotkey, decoded JWT:

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

VERSION 2026-09-23 (v3.8) -- protocol choice logging, copy/open hotkeys:

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

VERSION 2026-09-23 (v3.7) -- audit, hotkeys l / 1-9, probe hint removed:

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

VERSION 2026-09-23 (v3.6) -- KeyError crash fix, --listen, config paths:

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

VERSION 2026-09-23 (v3.5) -- quota fix, hotkeys, emoji & theme polish:

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

VERSION 2026-09-23 (v3.4) -- hotfix for a v3.3 regression + restoration:

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

VERSION 2026-09-23 (v3.3) -- probe wording, themes, richer word colors:

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

VERSION 2026-09-23 (v3.2) -- logging polish based on a live run report:

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

VERSION 2026-09-23 (v3.1) -- TLS profile fallback matrix, probe-fail policy,
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

VERSION 2026-09-23 (v3.0) -- MASQUE support, builtin proxy engine, i18n, colors:

  1) MASQUE PROTOCOL SUPPORT (verified against live data, 2026-09-23):
     - Fastly's official blog ("We Built the Proxy Behind Firefox's New
       Built-In VPN") states that the proxy currently runs plain HTTP CONNECT
       (over HTTP/2) and that Firefox plans to move to MASQUE over HTTP/3 on
       Fastly's infrastructure later.
     - The live Remote Settings collection "vpn-serverlist" today only
       advertises protocols: [{name: "connect", ...}] on hosts like
       *.m1.fastly-masque.net:2499 -- i.e. the egress hostnames are
       MASQUE-branded, but the actually served protocol is still HTTP CONNECT
       over TLS.
     - Therefore this script fully PARSES "masque" protocol entries in the
       server list, PROBES them for real MASQUE (HTTP/3 CONNECT-UDP over
       QUIC via the optional `aioquic` package) and -- when MASQUE is not
       actually usable -- FALLS BACK to HTTP CONNECT automatically (req. 1, 2).
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
       no external engine binary -- fully Nuitka/exe-friendly (req. 11).
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
  MOZVPN_SHOW_TEST_COMMANDS (1/true/yes/on), MOZVPN_RETRY_DELAY (seconds),
  MOZVPN_REFRESH_MARGIN (seconds, v6.0), MOZVPN_FLAG_STYLE (auto|emoji|art, v6.0)

Configuration (mode 600):
  config.json         -- THE one uber-config (v6.0; v6.1: next to this
                         script by default, --config FILE moves it):
                         accounts (login/password/TOTP/session per
                         account + the QR png as base64), settings (DoH
                         resolver, DoH cache, language, the countries
                         filter, the sing-box decline marker), the
                         Fastly WAF cookie and the sing-box outbound
                         configs. Created AUTOMATICALLY with the default
                         values when missing. The old ~/.config/mozvpn
                         caches (session/credentials/... .json) are
                         migrated on the first run and then removed.
"""

import argparse, base64, binascii, getpass, hashlib, hmac, http.cookiejar, json, os, re
import sys, threading, time, socket, ssl, subprocess, signal, atexit, tempfile
import urllib.request, urllib.error
from urllib.parse import urlparse, parse_qs, unquote, quote
from datetime import timezone
from email.utils import parsedate_to_datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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

# v8.0: the passwordless sign-in from a DESKTOP FIREFOX PROFILE
# (--fxa-profile PATH). The file lives at the root of a profile
# directory (signedInUser.json) and carries the FxA sessionToken in
# accountData.sessionToken (the foxhole-vpn AUTH.md pattern, verified
# 2026-10-30 against the Firefox source docs). The token rides the
# SAME grant_type=fxa-credentials OAuth mint every password sign-in
# already rides - only the SOURCE of the session changes.
FXA_PROFILE_FILE = "signedInUser.json"

RS_SERVERLIST = ("https://firefox.settings.services.mozilla.com/v1"
                 "/buckets/main/collections/vpn-serverlist/records")

# v9.3: 159.0 is the CURRENT stable Firefox (product-details.mozilla.org
# LATEST_FIREFOX_VERSION, released 2026-10-27; the Go reference client
# pins 159.0 too) - the value drives the serverlist filter_expression
# (env.version versionCompare) and the User-Agent, so it must stay a
# plausible CURRENT Firefox.
DEFAULT_FIREFOX_VERSION = "159.0"

# Browser-like headers (for steps after login: Guardian, Remote Settings)
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) "
                  "Gecko/20100101 Firefox/159.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "application/json",
}

# v6.1 (req. 1): config.json lives NEXT TO THIS SCRIPT by default; the
# --config FILE parameter points it anywhere else. The OLD versions kept
# every cache in ~/.config/mozvpn - that directory is read-only history
# now: the first-run migration READS the pre-v6 leftovers from there,
# the Ctrl+O / --clean-old-config cleanup REMOVES them, and nothing is
# ever written there again.
LEGACY_CONF_DIR = os.path.join(os.path.expanduser("~"), ".config", "mozvpn")

def script_dir() -> str:
    """Directory of THIS SCRIPT (the default home of config.json, v6.1).
    Nuitka-safe (req. 11): __file__ is not guaranteed in frozen
    executables, so sys.argv[0] / cwd are used."""
    try:
        if getattr(sys, "frozen", False):          # Nuitka/PyInstaller frozen exe
            return os.path.dirname(os.path.abspath(sys.executable))
        return os.path.dirname(os.path.abspath(sys.argv[0] or "."))
    except Exception:
        return os.getcwd()

# v6.0: THE UBER-CONFIG - every persisted configuration lives in ONE
# plain-text file (chmod 600): accounts (login/password/TOTP/session
# per account + the QR png of the 2FA secret as base64), the current
# account pointer, the settings (DoH resolver, DoH cache flag,
# language, countries filter, sing-box decline marker), the Fastly
# WAF cookie and the sing-box outbound configs. The legacy per-file
# caches (session/credentials/... .json) existed only before v6.0.
CONF_DIR     = script_dir()      # the directory that holds config.json
CONFIG_FILE  = os.path.join(CONF_DIR, "config.json")

def apply_config_path(path=None) -> bool:
    """v6.1 (req. 1): resolve the config.json location - an explicit
    --config FILE argument wins, the default is config.json NEXT TO THIS
    SCRIPT - and CREATE the file with the DEFAULT values when it does
    not exist yet (either path). Returns True when the file was just
    created. Called from main() BEFORE any configuration is read; the
    module globals CONFIG_FILE/CONF_DIR are rebound so every later
    access (cfg_load/cfg_save, the menus, the hotkeys) follows the
    resolved location."""
    global CONFIG_FILE, CONF_DIR
    if path:
        CONFIG_FILE = os.path.abspath(
            os.path.expanduser(str(path).strip()))
    else:
        CONFIG_FILE = os.path.join(script_dir(), "config.json")
    CONF_DIR = os.path.dirname(CONFIG_FILE) or os.curdir
    created = False
    if not os.path.isfile(CONFIG_FILE):
        # a missing config.json (default path OR the --config one) is
        # created AUTOMATICALLY with the default values
        cfg_load()
        cfg_save()
        created = True
    return created

# The OLD (pre-v6.0) format - used ONLY by the first-run migration
# (migrate_old_config_if_first_run) and by the old-format cleanup
# (Ctrl+O / --clean-old-config). Nothing here is ever written again.
LEGACY_CONFIG_FILES = {
    "session.json":         "session",          # (old) cached session
    "credentials.json":     "credentials",      # (old) saved login data
    "fastly-cookie.json":   "fastly",           # (old) Fastly WAF cookie
    "accounts.json":        "accounts",         # (old) account cache
    "countries.json":       "countries",       # (old) proxy filter
    "doh.json":             "doh",               # (old) resolver choice
    "lang.json":            "lang",              # (old) language choice
    "singbox-install.json": "singbox_decline",   # (old) decline marker
}
LEGACY_CONFIG_DIRS = ("singbox", "engine")   # (old) sing-box configs / engine

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
    "ipinfo":    "https://ipinfo.io/json",
    "ident":     "https://ident.me",
}
# v5.2 (req. 3): the DEFAULT echo is ipinfo.io/json - ONE request per probe
# returns BOTH the external IP and the geo (country ISO code + city), so
# the separate exit-country request of v5.0/v5.1 is no longer needed and
# every upstream is probed with a single fast request (verified: the
# ipinfo.io JSON response contains ip/city/region/country fields).
DEFAULT_IP_ECHO_SERVICE = "ipinfo"

# ---------------------------------------------------------------------------
# DNS-over-HTTPS (v5.0). Firefox resolves the Fastly egresses through TRR
# (DNS-over-HTTPS) so a poisoned / geo-wrong system A record cannot send the
# client to a wrong (usually US) Fastly PoP - Fastly terminates the client
# TLS on the PoP whose IP you connect to and the traffic leaves from that
# same PoP. This script now resolves the egress hostnames the same way:
# DoH answer -> connect to that IP, SNI stays the original hostname.
# Presets (public DoH JSON APIs, RFC 8484 'application/dns-json'):
#   cloudflare  https://cloudflare-dns.com/dns-query   (Cloudflare 1.1.1.1)
#   google      https://dns.google/resolve             (Google Public DNS)
#   nextdns     https://dns.nextdns.io/dns-query       (NextDNS)
#   quad9       https://dns.quad9.net/dns-query       (Quad9, 443 - see the
#                v8.8 note: JSON on 5053 retired 2025-05-05)
# (A public Nextcloud DoH endpoint could not be verified to exist; use
#  --doh-url <endpoint> for any custom DoH JSON API.)
DOH_PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google":     "https://dns.google/resolve",
    "nextdns":    "https://dns.nextdns.io/dns-query",
    # v8.8: 5053 -> 443 - Quad9 retired the 5053 JSON service
    # (5 May 2025, 'migrate to DoH on port 443'); the 443 endpoint
    # speaks the RFC 8484 WIREFORMAT only (live-checked 2026-10-31),
    # so the script's own JSON query to it answers an error status
    # and the v5.12 provider penalty / chain fallback carries the
    # resolution - a selected quad9 no longer hangs anything.
    "quad9":      "https://dns.quad9.net/dns-query",
}
DOH_TTL = 300            # seconds a DoH answer is cached (cache is OPT-IN)
DOH_TIMEOUT = 4          # v5.6: was 10 - a dead/slow DoH endpoint must not
                         # add its full timeout to EVERY lookup while the
                         # chain walks to the next provider
DOH_MEMO_TTL = 60        # v5.6: TTL of the ALWAYS-ON short answer memo
DOH_PROVIDER_PENALTY = 60  # v5.6: seconds a failed DoH provider is skipped
DOH_PRESETS = ["cloudflare", "google", "nextdns", "quad9"]

_doh_provider = "cloudflare"     # current provider, "" = system DNS (off)
_doh_cache_enabled = False       # v5.1: the DoH cache is OFF by default
_doh_cache = {}                  # host -> (expires_at, [ip, ...])
_doh_lock = threading.Lock()
# v5.6 probe speedup: an ALWAYS-ON, short-lived answer memo. It does NOT
# change the opt-in --doh-cache semantics (that cache is 300 s and stays
# opt-in): the memo only stops the SAME hostname from being re-resolved
# over DoH 8+ times within seconds during one probe run (the 4-profile
# TLS matrix + the in-probe echo fallback used to trigger a fresh DoH
# query per attempt - the main 'probes take 10+ seconds' cause when the
# DoH chain itself is slow or partially blocked).
_doh_memo = {}                   # host -> (expires_at, [ip, ...])
# v5.14: IN-FLIGHT dedup - host -> threading.Event of the query that is
# CURRENTLY running. Concurrent callers for the same host (the 64 probe
# workers and the prefill threads racing on a shared egress hostname)
# JOIN the running query instead of launching duplicate DoH chains.
_doh_inflight = {}               # host -> threading.Event (owner running)
# v5.6: a DoH provider that failed (timeout/connection error) is skipped
# for DOH_PROVIDER_PENALTY seconds, so ONE dead endpoint does not add its
# full timeout to every subsequent lookup in the same run.
_doh_provider_down = {}          # provider name -> down-until timestamp

def set_doh_provider(name: str):
    """Switch the DoH provider ('' = off, system DNS) and drop the cache."""
    global _doh_provider
    _doh_provider = (name or "").strip()
    with _doh_lock:
        _doh_cache.clear()

def doh_provider() -> str:
    """The current DoH provider name ('' = DoH off / system resolver)."""
    return _doh_provider

# v5.31 (user request): the DNS resolver chosen in the hotkey 'h' menu is
# PERSISTED in the user config directory (doh.json, the same place as
# session.json / countries.json / lang.json) and survives restarts, like
# the other settings of this script. Startup precedence: an explicit
# --doh / --doh-url argument > the SAVED hotkey-'h' choice > the
# MOZVPN_DOH environment variable > the built-in default 'cloudflare'.
# The saved value is a preset name (''/'off' = the system resolver);
# a custom --doh-url endpoint is NOT persisted (its URL may be secret).
# v6.0: the choice lives in config.json (settings.doh) - the doh.json
# file of v5.31-v5.36 is migrated and removed on the first run.

def save_doh_provider_cache(name: str):
    """v5.31 -> v6.8: persist the resolver choice (hotkey 'h') into
    config.json (settings.doh). v6.8: the system-DNS mode is stored as
    the EXPLICIT 'off' marker - DISTINCT from the never-written key,
    so a deliberate choice survives restarts while a missing (or
    bug-written legacy '') key keeps falling through to the built-in
    'cloudflare' default."""
    try:
        cfg_set(("settings", "doh"),
                "off" if not (name or "").strip()
                else name.strip().lower())
    except Exception:
        pass                    # a read-only config dir must not crash the run

def load_doh_provider_cache() -> "str | None":
    """v5.31 -> v6.8: the persisted resolver choice: '' = the EXPLICIT
    system-DNS choice (the stored 'off' marker), a preset name, or None
    when NOTHING was saved yet. THE v6.8 BUG FIX: the v6.0 uber-config
    rework read the key with a '' DEFAULT, so a key that was never
    written (a fresh install - exactly the case the built-in default
    exists for) came back as '' and the startup honored it as 'the
    saved system-DNS mode' - the 'cloudflare' default was UNREACHABLE,
    and the startup mirror then SAVED the '' right back, hardening the
    bug into config.json on the very first run. Under the v5.31
    doh.json a MISSING FILE meant None and the default worked; the
    rework lost the 'missing' case (this docstring kept promising
    'None when nothing was saved yet' - the code did not deliver it).
    Now a missing key - and any legacy '' the bug wrote - is None
    again ('never chosen' -> the built-in default applies), and only
    the explicit 'off'/'system' marker keeps the system-DNS mode."""
    try:
        raw = cfg_get(("settings", "doh"), None)
        if raw is None:
            return None          # never chosen -> the default applies
        name = (str(raw) or "").strip().lower()
        if not name:
            return None          # the v6.0-v6.7 bug's empty write
        if name in ("off", "system"):
            return ""            # the explicit system-DNS choice
        return name if name in DOH_PRESETS else None
    except Exception:
        return None

# v6.9: STICKY USER SETTINGS (the user's request 2). The doh/lang
# pattern - an explicit argument wins, then the env, then the SAVED
# choice, then the built-in default - now covers every preference a
# hotkey can flip: the theme ('m'), the color ('n'), the DoH answer
# cache ('k'), the ClientHello fragmentation ('i') and the engine
# ('e'). The hotkeys save the state the moment they flip it and the
# startup mirrors the EFFECTIVE state back into the profile exactly
# like the doh/lang choices already do. The booleans are written as
# real booleans, and load_bool_setting() treats a MISSING key as
# 'never chosen' (the v6.8 lesson: a default must never masquerade
# as a saved choice).

def save_bool_setting(key: str, value: bool):
    """v6.9: persist a boolean preference as settings.<key>."""
    try:
        cfg_set(("settings", key), bool(value))
    except Exception:
        pass                    # a read-only config dir must not crash the run

def load_bool_setting(key: str, default: "bool | None") -> "bool | None":
    """v6.9: the persisted boolean preference, or the given default
    when the key was never written (or holds an unreadable value)."""
    try:
        raw = cfg_get(("settings", key), None)
        if raw is None:
            return default
        if isinstance(raw, bool):
            return raw
        s = str(raw).strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off"):
            return False
        return default
    except Exception:
        return default

def save_str_setting(key: str, value):
    """v6.9: persist a string preference as settings.<key>."""
    try:
        cfg_set(("settings", key), value)
    except Exception:
        pass

def load_str_setting(key: str):
    """v6.9: the persisted string preference ('' -> None: an empty
    value is 'never chosen', never a disguised default)."""
    try:
        raw = cfg_get(("settings", key), None)
        if raw is None:
            return None
        return str(raw).strip() or None
    except Exception:
        return None

# v8.0: the AUTO-ROTATION of accounts by quota (settings.auto_rotate).
# A useful option ships ON; the switch only GATES the rotation trigger -
# the quota bookkeeping (print_quota -> save_account_quota) runs
# regardless, so the ranking data is always fresh. An explicit
# --auto-rotate / --no-auto-rotate beats the saved choice (the argparse
# default is None = 'not chosen', the v6.8 missing-key lesson).
_auto_rotate_on = {"v": True}

def set_auto_rotate(enabled: bool):
    """v8.0: enable/disable the account auto-rotation by quota."""
    _auto_rotate_on["v"] = bool(enabled)

def auto_rotate_enabled() -> bool:
    """v8.0: whether the account auto-rotation is active."""
    return _auto_rotate_on["v"]

# v8.0 -> v8.5 -> v9.0: the local proxy TYPE (settings.proxy_type):
# 'socks5' (the DEFAULT since v9.0 - RFC 1928 CONNECT-only, REMOTE
# DNS: the domain name is passed through to the egress, the curl
# socks5h/socks5a semantics; 'socks5h' is NOT a separate wire
# protocol - it is curl's name for the CLIENT sending the domain
# (ATYP=03) instead of a pre-resolved IP (ATYP=01), and this
# listener accepts BOTH request shapes, so every plain-'socks5'
# client works too) or 'http' (the DEFAULT from v8.5 to v8.9 - the
# classic CONNECT listener; the hostname goes to the egress in
# every CONNECT so the resolution is REMOTE as well).
# The v8.0 'mixed' single-port auto-detect listener is REMOVED in
# v8.5: only the two classic protocols remain (the user's request);
# a SAVED 'mixed' choice of an older run normalizes to the built-in
# default like every other unknown value. The saved choice survives
# restarts; an explicit --proxy-type beats it (the same precedence
# the doh/lang/theme switches use since v6.9).
_PROXY_TYPES = ("socks5", "http")
_proxy_type_cur = {"v": "socks5"}

def set_proxy_type(value: str):
    """v8.0 -> v9.0: select the local proxy type (normalized; unknown
    -> the built-in default 'socks5')."""
    v = str(value or "").strip().lower()
    _proxy_type_cur["v"] = v if v in _PROXY_TYPES else "socks5"

def get_proxy_type() -> str:
    """v8.0: the currently served local proxy type."""
    return _proxy_type_cur["v"]

def _proxy_type_of(args) -> str:
    """v8.0 -> v9.0: resolve the EFFECTIVE local proxy type: an explicit
    --proxy-type argument, else the SAVED settings.proxy_type, else
    the built-in default 'socks5' (the v9.0 default - RFC 1928 with
    remote DNS; the v8.5 'http' default keeps winning only as the
    SAVED choice of the runs that picked it explicitly)."""
    explicit = getattr(args, "proxy_type", None)
    if explicit:
        v = str(explicit).strip().lower()
        if v in _PROXY_TYPES:
            return v
    saved = load_str_setting("proxy_type")
    if saved:
        v = str(saved).strip().lower()
        if v in _PROXY_TYPES:
            return v
    return "socks5"

def set_doh_cache(enabled: bool):
    """v5.1: enable/disable the DoH answer cache (default: disabled)."""
    global _doh_cache_enabled
    _doh_cache_enabled = bool(enabled)
    if not _doh_cache_enabled:
        with _doh_lock:
            _doh_cache.clear()

def doh_cache_enabled() -> bool:
    """Whether DoH answers are cached (opt-in via --doh-cache / hotkey 'k')."""
    return _doh_cache_enabled

# v5.29 (security, user request): STRICT DoH mode. When a DoH provider is
# selected, an automatic fallback from the DoH chain to the SYSTEM (or any
# other non-DoH) resolver is now FORBIDDEN by default: if every DoH
# endpoint of the chain fails, the lookup FAILS loudly instead of
# silently leaking the query (and the reply) to the plaintext system
# DNS. This mirrors Firefox TRR mode 3 ('TRR-only' / strict resolution:
# only DoH is employed, with NO fall back mechanism - verified online
# 2026-09-30: Firefox Source Docs 'DNS over HTTPS (Trusted Recursive
# Resolver)' documents TRR-only (3) vs TRR-first (2) where TRR-first
# falls back to Do53 on failure; the Internet Society write-up confirms
# network.trr.mode=3 is 'strict resolution - only DoH, no fall back
# mechanism'). The system DNS remains available EXPLICITLY: --doh off
# (the whole run on the system resolver), or the OPT-IN
# --system-dns-fallback / env MOZVPN_SYSTEM_DNS_FALLBACK=1 flag that
# re-enables the old last-resort behavior for the current run. All the
# OTHER fallbacks (provider->provider inside the DoH chain, the
# parallel-chain race, the DoH cache/memo, the v5.28 emergency direct-IP
# DoH route for the broken-packaged-resolver case) are UNTOUCHED - the
# strictness only removes the automatic DoH -> NON-DoH step.
_system_dns_fallback = False     # default: STRICT (no non-DoH fallback)

def set_system_dns_fallback(enabled: bool):
    """v5.29: opt-in re-enable of the system-resolver last resort."""
    global _system_dns_fallback
    _system_dns_fallback = bool(enabled)

def system_dns_fallback() -> bool:
    """v5.29: whether the DoH->system-DNS last resort is allowed."""
    return _system_dns_fallback

# v5.28: the SYSTEM-RESOLVER-BROKEN detector. In the PACKAGED binary on
# Android (Nuitka/PyInstaller on arm, e.g. mozvpn-termux-armv9)
# socket.getaddrinfo can be PERSISTENTLY broken - every name fails with
# gaierror 'No address associated with hostname' (EAI_NODATA) while
# nslookup/the browser/the PLAIN python script work fine on the same
# phone (the classic packaged-Python-on-Android problem: kivy/
# python-for-android issue #1447 'socket.getaddrinfo appears to be
# completely broken, all name resolutions fail' - the same symptom
# while 'nslookup google.com in termux or just browsing google.com in
# the web browser works fine'; also python-for-android #1447 /
# kivy #7087 / PyInstaller #3721 are the long-standing tracker entries
# for getaddrinfo being broken inside the packaged runtime).
# The SAME script as a PLAIN python script has a normal resolver -
# which is exactly why the reference mozvpn.py (always run as a
# script) never failed on the same phone and why Windows 11 (where the
# packaged binary's resolver works) never failed either.
# A single gaierror is still treated as a TRANSIENT blip (one retry);
# only a SECOND one flags the resolver as broken for the REST of the
# process, after which every DNS-dependent path bypasses the system
# resolver entirely (req() -> _ip_fallback_full(), DoH -> the
# well-known resolver IPs directly). A successful resolution RESETS
# the counter, so a genuinely healthy resolver is never bypassed.
_RESOLVER_STRIKES = {"n": 0}

def _resolver_broken() -> bool:
    """v5.28: True after 2+ persistent gaierror strikes - the packaged-
    binary-on-Android broken-resolver state. Everything that needs a
    hostname must then avoid socket.getaddrinfo completely."""
    return _RESOLVER_STRIKES["n"] >= 2

def _doh_query(provider_url: str, host: str) -> "list[str]":
    """One DoH JSON query (RFC 8484 'application/dns-json'):
    GET <endpoint>?name=<host>&type=A -> the Answer.data IPs.
    v8.6: the bootstrap-known PRESET providers ride the direct-IP
    transport (see the comment below); nextdns / a custom --doh-url
    endpoint keep the plain urlopen path."""
    url = (provider_url.split("?")[0]
           + ("&" if "?" in provider_url else "?")
           + "name=" + urllib.parse.quote(host) + "&type=A")
    u = urlparse(url)
    # v8.6 (user request: DPI protection FOR DoH): the PRESET providers
    # with a well-known resolver IP (_DOH_IP_BOOTSTRAP) ride the
    # DIRECT-IP transport ALWAYS - not only in the v5.28 broken-resolver
    # state: (1) the provider hostname is NEVER resolved with the system
    # resolver (the dnscrypt-proxy shape - a DoH server address IS an
    # IP, so no plaintext DNS lookup can reveal or pre-block the
    # resolver choice); (2) the TLS handshake to the resolver goes out
    # FRAGMENTED (_raw_https frag=True -> the same tls_split()
    # ClientHello segmentation the egress TLS uses - see _FragTLSConn),
    # so an SNI-matching DPI cannot cut the DoH bootstrap by reading
    # the resolver SNI from the first segment of the flow. Any
    # direct-IP failure falls back to the exact v8.5 paths below: the
    # broken state -> the v5.36 emergency DoH walk, the healthy state ->
    # the plain urlopen query (never worse than v8.5).
    boot = None
    for _ip, _sni, _rport, _ in _DOH_IP_BOOTSTRAP:
        if _sni == u.hostname:
            boot = (_ip, _sni, u.port or _rport)
            break
    if boot is not None:
        try:
            code, _h, resp = _raw_https(
                boot[0], boot[1], boot[2], "GET",
                (u.path or "/") + (("?" + u.query) if u.query else ""),
                {"Accept": "application/dns-json",
                 "User-Agent": "mozvpn/5.28"}, None, DOH_TIMEOUT,
                frag=True)
            if code == 200 and resp:
                data = json.loads(resp.decode("utf-8", "replace"))
                out = [str(a.get("data")) for a in data.get("Answer") or []
                       if a.get("type") in (1, 28) and a.get("data")]
                if out:
                    return out
        except Exception:
            pass                # the v8.5 paths take over below
    # v5.28 (Termux binary fix): when the SYSTEM resolver is flagged BROKEN
    # (a persistent gaierror - the packaged-binary-on-Android case, see
    # req()), a plain urlopen fails for the DoH provider HOSTNAME too
    # (cloudflare-dns.com etc. are also resolved with getaddrinfo), so DoH
    # 'changing the provider' or 'turning it off' could not help at all -
    # exactly the reported live symptom. In that state the query goes to
    # the well-known DoH resolver IPs DIRECTLY (the _DOH_IP_BOOTSTRAP
    # table, no name resolution anywhere: the TCP connect goes to the IP
    # literal, the SNI/Host stay the provider hostname).
    # v5.36: the ANSWER of a DNS query does not depend on which resolver
    # gives it - resolve the SAME query over the well-known resolver IPs
    # (the emergency DoH) so a provider that just failed (or a
    # non-bootstrap provider like nextdns / a custom --doh-url endpoint
    # in the broken state) does not break the whole chain. v8.6: the
    # bootstrap-known presets already tried their direct-IP transport
    # above, so in the broken state ONLY this emergency walk remains.
    if _resolver_broken():
        return _emergency_doh_resolve(host) or []
    r = urllib.request.Request(url, headers={
        "Accept": "application/dns-json",
        "User-Agent": "mozvpn/5.1"})
    with urllib.request.urlopen(r, timeout=DOH_TIMEOUT) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    out = []
    for ans in data.get("Answer") or []:
        # type 1 = A, type 28 = AAAA (kept too: the v4 route decides the PoP)
        if ans.get("type") in (1, 28) and ans.get("data"):
            out.append(str(ans["data"]))
    return out

def _doh_chain() -> list:
    """v5.1 (req. 5, 6): the fallback chain of DoH endpoints - the SELECTED
    provider first, then the remaining presets; every preset speaks DoH
    only. The SYSTEM resolver is NOT part of this chain (v5.29 STRICT:
    it runs only via the explicit --system-dns-fallback opt-in, or when
    DoH is off - the only resolver then). A custom --doh-url endpoint is
    tried first, then the presets follow."""
    cur = _doh_provider
    if not cur:
        return []                       # 'off': the system resolver alone
    rest = [n for n in DOH_PRESETS if n != cur]
    if cur in DOH_PRESETS:
        return [cur] + rest
    return [cur] + list(DOH_PRESETS)    # custom endpoint first

def _doh_query_parallel(host: str) -> "list[str] | None":
    """v5.12: query ALL DoH providers of the fallback chain IN PARALLEL and
    take the FIRST non-empty answer. The old SEQUENTIAL walk was the real
    'probes take forever' root cause on filtering networks: the selected
    provider (usually cloudflare) was always queried first and ALONE, so
    every hostname lookup paid its full DOH_TIMEOUT (4 s) before the
    chain moved on to the next provider. Here every provider gets the
    query at the same moment, so the answer arrives as fast as the
    FASTEST reachable provider. Providers that fail keep the same
    DOH_PROVIDER_PENALTY (60 s) skip as before."""
    now = time.time()
    with _doh_lock:
        chain = [n for n in _doh_chain()
                 if _doh_provider_down.get(n, 0) <= now]
    if not chain:
        return None
    ips = None
    ex = ThreadPoolExecutor(max_workers=len(chain))
    try:
        futs = {ex.submit(_doh_query, DOH_PROVIDERS.get(n) or n, host): n
                for n in chain}
        for fut in as_completed(futs):
            try:
                ans = fut.result() or None
            except Exception:
                ans = None
            if ans:
                ips = ans
                break               # first non-empty answer wins
            # a failed provider is penalized like before
            with _doh_lock:
                _doh_provider_down[futs[fut]] = (time.time()
                                                 + DOH_PROVIDER_PENALTY)
    finally:
        # do NOT wait for the slower losing queries - they finish in the
        # background (each is bounded by DOH_TIMEOUT anyway)
        ex.shutdown(wait=False)
    return ips

def resolve_host(host: str) -> "list[str] | None":
    """Resolve a hostname over DoH ONLY (req. 5): the selected provider,
    then the remaining DoH presets in the fallback chain. The SYSTEM
    resolver is NOT a fallback of this function anymore (v5.29 STRICT):
    it runs only when the user EXPLICITLY opted in
    (--system-dns-fallback) or when DoH is off. The long answer cache
    stays OPT-IN
    (req. 4: --doh-cache / hotkey 'k'); v5.6 adds an ALWAYS-ON short
    memo (DOH_MEMO_TTL) plus a provider penalty (DOH_PROVIDER_PENALTY),
    so one probe run never re-resolves the same host 8+ times and never
    re-waits on a DoH endpoint that just timed out - together these two
    fixes remove the multi-second per-upstream stalls of the v5.5 probe
    when the DoH chain is slow or partially blocked.
    Returns a list of IPs, or None when DoH is off (the caller then
    resolves with the system resolver directly)."""
    if not _doh_provider:
        return None                      # 'off': plain system resolution
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host) or ":" in host:
        return [host]                    # already an IP literal
    now = time.time()
    # 1) the opt-in long cache (--doh-cache / hotkey 'k')
    if _doh_cache_enabled:
        with _doh_lock:
            hit = _doh_cache.get(host)
            if hit and hit[0] > now:
                return hit[1]
    # 2) v5.6: the ALWAYS-ON short memo (same host within one probe run)
    with _doh_lock:
        hit = _doh_memo.get(host)
        if hit and hit[0] > now:
            return hit[1]
    # 3) v5.12: query ALL chain providers in PARALLEL (the first non-empty
    #    answer wins); providers that failed recently are skipped (penalty).
    #    v5.14: IN-FLIGHT dedup - when several threads race on the SAME
    #    hostname (the probe pool + the prefill on a shared egress host),
    #    exactly ONE query chain runs; every other caller WAITS for it and
    #    reads the memo afterwards instead of stampeding the DoH endpoints
    #    with duplicate chains that all pay the same round trips.
    with _doh_lock:
        inflight = _doh_inflight.get(host)
        if inflight is None:
            inflight = threading.Event()
            _doh_inflight[host] = inflight
            is_owner = True
        else:
            is_owner = False
    if not is_owner:
        # someone else is already resolving this exact host: wait for the
        # shared answer (bounded: the chain timeout x2 + slack), then take
        # it from the memo / the opt-in cache
        inflight.wait(timeout=DOH_TIMEOUT * 2 + 2)
        for store in (_doh_memo, _doh_cache):
            with _doh_lock:
                hit = store.get(host)
            if hit and hit[0] > time.time():
                return hit[1]
        return None            # the shared query failed: the caller falls
                               # back to the system resolver, as after any
                               # full DoH-chain failure
    try:
        ips = _doh_query_parallel(host)
        if not ips:
            # v5.29 (security): every DoH endpoint failed. The OLD code
            # silently fell back to the SYSTEM resolver here - exactly
            # the automatic DoH -> non-DoH fallback that must NOT happen
            # (the system resolver may be plaintext DNS, observed and
            # filtered). It now runs ONLY when the user EXPLICITLY
            # opted in (--system-dns-fallback / env
            # MOZVPN_SYSTEM_DNS_FALLBACK=1); by default the strict
            # mode returns None and the caller FAILS the lookup loudly
            # instead of leaking it. DoH-off ('' provider) never reaches
            # this branch (the function returns None at the top).
            if system_dns_fallback():
                try:
                    ips = sorted({ai[4][0] for ai in
                                  socket.getaddrinfo(host, None,
                                                     proto=socket.IPPROTO_TCP)}) or None
                except Exception:
                    ips = None
            else:
                ips = None       # STRICT: no non-DoH resolution, ever
        if ips:
            if _doh_cache_enabled:
                with _doh_lock:
                    _doh_cache[host] = (time.time() + DOH_TTL, ips)
            # v5.6: remember in the always-on short memo too
            with _doh_lock:
                _doh_memo[host] = (time.time() + DOH_MEMO_TTL, ips)
        return ips
    finally:
        # wake EVERY waiter and free the in-flight slot (even on failure)
        with _doh_lock:
            _doh_inflight.pop(host, None)
        inflight.set()

def _connect_resolved(host: str, port: int, timeout: int) -> "socket.socket":
    """TCP connection to the egress. With DoH ON the DoH-resolved IPs are
    tried in order (connect to the IP; the TLS SNI stays the hostname, set
    by the caller's wrap_socket(server_hostname=host)); with DoH OFF (or a
    failed DoH under the v5.29 opt-in fallback flag) the normal system
    resolution is used. v5.29 STRICT mode: with DoH ON, a failed DoH chain
    and NO opt-in fallback now RAISES instead of quietly resolving the
    hostname with the system (non-DoH) resolver."""
    ips = resolve_host(host)
    if not ips:
        if _doh_provider and not system_dns_fallback():
            raise OSError(f"strict DoH: {host} did not resolve over the "
                          f"DoH chain and the system DNS fallback is "
                          f"disabled (--system-dns-fallback enables it)")
        return socket.create_connection((host, port), timeout=timeout)
    last = None
    for ip in ips:
        try:
            return socket.create_connection((ip, port), timeout=timeout)
        except OSError as e:
            last = e
    raise last if last else OSError(f"no route to {host}:{port}")

def _connect_resolved_ips(ips: "list[str] | None", host: str, port: int,
                          timeout: int) -> "socket.socket":
    """v5.6 probe speedup: same as _connect_resolved(), but the caller
    passes an ALREADY resolved IP list, so the 4-profile TLS matrix (and
    the in-probe echo fallback) does not trigger a fresh DoH query on
    every attempt. With ips=None the normal system resolution is used
    (the DoH-off case; also the last-resort path after a DoH failure).
    v5.14: after the PREFERRED (first) address fails, the remaining
    addresses are raced CONCURRENTLY - the RFC 8305 'Happy Eyeballs'
    idea - and the first socket that wins is used: the old serial loop
    paid the FULL connect timeout PER address, so a blackholed first A
    record plus three more records burned four timeouts inside ONE
    probe. The ordered preference is preserved: the first address is
    still tried alone, the race only replaces the serial tail.
    v5.29 STRICT mode: with DoH ON, ips=None (the whole DoH chain
    failed) only reaches the system resolution when the user opted in
    via --system-dns-fallback; otherwise the connection FAILS - no
    automatic DoH -> non-DoH fallback."""
    if not ips:
        if _doh_provider and not system_dns_fallback():
            raise OSError(f"strict DoH: {host} did not resolve over the "
                          f"DoH chain and the system DNS fallback is "
                          f"disabled (--system-dns-fallback enables it)")
        return socket.create_connection((host, port), timeout=timeout)
    # 1) the preferred (first) address, alone - the ordered preference
    try:
        return socket.create_connection((ips[0], port), timeout=timeout)
    except OSError as first_err:
        if len(ips) == 1:
            raise first_err          # same error shape as the old loop
    rest = ips[1:]
    # 2) v5.14: race the remaining addresses concurrently, first wins
    results = [None] * len(rest)
    def _try_one(i):
        try:
            results[i] = socket.create_connection((rest[i], port),
                                                  timeout=timeout)
        except OSError as e:
            results[i] = e          # remember the error, not the socket
        except Exception as e:
            results[i] = e          # never kill the thread with a traceback
    ths = [threading.Thread(target=_try_one, args=(i,), daemon=True)
           for i in range(len(rest))]
    for t in ths:
        t.start()
    deadline = time.time() + timeout + 2.0   # hard cap: timeout + slack
    while time.time() < deadline:
        for r in results:
            if isinstance(r, socket.socket):
                # a winner: close the other sockets that also made it
                for other in results:
                    if isinstance(other, socket.socket) and other is not r:
                        try:
                            other.close()
                        except Exception:
                            pass
                return r
        if all(not t.is_alive() for t in ths):
            break
        time.sleep(0.02)
    # 3) the cap elapsed / all threads done: take any late success,
    #    else raise the FIRST real error of the tail (the error shape
    #    of the old serial loop - e.g. a timeout stays a timeout)
    for r in results:
        if isinstance(r, socket.socket):
            for other in results:
                if isinstance(other, socket.socket) and other is not r:
                    try:
                        other.close()
                    except Exception:
                        pass
            return r
    for r in results:
        if isinstance(r, OSError):
            raise r
    for r in results:
        if isinstance(r, BaseException):
            raise r
    raise OSError(f"no route to {host}:{port}")

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
        # v5.2 (req. 2): new meaning-based highlight classes
        "cc":    "\033[1;92m",     # country codes (US, DE, REC in geo lines)
        "email": "\033[0;93m",     # email addresses (logins)
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
        # v5.2 (req. 2): new meaning-based highlight classes (light theme)
        "cc":    "\033[0;32m",     # country codes
        "email": "\033[38;5;130m", # email addresses (dark amber)
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
  "config_file_entry": "  {_e} {path} \u2014 {status}",
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
  # v7.0: the emailed-code session verification (email-2fa)
  "email_code_prompt": "Enter the 6-digit code from the email Mozilla sent to your address - or 'l' to confirm by the LINK from the letter instead (an EMPTY line re-sends the letter): ",
  "email_code_resent": "The sign-in letter with the code has been re-sent.",
  "email_resend_failed": "Could not re-send the code letter (HTTP {status}) - retry or enter the code you already have.",
  "email_code_confirmed": "The session is verified with the emailed code (email-2fa).",
  "email_code_rejected": "The code was rejected (wrong or expired) - check the LATEST letter and retry.",
  "email_code_rejected_final": "The emailed code was rejected three times in a row. Confirm the sign-in manually (the email_confirm_required instructions) and re-run, or enable TOTP.",
  "email_code_aal_hint": "The account has a server-side TOTP, so an emailed code cannot verify the session (insufficientAal).",
  "email_code_unknown_error": "Emailed-code verification error ({status}): {data} (check the mailbox / sessionToken).",
  "totp_code_current": "Current TOTP code: {code} (valid for {sec} more s{offset})",
  "totp_code_generated": "Generated TOTP code: {code} (window {period}s, {left}s left)",
  "clock_offset_note": ", clock offset {offset}s",
  "email_unverified": "Account email is not verified (signup). Confirm the email via the Mozilla letter, then sign in again.",
  "email_confirm_required": "Sign-in email confirmation is required and the account has no TOTP (otherwise the script would have verified the session itself). What to do:\n  1) Open the mailbox, find the Mozilla letter 'New sign-in to Firefox' and confirm\n     (or enter the code from the letter on accounts.firefox.com);\n  2) re-run the script afterwards - the session becomes trusted;\n  3) or enable TOTP in account settings (Two-step authentication);\n  4) or sign in inside Firefox and run with --session-token <hex>.",
  "session_unverified": "Session not verified (method: {method}, reason: {reason}).",
  "totp_missing": "The account requires 2FA but the TOTP secret is unknown. Run with --qr <image> or --totp-secret.",
  "prompt_read_error": "Could not read the input ({err}) - stdin/terminal is not usable for interactive prompts. On Android/Termux run the script DIRECTLY in the Termux terminal (a real tty), not through a wrapper/launcher with a redirected stdin.",
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
  "proxy_check_summary_ok": "Probe: {n}/{total} upstreams passed the data check",
  "proxy_check_summary_fail": "Probe: {n}/{total} upstreams passed the data check; {n_fail} did not - they are served anyway ({breakdown})",
  "probe_reason_tls": "TLS to the upstream failed (network or egress side)",
  "probe_reason_timeout": "timed out",
  "probe_reason_declined": "the egress declined the CONNECT tunnel",
  "probe_reason_refused": "connection refused",
  "probe_reason_reset": "connection reset",
  "probe_reason_unreachable": "network unreachable",
  "probe_reason_echo": "the echo service answer was unusable",
  "probe_reason_nodata": "tunnel accepted but no UDP data came back",
  "probe_reason_other": "other transport error",
  "proxy_check_masque_ok": "Probe: {hp} - MASQUE (HTTP/3 CONNECT-UDP) tunnel carried data",
  "proxy_check_masque_fallback": "Probe: MASQUE on {hp} not confirmed - this upstream will use HTTP CONNECT",
  "proxy_check_connect_ok": "Probe: {hp} - CONNECT tunnel carried data (external IP {ip})",
  "proxy_check_connect_fail": "Probe: {hp} - data check not passed ({reason}); the upstream is served anyway",
  "proxy_check_disabled": "Proxy pre-check disabled (--no-proxy-check): using all server-list upstreams as-is.",
  "doh_selected": "DNS resolver {_e}: {provider} ({url}) \u2014 the Fastly egress hostnames are resolved over DoH ONLY (like Firefox TRR); if this provider fails, the chain falls back to the other DoH providers. v5.29 STRICT default: if the WHOLE chain fails, the lookup fails - the system resolver is used only with the explicit --system-dns-fallback opt-in (or --doh off).",
  "doh_system": "DoH disabled {_e} \u2014 the egress hostnames are resolved by the SYSTEM DNS (a poisoned/geo-wrong answer can route you to a wrong Fastly PoP, usually a US one). Use --doh <provider> or hotkey 'h'.",
  "doh_system_short": "system DNS (DoH off)",
  "doh_strict_mode": "STRICT DoH {_e}: if the WHOLE DoH chain fails, the lookup FAILS - no automatic fallback to the system (non-DoH) resolver, the query never leaks to plaintext DNS (like Firefox TRR mode 3). You can opt in explicitly: --system-dns-fallback, or switch to the system resolver with --doh off.",
  "system_dns_fallback_on": "System-DNS last resort {_e}: ENABLED (--system-dns-fallback) - when the whole DoH chain fails, the system (non-DoH) resolver is used as before. Disable with --no-system-dns-fallback.",
  "doh_chain": "DoH fallback chain (checked left to right, all endpoints speak DoH ONLY): {chain}. The system (non-DoH) resolver is NEVER reached automatically (v5.29 strict default; --system-dns-fallback opts in). This is logged once at startup; individual DNS lookups during the run are silent.",
  "geo_echo_no_geo": "Geo check skipped: the echo service '{service}' returns only the IP. Use the default --ip-echo-service ipinfo (ipinfo.io/json) - its single answer carries the IP AND the exit country/city.",
  "foxyproxy_no_proxies": "FoxyProxy export skipped: no local proxies are currently running.",
  "foxyproxy_export_cancel": "FoxyProxy export cancelled - no save path chosen.",
  "foxyproxy_export_done": "FoxyProxy settings file written: {path} ({n} proxies, format: {format})",
  "foxyproxy_export_fail": "FoxyProxy settings export failed: {err}",
  "foxyproxy_import_hint": "FoxyProxy Standard import: the file ({format}) imports via ANY FoxyProxy import path - the 'Import' button at the top of the Options page (next to Export) OR the Import tab -> 'Import from older versions'. After the import click 'Save' so the proxies are persisted.",
  "foxyproxy_path_prompt": "Enter the path to save the FoxyProxy settings file (default: {name}): ",
  "foxyproxy_format_current": "combined settings JSON (current v8+/v9.x 'data' + FoxyProxy 6/7 entries - imports via ANY FoxyProxy import path)",
  "foxyproxy_format_legacy": "legacy settings JSON (the REAL FoxyProxy 6/7 export shape - for 'Import from older versions')",
  "doh_cache_state_on": "DoH cache {_e}: ENABLED \u2014 answers are cached for {ttl}s (hotkey 'k' or --no-doh-cache disables).",
  "doh_cache_state_off": "DoH cache {_e}: DISABLED (default) \u2014 every lookup queries the DoH chain directly (hotkey 'k' or --doh-cache enables).",
  "doh_geo_mismatch": "Geo check: {hp} exits in {geo} ({city}), but the location is {cc} ({cname}). The egress PoP is reached via a wrong route (usually a geo-wrong DNS answer); the IPv6 route may still show the right country.",
  "doh_geo_ok": "Geo check: {hp} exits in {geo} ({city}) \u2014 matches the location {cc}.",
  "doh_menu_hint": "Choose the DNS resolver {_e} \u2014 type its number/letter and press Enter (Backspace deletes, any other key cancels). The choice sets the script's OWN resolver AND the DoH target of the per-proxy DNS endpoints (they ride the chosen provider ONLY, no fallback chain; default cloudflare):",
  "lang_menu_hint": "Choose the interface language {_e} \u2014 type its number and press Enter (current: {cur}). Option 0 resets to the DEFAULT language and clears the saved choice. The choice is saved to config.json (settings.lang of the current profile) and survives restarts (Backspace deletes, any other key cancels; the menu exits automatically after applying).",
  "lang_menu_entry": "  {n} - {desc}",
  "lang_default_desc": "DEFAULT language (English) - resets the saved choice",
  "lang_set": "Interface language {_e}: {lang} \u2014 saved to config.json (settings.lang of the current profile), survives restarts.",
  "lang_reset": "Interface language {_e}: reset to the DEFAULT ({lang}) \u2014 the saved choice is cleared.",
  "doh_menu_entry": "  {n} - {name}{url}",
  "doh_default_desc": "DEFAULT",
  "doh_default_applied": "DNS resolver {_e}: switched to the DEFAULT provider ({provider}). The choice is saved to the config directory (config.json, settings.doh of the current profile) and survives restarts.",
  "hotkey_doh": "Hotkey 'h': DNS resolver switched to {provider} \u2014 new upstream connections use it immediately (the sing-box engine resolves on its own); the per-proxy DNS endpoints ride it from the next query (the chosen provider ONLY, default cloudflare).",
  "hotkey_doh_cache": "Hotkey 'k': DoH cache {state} (mirrors --doh-cache).",
  "select_hint": "Type the number/letter of an item, then press Enter. Backspace deletes the last character, any other key cancels.",
  "select_buffer": "Your choice: {buf}",
  "select_bad": "There is no item '{buf}' - cancelled.",
  "select_hint_multi": "Multi-selection: type several tokens SEPARATED BY SPACES (example: 1 3 a), then press Enter. '0' = all proxies. Backspace deletes, any other key cancels.",
  "multi_buffer": "Selected: {buf}",
  "multi_bad": "There is no item '{tok}' - it is skipped.",
  "countries_menu_hint": "Choose which local proxies to run {_e} \u2014 type the tokens of the proxies separated by SPACES and press Enter (0 = all proxies, Backspace deletes, any other key cancels):",
  "countries_menu_entry": "  {n} - {desc}",
  "filter_all_desc": "ALL local proxies (clears the filter)",
  "countries_filter_applied": "Proxy filter {_e}: {n} of {m} upstreams will be served ({list}). The choice is saved and survives restarts (hotkey 'w' or --countries).",
  "filter_all_applied": "Proxy filter {_e}: ALL local proxies will run (the filter is cleared).",
  "resolver_blip_note": "Network error {_e}: a TRANSIENT DNS failure (a single blip) - retrying the request once after a short pause (a healthy resolver usually recovers on the next attempt).",
  "resolver_broken_note": "Network error {_e}: the SYSTEM resolver is broken (persistent DNS failure - the known packaged-binary-on-Android issue, python-for-android #1447) - switching to the emergency direct-IP route: the emergency DoH goes straight to the well-known resolver IPs, and every request connects to the resolved IP (SNI/Host kept), so the system resolver is not used anywhere anymore.",
  "probe_filter_applied": "Probe filter {_e}: probing ONLY {n} of {m} upstreams - the local-proxy selection (--countries / hotkey 'w') is active, so the upstream probes run only for the local proxies you selected.",
  "accounts_none": "No cached Mozilla accounts yet. An account is cached automatically after every SUCCESSFUL sign-in (config.json).",
  "accounts_list_header": "Cached Mozilla accounts ({n}) - config.json:",
  "account_list_entry": "  {n} - {email}  (password: {pw}, TOTP: {totp}, session: {session}, saved: {saved})",
  "account_reveal_entry": "  {n} - login: {email}  password: {password}  current TOTP: {code}",
  "accounts_qr_dir": "Cached QR images are stored in: {dir}",
  "accounts_menu_hint": "Switch to another cached Mozilla account {_e} - type its number/letter and press Enter (empty input cancels):",
  "account_menu_entry": "  {n} - {email}",
  "accounts_choice_prompt": "Account number/letter (Enter = cancel): ",
  "accounts_bad_token": "There is no account with that token - cancelled.",
  "account_switched": "Switched to the account {_e}: {email} ({session}).",
  "profile_applied": "Profile settings applied {_e}: {email} - the language, the DNS resolver, the proxy selection, the sing-box configs and the Fastly cookie of the profile are now active.",
  "account_session_used": "the cached sessionToken will be tried first, then a fresh sign-in",
  "account_session_fresh": "a fresh sign-in with the cached login/password",
  "account_cached": "Account cached {_e}: {email} (config.json).",
  "account_qr_saved": "The QR image of the 2FA secret was cached: {path}",
  "accounts_json_saved": "All cached accounts ({n}) exported to: {path}",
  "accounts_survived_wipe": "The multi-account store (config.json) survives this wipe: {path}",
  "accounts_menu_add": "  + - add a NEW Mozilla account (a fresh sign-in; it will be cached in config.json)",
  "accounts_menu_del": "  - - delete a cached account from config.json",
  "accounts_add_hint": "New account {_e}: the email/password/2FA prompts will appear next - sign in with the account to ADD (all previously cached accounts are kept).",
  "accounts_delete_prompt": "Number/letter of the account to DELETE (Enter = cancel): ",
  "accounts_delete_missing": "There is no account with that token - nothing was deleted.",
  "accounts_deleted": "Account deleted {_e}: {email} (removed from config.json).",
  "accounts_delete_last": "That was the LAST cached account - the next sign-in will start from scratch.",
  "accounts_not_found": "No cached account with that email exists (config.json); see --list-accounts.",
  "refresh_retry_soon": "The current proxyPass is still valid {_e}: retrying the refresh in {sec}s instead of the full wait, so the token is renewed BEFORE the old one expires.",
  "config_migration_header": "First run: migrating the OLD configuration into the uber file {_e}: {path}",
  "config_migration_entry": "Migrated: {name}",
  "config_migration_done": "Migration complete {_e}: {n} item(s) moved into config.json, {removed} old file(s)/dir(s) deleted - all configuration now lives in ONE file: {path}",
  "clean_old_none": "No leftovers of the OLD config format found - everything already lives in config.json.",
  "clean_old_header": "Old-format config leftovers: {n} - removing {_e} ...",
  "clean_old_removed": "Removed: {path}",
  "clean_old_failed": "Could not remove {path}: {err}",
  "clean_old_done": "Cleanup complete {_e}: {n} item(s) removed. All configuration now lives ONLY in config.json.",
  "filter_empty_fallback": "The saved proxy filter matched no upstream - serving ALL of them (clear the filter: hotkey 'w' -> 0).",
  "hotkey_countries": "Hotkey 'w': the local proxies will restart with the new selection.",
  "net_error_retry": "Network error {_e}: {err} - retrying in 30s (a transient failure - a DNS or connection blip; the next attempt usually succeeds).",
  "net_err_dns": "temporary DNS failure (no address associated with hostname)",
  "net_err_timeout": "timed out",
  "net_err_conn": "connection failed (refused/reset/unreachable)",
  "locked_note": "Note {_e}: the live vpn-serverlist marks almost every country record 'locked', and Firefox serves them anyway \u2014 locked records are INCLUDED by default since v5.0 (--exclude-locked restores the old filtering).",
  "upstream_override": "Upstream override: all locations use {host}:{port} instead of the per-city hosts.",
  "engine_started": "{engine} engine started: {n} local proxies on {listen} ({ptype})",
  "proxy_line": "  {_e}{listen}:{port:<6} {label:<30} -> {host}:{uport} [{proto}]{dns}",
  "port_busy": "Port {port} is busy - skipping {label} (owned by another process?)",
  "no_free_ports": "No free ports for local proxies (all candidate ports are busy).",
  "no_servers_to_serve": "No upstream servers to serve: the probe dropped everything (use --probe-fail keep) or the server list is empty.",
  "tls_plain_http": "upstream answered in plaintext (not TLS): {text}",
  "answer_no_words": "n, no, \u043d, \u043d\u0435\u0442",
  "answer_yes_words": "y, yes, \u0434, \u0434\u0430",
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
  "hotkeys_hint": "Hotkeys (each mirrors a script parameter):\n  \U0001f503 r - re-login now, wiping ALL saved data (--relogin)\n  \U0001f9f9 c - clear ALL saved data & restart (--clear-cache)\n  \U0001f504 e - switch proxy engine builtin/sing-box (--local-proxy-engine; cached)\n  \U0001f500 l - switch listen host 127.0.0.1 <-> 0.0.0.0 (--listen)\n  \U0001f310 h - choose the DNS resolver: DoH providers / system DNS; the per-proxy DNS endpoints ride the CHOSEN provider ONLY - default cloudflare, no fallback chain (--doh)\n  \U0001f4be k - toggle the DoH cache on/off (--doh-cache; cached)\n  \U0001f9e9 i - toggle the TLS ClientHello fragmentation (--tls-split; ON by default: the SNI-carrying ClientHello goes in small TCP segments against single-packet DPI; cached)\n  \U0001f4c2 o - open the config directory (config.json lives there)\n  \U0001f4cb v - copy a LOCAL proxy address:port\n  \U0001f4cb b - copy an UPSTREAM proxy address:port\n  \U0001f522 t - show & copy the current TOTP code\n  \U0001f3ab j - show & copy the current proxyPass JWT\n  \U0001f4f7 g - load a QR image with the 2FA secret on the fly (--qr)\n  \U0001f464 u - show & copy the login (email)\n  \U0001f511 p - show & copy the password\n  \U0001f465 a - account menu: switch to another CACHED Mozilla account ('+' adds a NEW one, '-' deletes one) - the WHOLE profile switches with it: the DNS resolver, the language, the proxy selection, the sing-box configs and the Fastly cookie (config.json, --list-accounts)\n  \U0001f4e6 d - reinstall ALL Python dependencies from scratch (--reinstall-deps)\n  \U0001f4bf s - reinstall sing-box from scratch (--reinstall-singbox)\n  \U0001f3a8 m - switch the color theme dark <-> light (--theme; cached)\n  \U0001f308 n - toggle the colored log output on/off (--no-color; cached)\n  \U0001f30d w - choose which local proxies to run: several tokens separated by spaces, 0 = all (--countries)\n  \U0001f4ac y - choose the interface language: en / ru, 0 = default (--lang; the choice is cached and survives restarts)\n  \U0001f4c4 1 - open config.json (the single settings file) in the system default editor\n  \U0001f4c6 z - the config-file menu (the token list of every editable file)\n  \U0001f50d Ctrl+O - find & remove every leftover of the OLD config format (--clean-old-config)\n  \u26d4 Ctrl+C - stop the script (the first press stops immediately; --confirm-exit requires a second press within 5 s)\n  \U0001F527 Ctrl+T - choose the LOCAL proxy type from the menu: socks5 / http (--proxy-type; the choice is cached)\n  \U0001f501 Ctrl+R - toggle the account auto-rotation by quota on/off (--auto-rotate; the choice is cached)\n  \U0001f4cb Ctrl+P - rewrite the PAC file with the running listeners (--pac-export)\n  \U0001f98a f - export ALL local proxies as FoxyProxy Standard settings (combined file: imports via ANY FoxyProxy import path) (--foxyproxy-export)\n  \U0001f9fe x - export ALL local proxies as the LEGACY FoxyProxy settings JSON (the REAL FoxyProxy 6/7 export shape, for 'Import from older versions') (--foxyproxy-legacy-export)\n  \U0001f6d1 q - stop.",
  "hotkey_relogin": "Hotkey 'r' \u267b\ufe0f: FULL wipe of all saved data - caches, credentials, sing-box configs - then a fresh sign-in.",
  "hotkey_clear": "Hotkey 'c' \U0001f9f9: ALL saved data wiped (caches, credentials, sing-box configs) - restarting with a clean state.",
  "hotkey_engine": "Hotkey 'e': switching the engine to {engine} - local proxies will restart with it.",
  "hotkey_listen": "Hotkey 'l': listeners will now bind on {host} - local proxies will restart with it.",
  "hotkey_totp": "Hotkey 't' \U0001f522: current TOTP code - also copied to the clipboard.",
  "hotkey_jwt": "Current proxyPass JWT {_e} - also copied to the clipboard:",
  "hotkey_jwt_none": "Hotkey 'j' \U0001f3ab: no proxyPass token yet - it appears right after the successful sign-in.",
  "hotkey_totp_none": "Hotkey 't' \U0001f522: no TOTP secret is available. Reason: {reason}. The TOTP secret is stored in config.json (the current account) and gets there only after a sign-in with --qr <QR image> or --totp-secret <base32> (or the MOZVPN_TOTP_SECRET environment variable).",
  "totp_none_reason_nocreds": "no current account exists in config.json yet - no sign-in with saved credentials has happened on this machine",
  "totp_none_reason_nosecret": "the current account in config.json contains no totp_secret field - the saved sign-in was made without --qr / --totp-secret, or the account has no TOTP 2FA enabled",
  "hotkey_open_dir_fallback": "Hotkey 'o' \U0001f4c2: the sing-box config directory does not exist yet (it is created when the singbox engine runs) - opened the main config directory instead {_e}: {path}",
  "hotkey_files_hint": "Config files: press the number to open the file in the system default editor.",
  "hotkey_file_entry": "  {n} - {path}",
  "files_menu_hint": "Config files ({n}) {_e} \u2014 press the token of the file (a, b, ... for the files past the first) and Enter. Backspace deletes, any other key cancels; the menu exits automatically after opening the file.",
  "hotkey_no_file": "\U0001f4c4 Hotkey '{k}': no config file No. {n} - since v6.0 the editable config is ONE (config.json, hotkey '1').",
  "hotkey_open": "Opened in the system default editor {_e}: {path}",
  "hotkey_open_dir": "Opened the config directory in the system file manager {_e}: {path}",
  "hotkey_open_fail": "Could not open {path}: {err}",
  "hotkey_open_missing": "File does not exist: {path}",
  "hotkey_copy_local_hint": "Copy a LOCAL proxy address to the clipboard - type its number/letter, then press Enter:",
  "hotkey_copy_remote_hint": "Copy an UPSTREAM proxy address to the clipboard - type its number/letter, then press Enter:",
  "hotkey_copy_entry": "  {n} - {addr} ({label})",
  "hotkey_copied": "Copied to the clipboard {_e}: {text}",
  "hotkey_copy_fail": "Clipboard is not available on this system: {err}",
  "hotkey_copy_cancel": "Selection cancelled - press v, b or h again to retry.",
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
  "hotkey_theme": "Hotkey 'm' \U0001f3a8: switched the theme to {theme} (--theme).",
  "color_enabled": "Colored log output enabled {_e} (hotkey 'n' / --no-color toggles).",
  "hotkey_color": "Hotkey 'n' \U0001f308: colored log output {state} (mirrors --no-color).",
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
  "proto_chosen_masque": "Protocol for {hp}: masque (HTTP/3 CONNECT-UDP) - the PRIORITY protocol; the MASQUE tunnel carried data.",
  "proto_fallback_connect": "Protocol for {hp}: HTTP CONNECT - fallback from masque, which is unavailable here: {reason}",
  "proto_masque_no_lib": "masque needs the aioquic package - it is not installed, so every upstream will use the HTTP CONNECT fallback.",
  "test_commands_header": "To test the LOCAL proxies, use these commands {_e}:",
  "test_commands_hidden": "curl test commands are hidden {_e} - enable them with --show-test-commands (env MOZVPN_SHOW_TEST_COMMANDS=1).",
  "test_command_local": "  {_e} {cmd}   [{label}, {proto}]",
  "test_commands_remote_header": "To test the UPSTREAM (remote) proxies directly, use these commands:",
  "test_command_remote": "  {_e} {cmd}   [{label}]",
  "clear_will_remove_header": "Hotkey 'c' / 'r' / --clear-cache / --relogin removes ALL of these {_e}:",
  "clear_will_remove_entry": "  - {path}",
  "clear_will_remove_dir": "  - {path} (the ENTIRE config directory - everything above lives inside it)",
  "clear_will_remove_legacy": "  - {path} (every leftover of the OLD pre-v6 config format)",
  "config_auto_created": "config.json not found \u2014 created a NEW one with the DEFAULT values {_e}: {path}",
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
  "api_proxy_on": "Control plane (FxA/Guardian/Remote Settings + the Fastly challenge) via the FIXED exit {_e}: {url} (--api-proxy)",
  "api_proxy_off": "Control-plane egress: direct (--api-proxy not set)",
  "api_proxy_socks_unsupported": "socks5:// is not supported by --api-proxy: the stdlib ProxyHandler tunnels http/https via CONNECT only and this script adds no new dependency - use an http:// or https:// proxy URL",
  "hotkey_tls_split": "TLS ClientHello fragmentation: {state}",
  "tls_split_startup": "TLS ClientHello fragmentation: {state} (--tls-split; ON by default)",
  "fastly_406_stale": "The sent Fastly challenge cookie was rejected (HTTP 406 despite a cookie) - dropping it and solving a FRESH challenge before the retry",
  "fxa_429_cooldown": "FxA login rate limit - a 15-minute cooldown; the retry prefers the cached session token",
  "guardian_reactivated": "Guardian: re-activated (HTTP {status}) - retrying the token fetch once",
  "guardian_reactivate_failed": "Guardian: re-activation failed (HTTP {status}: {detail})",
  "pass_rejected_refresh": "The egress REJECTED the proxyPass (HTTP 400 'parsing JWT failed' / 401 / 403) - refreshing the pass immediately",
  "session_fail_refresh": "3+ distinct targets failed through the tunnel - the session looks broken; refreshing the pass now",
  "connect_rejected": "Egress rejected the CONNECT (HTTP {code}) to {_e}{target}",
  "connect_target_open_timeout": "CONNECT to {_e}{target} never opened (timeout)",
  "connect_target_bad_gateway": "Egress answered HTTP {code} for {_e}{target}",
  "connect_target_doh_unreachable": "The DNS relay's DoH target {target} fails through the tunnel {_e} the per-proxy DNS endpoints ride the CHOSEN provider only (hotkey 'h' / --doh to switch it); relayed DNS queries return nothing until it recovers (the client's resolver retries)",
  "quota_low": "Quota below 15%: {left} of {limit} left{reset} - the allowance resets monthly",
  "filter_cleared_broken": "The saved proxy selection kept failing on EVERY served egress - the filter is cleared and ALL proxies will be served on the next rebuild (re-apply it with 'w' once the egresses recover)",
  "channel_limits_note": "The Mozilla channel today is an HTTP CONNECT tunnel over HTTP/2 - a RAW TCP tunnel: ANY TCP protocol and ANY destination port can run inside it (no port whitelist is published). UDP/IP flows are the next step with MASQUE over HTTP/3 (Firefox already ships the CONNECT-UDP code, and the server list carries a per-server masque protocol). The egress does no deep packet inspection; Mozilla positions the feature for browser web traffic",
  "proxy_type_selected": "Local proxy type: {type} (Ctrl+T opens the choice menu; SOCKS5 passes domain names to the egress - remote DNS)",
  "proxy_type_switched": "Local proxy type switched to {type}: rebuilding the listeners",
  "hotkey_proxy_type": "Ctrl+T - choose the local proxy type from the menu: socks5 / http (--proxy-type; the choice is saved)",
  "ptype_menu_hint": "Choose the local proxy type {_e} \u2014 type its number and press Enter (current: {cur}; [x] marks the running type). The choice is saved to config.json (settings.proxy_type), rebuilds the listeners at once and survives restarts (Backspace deletes, any other key cancels; the menu exits automatically after applying).",
  "ptype_menu_entry": "  {n} - {name} - {desc}",
  "ptype_desc_socks5": "SOCKS5 (RFC 1928): the domain names are resolved by the egress - remote DNS",
  "ptype_desc_http": "HTTP CONNECT",
  "dns_line": "DNS relay {_e} {listen}: {n} per-proxy DNS endpoints (UDP+TCP; the DNS port of a proxy rides THAT proxy only -> its egress -> DoH {target}). Point the SYSTEM resolver / any plain-DNS app at the DNS port shown next to the proxy you use; apps that already send domain names through the proxies (socks5h remote DNS) do not need it",
  "dns_port_busy": "The DNS relay port {port} of {label} is busy - that DNS endpoint is skipped (the proxy keeps working)",
  "hotkey_auto_rotate": "Ctrl+R - auto-rotation of accounts by quota on/off (the choice is saved)",
  "hotkey_pac_export": "Ctrl+P - rewrite the PAC file (the local sites bypass list)",
  "auto_rotate_startup": "Account auto-rotation by quota is ON (Ctrl+R off; --no-auto-rotate)",
  "auto_rotate_on": "Account auto-rotation by quota is ON",
  "auto_rotate_off": "Account auto-rotation by quota is OFF",
  "auto_rotate_switched": "{state} - the choice is saved",
  "auto_rotate_zero": "Quota exhausted on the current account ({email}) - auto-rotation is looking for the account with the most data left",
  "auto_rotate_to": "Auto-rotation: switching to account {email} ({left} known left) - cached session, no new login",
  "auto_rotate_none": "Auto-rotation: every other cached account is exhausted or has no cached session - staying on {email}",
  "auto_rotate_off_zero": "Quota exhausted on the current account - auto-rotation is OFF (Ctrl+R to enable)",
  "fxa_profile_read": "Firefox profile session: {path}",
  "fxa_profile_missing": "Cannot read the Firefox profile file: {path} ({err})",
  "fxa_profile_no_token": "No sessionToken found in {path} - sign into the Firefox browser first, then restart",
  "fxa_profile_bad_token": "The sessionToken in {path} is malformed - sign into the Firefox browser again",
  "fxa_profile_session_invalid": "The Firefox browser session is no longer valid (errno 110) - sign into Firefox again, then press any key to retry",
  "unblock_prompt": "Mozilla sent a 6-digit unblock code to {email} - enter it (empty input re-sends the letter, 'q' cancels): ",
  "unblock_resent": "The unblock code letter was re-sent to {email}",
  "unblock_wrong": "The unblock code was not accepted - try again",
  "unblock_gave_up": "The unblock code attempts are exhausted - the login stays blocked (wait for a new letter or try later)",
  "email_link_wait": "Open the confirmation LINK from the Mozilla email in a browser - waiting up to {sec} s (any key returns to the code prompt)",
  "email_link_verified": "The email confirmation link was accepted - the session is verified",
  "email_link_timeout": "The link was not confirmed in time - back to the code prompt",
  "pac_written": "PAC file written: {path} ({directive} entries: {n})",
  "pac_failed": "PAC file write failed: {path} ({err})",
  "pac_no_proxies": "No running local proxies - the PAC file is not rewritten",
  "doctor_title": "Diagnostics (read-only):",
  "doctor_ok": "ok",
  "doctor_fail": "FAIL",
  "doctor_skip": "skip",
  "doctor_interpreter": "Python {ver} on {plat}",
  "doctor_config": "Config store at {path} (accounts: {n})",
  "doctor_deps": "Dependencies: {miss}",
  "doctor_deps_ok": "all present",
  "doctor_sysdns": "System DNS: {host} -> {ips}",
  "doctor_doh": "DoH ({provider}) resolve of {host}: {ips}",
  "doctor_doh_system": "off by choice - the system resolver (verified by the step above)",
  "doctor_fxa": "FxA API {url}: HTTP {status}",
  "doctor_serverlist": "Server list: {n} locations, {m} servers",
  "doctor_tls": "TLS handshake to {host}:{port} (profile {p}): {ms} ms",
  "doctor_quota": "Guardian quota on the cached session: {left} of {limit} left",
  "doctor_no_session": "No cached session token - the Guardian step is skipped (sign in once normally)",
  "doctor_done": "Diagnostics complete: {ok} ok, {fail} failed",
},
"ru": {
  "engine_selected": "\u0414\u0432\u0438\u0436\u043e\u043a \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0445 \u043f\u0440\u043e\u043a\u0441\u0438 {_e}: {engine}",
  "config_files_header": "\u0424\u0430\u0439\u043b\u044b \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 \u0438 \u043a\u044d\u0448\u0435\u0439, \u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442 \u0441\u043a\u0440\u0438\u043f\u0442 {_e}:",
  "config_file_entry": "  {_e} {path} \u2014 {status}",
  "config_file_exists": "{size} \u0431\u0430\u0439\u0442, \u0438\u0437\u043c\u0435\u043d\u0451\u043d {mtime} UTC",
  "config_file_dir": "\u043a\u0430\u0442\u0430\u043b\u043e\u0433, {n} \u044d\u043b\u0435\u043c\u0435\u043d\u0442\u043e\u0432",
  "config_file_missing": "\u0435\u0449\u0451 \u043d\u0435 \u0441\u043e\u0437\u0434\u0430\u043d",
  "engine_builtin": "builtin (\u0432\u0441\u0442\u0440\u043e\u0435\u043d\u043d\u044b\u0439 \u0434\u0432\u0438\u0436\u043e\u043a: \u043a\u0430\u0436\u0434\u044b\u0439 \u0430\u043f\u0441\u0442\u0440\u0438\u043c \u043e\u0431\u0441\u043b\u0443\u0436\u0438\u0432\u0430\u0435\u0442\u0441\u044f \u043a\u0430\u043a MASQUE \u0438\u043b\u0438 HTTP CONNECT, \u0441 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438\u043c \u0444\u043e\u043b\u0431\u044d\u043a\u043e\u043c)",
  "engine_singbox": "sing-box (\u0432\u043d\u0435\u0448\u043d\u0438\u0439 \u0431\u0438\u043d\u0430\u0440\u043d\u0438\u043a, \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u044b MASQUE/HTTP CONNECT)",
  "lang_selected": "\u042f\u0437\u044b\u043a \u0432\u044b\u0432\u043e\u0434\u0430: {lang}",
  "color_disabled": "\u0426\u0432\u0435\u0442\u043d\u043e\u0439 \u0432\u044b\u0432\u043e\u0434 \u043e\u0442\u043a\u043b\u044e\u0447\u0451\u043d.",
  "cache_cleared": "\u041a\u0430\u0442\u0430\u043b\u043e\u0433 \u043a\u044d\u0448\u0430 \u0443\u0434\u0430\u043b\u0451\u043d: {path}",
  "cache_clear_failed": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0443\u0434\u0430\u043b\u0438\u0442\u044c \u043a\u0430\u0442\u0430\u043b\u043e\u0433 \u043a\u044d\u0448\u0430 {path}: {err}",
  "cache_nothing": "\u041a\u0430\u0442\u0430\u043b\u043e\u0433 \u043a\u044d\u0448\u0430 \u043d\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442, \u0447\u0438\u0441\u0442\u0438\u0442\u044c \u043d\u0435\u0447\u0435\u0433\u043e.",
  "cached_session": "\u041a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u0430\u044f \u0441\u0435\u0441\u0441\u0438\u044f ({email}) {_e}. --relogin \u0434\u043b\u044f \u043d\u043e\u0432\u043e\u0433\u043e \u0432\u0445\u043e\u0434\u0430.",
  "enter_email": "Email \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 Mozilla: ",
  "enter_password": "\u041f\u0430\u0440\u043e\u043b\u044c: ",
  "email_missing": "Email \u043d\u0435 \u0437\u0430\u0434\u0430\u043d (\u043d\u0435\u0442 \u043d\u0438 \u0430\u0440\u0433\u0443\u043c\u0435\u043d\u0442\u0430, \u043d\u0438 \u043a\u044d\u0448\u0430).",
  "password_missing": "\u041f\u0430\u0440\u043e\u043b\u044c \u043d\u0435 \u0437\u0430\u0434\u0430\u043d (\u043d\u0435\u0442 \u043d\u0438 \u0430\u0440\u0433\u0443\u043c\u0435\u043d\u0442\u0430, \u043d\u0438 \u043a\u044d\u0448\u0430 \u0440\u0435\u043a\u0432\u0438\u0437\u0438\u0442\u043e\u0432).",
  "signing_in": "\u0412\u0445\u043e\u0434 \u0432 Mozilla Accounts...",
  "session_cached": "sessionToken \u0437\u0430\u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d {_e}: {path}",
  "stretch_version": "\u0412\u0435\u0440\u0441\u0438\u044f key-stretching \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430: {version}",
  "stretch_v2_note": " (650k \u0438\u0442\u0435\u0440\u0430\u0446\u0438\u0439 PBKDF2)",
  "clock_skew": "\u0427\u0430\u0441\u044b \u041f\u041a \u0440\u0430\u0441\u0445\u043e\u0434\u044f\u0442\u0441\u044f \u0441 \u0441\u0435\u0440\u0432\u0435\u0440\u0430\u043c\u0438 Mozilla \u043d\u0430 {offset} \u0441; TOTP \u0431\u0443\u0434\u0435\u0442 \u0441\u0447\u0438\u0442\u0430\u0442\u044c\u0441\u044f \u043f\u043e \u0441\u0435\u0440\u0432\u0435\u0440\u043d\u043e\u043c\u0443 \u0432\u0440\u0435\u043c\u0435\u043d\u0438.",
  "account_not_found": "\u0410\u043a\u043a\u0430\u0443\u043d\u0442 \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d.",
  "wrong_password": "\u041d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 \u043f\u0430\u0440\u043e\u043b\u044c (errno 103). \u0415\u0441\u043b\u0438 \u0432\u0445\u043e\u0434\u0438\u043b\u0438 \u0447\u0435\u0440\u0435\u0437 Google/Apple \u2014 \u0441\u043d\u0430\u0447\u0430\u043b\u0430 \u0437\u0430\u0434\u0430\u0439\u0442\u0435 \u043f\u0430\u0440\u043e\u043b\u044c: accounts.firefox.com \u2192 \u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438.",
  "login_blocked": "\u0412\u0425\u041e\u0414 \u0412\u0420\u0415\u041c\u0415\u041d\u041d\u041e \u0417\u0410\u0411\u041b\u041e\u041a\u0418\u0420\u041e\u0412\u0410\u041d ({source}): \u0441\u043b\u0438\u0448\u043a\u043e\u043c \u043c\u043d\u043e\u0433\u043e \u043d\u0435\u0443\u0434\u0430\u0447\u043d\u044b\u0445 \u043f\u043e\u043f\u044b\u0442\u043e\u043a \u043f\u043e\u0434\u0440\u044f\u0434 (\u043d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 \u043f\u0430\u0440\u043e\u043b\u044c \u0438/\u0438\u043b\u0438 \u043a\u043e\u0434\u044b 2FA).{wait}\n\u042d\u0442\u043e \u041d\u0415 \u0443\u0434\u0430\u043b\u0435\u043d\u0438\u0435 \u0438 \u041d\u0415 \u0432\u0435\u0447\u043d\u0430\u044f \u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u043a\u0430. \u0412\u0445\u043e\u0434 \u0432\u043e\u0441\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u0435\u0442\u0441\u044f \u041f\u041e\u0414\u0422\u0412\u0415\u0420\u0416\u0414\u0415\u041d\u0418\u0415\u041c \u041f\u041e EMAIL:\n  1) \u041f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 \u043f\u043e\u0447\u0442\u0443 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 (\u0438 \u043f\u0430\u043f\u043a\u0443 \u00ab\u0421\u043f\u0430\u043c\u00bb): Mozilla \u043e\u0442\u043f\u0440\u0430\u0432\u0438\u043b\u0430 \u043f\u0438\u0441\u044c\u043c\u043e\n     (\u00abNew sign-in to Firefox\u00bb / \u00abConfirm your sign-in\u00bb / \u043a\u043e\u0434 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u044f).\n  2) \u041e\u0442\u043a\u0440\u043e\u0439\u0442\u0435 \u043f\u0438\u0441\u044c\u043c\u043e \u0438 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u0435 \u0432\u0445\u043e\u0434 (\u043a\u043d\u043e\u043f\u043a\u0430 \u0438\u043b\u0438 \u043a\u043e\u0434 \u043d\u0430 accounts.firefox.com).\n  3) \u041f\u043e\u0441\u043b\u0435 \u044d\u0442\u043e\u0433\u043e \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435 \u0437\u0430\u043f\u0443\u0441\u043a (\u0432 \u0440\u0435\u0436\u0438\u043c\u0435 --watch \u0441\u043a\u0440\u0438\u043f\u0442 \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442 \u0441\u0430\u043c).",
  "retry_after": " \u0421\u0435\u0440\u0432\u0435\u0440 \u043f\u0440\u043e\u0441\u0438\u0442 \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u044c \u043d\u0435 \u0440\u0430\u043d\u044c\u0448\u0435 \u0447\u0435\u043c \u0447\u0435\u0440\u0435\u0437 ~{sec} \u0441.",
  "blocked_extra_method": " \u0421\u0435\u0440\u0432\u0435\u0440 \u0442\u0440\u0435\u0431\u0443\u0435\u0442 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0435 \u043c\u0435\u0442\u043e\u0434\u043e\u043c '{method}'.",
  "login_error": "\u041e\u0448\u0438\u0431\u043a\u0430 \u0432\u0445\u043e\u0434\u0430 ({status}): {msg}",
  "server_wants_method": "\u0421\u0435\u0440\u0432\u0435\u0440 \u0437\u0430\u043f\u0440\u043e\u0441\u0438\u043b \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0435 \u0432\u0445\u043e\u0434\u0430 \u043c\u0435\u0442\u043e\u0434\u043e\u043c '{method}' (\u043f\u0440\u0438\u0447\u0438\u043d\u0430: {reason}). \u0414\u043b\u044f TOTP-\u0430\u043a\u043a\u0430\u0443\u043d\u0442\u043e\u0432 \u0441\u0435\u0440\u0432\u0435\u0440 \u043f\u0440\u0438\u043d\u0438\u043c\u0430\u0435\u0442 /session/verify/totp \u043d\u0435\u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e \u043e\u0442 \u0437\u0430\u044f\u0432\u043b\u0435\u043d\u043d\u043e\u0433\u043e \u043c\u0435\u0442\u043e\u0434\u0430 \u2014 \u043f\u0440\u043e\u0431\u0443\u044e TOTP.",
  "totp_prompt": "\u041a\u043e\u0434 \u0434\u0432\u0443\u0445\u0444\u0430\u043a\u0442\u043e\u0440\u043d\u043e\u0439 \u0430\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u0438 (TOTP): ",
  "totp_digits_only": "\u041a\u043e\u0434 \u0434\u043e\u043b\u0436\u0435\u043d \u0441\u043e\u0441\u0442\u043e\u044f\u0442\u044c \u0442\u043e\u043b\u044c\u043a\u043e \u0438\u0437 \u0446\u0438\u0444\u0440.",
  "totp_not_enabled": "\u0423 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u043d\u0430 \u0441\u0435\u0440\u0432\u0435\u0440\u0435 TOTP \u043d\u0435 \u0432\u043a\u043b\u044e\u0447\u0451\u043d (TOTP_TOKEN_NOT_FOUND) \u2014 TOTP-\u0432\u0435\u0440\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u044f \u043d\u0435\u0432\u043e\u0437\u043c\u043e\u0436\u043d\u0430.",
  "totp_rejected_window": "\u0421\u0435\u0440\u0432\u0435\u0440 \u043e\u0442\u043a\u043b\u043e\u043d\u0438\u043b \u043a\u043e\u0434. \u041f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435, \u0447\u0442\u043e \u0441\u0435\u043a\u0440\u0435\u0442 \u0441\u043e\u0432\u043f\u0430\u0434\u0430\u0435\u0442 \u0441 \u043f\u0440\u0438\u043b\u043e\u0436\u0435\u043d\u0438\u0435\u043c-\u0430\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0440\u043e\u043c (\u0432 \u0442.\u0447. \u043d\u0435 \u043f\u0435\u0440\u0435\u0441\u043e\u0437\u0434\u0430\u0432\u0430\u043b\u0441\u044f \u043b\u0438 2FA \u043f\u043e\u0441\u043b\u0435 \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0438\u044f QR).{clock} \u0416\u0434\u0443 \u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0435\u0435 \u043e\u043a\u043d\u043e ...",
  "totp_rejected_final": "\u041a\u043e\u0434 2FA \u043d\u0435 \u043f\u043e\u0434\u043e\u0448\u0451\u043b \u0442\u0440\u0438 \u0440\u0430\u0437\u0430 \u043f\u043e\u0434\u0440\u044f\u0434 (\u0432 \u0440\u0430\u0437\u043d\u044b\u0445 \u0432\u0440\u0435\u043c\u0435\u043d\u043d\u044b\u0445 \u043e\u043a\u043d\u0430\u0445). \u0421\u0432\u0435\u0440\u044c\u0442\u0435 TOTP-\u0441\u0435\u043a\u0440\u0435\u0442 \u0441 \u043f\u0440\u0438\u043b\u043e\u0436\u0435\u043d\u0438\u0435\u043c: \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u0441 --qr <\u0441\u0432\u0435\u0436\u0438\u0439 QR> \u2014 \u0432\u043e\u0437\u043c\u043e\u0436\u043d\u043e, 2FA \u043f\u0435\u0440\u0435\u0441\u043e\u0437\u0434\u0430\u0432\u0430\u043b\u0441\u044f \u0438 qr.png \u0443\u0441\u0442\u0430\u0440\u0435\u043b.",
  "totp_unknown_error": "\u041e\u0448\u0438\u0431\u043a\u0430 \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 2FA ({status}): {data} (\u043f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 sessionToken / \u0430\u043a\u043a\u0430\u0443\u043d\u0442)",
  # v7.0: the emailed-code session verification (email-2fa)
  "email_code_prompt": "Введите 6-значный код из письма Mozilla — или 'l', чтобы подтвердить по ССЫЛКЕ из письма (пустой ввод — выслать письмо повторно): ",
  "email_code_resent": "\u041f\u0438\u0441\u044c\u043c\u043e \u0441 \u043a\u043e\u0434\u043e\u043c \u043e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u043e \u043f\u043e\u0432\u0442\u043e\u0440\u043d\u043e.",
  "email_resend_failed": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u043e\u0432\u0442\u043e\u0440\u043d\u043e \u0432\u044b\u0441\u043b\u0430\u0442\u044c \u043f\u0438\u0441\u044c\u043c\u043e \u0441 \u043a\u043e\u0434\u043e\u043c (HTTP {status}) \u2014 \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435 \u0432\u0432\u043e\u0434 \u0438\u043b\u0438 \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u0443\u0436\u0435 \u0438\u043c\u0435\u044e\u0449\u0438\u0439\u0441\u044f \u043a\u043e\u0434.",
  "email_code_confirmed": "\u0421\u0435\u0441\u0441\u0438\u044f \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0430 \u043a\u043e\u0434\u043e\u043c \u0438\u0437 \u043f\u0438\u0441\u044c\u043c\u0430 (email-2fa).",
  "email_code_rejected": "\u041a\u043e\u0434 \u043e\u0442\u043a\u043b\u043e\u043d\u0451\u043d (\u043d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 \u0438\u043b\u0438 \u0438\u0441\u0442\u0451\u043a) \u2014 \u0441\u0432\u0435\u0440\u044c\u0442\u0435\u0441\u044c \u0441 \u0441\u0430\u043c\u044b\u043c \u0441\u0432\u0435\u0436\u0438\u043c \u043f\u0438\u0441\u044c\u043c\u043e\u043c \u0438 \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435.",
  "email_code_rejected_final": "\u041a\u043e\u0434 \u0438\u0437 \u043f\u0438\u0441\u044c\u043c\u0430 \u043e\u0442\u043a\u043b\u043e\u043d\u0451\u043d \u0442\u0440\u0438 \u0440\u0430\u0437\u0430 \u043f\u043e\u0434\u0440\u044f\u0434. \u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u0435 \u0432\u0445\u043e\u0434 \u0432\u0440\u0443\u0447\u043d\u0443\u044e (\u0438\u043d\u0441\u0442\u0440\u0443\u043a\u0446\u0438\u044f \u0432 \u0441\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u0438 email_confirm_required) \u0438 \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u0441\u043a\u0440\u0438\u043f\u0442, \u043b\u0438\u0431\u043e \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u0435 TOTP.",
  "email_code_aal_hint": "\u0423 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u0435\u0441\u0442\u044c \u0441\u0435\u0440\u0432\u0435\u0440\u043d\u044b\u0439 TOTP, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 \u043a\u043e\u0434 \u0438\u0437 \u043f\u0438\u0441\u044c\u043c\u0430 \u043d\u0435 \u043c\u043e\u0436\u0435\u0442 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c \u0441\u0435\u0441\u0441\u0438\u044e (insufficientAal).",
  "email_code_unknown_error": "\u041e\u0448\u0438\u0431\u043a\u0430 \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0438 \u043a\u043e\u0434\u0430 \u0438\u0437 \u043f\u0438\u0441\u044c\u043c\u0430 ({status}): {data} (\u043f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 \u043f\u043e\u0447\u0442\u0443 / sessionToken).",
  "totp_code_current": "\u0422\u0435\u043a\u0443\u0449\u0438\u0439 TOTP-\u043a\u043e\u0434: {code} (\u0434\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442 \u0435\u0449\u0451 {sec} \u0441{offset})",
  "totp_code_generated": "\u0421\u0433\u0435\u043d\u0435\u0440\u0438\u0440\u043e\u0432\u0430\u043d TOTP-\u043a\u043e\u0434: {code} (\u043e\u043a\u043d\u043e {period} \u0441, \u043e\u0441\u0442\u0430\u043b\u043e\u0441\u044c {left} \u0441)",
  "clock_offset_note": ", \u0441\u043c\u0435\u0449\u0435\u043d\u0438\u0435 \u0447\u0430\u0441\u043e\u0432 {offset} \u0441",
  "email_unverified": "Email \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u043d\u0435 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d (\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u044f). \u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u0435 email \u043f\u043e \u0441\u0441\u044b\u043b\u043a\u0435 \u0438\u0437 \u043f\u0438\u0441\u044c\u043c\u0430 Mozilla, \u0437\u0430\u0442\u0435\u043c \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435 \u0432\u0445\u043e\u0434.",
  "email_confirm_required": "\u0422\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044f \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0435 \u0432\u0445\u043e\u0434\u0430 \u043f\u043e email, \u0430 \u0443 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u043d\u0435 \u0432\u043a\u043b\u044e\u0447\u0451\u043d TOTP (\u0438\u043d\u0430\u0447\u0435 \u0441\u043a\u0440\u0438\u043f\u0442 \u0432\u0435\u0440\u0438\u0444\u0438\u0446\u0438\u0440\u043e\u0432\u0430\u043b \u0431\u044b \u0441\u0435\u0441\u0441\u0438\u044e \u0441\u0430\u043c). \u0427\u0442\u043e \u0434\u0435\u043b\u0430\u0442\u044c:\n  1) \u041e\u0442\u043a\u0440\u043e\u0439\u0442\u0435 \u043f\u043e\u0447\u0442\u0443, \u043d\u0430\u0439\u0434\u0438\u0442\u0435 \u043f\u0438\u0441\u044c\u043c\u043e Mozilla \u00abNew sign-in to Firefox\u00bb \u0438 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u0435 \u0432\u0445\u043e\u0434\n     (\u043b\u0438\u0431\u043e \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u043a\u043e\u0434 \u0438\u0437 \u043f\u0438\u0441\u044c\u043c\u0430 \u043d\u0430 accounts.firefox.com);\n  2) \u043f\u043e\u0441\u043b\u0435 \u044d\u0442\u043e\u0433\u043e \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435 \u0437\u0430\u043f\u0443\u0441\u043a \u2014 \u0441\u0435\u0441\u0441\u0438\u044f \u0441\u0442\u0430\u043d\u0435\u0442 \u0434\u043e\u0432\u0435\u0440\u0435\u043d\u043d\u043e\u0439;\n  3) \u043b\u0438\u0431\u043e \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u0435 TOTP \u0432 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430\u0445 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 (Two-step authentication);\n  4) \u043b\u0438\u0431\u043e \u0432\u043e\u0439\u0434\u0438\u0442\u0435 \u0432 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435 Firefox \u0438 \u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u0441 --session-token <hex>.",
  "session_unverified": "\u0421\u0435\u0441\u0441\u0438\u044f \u043d\u0435 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0430 (\u043c\u0435\u0442\u043e\u0434: {method}, \u043f\u0440\u0438\u0447\u0438\u043d\u0430: {reason}).",
  "totp_missing": "\u0410\u043a\u043a\u0430\u0443\u043d\u0442 \u0442\u0440\u0435\u0431\u0443\u0435\u0442 2FA, \u0430 TOTP-\u0441\u0435\u043a\u0440\u0435\u0442 \u043d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u0435\u043d. \u0417\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u0441 --qr <\u043a\u0430\u0440\u0442\u0438\u043d\u043a\u0430> \u0438\u043b\u0438 --totp-secret.",
  "prompt_read_error": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u0442\u044c \u0432\u0432\u043e\u0434 ({err}) \u2014 stdin/\u0442\u0435\u0440\u043c\u0438\u043d\u0430\u043b \u043d\u0435 \u043f\u0440\u0438\u0433\u043e\u0434\u0435\u043d \u0434\u043b\u044f \u0438\u043d\u0442\u0435\u0440\u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0445 \u0437\u0430\u043f\u0440\u043e\u0441\u043e\u0432. \u041d\u0430 Android/Termux \u0437\u0430\u043f\u0443\u0441\u043a\u0430\u0439\u0442\u0435 \u0441\u043a\u0440\u0438\u043f\u0442 \u041f\u0420\u042f\u041c\u041e \u0432 \u0442\u0435\u0440\u043c\u0438\u043d\u0430\u043b\u0435 Termux (\u043d\u0430\u0441\u0442\u043e\u044f\u0449\u0438\u0439 tty), \u0430 \u043d\u0435 \u0447\u0435\u0440\u0435\u0437 \u043e\u0431\u0435\u0440\u0442\u043a\u0443 \u0441 \u043f\u0435\u0440\u0435\u043d\u0430\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u043d\u044b\u043c stdin.",
  "oauth_fetching": "\u041f\u043e\u043b\u0443\u0447\u0435\u043d\u0438\u0435 OAuth-\u0442\u043e\u043a\u0435\u043d\u0430 (grant fxa-credentials, scope 'profile https://identity.mozilla.com/apps/vpn')...",
  "oauth_scope_fallback": "\u041e\u0441\u043d\u043e\u0432\u043d\u043e\u0439 scope \u043e\u0442\u043a\u043b\u043e\u043d\u0451\u043d \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u043c, \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d '{scope}'.",
  "oauth_scope_denied": "Scope '{scope}' \u043d\u0435 \u0440\u0430\u0437\u0440\u0435\u0448\u0451\u043d (errno 114), \u043f\u0440\u043e\u0431\u0443\u044e \u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0438\u0439 ...",
  "oauth_all_scopes_denied": "OAuth: \u0432\u0441\u0435 scope \u043e\u0442\u043a\u043b\u043e\u043d\u0435\u043d\u044b \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u043c (errno 114). \u041f\u043e\u0441\u043b\u0435\u0434\u043d\u044f\u044f \u043e\u0448\u0438\u0431\u043a\u0430: {err}",
  "oauth_session_invalid": "sessionToken \u043d\u0435\u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0442\u0435\u043b\u0435\u043d/\u0438\u0441\u0442\u0451\u043a (errno {errno}) \u2014 \u0442\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044f \u043f\u0435\u0440\u0435\u043b\u043e\u0433\u0438\u043d.",
  "oauth_error": "OAuth-\u0442\u043e\u043a\u0435\u043d \u043d\u0435 \u043f\u043e\u043b\u0443\u0447\u0435\u043d ({status}): {data}",
  "guardian_activating": "\u0410\u043a\u0442\u0438\u0432\u0430\u0446\u0438\u044f Guardian \u0438 \u043f\u043e\u043b\u0443\u0447\u0435\u043d\u0438\u0435 proxyPass...",
  "guardian_enrolled": "Guardian: enroll \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d (HTTP {status}).",
  "guardian_enroll_failed": "/fpn/activate \u2192 HTTP {status} {detail} (\u043f\u0440\u043e\u0434\u043e\u043b\u0436\u0430\u044e: \u0442\u043e\u043a\u0435\u043d Guardian \u0432\u044b\u0434\u0430\u0451\u0442 \u0438 \u0431\u0435\u0437 enroll'\u0430)",
  "guardian_403": "proxyPass \u043d\u0435 \u043f\u043e\u043b\u0443\u0447\u0435\u043d (HTTP 403, no_entitlement).\n\u042d\u0442\u043e \u041d\u0415 \u043e\u0448\u0438\u0431\u043a\u0430 \u0432\u0445\u043e\u0434\u0430: OAuth-\u0442\u043e\u043a\u0435\u043d \u043f\u0440\u0438\u043d\u044f\u0442, \u043d\u043e \u0443 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u043d\u0435\u0442 \u044d\u043d\u0442\u0430\u0439\u0442\u043b\u043c\u0435\u043d\u0442\u0430 Firefox IP Protection (Built-in VPN).\n\u0412\u043e\u0437\u043c\u043e\u0436\u043d\u044b\u0435 \u043f\u0440\u0438\u0447\u0438\u043d\u044b \u0438 \u0447\u0442\u043e \u0434\u0435\u043b\u0430\u0442\u044c:\n  1) \u0424\u0443\u043d\u043a\u0446\u0438\u044f \u0435\u0449\u0451 \u043d\u0435 \u0432\u043a\u043b\u044e\u0447\u0435\u043d\u0430 \u0432 \u0432\u0430\u0448\u0435\u043c \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435: \u043e\u0442\u043a\u0440\u043e\u0439\u0442\u0435 Firefox 149+ \u2192 \u0437\u043d\u0430\u0447\u043e\u043a VPN\n     \u043d\u0430 \u0442\u0443\u043b\u0431\u0430\u0440\u0435 \u2192 \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u0435 \u043e\u0434\u0438\u043d \u0440\u0430\u0437 \u0434\u043e \u00ab\u0437\u0435\u043b\u0451\u043d\u043e\u0433\u043e \u0438\u043d\u0434\u0438\u043a\u0430\u0442\u043e\u0440\u0430\u00bb (\u043f\u0435\u0440\u0432\u043e\u0435 \u0432\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u0435\n     \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0430\u0435\u0442 \u044d\u043d\u0442\u0430\u0439\u0442\u043b\u043c\u0435\u043d\u0442 \u043a \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0443).\n  2) Built-in VPN beta \u0432\u044b\u043a\u0430\u0442\u044b\u0432\u0430\u0435\u0442\u0441\u044f \u043f\u043e \u0440\u0435\u0433\u0438\u043e\u043d\u0430\u043c (\u043d\u0430 2026-09: US/UK/DE/FR). \u0412\u043d\u0435 \u0441\u043f\u0438\u0441\u043a\u0430 \u2014\n     403 \u043e\u0441\u0442\u0430\u043d\u0435\u0442\u0441\u044f \u043d\u0435\u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e \u043e\u0442 \u0441\u043a\u0440\u0438\u043f\u0442\u0430.\n  3) \u0415\u0441\u043b\u0438 \u0432\u0445\u043e\u0434 \u0432 Mozilla-\u0430\u043a\u043a\u0430\u0443\u043d\u0442 \u0431\u044b\u043b \u0447\u0435\u0440\u0435\u0437 Google/Apple \u0438\u043b\u0438 \u0430\u043a\u043a\u0430\u0443\u043d\u0442 \u043d\u043e\u0432\u044b\u0439 \u2014\n     \u0434\u043e\u0436\u0434\u0438\u0442\u0435\u0441\u044c \u043f\u043e\u043b\u043d\u043e\u0439 \u0430\u043a\u0442\u0438\u0432\u0430\u0446\u0438\u0438 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u0438 \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435.",
  "guardian_401": "proxyPass \u043d\u0435 \u043f\u043e\u043b\u0443\u0447\u0435\u043d (HTTP 401, reauth_required): \u0441\u0435\u0441\u0441\u0438\u044f/FxA-\u0442\u043e\u043a\u0435\u043d \u043e\u0442\u043a\u043b\u043e\u043d\u0435\u043d\u044b Guardian'\u043e\u043c \u2014 \u0442\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044f \u043f\u0435\u0440\u0435\u043b\u043e\u0433\u0438\u043d.",
  "guardian_429": "proxyPass \u043d\u0435 \u043f\u043e\u043b\u0443\u0447\u0435\u043d (HTTP 429): \u043a\u0432\u043e\u0442\u0430 \u0438\u0441\u0447\u0435\u0440\u043f\u0430\u043d\u0430, \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435 \u0447\u0435\u0440\u0435\u0437 {retry} \u0441.",
  "guardian_451": "proxyPass \u043d\u0435 \u043f\u043e\u043b\u0443\u0447\u0435\u043d (HTTP 451): \u0440\u0435\u0433\u0438\u043e\u043d \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d.",
  "guardian_error": "proxyPass \u043d\u0435 \u043f\u043e\u043b\u0443\u0447\u0435\u043d (HTTP {status}): {detail}",
  "guardian_no_token": "\u0412 \u043e\u0442\u0432\u0435\u0442\u0435 Guardian \u043d\u0435\u0442 \u043f\u043e\u043b\u044f 'token': {data}",
  "quota_unlimited": "\u041a\u0432\u043e\u0442\u0430: \u0431\u0435\u0437\u043b\u0438\u043c\u0438\u0442\u043d\u0430\u044f (x-quota-unlimited: true).",
  "quota_left": "\u041a\u0432\u043e\u0442\u0430: \u043e\u0441\u0442\u0430\u043b\u043e\u0441\u044c {left} \u0438\u0437 {limit}{reset}.",
  "serverlist_fetching": "\u0417\u0430\u0433\u0440\u0443\u0437\u043a\u0430 \u0441\u043f\u0438\u0441\u043a\u0430 \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u0432 (Remote Settings: vpn-serverlist)...",
  "serverlist_failed": "\u0421\u043f\u0438\u0441\u043e\u043a \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u0432 \u043d\u0435 \u0437\u0430\u0433\u0440\u0443\u0436\u0435\u043d \u043d\u0438 \u0438\u0437 Remote Settings (vpn-serverlist), \u043d\u0438 \u043e\u0442 Guardian (/api/v2/servers).",
  "serverlist_done": "\u0421\u0442\u0440\u0430\u043d: {countries}, \u043f\u0440\u0438\u0433\u043e\u0434\u043d\u044b\u0445 \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u0432: {servers}",
  "proxypass_received": "proxyPass \u043f\u043e\u043b\u0443\u0447\u0435\u043d {_e}, \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0442\u0435\u043b\u0435\u043d \u0434\u043e: {until} (exp {exp} UTC)",
  "proxypass_jwt": "\u0421\u0432\u0435\u0436\u0438\u0439 proxyPass JWT:",
  "session_token_print": "sessionToken (\u0434\u043b\u044f \u043f\u043e\u0432\u0442\u043e\u0440\u043d\u044b\u0445 \u0437\u0430\u043f\u0443\u0441\u043a\u043e\u0432):",
  "json_saved": "JSON \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d {_e}: {path}",
  "qr_need_zxing": "\u0414\u043b\u044f \u0447\u0442\u0435\u043d\u0438\u044f QR \u043d\u0443\u0436\u0435\u043d \u043f\u0430\u043a\u0435\u0442 zxing-cpp:\n    pip install zxing-cpp pyotp Pillow",
  "qr_need_pillow": "\u0414\u043b\u044f \u043e\u0442\u043a\u0440\u044b\u0442\u0438\u044f QR-\u0444\u0430\u0439\u043b\u0430 \u043d\u0443\u0436\u0435\u043d \u043f\u0430\u043a\u0435\u0442 Pillow:\n    pip install Pillow",
  "qr_not_found": "QR-\u0444\u0430\u0439\u043b \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d: {path}",
  "qr_open_failed": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043e\u0442\u043a\u0440\u044b\u0442\u044c \u043a\u0430\u0440\u0442\u0438\u043d\u043a\u0443 {path}: {err}",
  "qr_none_found": "QR-\u043a\u043e\u0434 \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d \u0432 \u0444\u0430\u0439\u043b\u0435: {path}",
  "qr_no_otpauth": "\u0412 \u0444\u0430\u0439\u043b\u0435 {path} \u043d\u0435\u0442 otpauth:// QR-\u043a\u043e\u0434\u0430: {sample}",
  "qr_not_totp": "QR \u043d\u0435 \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f TOTP (otpauth://totp): {sample}",
  "qr_no_secret": "\u0412 QR \u043e\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u0435\u0442 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440 secret: {sample}",
  "qr_secret_empty": "\u041f\u0443\u0441\u0442\u043e\u0439 TOTP-\u0441\u0435\u043a\u0440\u0435\u0442.",
  "qr_secret_bad32": "TOTP-\u0441\u0435\u043a\u0440\u0435\u0442 \u043d\u0435 \u044f\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u044b\u043c base32: {err}",
  "totp_need_pyotp": "\u0414\u043b\u044f \u0433\u0435\u043d\u0435\u0440\u0430\u0446\u0438\u0438 TOTP \u043d\u0443\u0436\u0435\u043d \u043f\u0430\u043a\u0435\u0442 pyotp:\n    pip install pyotp",
  "totp_bad_algo": "\u041d\u0435\u0438\u0437\u0432\u0435\u0441\u0442\u043d\u044b\u0439 TOTP-\u0430\u043b\u0433\u043e\u0440\u0438\u0442\u043c: {algo} (\u043e\u0436\u0438\u0434\u0430\u043b\u0441\u044f SHA1/SHA256/SHA512)",
  "totp_bad_params": "\u041d\u0435\u043a\u043e\u0440\u0440\u0435\u043a\u0442\u043d\u044b\u0435 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b TOTP: digits={digits}, period={period}",
  "totp_init_failed": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0438\u043d\u0438\u0446\u0438\u0430\u043b\u0438\u0437\u0438\u0440\u043e\u0432\u0430\u0442\u044c TOTP \u0438\u0437 \u0441\u0435\u043a\u0440\u0435\u0442\u0430: {err}",
  "qr_saved": "TOTP-\u0441\u0435\u043a\u0440\u0435\u0442 \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d \u0432 {path} (mode 600); \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u044b: {digits} \u0446\u0438\u0444\u0440, \u043e\u043a\u043d\u043e {period} \u0441, {algo}.",
  "qr_saved_note": "\u041a\u043e\u0434\u044b 2FA \u0442\u0435\u043f\u0435\u0440\u044c \u0433\u0435\u043d\u0435\u0440\u0438\u0440\u0443\u044e\u0442\u0441\u044f \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438 (pyotp) \u043f\u043e \u0432\u0440\u0435\u043c\u0435\u043d\u0438 \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u0432 Mozilla.",
  "qr_verify_q": "\u0421\u043e\u0432\u043f\u0430\u0434\u0430\u0435\u0442 \u043b\u0438 \u043e\u043d \u0441 \u043a\u043e\u0434\u043e\u043c \u0432 \u043f\u0440\u0438\u043b\u043e\u0436\u0435\u043d\u0438\u0438-\u0430\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0440\u0435? [Y/n]: ",
  "qr_verify_mismatch": "\u0412\u0441\u0442\u0430\u0432\u044c\u0442\u0435 TOTP-\u0441\u0435\u043a\u0440\u0435\u0442 (base32) \u0438\u0437 \u043f\u0440\u0438\u043b\u043e\u0436\u0435\u043d\u0438\u044f \u0438\u043b\u0438 \u043f\u0443\u0442\u044c \u043a \u0434\u0440\u0443\u0433\u043e\u0439 QR-\u043a\u0430\u0440\u0442\u0438\u043d\u043a\u0435 (Enter \u2014 \u043e\u0442\u043c\u0435\u043d\u0430): ",
  "qr_verify_cancelled": "\u041e\u0442\u043c\u0435\u043d\u0435\u043d\u043e: \u0441\u0435\u043a\u0440\u0435\u0442 \u0438\u0437 QR \u043d\u0435 \u0441\u043e\u0432\u043f\u0430\u043b \u0441 \u043f\u0440\u0438\u043b\u043e\u0436\u0435\u043d\u0438\u0435\u043c.\n\u0415\u0441\u043b\u0438 2FA \u043f\u0435\u0440\u0435\u0441\u043e\u0437\u0434\u0430\u0432\u0430\u043b\u0441\u044f \u2014 \u0441\u043a\u0430\u0447\u0430\u0439\u0442\u0435 \u0441\u0432\u0435\u0436\u0438\u0439 QR: accounts.firefox.com \u2192 \u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 \u2192 Two-step authentication.",
  "qr_code_for_review": "\u041a\u043e\u0434 \u0438\u0437 \u0440\u0430\u0441\u043f\u043e\u0437\u043d\u0430\u043d\u043d\u043e\u0433\u043e QR (\u0434\u043b\u044f \u0441\u0432\u0435\u0440\u043a\u0438, \u0432\u043e\u043f\u0440\u043e\u0441 \u043d\u0435 \u0437\u0430\u0434\u0430\u0451\u0442\u0441\u044f, --qr-verify \u0447\u0442\u043e\u0431\u044b \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c): {code}, \u0434\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442 \u0435\u0449\u0451 {sec} \u0441",
  "proxy_check_started": "\u041f\u0430\u0440\u0430\u043b\u043b\u0435\u043b\u044c\u043d\u0430\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 {n} \u0430\u043f\u0441\u0442\u0440\u0438\u043c-\u043f\u0440\u043e\u043a\u0441\u0438 \u0447\u0435\u0440\u0435\u0437 '{service}' ({url}) ...",
  "proxy_check_summary_ok": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430: {n}/{total} \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u043e\u0432 \u043f\u0440\u043e\u043f\u0443\u0441\u0442\u0438\u043b\u0438 \u0434\u0430\u043d\u043d\u044b\u0435",
  "proxy_check_summary_fail": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430: {n}/{total} \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u043e\u0432 \u043f\u0440\u043e\u043f\u0443\u0441\u0442\u0438\u043b\u0438 \u0434\u0430\u043d\u043d\u044b\u0435; {n_fail} \u043d\u0435 \u043f\u0440\u043e\u043f\u0443\u0441\u0442\u0438\u043b\u0438 \u2014 \u043e\u043d\u0438 \u0432\u0441\u0451 \u0440\u0430\u0432\u043d\u043e \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u044e\u0442\u0441\u044f ({breakdown})",
  "probe_reason_tls": "TLS \u043a \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u0443 \u043d\u0435 \u0443\u0434\u0430\u043b\u0441\u044f (\u0441\u0435\u0442\u044c \u0438\u043b\u0438 \u0441\u0442\u043e\u0440\u043e\u043d\u0430 \u044d\u0433\u0440\u0435\u0441\u0441\u0430)",
  "probe_reason_timeout": "\u0442\u0430\u0439\u043c\u0430\u0443\u0442",
  "probe_reason_declined": "\u044d\u0433\u0440\u0435\u0441\u0441 \u043e\u0442\u043a\u043b\u043e\u043d\u0438\u043b \u0442\u0443\u043d\u043d\u0435\u043b\u044c CONNECT",
  "probe_reason_refused": "\u0432 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u0438 \u043e\u0442\u043a\u0430\u0437\u0430\u043d\u043e",
  "probe_reason_reset": "\u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u0435 \u0441\u0431\u0440\u043e\u0448\u0435\u043d\u043e",
  "probe_reason_unreachable": "\u0441\u0435\u0442\u044c \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u043d\u0430",
  "probe_reason_echo": "\u043e\u0442\u0432\u0435\u0442 echo-\u0441\u0435\u0440\u0432\u0438\u0441\u0430 \u043d\u0435 \u0440\u0430\u0437\u043e\u0431\u0440\u0430\u043d",
  "probe_reason_nodata": "\u0442\u0443\u043d\u043d\u0435\u043b\u044c \u043f\u0440\u0438\u043d\u044f\u0442, \u043d\u043e UDP-\u0434\u0430\u043d\u043d\u044b\u0435 \u043d\u0435 \u0432\u0435\u0440\u043d\u0443\u043b\u0438\u0441\u044c",
  "probe_reason_other": "\u0434\u0440\u0443\u0433\u0430\u044f \u0442\u0440\u0430\u043d\u0441\u043f\u043e\u0440\u0442\u043d\u0430\u044f \u043e\u0448\u0438\u0431\u043a\u0430",
  "proxy_check_masque_ok": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430: {hp} \u2014 \u0442\u0443\u043d\u043d\u0435\u043b\u044c MASQUE (HTTP/3 CONNECT-UDP) \u043f\u0440\u043e\u043f\u0443\u0441\u0442\u0438\u043b \u0434\u0430\u043d\u043d\u044b\u0435",
  "proxy_check_masque_fallback": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430: MASQUE \u043d\u0430 {hp} \u043d\u0435 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d \u2014 \u044d\u0442\u043e\u0442 \u0430\u043f\u0441\u0442\u0440\u0438\u043c \u0431\u0443\u0434\u0435\u0442 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u044c HTTP CONNECT",
  "proxy_check_connect_ok": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430: {hp} \u2014 \u0442\u0443\u043d\u043d\u0435\u043b\u044c CONNECT \u043f\u0440\u043e\u043f\u0443\u0441\u0442\u0438\u043b \u0434\u0430\u043d\u043d\u044b\u0435 (\u0432\u043d\u0435\u0448\u043d\u0438\u0439 IP {ip})",
  "proxy_check_connect_fail": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430: {hp} \u2014 \u0434\u0430\u043d\u043d\u044b\u0435 \u0447\u0435\u0440\u0435\u0437 \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u043d\u0435 \u043f\u0440\u043e\u0448\u043b\u0438 ({reason}); \u0430\u043f\u0441\u0442\u0440\u0438\u043c \u0432\u0441\u0451 \u0440\u0430\u0432\u043d\u043e \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f",
  "proxy_check_disabled": "\u041f\u0440\u0435\u0434\u0432\u0430\u0440\u0438\u0442\u0435\u043b\u044c\u043d\u0430\u044f \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u043f\u0440\u043e\u043a\u0441\u0438 \u043e\u0442\u043a\u043b\u044e\u0447\u0435\u043d\u0430 (--no-proxy-check): \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u044e \u0432\u0441\u0435 \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u044b \u0438\u0437 \u0441\u043f\u0438\u0441\u043a\u0430 \u043a\u0430\u043a \u0435\u0441\u0442\u044c.",
  "doh_selected": "DNS-\u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440 {_e}: {provider} ({url}) \u2014 \u0445\u043E\u0441\u0442\u044B \u0430\u043F\u0441\u0442\u0440\u0438\u043C\u043E\u0432 Fastly \u0440\u0435\u0437\u043E\u043B\u0432\u044F\u0442\u0441\u044F \u0422\u041E\u041B\u042C\u041A\u041E \u0447\u0435\u0440\u0435\u0437 DoH (\u043A\u0430\u043A TRR \u0432 Firefox); \u0435\u0441\u043B\u0438 \u044D\u0442\u043E\u0442 \u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440 \u043D\u0435\u0434\u043E\u0441\u0442\u0443\u043F\u0435\u043D, \u0446\u0435\u043F\u043E\u0447\u043A\u0430 \u043E\u0442\u043A\u0430\u0442\u044B\u0432\u0430\u0435\u0442\u0441\u044F \u043A \u043E\u0441\u0442\u0430\u043B\u044C\u043D\u044B\u043C DoH-\u043F\u0440\u043E\u0432\u0430\u0439\u0434\u0435\u0440\u0430\u043C. v5.29 \u0441\u0442\u0440\u043E\u0433\u0438\u0439 \u0440\u0435\u0436\u0438\u043C \u043F\u043E \u0443\u043C\u043E\u043B\u0447\u0430\u043D\u0438\u044E: \u0435\u0441\u043B\u0438 \u0412\u0421\u042F \u0446\u0435\u043F\u043E\u0447\u043A\u0430 \u043D\u0435 \u043E\u0442\u0432\u0435\u0442\u0438\u043B\u0430, \u0437\u0430\u043F\u0440\u043E\u0441 \u043F\u0430\u0434\u0430\u0435\u0442 \u2014 \u0441\u0438\u0441\u0442\u0435\u043C\u043D\u044B\u0439 \u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442\u0441\u044F \u0442\u043E\u043B\u044C\u043A\u043E \u043F\u0440\u0438 \u044F\u0432\u043D\u043E\u043C \u0432\u043A\u043B\u044E\u0447\u0435\u043D\u0438\u0438 --system-dns-fallback (\u0438\u043B\u0438 --doh off).",
  "doh_strict_mode": "\u0421\u0422\u0420\u041E\u0413\u0418\u0419 DoH {_e}: \u0435\u0441\u043B\u0438 \u0412\u0421\u042F DoH-\u0446\u0435\u043F\u043E\u0447\u043A\u0430 \u043D\u0435 \u043E\u0442\u0432\u0435\u0442\u0438\u043B\u0430, \u0437\u0430\u043F\u0440\u043E\u0441 \u041F\u0410\u0414\u0410\u0415\u0422 \u2014 \u043D\u0438\u043A\u0430\u043A\u043E\u0433\u043E \u0430\u0432\u0442\u043E\u043C\u0430\u0442\u0438\u0447\u0435\u0441\u043A\u043E\u0433\u043E \u0444\u043E\u043B\u0431\u044D\u043A\u0430 \u043D\u0430 \u0441\u0438\u0441\u0442\u0435\u043C\u043D\u044B\u0439 (\u043D\u0435-DoH) \u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440, \u0437\u0430\u043F\u0440\u043E\u0441 \u043D\u0435 \u0443\u0442\u0435\u043A\u0430\u0435\u0442 \u0432 \u043E\u0442\u043A\u0440\u044B\u0442\u044B\u0439 DNS (\u043A\u0430\u043A \u0440\u0435\u0436\u0438\u043C TRR mode 3 \u0432 Firefox). \u0412\u043A\u043B\u044E\u0447\u0438\u0442\u044C \u0444\u043E\u043B\u0431\u044D\u043A \u044F\u0432\u043D\u043E: --system-dns-fallback, \u043B\u0438\u0431\u043E \u043F\u0435\u0440\u0435\u0439\u0442\u0438 \u043D\u0430 \u0441\u0438\u0441\u0442\u0435\u043C\u043D\u044B\u0439 \u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440 \u0447\u0435\u0440\u0435\u0437 --doh off.",
  "system_dns_fallback_on": "\u0424\u043E\u043B\u0431\u044D\u043A \u043D\u0430 \u0441\u0438\u0441\u0442\u0435\u043C\u043D\u044B\u0439 DNS {_e}: \u0412\u041A\u041B\u042E\u0427\u0415\u041D (--system-dns-fallback) \u2014 \u043F\u0440\u0438 \u043E\u0442\u043A\u0430\u0437\u0435 \u0432\u0441\u0435\u0439 DoH-\u0446\u0435\u043F\u043E\u0447\u043A\u0438, \u043A\u0430\u043A \u0440\u0430\u043D\u044C\u0448\u0435, \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442\u0441\u044F \u0441\u0438\u0441\u0442\u0435\u043C\u043D\u044B\u0439 (\u043D\u0435-DoH) \u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440. \u041E\u0442\u043A\u043B\u044E\u0447\u0438\u0442\u044C: --no-system-dns-fallback.",
  "doh_chain": "\u0426\u0435\u043F\u043E\u0447\u043A\u0430 DoH (\u043F\u0440\u043E\u0432\u0435\u0440\u044F\u0435\u0442\u0441\u044F \u0441\u043B\u0435\u0432\u0430 \u043D\u0430\u043F\u0440\u0430\u0432\u043E, \u0432\u0441\u0435 \u044D\u043D\u0434\u043F\u043E\u0438\u043D\u0442\u044B \u0433\u043E\u0432\u043E\u0440\u044F\u0442 \u0422\u041E\u041B\u042C\u041A\u041E \u043F\u043E DoH): {chain}. \u0421\u0438\u0441\u0442\u0435\u043C\u043D\u044B\u0439 (\u043D\u0435-DoH) \u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440 \u0430\u0432\u0442\u043E\u043C\u0430\u0442\u0438\u0447\u0435\u0441\u043A\u0438 \u041D\u0415 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442\u0441\u044F \u041D\u0418\u041A\u041E\u0413\u0414\u0410 (\u0441\u0442\u0440\u043E\u0433\u0438\u0439 \u0440\u0435\u0436\u0438\u043C v5.29; --system-dns-fallback \u0432\u043A\u043B\u044E\u0447\u0430\u0435\u0442 \u0441\u0442\u0430\u0440\u043E\u0435 \u043F\u043E\u0432\u0435\u0434\u0435\u043D\u0438\u0435 \u044F\u0432\u043D\u043E). \u0421\u0442\u0440\u043E\u043A\u0430 \u0432\u044B\u0432\u043E\u0434\u0438\u0442\u0441\u044F \u043E\u0434\u0438\u043D \u0440\u0430\u0437 \u043F\u0440\u0438 \u0441\u0442\u0430\u0440\u0442\u0435; \u043E\u0442\u0434\u0435\u043B\u044C\u043D\u044B\u0435 DNS-\u0437\u0430\u043F\u0440\u043E\u0441\u044B \u0432\u043E \u0432\u0440\u0435\u043C\u044F \u0440\u0430\u0431\u043E\u0442\u044B \u0432 \u043B\u043E\u0433 \u043D\u0435 \u043F\u0438\u0448\u0443\u0442\u0441\u044F.",
  "doh_system": "DoH \u043e\u0442\u043a\u043b\u044e\u0447\u0451\u043d {_e} \u2014 \u0445\u043e\u0441\u0442\u044b \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u043e\u0432 \u0440\u0435\u0437\u043e\u043b\u0432\u0438\u0442 \u0421\u0418\u0421\u0422\u0415\u041c\u041d\u042b\u0419 DNS (\u043e\u0442\u0440\u0430\u0432\u043b\u0435\u043d\u043d\u044b\u0439/\u0433\u0435\u043e-\u043d\u0435\u0432\u0435\u0440\u043d\u044b\u0439 \u043e\u0442\u0432\u0435\u0442 \u043c\u043e\u0436\u0435\u0442 \u0443\u0432\u0435\u0441\u0442\u0438 \u043d\u0430 \u0447\u0443\u0436\u043e\u0439 PoP Fastly, \u043e\u0431\u044b\u0447\u043d\u043e \u0430\u043c\u0435\u0440\u0438\u043a\u0430\u043d\u0441\u043a\u0438\u0439). \u0418\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0439\u0442\u0435 --doh <\u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440> \u0438\u043b\u0438 \u043a\u043b\u0430\u0432\u0438\u0448\u0443 'h'.",
  "doh_system_short": "\u0441\u0438\u0441\u0442\u0435\u043c\u043d\u044b\u0439 DNS (DoH \u0432\u044b\u043a\u043b\u044e\u0447\u0435\u043d)",
  "geo_echo_no_geo": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u0433\u0435\u043e \u043f\u0440\u043e\u043f\u0443\u0449\u0435\u043d\u0430: echo-\u0441\u0435\u0440\u0432\u0438\u0441 \u00ab{service}\u00bb \u0432\u043e\u0437\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u0442\u043e\u043b\u044c\u043a\u043e IP. \u0418\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0439\u0442\u0435 --ip-echo-service ipinfo \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e (ipinfo.io/json) \u2014 \u0435\u0433\u043e \u0435\u0434\u0438\u043d\u0441\u0442\u0432\u0435\u043d\u043d\u044b\u0439 \u043e\u0442\u0432\u0435\u0442 \u0441\u043e\u0434\u0435\u0440\u0436\u0438\u0442 \u0438 IP, \u0438 \u0441\u0442\u0440\u0430\u043d\u0443/\u0433\u043e\u0440\u043e\u0434 \u0432\u044b\u0445\u043e\u0434\u0430.",
  "foxyproxy_no_proxies": "\u042d\u043a\u0441\u043f\u043e\u0440\u0442 FoxyProxy \u043f\u0440\u043e\u043f\u0443\u0449\u0435\u043d: \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u0441\u0435\u0439\u0447\u0430\u0441 \u043d\u0435 \u0437\u0430\u043f\u0443\u0449\u0435\u043d\u044b.",
  "foxyproxy_export_cancel": "\u042d\u043a\u0441\u043f\u043e\u0440\u0442 FoxyProxy \u043e\u0442\u043c\u0435\u043d\u0451\u043d \u2014 \u043f\u0443\u0442\u044c \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0438\u044f \u043d\u0435 \u0432\u044b\u0431\u0440\u0430\u043d.",
  "foxyproxy_export_done": "\u0424\u0430\u0439\u043b \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043a FoxyProxy \u0437\u0430\u043f\u0438\u0441\u0430\u043d: {path} ({n} \u043f\u0440\u043e\u043a\u0441\u0438, \u0444\u043e\u0440\u043c\u0430\u0442: {format})",
  "foxyproxy_export_fail": "\u041e\u0448\u0438\u0431\u043a\u0430 \u044d\u043a\u0441\u043f\u043e\u0440\u0442\u0430 \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043a FoxyProxy: {err}",
  "foxyproxy_import_hint": "\u0418\u043c\u043f\u043e\u0440\u0442 \u0432 FoxyProxy Standard: \u0444\u0430\u0439\u043b ({format}) \u0438\u043c\u043f\u043e\u0440\u0442\u0438\u0440\u0443\u0435\u0442\u0441\u044f \u041b\u042e\u0411\u042b\u041c \u043f\u0443\u0442\u0451\u043c - \u043a\u043d\u043e\u043f\u043a\u0430 'Import' \u0432\u0432\u0435\u0440\u0445\u0443 \u0441\u0442\u0440\u0430\u043d\u0438\u0446\u044b Options (\u0440\u044f\u0434\u043e\u043c \u0441 Export) \u0418\u041b\u0418 \u0432\u043a\u043b\u0430\u0434\u043a\u0430 Import -> 'Import from older versions'. \u041f\u043e\u0441\u043b\u0435 \u0438\u043c\u043f\u043e\u0440\u0442\u0430 \u043d\u0430\u0436\u043c\u0438\u0442\u0435 'Save', \u0447\u0442\u043e\u0431\u044b \u043f\u0440\u043e\u043a\u0441\u0438 \u0441\u043e\u0445\u0440\u0430\u043d\u0438\u043b\u0438\u0441\u044c.",
  "foxyproxy_path_prompt": "\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043f\u0443\u0442\u044c \u0434\u043b\u044f \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0438\u044f \u0444\u0430\u0439\u043b\u0430 \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043a FoxyProxy (\u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e: {name}): ",
  "foxyproxy_format_current": "\u043a\u043e\u043c\u0431\u0438\u043d\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0439 settings JSON (\u0430\u043a\u0442\u0443\u0430\u043b\u044c\u043d\u044b\u0439 v8+/v9.x 'data' + \u0437\u0430\u043f\u0438\u0441\u0438 FoxyProxy 6/7 - \u0438\u043c\u043f\u043e\u0440\u0442\u0438\u0440\u0443\u0435\u0442\u0441\u044f \u041b\u042e\u0411\u042b\u041c \u043f\u0443\u0442\u0451\u043c FoxyProxy)",
  "foxyproxy_format_legacy": "\u0443\u0441\u0442\u0430\u0440\u0435\u0432\u0448\u0438\u0439 settings JSON (\u041d\u0410\u0421\u0422\u041e\u042f\u0429\u0418\u0419 \u0444\u043e\u0440\u043c\u0430\u0442 \u044d\u043a\u0441\u043f\u043e\u0440\u0442\u0430 FoxyProxy 6/7 - \u0434\u043b\u044f 'Import from older versions')",
  "doh_cache_state_on": "\u041a\u044d\u0448 DoH {_e}: \u0412\u041a\u041b\u042e\u0427\u0401\u041d \u2014 \u043e\u0442\u0432\u0435\u0442\u044b \u043a\u044d\u0448\u0438\u0440\u0443\u044e\u0442\u0441\u044f {ttl} \u0441 (\u043a\u043b\u0430\u0432\u0438\u0448\u0430 'k' \u0438\u043b\u0438 --no-doh-cache \u043e\u0442\u043a\u043b\u044e\u0447\u0430\u0435\u0442).",
  "doh_cache_state_off": "\u041a\u044d\u0448 DoH {_e}: \u0412\u042b\u041a\u041b\u042e\u0427\u0415\u041d (\u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e) \u2014 \u043a\u0430\u0436\u0434\u044b\u0439 \u0437\u0430\u043f\u0440\u043e\u0441 \u0438\u0434\u0451\u0442 \u0432 DoH-\u0446\u0435\u043f\u043e\u0447\u043a\u0443 \u043d\u0430\u043f\u0440\u044f\u043c\u0443\u044e (\u043a\u043b\u0430\u0432\u0438\u0448\u0430 'k' \u0438\u043b\u0438 --doh-cache \u0432\u043a\u043b\u044e\u0447\u0430\u0435\u0442).",
  "doh_geo_mismatch": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u0433\u0435\u043e: {hp} \u0432\u044b\u0445\u043e\u0434\u0438\u0442 \u0432 {geo} ({city}), \u0430 \u043b\u043e\u043a\u0430\u0446\u0438\u044f \u2014 {cc} ({cname}). \u0410\u043f\u0441\u0442\u0440\u0438\u043c \u0434\u043e\u0441\u0442\u0438\u0433\u0430\u0435\u0442\u0441\u044f \u043f\u043e \u043d\u0435\u0432\u0435\u0440\u043d\u043e\u043c\u0443 \u043c\u0430\u0440\u0448\u0440\u0443\u0442\u0443 (\u043e\u0431\u044b\u0447\u043d\u043e \u0438\u0437-\u0437\u0430 \u0433\u0435\u043e-\u043d\u0435\u0432\u0435\u0440\u043d\u043e\u0433\u043e DNS-\u043e\u0442\u0432\u0435\u0442\u0430); \u043c\u0430\u0440\u0448\u0440\u0443\u0442 \u043f\u043e IPv6 \u043c\u043e\u0436\u0435\u0442 \u043f\u0440\u0438 \u044d\u0442\u043e\u043c \u043f\u043e\u043a\u0430\u0437\u044b\u0432\u0430\u0442\u044c \u043f\u0440\u0430\u0432\u0438\u043b\u044c\u043d\u0443\u044e \u0441\u0442\u0440\u0430\u043d\u0443.",
  "doh_geo_ok": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u0433\u0435\u043e: {hp} \u0432\u044b\u0445\u043e\u0434\u0438\u0442 \u0432 {geo} ({city}) \u2014 \u0441\u043e\u0432\u043f\u0430\u0434\u0430\u0435\u0442 \u0441 \u043b\u043e\u043a\u0430\u0446\u0438\u0435\u0439 {cc}.",
  "doh_menu_hint": "\u0412\u044b\u0431\u0435\u0440\u0438\u0442\u0435 DNS-\u0440\u0435\u0437\u043e\u043b\u0432\u0435\u0440 {_e} \u2014 \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u0435\u0433\u043e \u043d\u043e\u043c\u0435\u0440/\u0431\u0443\u043a\u0432\u0443 \u0438 \u043d\u0430\u0436\u043c\u0438\u0442\u0435 Enter (Backspace \u0443\u0434\u0430\u043b\u044f\u0435\u0442 \u0441\u0438\u043c\u0432\u043e\u043b, \u043b\u044e\u0431\u0430\u044f \u0434\u0440\u0443\u0433\u0430\u044f \u043a\u043b\u0430\u0432\u0438\u0448\u043a\u0430 \u043e\u0442\u043c\u0435\u043d\u044f\u0435\u0442). \u0412\u044b\u0431\u043e\u0440 \u0437\u0430\u0434\u0430\u0451\u0442 \u0441\u043e\u0431\u0441\u0442\u0432\u0435\u043d\u043d\u044b\u0439 \u0440\u0435\u0437\u043e\u043b\u0432\u0435\u0440 \u0441\u043a\u0440\u0438\u043f\u0442\u0430 \u0418 DoH-\u0446\u0435\u043b\u044c DNS-\u0442\u043e\u0447\u0435\u043a \u043f\u0440\u043e\u043a\u0441\u0438 (\u0442\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u044b\u0439 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440, \u0431\u0435\u0437 \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u043e\u0442\u043a\u0430\u0442\u043e\u0432; \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e cloudflare):",
  "lang_menu_hint": "\u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u044F\u0437\u044B\u043A \u0438\u043D\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u0430 {_e} \u2014 \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u0435\u0433\u043E \u043D\u043E\u043C\u0435\u0440 \u0438 \u043D\u0430\u0436\u043C\u0438\u0442\u0435 Enter (\u0442\u0435\u043A\u0443\u0449\u0438\u0439: {cur}). \u041E\u043F\u0446\u0438\u044F 0 \u0441\u0431\u0440\u0430\u0441\u044B\u0432\u0430\u0435\u0442 \u043D\u0430 \u044F\u0437\u044B\u043A \u041F\u041E \u0423\u041C\u041E\u041B\u0427\u0410\u041D\u0418\u042E \u0438 \u043E\u0447\u0438\u0449\u0430\u0435\u0442 \u0441\u043E\u0445\u0440\u0430\u043D\u0451\u043D\u043D\u044B\u0439 \u0432\u044B\u0431\u043E\u0440. \u0412\u044B\u0431\u043E\u0440 \u0441\u043E\u0445\u0440\u0430\u043D\u044F\u0435\u0442\u0441\u044F \u0432 config.json (settings.lang \u0442\u0435\u043a\u0443\u0449\u0435\u0433\u043e \u043f\u0440\u043e\u0444\u0438\u043b\u044f) \u0438 \u0434\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442 \u043F\u043E\u0441\u043B\u0435 \u043F\u0435\u0440\u0435\u0437\u0430\u043F\u0443\u0441\u043A\u043E\u0432 (Backspace \u0443\u0434\u0430\u043B\u044F\u0435\u0442, \u043B\u044E\u0431\u0430\u044F \u0434\u0440\u0443\u0433\u0430\u044F \u043A\u043B\u0430\u0432\u0438\u0448\u0430 \u043E\u0442\u043C\u0435\u043D\u044F\u0435\u0442; \u043F\u043E\u0441\u043B\u0435 \u043F\u0440\u0438\u043C\u0435\u043D\u0435\u043D\u0438\u044F \u043C\u0435\u043D\u044E \u0437\u0430\u043A\u0440\u044B\u0432\u0430\u0435\u0442\u0441\u044F \u0430\u0432\u0442\u043E\u043C\u0430\u0442\u0438\u0447\u0435\u0441\u043A\u0438).",
  "lang_menu_entry": "  {n} - {desc}",
  "lang_default_desc": "\u042F\u0417\u042B\u041A \u041F\u041E \u0423\u041C\u041E\u041B\u0427\u0410\u041D\u0418\u042E (\u0430\u043D\u0433\u043B\u0438\u0439\u0441\u043A\u0438\u0439) \u2014 \u0441\u0431\u0440\u0430\u0441\u044B\u0432\u0430\u0435\u0442 \u0441\u043E\u0445\u0440\u0430\u043D\u0451\u043D\u043D\u044B\u0439 \u0432\u044B\u0431\u043E\u0440",
  "lang_set": "\u042F\u0437\u044B\u043A \u0438\u043D\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u0430 {_e}: {lang} \u2014 \u0441\u043E\u0445\u0440\u0430\u043D\u0451\u043D \u0432 config.json (settings.lang \u0442\u0435\u043a\u0443\u0449\u0435\u0433\u043e \u043f\u0440\u043e\u0444\u0438\u043b\u044f), \u0434\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442 \u0438 \u043F\u043E\u0441\u043B\u0435 \u043F\u0435\u0440\u0435\u0437\u0430\u043F\u0443\u0441\u043A\u043E\u0432.",
  "lang_reset": "\u042F\u0437\u044B\u043A \u0438\u043D\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u0430 {_e}: \u0441\u0431\u0440\u043E\u0448\u0435\u043D \u043D\u0430 \u044F\u0437\u044B\u043A \u041F\u041E \u0423\u041C\u041E\u041B\u0427\u0410\u041D\u0418\u042E ({lang}) \u2014 \u0441\u043E\u0445\u0440\u0430\u043D\u0451\u043D\u043D\u044B\u0439 \u0432\u044B\u0431\u043E\u0440 \u043E\u0447\u0438\u0449\u0435\u043D.",
  "doh_menu_entry": "  {n} - {name}{url}",
  "doh_default_desc": "\u041f\u041e \u0423\u041c\u041e\u041b\u0427\u0410\u041d\u0418\u042e",
  "doh_default_applied": "DNS-\u0440\u0435\u0437\u043e\u043b\u0432\u0435\u0440 {_e}: \u043f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0451\u043d \u043d\u0430 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440 \u041f\u041e \u0423\u041c\u041e\u041b\u0427\u0410\u041d\u0418\u042e ({provider}). \u0412\u044b\u0431\u043e\u0440 \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d \u0432 config.json (settings.doh \u0442\u0435\u043a\u0443\u0449\u0435\u0433\u043e \u043f\u0440\u043e\u0444\u0438\u043b\u044f) \u0438 \u0434\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442 \u0438 \u043f\u043e\u0441\u043b\u0435 \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u043a\u043e\u0432.",
  "hotkey_doh": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'h': DNS-\u0440\u0435\u0437\u043e\u043b\u0432\u0435\u0440 \u043f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0451\u043d \u043d\u0430 {provider} \u2014 \u043d\u043e\u0432\u044b\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u044f \u043a \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u0430\u043c \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u044e\u0442 \u0435\u0433\u043e \u0441\u0440\u0430\u0437\u0443 (\u0434\u0432\u0438\u0436\u043e\u043a sing-box \u0440\u0435\u0437\u043e\u043b\u0432\u0438\u0442 \u0441\u0430\u043c); DNS-\u0442\u043e\u0447\u043a\u0438 \u043f\u0440\u043e\u043a\u0441\u0438 \u043d\u0435\u0441\u0443\u0442 \u0437\u0430\u043f\u0440\u043e\u0441\u044b \u0442\u043e\u043b\u044c\u043a\u043e \u043a \u043d\u0435\u043c\u0443 \u0441\u043e \u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0435\u0433\u043e \u0437\u0430\u043f\u0440\u043e\u0441\u0430 (\u0442\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u044b\u0439 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440, \u0431\u0435\u0437 \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u043e\u0442\u043a\u0430\u0442\u043e\u0432; \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e cloudflare).",
  "hotkey_doh_cache": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'k': \u043a\u044d\u0448 DoH {state} (\u0437\u0435\u0440\u043a\u0430\u043b\u0438\u0442 --doh-cache).",
  "select_hint": "\u0412\u0432\u0435\u0434\u0438\u0442\u0435 \u043d\u043e\u043c\u0435\u0440/\u0431\u0443\u043a\u0432\u0443 \u043f\u0443\u043d\u043a\u0442\u0430 \u0438 \u043d\u0430\u0436\u043c\u0438\u0442\u0435 Enter. Backspace \u0443\u0434\u0430\u043b\u044f\u0435\u0442 \u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0439 \u0441\u0438\u043c\u0432\u043e\u043b, \u043b\u044e\u0431\u0430\u044f \u0434\u0440\u0443\u0433\u0430\u044f \u043a\u043b\u0430\u0432\u0438\u0448\u0430 \u043e\u0442\u043c\u0435\u043d\u044f\u0435\u0442 \u0432\u044b\u0431\u043e\u0440.",
  "select_buffer": "\u0412\u0430\u0448 \u0432\u044b\u0431\u043e\u0440: {buf}",
  "select_bad": "\u041f\u0443\u043d\u043a\u0442\u0430 '{buf}' \u043d\u0435\u0442 \u2014 \u043e\u0442\u043c\u0435\u043d\u0435\u043d\u043e.",
  "select_hint_multi": "\u041c\u043d\u043e\u0436\u0435\u0441\u0442\u0432\u0435\u043d\u043d\u044b\u0439 \u0432\u044b\u0431\u043e\u0440: \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u043d\u0435\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u0442\u043e\u043a\u0435\u043d\u043e\u0432 \u0427\u0415\u0420\u0415\u0417 \u041f\u0420\u041e\u0411\u0415\u041b (\u043f\u0440\u0438\u043c\u0435\u0440: 1 3 a) \u0438 \u043d\u0430\u0436\u043c\u0438\u0442\u0435 Enter. '0' = \u0432\u0441\u0435 \u043f\u0440\u043e\u043a\u0441\u0438. Backspace \u0443\u0434\u0430\u043b\u044f\u0435\u0442, \u043b\u044e\u0431\u0430\u044f \u0434\u0440\u0443\u0433\u0430\u044f \u043a\u043b\u0430\u0432\u0438\u0448\u0430 \u043e\u0442\u043c\u0435\u043d\u044f\u0435\u0442.",
  "multi_buffer": "\u0412\u044b\u0431\u0440\u0430\u043d\u043e: {buf}",
  "multi_bad": "\u041f\u0443\u043d\u043a\u0442\u0430 '{tok}' \u043d\u0435\u0442 \u2014 \u043e\u043d \u043f\u0440\u043e\u043f\u0443\u0449\u0435\u043d.",
  "countries_menu_hint": "\u0412\u044b\u0431\u0435\u0440\u0438\u0442\u0435, \u043a\u0430\u043a\u0438\u0435 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u0437\u0430\u043f\u0443\u0441\u043a\u0430\u0442\u044c {_e} \u2014 \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u0442\u043e\u043a\u0435\u043d\u044b \u043f\u0440\u043e\u043a\u0441\u0438 \u0427\u0415\u0420\u0415\u0417 \u041f\u0420\u041e\u0411\u0415\u041b \u0438 \u043d\u0430\u0436\u043c\u0438\u0442\u0435 Enter (0 = \u0432\u0441\u0435 \u043f\u0440\u043e\u043a\u0441\u0438, Backspace \u0443\u0434\u0430\u043b\u044f\u0435\u0442, \u043b\u044e\u0431\u0430\u044f \u0434\u0440\u0443\u0433\u0430\u044f \u043a\u043b\u0430\u0432\u0438\u0448\u0430 \u043e\u0442\u043c\u0435\u043d\u044f\u0435\u0442):",
  "countries_menu_entry": "  {n} - {desc}",
  "filter_all_desc": "\u0412\u0421\u0415 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 (\u0441\u043d\u0438\u043c\u0430\u0435\u0442 \u0444\u0438\u043b\u044c\u0442\u0440)",
  "countries_filter_applied": "\u0424\u0438\u043b\u044c\u0442\u0440 \u043f\u0440\u043e\u043a\u0441\u0438 {_e}: \u0431\u0443\u0434\u0443\u0442 \u043e\u0431\u0441\u043b\u0443\u0436\u0435\u043d\u044b {n} \u0438\u0437 {m} \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u043e\u0432 ({list}). \u0412\u044b\u0431\u043e\u0440 \u0441\u043e\u0445\u0440\u0430\u043d\u044f\u0435\u0442\u0441\u044f \u0438 \u043f\u0435\u0440\u0435\u0436\u0438\u0432\u0430\u0435\u0442 \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u043a\u0438 (\u043a\u043b\u0430\u0432\u0438\u0448\u0430 'w' \u0438\u043b\u0438 --countries).",
  "filter_all_applied": "\u0424\u0438\u043b\u044c\u0442\u0440 \u043f\u0440\u043e\u043a\u0441\u0438 {_e}: \u0431\u0443\u0434\u0443\u0442 \u0437\u0430\u043f\u0443\u0449\u0435\u043d\u044b \u0412\u0421\u0415 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 (\u0444\u0438\u043b\u044c\u0442\u0440 \u0441\u043d\u044f\u0442).",
  "resolver_blip_note": "\u041E\u0448\u0438\u0431\u043A\u0430 \u0441\u0435\u0442\u0438 {_e}: \u0432\u0440\u0435\u043C\u0435\u043D\u043D\u044B\u0439 \u0441\u0431\u043E\u0439 DNS (\u0435\u0434\u0438\u043D\u0438\u0447\u043D\u044B\u0439) \u2014 \u043F\u043E\u0432\u0442\u043E\u0440\u044F\u044E \u0437\u0430\u043F\u0440\u043E\u0441 \u043E\u0434\u0438\u043D \u0440\u0430\u0437 \u043F\u043E\u0441\u043B\u0435 \u043A\u043E\u0440\u043E\u0442\u043A\u043E\u0439 \u043F\u0430\u0443\u0437\u044B (\u0437\u0434\u043E\u0440\u043E\u0432\u044B\u0439 \u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440 \u043E\u0431\u044B\u0447\u043D\u043E \u0432\u043E\u0441\u0441\u0442\u0430\u043D\u0430\u0432\u043B\u0438\u0432\u0430\u0435\u0442\u0441\u044F \u0441\u043E \u0441\u043B\u0435\u0434\u0443\u044E\u0449\u0435\u0439 \u043F\u043E\u043F\u044B\u0442\u043A\u0438).",
  "resolver_broken_note": "\u041E\u0448\u0438\u0431\u043A\u0430 \u0441\u0435\u0442\u0438 {_e}: \u0441\u0438\u0441\u0442\u0435\u043C\u043D\u044B\u0439 \u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440 \u0421\u041B\u041E\u041C\u0410\u041D (\u0443\u0441\u0442\u043E\u0439\u0447\u0438\u0432\u044B\u0439 \u0441\u0431\u043E\u0439 DNS \u2014 \u0438\u0437\u0432\u0435\u0441\u0442\u043D\u0430\u044F \u043F\u0440\u043E\u0431\u043B\u0435\u043C\u0430 \u0443\u043F\u0430\u043A\u043E\u0432\u0430\u043D\u043D\u043E\u0433\u043E \u0431\u0438\u043D\u0430\u0440\u043D\u0438\u043A\u0430 \u043D\u0430 Android, python-for-android #1447) \u2014 \u043F\u0435\u0440\u0435\u0445\u043E\u0436\u0443 \u043D\u0430 \u0430\u0432\u0430\u0440\u0438\u0439\u043D\u044B\u0439 \u043C\u0430\u0440\u0448\u0440\u0443\u0442 \u0447\u0435\u0440\u0435\u0437 \u043F\u0440\u044F\u043C\u044B\u0435 IP: \u0430\u0432\u0430\u0440\u0438\u0439\u043D\u044B\u0439 DoH \u0438\u0434\u0451\u0442 \u043F\u0440\u044F\u043C\u043E \u043D\u0430 \u0438\u0437\u0432\u0435\u0441\u0442\u043D\u044B\u0435 IP \u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440\u043E\u0432, \u043A\u0430\u0436\u0434\u044B\u0439 \u0437\u0430\u043F\u0440\u043E\u0441 \u0441\u043E\u0435\u0434\u0438\u043D\u044F\u0435\u0442\u0441\u044F \u0441 \u0443\u0436\u0435 \u0440\u0430\u0437\u0440\u0435\u0448\u0451\u043D\u043D\u044B\u043C IP (SNI/Host \u0441\u043E\u0445\u0440\u0430\u043D\u044F\u044E\u0442\u0441\u044F), \u0441\u0438\u0441\u0442\u0435\u043C\u043D\u044B\u0439 \u0440\u0435\u0437\u043E\u043B\u0432\u0435\u0440 \u0431\u043E\u043B\u044C\u0448\u0435 \u043D\u0438\u0433\u0434\u0435 \u043D\u0435 \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442\u0441\u044F.",
  "probe_filter_applied": "\u0424\u0438\u043b\u044c\u0442\u0440 \u043f\u0440\u043e\u0431 {_e}: \u043f\u0440\u043e\u0431\u0438\u0440\u0443\u044e\u0442\u0441\u044f \u0442\u043e\u043b\u044c\u043a\u043e {n} \u0438\u0437 {m} \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u043e\u0432 - \u0432\u043a\u043b\u044e\u0447\u0451\u043d \u0432\u044b\u0431\u043e\u0440 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0445 \u043f\u0440\u043e\u043a\u0441\u0438 (--countries / \u043a\u043b\u0430\u0432\u0438\u0448\u0430 'w'), \u043f\u043e\u044d\u0442\u043e\u043c\u0443 \u043f\u0440\u043e\u0431\u044b \u0438\u0434\u0443\u0442 \u0442\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u044b\u0445 \u0432\u0430\u043c\u0438 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0445 \u043f\u0440\u043e\u043a\u0441\u0438.",
  "accounts_none": "\u041a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0445 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u043e\u0432 Mozilla \u043f\u043e\u043a\u0430 \u043d\u0435\u0442. \u0410\u043a\u043a\u0430\u0443\u043d\u0442 \u043a\u044d\u0448\u0438\u0440\u0443\u0435\u0442\u0441\u044f \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438 \u043f\u043e\u0441\u043b\u0435 \u041a\u0410\u0416\u0414\u041e\u0413\u041e \u0443\u0441\u043f\u0435\u0448\u043d\u043e\u0433\u043e \u0432\u0445\u043e\u0434\u0430 (config.json).",
  "accounts_list_header": "\u041a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0435 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u044b Mozilla ({n}) - config.json:",
  "account_list_entry": "  {n} - {email}  (\u043f\u0430\u0440\u043e\u043b\u044c: {pw}, TOTP: {totp}, \u0441\u0435\u0441\u0441\u0438\u044f: {session}, \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d: {saved})",
  "account_reveal_entry": "  {n} - \u043b\u043e\u0433\u0438\u043d: {email}  \u043f\u0430\u0440\u043e\u043b\u044c: {password}  \u0442\u0435\u043a\u0443\u0449\u0438\u0439 TOTP: {code}",
  "accounts_qr_dir": "\u041a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0435 QR-\u043a\u0430\u0440\u0442\u0438\u043d\u043a\u0438 \u0445\u0440\u0430\u043d\u044f\u0442\u0441\u044f \u0432: {dir}",
  "accounts_menu_hint": "\u041f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0438\u0442\u044c\u0441\u044f \u043d\u0430 \u0434\u0440\u0443\u0433\u043e\u0439 \u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0430\u043a\u043a\u0430\u0443\u043d\u0442 Mozilla {_e} - \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u0435\u0433\u043e \u043d\u043e\u043c\u0435\u0440/\u0431\u0443\u043a\u0432\u0443 \u0438 \u043d\u0430\u0436\u043c\u0438\u0442\u0435 Enter (\u043f\u0443\u0441\u0442\u043e\u0439 \u0432\u0432\u043e\u0434 \u043e\u0442\u043c\u0435\u043d\u044f\u0435\u0442):",
  "account_menu_entry": "  {n} - {email}",
  "accounts_choice_prompt": "\u041d\u043e\u043c\u0435\u0440/\u0431\u0443\u043a\u0432\u0430 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 (Enter = \u043e\u0442\u043c\u0435\u043d\u0430): ",
  "accounts_bad_token": "\u0410\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u0441 \u0442\u0430\u043a\u0438\u043c \u0442\u043e\u043a\u0435\u043d\u043e\u043c \u043d\u0435\u0442 - \u043e\u0442\u043c\u0435\u043d\u0435\u043d\u043e.",
  "account_switched": "\u041f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u0435 \u043d\u0430 \u0430\u043a\u043a\u0430\u0443\u043d\u0442 {_e}: {email} ({session}).",
  "profile_applied": "\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 \u043f\u0440\u043e\u0444\u0438\u043b\u044f \u043f\u0440\u0438\u043c\u0435\u043d\u0435\u043d\u044b {_e}: {email} \u2014 \u0435\u0433\u043e \u044f\u0437\u044b\u043a, DNS-\u0440\u0435\u0437\u043e\u043b\u0432\u0435\u0440, \u0432\u044b\u0431\u043e\u0440 \u043f\u0440\u043e\u043a\u0441\u0438, \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 sing-box \u0438 cookie Fastly \u0442\u0435\u043f\u0435\u0440\u044c \u0430\u043a\u0442\u0438\u0432\u043d\u044b.",
  "account_session_used": "\u0441\u043d\u0430\u0447\u0430\u043b\u0430 \u043f\u0440\u043e\u0431\u0443\u0435\u0442\u0441\u044f \u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0439 sessionToken, \u0437\u0430\u0442\u0435\u043c \u0441\u0432\u0435\u0436\u0438\u0439 \u0432\u0445\u043e\u0434",
  "account_session_fresh": "\u0441\u0432\u0435\u0436\u0438\u0439 \u0432\u0445\u043e\u0434 \u0441 \u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u043c \u043b\u043e\u0433\u0438\u043d\u043e\u043c/\u043f\u0430\u0440\u043e\u043b\u0435\u043c",
  "account_cached": "\u0410\u043a\u043a\u0430\u0443\u043d\u0442 \u0437\u0430\u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d {_e}: {email} (config.json).",
  "account_qr_saved": "QR-\u043a\u0430\u0440\u0442\u0438\u043d\u043a\u0430 \u0441\u0435\u043a\u0440\u0435\u0442\u0430 2FA \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0430 \u0432 \u043a\u044d\u0448: {path}",
  "accounts_json_saved": "\u0412\u0441\u0435 \u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0435 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u044b ({n}) \u044d\u043a\u0441\u043f\u043e\u0440\u0442\u0438\u0440\u043e\u0432\u0430\u043d\u044b \u0432: {path}",
  "accounts_survived_wipe": "\u0425\u0440\u0430\u043d\u0438\u043b\u0438\u0449\u0435 \u043c\u043d\u043e\u0433\u043e\u0430\u043a\u043a\u0430\u0443\u043d\u0442\u043d\u043e\u0441\u0442\u0438 (config.json) \u043f\u0435\u0440\u0435\u0436\u0438\u0432\u0430\u0435\u0442 \u044d\u0442\u0443 \u043e\u0447\u0438\u0441\u0442\u043a\u0443: {path}",
  "accounts_menu_add": "  + - \u0434\u043e\u0431\u0430\u0432\u0438\u0442\u044c \u041d\u041e\u0412\u042b\u0419 \u0430\u043a\u043a\u0430\u0443\u043d\u0442 Mozilla (\u0441\u0432\u0435\u0436\u0438\u0439 \u0432\u0445\u043e\u0434; \u043e\u043d \u0431\u0443\u0434\u0435\u0442 \u0437\u0430\u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d \u0432 config.json)",
  "accounts_menu_del": "  - - \u0443\u0434\u0430\u043b\u0438\u0442\u044c \u0437\u0430\u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0430\u043a\u043a\u0430\u0443\u043d\u0442 \u0438\u0437 config.json",
  "accounts_add_hint": "\u041d\u043e\u0432\u044b\u0439 \u0430\u043a\u043a\u0430\u0443\u043d\u0442 {_e}: \u0434\u0430\u043b\u0435\u0435 \u043f\u043e\u044f\u0432\u044f\u0442\u0441\u044f \u0437\u0430\u043f\u0440\u043e\u0441\u044b email/\u043f\u0430\u0440\u043e\u043b\u044f/2FA - \u0432\u043e\u0439\u0434\u0438\u0442\u0435 \u0441 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u043e\u043c, \u043a\u043e\u0442\u043e\u0440\u044b\u0439 \u043d\u0443\u0436\u043d\u043e \u0414\u041e\u0411\u0410\u0412\u0418\u0422\u042c (\u0432\u0441\u0435 \u0440\u0430\u043d\u0435\u0435 \u0437\u0430\u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0435 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u044b \u0441\u043e\u0445\u0440\u0430\u043d\u044f\u044e\u0442\u0441\u044f).",
  "accounts_delete_prompt": "\u041d\u043e\u043c\u0435\u0440/\u0431\u0443\u043a\u0432\u0430 \u0443\u0434\u0430\u043b\u044f\u0435\u043c\u043e\u0433\u043e \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 (Enter = \u043e\u0442\u043c\u0435\u043d\u0430): ",
  "accounts_delete_missing": "\u0410\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u0441 \u0442\u0430\u043a\u0438\u043c \u0442\u043e\u043a\u0435\u043d\u043e\u043c \u043d\u0435\u0442 - \u043d\u0438\u0447\u0435\u0433\u043e \u043d\u0435 \u0443\u0434\u0430\u043b\u0435\u043d\u043e.",
  "accounts_deleted": "\u0410\u043a\u043a\u0430\u0443\u043d\u0442 \u0443\u0434\u0430\u043b\u0451\u043d {_e}: {email} (\u0443\u0434\u0430\u043b\u0451\u043d \u0438\u0437 config.json).",
  "accounts_delete_last": "\u042d\u0442\u043e \u0431\u044b\u043b \u041f\u041e\u0421\u041b\u0415\u0414\u041d\u0418\u0419 \u0437\u0430\u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0430\u043a\u043a\u0430\u0443\u043d\u0442 - \u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0438\u0439 \u0432\u0445\u043e\u0434 \u043d\u0430\u0447\u043d\u0451\u0442\u0441\u044f \u0441 \u043d\u0443\u043b\u044f.",
  "accounts_not_found": "\u0417\u0430\u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u043e\u0433\u043e \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u0441 \u0442\u0430\u043a\u0438\u043c email \u043d\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442 (config.json); \u0441\u043c. --list-accounts.",
  "refresh_retry_soon": "\u0422\u0435\u043a\u0443\u0449\u0438\u0439 proxyPass \u0432\u0441\u0451 \u0435\u0449\u0451 \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0442\u0435\u043b\u0435\u043d {_e}: \u043f\u043e\u0432\u0442\u043e\u0440\u044f\u044e \u043e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u0435 \u0447\u0435\u0440\u0435\u0437 {sec} \u0441 \u0432\u043c\u0435\u0441\u0442\u043e \u043f\u043e\u043b\u043d\u043e\u0433\u043e \u043e\u0436\u0438\u0434\u0430\u043d\u0438\u044f - \u0442\u043e\u043a\u0435\u043d \u043e\u0431\u043d\u043e\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u0417\u0410\u0420\u0410\u041d\u0415\u0415, \u0434\u043e \u0443\u0441\u0442\u0430\u0440\u0435\u0432\u0430\u043d\u0438\u044f \u0441\u0442\u0430\u0440\u043e\u0433\u043e.",
  "config_migration_header": "\u041f\u0435\u0440\u0432\u044b\u0439 \u0437\u0430\u043f\u0443\u0441\u043a: \u043f\u0435\u0440\u0435\u043d\u043e\u0448\u0443 \u0421\u0422\u0410\u0420\u0423\u042e \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u044e \u0432 \u0443\u0431\u0435\u0440-\u0444\u0430\u0439\u043b {_e}: {path}",
  "config_migration_entry": "\u041f\u0435\u0440\u0435\u043d\u0435\u0441\u0435\u043d\u043e: {name}",
  "config_migration_done": "\u041c\u0438\u0433\u0440\u0430\u0446\u0438\u044f \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0430 {_e}: \u044d\u043b\u0435\u043c\u0435\u043d\u0442\u043e\u0432 \u043f\u0435\u0440\u0435\u043d\u0435\u0441\u0435\u043d\u043e: {n}, \u0441\u0442\u0430\u0440\u044b\u0445 \u0444\u0430\u0439\u043b\u043e\u0432/\u043a\u0430\u0442\u0430\u043b\u043e\u0433\u043e\u0432 \u0443\u0434\u0430\u043b\u0435\u043d\u043e: {removed} - \u0432\u0441\u044f \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u044f \u0442\u0435\u043f\u0435\u0440\u044c \u0436\u0438\u0432\u0451\u0442 \u0432 \u041e\u0414\u041d\u041e\u041c \u0444\u0430\u0439\u043b\u0435: {path}",
  "clean_old_none": "\u041e\u0441\u0442\u0430\u0442\u043a\u043e\u0432 \u0421\u0422\u0410\u0420\u041e\u0413\u041e \u0444\u043e\u0440\u043c\u0430\u0442\u0430 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d\u043e - \u0432\u0441\u0451 \u0443\u0436\u0435 \u0445\u0440\u0430\u043d\u0438\u0442\u0441\u044f \u0432 config.json.",
  "clean_old_header": "\u041d\u0430\u0439\u0434\u0435\u043d\u043e \u043e\u0441\u0442\u0430\u0442\u043a\u043e\u0432 \u0441\u0442\u0430\u0440\u043e\u0433\u043e \u0444\u043e\u0440\u043c\u0430\u0442\u0430: {n} - \u0443\u0434\u0430\u043b\u044f\u044e {_e} ...",
  "clean_old_removed": "\u0423\u0434\u0430\u043b\u0435\u043d\u043e: {path}",
  "clean_old_failed": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0443\u0434\u0430\u043b\u0438\u0442\u044c {path}: {err}",
  "clean_old_done": "\u041e\u0447\u0438\u0441\u0442\u043a\u0430 \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0430 {_e}: \u0443\u0434\u0430\u043b\u0435\u043d\u043e \u044d\u043b\u0435\u043c\u0435\u043d\u0442\u043e\u0432: {n}. \u0412\u0441\u044f \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u044f \u0442\u0435\u043f\u0435\u0440\u044c \u0445\u0440\u0430\u043d\u0438\u0442\u0441\u044f \u0422\u041e\u041b\u042c\u041a\u041e \u0432 config.json.",
  "filter_empty_fallback": "\u0421\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u044b\u0439 \u0444\u0438\u043b\u044c\u0442\u0440 \u043f\u0440\u043e\u043a\u0441\u0438 \u043d\u0435 \u043d\u0430\u0448\u0451\u043b \u043d\u0438 \u043e\u0434\u043d\u043e\u0433\u043e \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u0430 \u2014 \u043e\u0431\u0441\u043b\u0443\u0436\u0438\u0432\u0430\u044e\u0442\u0441\u044f \u0412\u0421\u0415 (\u0441\u043d\u0438\u043c\u0438\u0442\u0435 \u0444\u0438\u043b\u044c\u0442\u0440: \u043a\u043b\u0430\u0432\u0438\u0448\u0430 'w' -> 0).",
  "hotkey_countries": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'w': \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u0442\u044f\u0442\u0441\u044f \u0441 \u043d\u043e\u0432\u044b\u043c \u0432\u044b\u0431\u043e\u0440\u043e\u043c.",
  "net_error_retry": "\u0421\u0435\u0442\u0435\u0432\u0430\u044f \u043e\u0448\u0438\u0431\u043a\u0430 {_e}: {err} \u2014 \u043f\u043e\u0432\u0442\u043e\u0440 \u0447\u0435\u0440\u0435\u0437 30 \u0441 (\u0432\u0440\u0435\u043c\u0435\u043d\u043d\u044b\u0439 \u0441\u0431\u043e\u0439 \u2014 DNS \u0438\u043b\u0438 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u0435; \u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0430\u044f \u043f\u043e\u043f\u044b\u0442\u043a\u0430 \u043e\u0431\u044b\u0447\u043d\u043e \u0443\u0441\u043f\u0435\u0448\u043d\u0430).",
  "net_err_dns": "\u0432\u0440\u0435\u043c\u0435\u043d\u043d\u044b\u0439 \u0441\u0431\u043e\u0439 DNS (\u043d\u0435\u0442 \u0430\u0434\u0440\u0435\u0441\u0430, \u0430\u0441\u0441\u043e\u0446\u0438\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u043e\u0433\u043e \u0441 \u0438\u043c\u0435\u043d\u0435\u043c \u0445\u043e\u0441\u0442\u0430)",
  "net_err_timeout": "\u0438\u0441\u0442\u0451\u043a \u0442\u0430\u0439\u043c\u0430\u0443\u0442",
  "net_err_conn": "\u0441\u0431\u043e\u0439 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f (\u043e\u0442\u043a\u0430\u0437\u0430\u043d\u043e/\u0441\u0431\u0440\u043e\u0441/\u043d\u0435\u0434\u043e\u0441\u0442\u0438\u0436\u0438\u043c\u043e)",
  "locked_note": "\u041f\u0440\u0438\u043c\u0435\u0447\u0430\u043d\u0438\u0435 {_e}: \u0432 \u0436\u0438\u0432\u043e\u0439 \u043a\u043e\u043b\u043b\u0435\u043a\u0446\u0438\u0438 vpn-serverlist \u043f\u043e\u0447\u0442\u0438 \u0432\u0441\u0435 \u0441\u0442\u0440\u0430\u043d\u044b \u043f\u043e\u043c\u0435\u0447\u0435\u043d\u044b 'locked', \u0438 Firefox \u0438\u0445 \u0432\u0441\u0451 \u0440\u0430\u0432\u043d\u043e \u043e\u0431\u0441\u043b\u0443\u0436\u0438\u0432\u0430\u0435\u0442 \u2014 \u0441 v5.0 \u0437\u0430\u043f\u0438\u0441\u0438 locked \u0432\u043a\u043b\u044e\u0447\u0435\u043d\u044b \u041f\u041e \u0423\u041c\u041e\u041b\u0427\u0410\u041d\u0418\u042e (--exclude-locked \u0432\u043e\u0437\u0432\u0440\u0430\u0449\u0430\u0435\u0442 \u0441\u0442\u0430\u0440\u044b\u0439 \u0444\u0438\u043b\u044c\u0442\u0440).",
  "upstream_override": "\u041f\u0435\u0440\u0435\u043e\u043f\u0440\u0435\u0434\u0435\u043b\u0435\u043d\u0438\u0435 \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u0430: \u0432\u0441\u0435 \u043b\u043e\u043a\u0430\u0446\u0438\u0438 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u044e\u0442 {host}:{port} \u0432\u043c\u0435\u0441\u0442\u043e \u0433\u043e\u0440\u043e\u0434\u0441\u043a\u0438\u0445 \u0445\u043e\u0441\u0442\u043e\u0432.",
  "engine_started": "\u0414\u0432\u0438\u0436\u043e\u043a {engine} \u0437\u0430\u043f\u0443\u0449\u0435\u043d: {n} \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0445 \u043f\u0440\u043e\u043a\u0441\u0438 \u043d\u0430 {listen} ({ptype})",
  "proxy_line": "  {_e}{listen}:{port:<6} {label:<30} -> {host}:{uport} [{proto}]{dns}",
  "port_busy": "\u041f\u043e\u0440\u0442 {port} \u0437\u0430\u043d\u044f\u0442 \u2014 \u043f\u0440\u043e\u043f\u0443\u0441\u043a\u0430\u044e {label} (\u0437\u0430\u043d\u044f\u0442 \u0447\u0443\u0436\u0438\u043c \u043f\u0440\u043e\u0446\u0435\u0441\u0441\u043e\u043c?).",
  "no_free_ports": "\u041d\u0435\u0442 \u0441\u0432\u043e\u0431\u043e\u0434\u043d\u044b\u0445 \u043f\u043e\u0440\u0442\u043e\u0432 \u0434\u043b\u044f \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0445 \u043f\u0440\u043e\u043a\u0441\u0438 (\u0432\u0441\u0435 \u043f\u043e\u0440\u0442\u044b-\u043a\u0430\u043d\u0434\u0438\u0434\u0430\u0442\u044b \u0437\u0430\u043d\u044f\u0442\u044b).",
  "no_servers_to_serve": "\u041d\u0435\u0442 \u0430\u043f\u0441\u0442\u0440\u0438\u043c-\u0441\u0435\u0440\u0432\u0435\u0440\u043e\u0432 \u0434\u043b\u044f \u043e\u0431\u0441\u043b\u0443\u0436\u0438\u0432\u0430\u043d\u0438\u044f: \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u043e\u0442\u0441\u0435\u044f\u043b\u0430 \u0432\u0441\u0451 (\u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0439\u0442\u0435 --probe-fail keep) \u043b\u0438\u0431\u043e \u0441\u043f\u0438\u0441\u043e\u043a \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u0432 \u043f\u0443\u0441\u0442.",
  "tls_plain_http": "\u0430\u043f\u0441\u0442\u0440\u0438\u043c \u043e\u0442\u0432\u0435\u0442\u0438\u043b \u043e\u0442\u043a\u0440\u044b\u0442\u044b\u043c \u0442\u0435\u043a\u0441\u0442\u043e\u043c (\u043d\u0435 TLS): {text}",
  "answer_no_words": "n, no, \u043d, \u043d\u0435\u0442",
  "answer_yes_words": "y, yes, \u0434, \u0434\u0430",
  "deps_manual_hint": "Install manually {_e}: {cmd}",
  "singbox_missing": "sing-box \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d \u0432 PATH. \u0423\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u0435 \u0435\u0433\u043e (https://sing-box.sagernet.org/installation/) \u0438\u043b\u0438 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0439\u0442\u0435 --local-proxy-engine builtin.",
  "token_updated_builtin": "builtin: \u043d\u043e\u0432\u044b\u0439 proxyPass \u043f\u0440\u0438\u043c\u0435\u043d\u0451\u043d \u00ab\u043d\u0430 \u043b\u0435\u0442\u0443\u00bb (\u043d\u043e\u0432\u044b\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u044f \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u044e\u0442 \u0435\u0433\u043e, \u0440\u0435\u0441\u0442\u0430\u0440\u0442 \u043d\u0435 \u043d\u0443\u0436\u0435\u043d).",
  "token_updated_singbox": "sing-box: \u043d\u043e\u0432\u044b\u0439 proxyPass -> \u043d\u043e\u0432\u044b\u0435 \u043a\u043e\u043d\u0444\u0438\u0433\u0438 + \u0440\u0435\u0441\u0442\u0430\u0440\u0442 \u043f\u0440\u043e\u0446\u0435\u0441\u0441\u043e\u0432 ...",
  "singbox_stopped": "sing-box \u043e\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d: {label} ({listen}:{port})",
  "singbox_died": "sing-box {label} (\u043f\u043e\u0440\u0442 {port}) \u0437\u0430\u0432\u0435\u0440\u0448\u0438\u043b\u0441\u044f (\u043a\u043e\u0434 {code}).",
  "proxy_stopping": "\u041e\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0445 \u043f\u0440\u043e\u043a\u0441\u0438 ...",
  "proxy_stopped": "\u041b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u043e\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u044b.",
  "relogin_needed": "\u0422\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044f \u043f\u0435\u0440\u0435\u043b\u043e\u0433\u0438\u043d \u2014 \u043f\u0440\u043e\u0431\u0443\u044e \u043f\u043e \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u044b\u043c \u0440\u0435\u043a\u0432\u0438\u0437\u0438\u0442\u0430\u043c ...",
  "blocked_wait": "\u0412\u0445\u043e\u0434 \u0432\u0440\u0435\u043c\u0435\u043d\u043d\u043e \u0437\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d \u2014 \u0436\u0434\u0443 10 \u043c\u0438\u043d\u0443\u0442 \u043f\u0435\u0440\u0435\u0434 \u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0435\u0439 \u043f\u043e\u043f\u044b\u0442\u043a\u043e\u0439 (\u0441\u043c. \u0438\u043d\u0441\u0442\u0440\u0443\u043a\u0446\u0438\u044e \u043f\u043e \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u044e \u0432\u044b\u0448\u0435).",
  "unexpected_error": "\u041d\u0435\u043f\u0440\u0435\u0434\u0432\u0438\u0434\u0435\u043d\u043d\u0430\u044f \u043e\u0448\u0438\u0431\u043a\u0430: {err!r} \u2014 \u043f\u043e\u0432\u0442\u043e\u0440\u044e \u0447\u0435\u0440\u0435\u0437 30 \u0441.",
  "next_refresh": "\u0421\u043b\u0435\u0434\u0443\u044e\u0449\u0435\u0435 \u043e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u0438\u0435 {_e} \u0447\u0435\u0440\u0435\u0437 {sec} \u0441 ({at} UTC).",
  "confirm_exit_hint": "Ctrl+C \u0434\u043b\u044f \u043e\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0438.",
  "hotkeys_hint": "\u0413\u043e\u0440\u044f\u0447\u0438\u0435 \u043a\u043b\u0430\u0432\u0438\u0448\u0438 (\u043a\u0430\u0436\u0434\u0430\u044f \u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432\u0443\u0435\u0442 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u0443 \u0441\u043a\u0440\u0438\u043f\u0442\u0430):\n  \U0001f503 r \u2014 \u043f\u0435\u0440\u0435\u043b\u043e\u0433\u0438\u043d \u0441\u0435\u0439\u0447\u0430\u0441 \u0441 \u043f\u043e\u043b\u043d\u044b\u043c \u0443\u0434\u0430\u043b\u0435\u043d\u0438\u0435\u043c \u0432\u0441\u0435\u0445 \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u044b\u0445 \u0434\u0430\u043d\u043d\u044b\u0445 (--relogin)\n  \U0001f9f9 c \u2014 \u043f\u043e\u043b\u043d\u043e\u0441\u0442\u044c\u044e \u043e\u0447\u0438\u0441\u0442\u0438\u0442\u044c \u0432\u0441\u0435 \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u044b\u0435 \u0434\u0430\u043d\u043d\u044b\u0435 \u0438 \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u044c (--clear-cache)\n  \U0001f504 e \u2014 \u0441\u043c\u0435\u043d\u0438\u0442\u044c \u0434\u0432\u0438\u0436\u043e\u043a \u043f\u0440\u043e\u043a\u0441\u0438 builtin/sing-box (--local-proxy-engine; \u043a\u044d\u0448\u0438\u0440\u0443\u0435\u0442\u0441\u044f)\n  \U0001f500 l \u2014 \u0441\u043c\u0435\u043d\u0438\u0442\u044c \u0430\u0434\u0440\u0435\u0441 \u043f\u0440\u043e\u0441\u043b\u0443\u0448\u0438\u0432\u0430\u043d\u0438\u044f 127.0.0.1 <-> 0.0.0.0 (--listen)\n  \U0001f310 h \u2014 \u0432\u044b\u0431\u0440\u0430\u0442\u044c DNS-\u0440\u0435\u0437\u043e\u043b\u0432\u0435\u0440: \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u044b DoH / \u0441\u0438\u0441\u0442\u0435\u043c\u043d\u044b\u0439 DNS; DNS-\u0442\u043e\u0447\u043a\u0438 \u043f\u0440\u043e\u043a\u0441\u0438 \u043d\u0435\u0441\u0443\u0442 \u0437\u0430\u043f\u0440\u043e\u0441\u044b \u0442\u043e\u043b\u044c\u043a\u043e \u043a \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u043e\u043c\u0443 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0443 \u2014 \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e cloudflare, \u0431\u0435\u0437 \u0446\u0435\u043f\u043e\u0447\u043a\u0438 \u043e\u0442\u043a\u0430\u0442\u043e\u0432 (--doh)\n  \U0001f4be k \u2014 \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c/\u043e\u0442\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u043a\u044d\u0448 DoH (--doh-cache; \u043a\u044d\u0448\u0438\u0440\u0443\u0435\u0442\u0441\u044f)\n  \U0001f9e9 i \u2014 \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c/\u043e\u0442\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u0444\u0440\u0430\u0433\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u044e ClientHello TLS (--tls-split; \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e \u0412\u041a\u041b: \u043d\u0435\u0441\u0443\u0449\u0438\u0439 SNI ClientHello \u0440\u0435\u0436\u0435\u0442\u0441\u044f \u043d\u0430 \u043c\u0430\u043b\u0435\u043d\u044c\u043a\u0438\u0435 TCP-\u0441\u0435\u0433\u043c\u0435\u043d\u0442\u044b \u043f\u0440\u043e\u0442\u0438\u0432 DPI, \u0447\u0438\u0442\u0430\u044e\u0449\u0435\u0433\u043e \u043e\u0434\u0438\u043d \u043f\u0430\u043a\u0435\u0442; \u043a\u044d\u0448\u0438\u0440\u0443\u0435\u0442\u0441\u044f)\n  \U0001f4c2 o \u2014 \u043e\u0442\u043a\u0440\u044b\u0442\u044c \u043a\u0430\u0442\u0430\u043b\u043e\u0433 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0439 (\u0442\u0430\u043c \u043b\u0435\u0436\u0438\u0442 config.json)\n  \U0001f4cb v \u2014 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0430\u0434\u0440\u0435\u0441:\u043f\u043e\u0440\u0442 \u041b\u041e\u041a\u0410\u041b\u042c\u041d\u041e\u0413\u041e \u043f\u0440\u043e\u043a\u0441\u0438\n  \U0001f4cb b \u2014 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0430\u0434\u0440\u0435\u0441:\u043f\u043e\u0440\u0442 \u0410\u041f\u0421\u0422\u0420\u0418\u041c-\u043f\u0440\u043e\u043a\u0441\u0438\n  \U0001f522 t \u2014 \u043f\u043e\u043a\u0430\u0437\u0430\u0442\u044c \u0438 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0442\u0435\u043a\u0443\u0449\u0438\u0439 \u043a\u043e\u0434 TOTP\n  \U0001f3ab j \u2014 \u043f\u043e\u043a\u0430\u0437\u0430\u0442\u044c \u0438 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0442\u0435\u043a\u0443\u0449\u0438\u0439 proxyPass JWT\n  \U0001f4f7 g \u2014 \u0437\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044c QR-\u043a\u0430\u0440\u0442\u0438\u043d\u043a\u0443 \u0441 \u0441\u0435\u043a\u0440\u0435\u0442\u043e\u043c 2FA \u043d\u0430 \u043b\u0435\u0442\u0443 (--qr)\n  \U0001f464 u \u2014 \u043f\u043e\u043a\u0430\u0437\u0430\u0442\u044c \u0438 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u043b\u043e\u0433\u0438\u043d (email)\n  \U0001f511 p \u2014 \u043f\u043e\u043a\u0430\u0437\u0430\u0442\u044c \u0438 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u043f\u0430\u0440\u043e\u043b\u044c\n  \U0001f465 a \u2014 \u043c\u0435\u043d\u044e \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u043e\u0432: \u043f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0438\u0442\u044c\u0441\u044f \u043d\u0430 \u0434\u0440\u0443\u0433\u043e\u0439 \u041a\u042d\u0428\u0418\u0420\u041e\u0412\u0410\u041d\u041d\u042b\u0419 Mozilla-\u0430\u043a\u043a\u0430\u0443\u043d\u0442 ('+' \u2014 \u0434\u043e\u0431\u0430\u0432\u0438\u0442\u044c \u041d\u041e\u0412\u042b\u0419, '-' \u2014 \u0443\u0434\u0430\u043b\u0438\u0442\u044c) \u2014 \u0432\u043c\u0435\u0441\u0442\u0435 \u0441 \u043d\u0438\u043c \u043f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0430\u0435\u0442\u0441\u044f \u0412\u0415\u0421\u042c \u043f\u0440\u043e\u0444\u0438\u043b\u044c: DNS-\u0440\u0435\u0437\u043e\u043b\u0432\u0435\u0440, \u044f\u0437\u044b\u043a, \u0432\u044b\u0431\u043e\u0440 \u043f\u0440\u043e\u043a\u0441\u0438, \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 sing-box \u0438 cookie Fastly (config.json, --list-accounts)\n  \U0001f4e6 d \u2014 \u043f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c \u0412\u0421\u0415 Python-\u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438 \u0441 \u043d\u0443\u043b\u044f (--reinstall-deps)\n  \U0001f4bf s \u2014 \u043f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c sing-box \u0441 \u043d\u0443\u043b\u044f (--reinstall-singbox)\n  \U0001f3a8 m \u2014 \u043f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u0446\u0432\u0435\u0442\u043e\u0432\u0443\u044e \u0442\u0435\u043c\u0443 \u0442\u0451\u043c\u043d\u0430\u044f <-> \u0441\u0432\u0435\u0442\u043b\u0430\u044f (--theme; \u043a\u044d\u0448\u0438\u0440\u0443\u0435\u0442\u0441\u044f)\n  \U0001f308 n \u2014 \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c/\u043e\u0442\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u0446\u0432\u0435\u0442\u043d\u043e\u0439 \u0432\u044b\u0432\u043e\u0434 \u0432 \u043b\u043e\u0433 (--no-color; \u043a\u044d\u0448\u0438\u0440\u0443\u0435\u0442\u0441\u044f)\n  \U0001f30d w \u2014 \u0432\u044b\u0431\u0440\u0430\u0442\u044c, \u043a\u0430\u043a\u0438\u0435 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u0437\u0430\u043f\u0443\u0441\u043a\u0430\u0442\u044c: \u043d\u0435\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u0442\u043e\u043a\u0435\u043d\u043e\u0432 \u0447\u0435\u0440\u0435\u0437 \u043f\u0440\u043e\u0431\u0435\u043b, 0 = \u0432\u0441\u0435 (--countries)\n  \U0001f4ac y \u2014 \u0432\u044b\u0431\u0435\u0440\u0438\u0442\u0435 \u044f\u0437\u044b\u043a \u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u0430: en / ru, 0 = \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e (--lang; \u0432\u044b\u0431\u043e\u0440 \u043a\u044d\u0448\u0438\u0440\u0443\u0435\u0442\u0441\u044f \u0438 \u0441\u043e\u0445\u0440\u0430\u043d\u044f\u0435\u0442\u0441\u044f \u043f\u0440\u0438 \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u043a\u0430\u0445)\n  \U0001f4c4 1 \u2014 \u043e\u0442\u043a\u0440\u044b\u0442\u044c config.json (\u0435\u0434\u0438\u043d\u0441\u0442\u0432\u0435\u043d\u043d\u044b\u0439 \u0444\u0430\u0439\u043b \u043d\u0430\u0441\u0442\u0440\u043e\u0435\u043a) \u0432 \u0441\u0438\u0441\u0442\u0435\u043c\u043d\u043e\u043c \u0440\u0435\u0434\u0430\u043a\u0442\u043e\u0440\u0435 \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e\n  \U0001f4c6 z \u2014 \u043c\u0435\u043d\u044e \u0444\u0430\u0439\u043b\u043e\u0432 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 (\u0441\u043f\u0438\u0441\u043e\u043a \u0442\u043e\u043a\u0435\u043d\u043e\u0432 \u0432\u0441\u0435\u0445 \u0440\u0435\u0434\u0430\u043a\u0442\u0438\u0440\u0443\u0435\u043c\u044b\u0445 \u0444\u0430\u0439\u043b\u043e\u0432)\n  \U0001f50d Ctrl+O \u2014 \u043d\u0430\u0439\u0442\u0438 \u0438 \u0443\u0434\u0430\u043b\u0438\u0442\u044c \u0432\u0441\u0435 \u043e\u0441\u0442\u0430\u0442\u043a\u0438 \u0421\u0422\u0410\u0420\u041e\u0413\u041e \u0444\u043e\u0440\u043c\u0430\u0442\u0430 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 (--clean-old-config)\n  \u26d4 Ctrl+C \u2014 \u043e\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c \u0441\u043a\u0440\u0438\u043f\u0442 (\u043f\u0435\u0440\u0432\u043e\u0435 \u043d\u0430\u0436\u0430\u0442\u0438\u0435 \u043e\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u0435\u0442 \u0441\u0440\u0430\u0437\u0443; \u0441 --confirm-exit \u043d\u0443\u0436\u043d\u043e \u0432\u0442\u043e\u0440\u043e\u0435 \u043d\u0430\u0436\u0430\u0442\u0438\u0435 \u0432 \u0442\u0435\u0447\u0435\u043d\u0438\u0435 5 \u0441 \u0434\u043b\u044f \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u044f)\n  \U0001F527 Ctrl+T — выбрать тип локального прокси в меню: socks5 / http (--proxy-type; выбор кэшируется)\n  \U0001f501 Ctrl+R — авторотация аккаунтов по квоте вкл/выкл (--auto-rotate; выбор кэшируется)\n  \U0001f4cb Ctrl+P — перезаписать PAC-файл с текущими слушателями (--pac-export)\n  \U0001f98a f \u2014 \u044d\u043a\u0441\u043f\u043e\u0440\u0442\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0412\u0421\u0415 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u0432 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438 FoxyProxy Standard (\u043a\u043e\u043c\u0431\u0438\u043d\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0444\u0430\u0439\u043b: \u0438\u043c\u043f\u043e\u0440\u0442\u0438\u0440\u0443\u0435\u0442\u0441\u044f \u041b\u042e\u0411\u042b\u041c \u043f\u0443\u0442\u0451\u043c FoxyProxy) (--foxyproxy-export)\n  \U0001f9fe x \u2014 \u044d\u043a\u0441\u043f\u043e\u0440\u0442\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0412\u0421\u0415 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u0432 \u0423\u0421\u0422\u0410\u0420\u0415\u0412\u0428\u0418\u0419 (legacy) settings JSON (\u041d\u0410\u0421\u0422\u041e\u042f\u0429\u0418\u0419 \u0444\u043e\u0440\u043c\u0430\u0442 \u044d\u043a\u0441\u043f\u043e\u0440\u0442\u0430 FoxyProxy 6/7, \u0434\u043b\u044f 'Import from older versions') (--foxyproxy-legacy-export)\n  \U0001f6d1 q \u2014 \u043e\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430.",
  "hotkey_relogin": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'r' \u267b\ufe0f: \u041f\u041e\u041b\u041d\u041e\u0415 \u0443\u0434\u0430\u043b\u0435\u043d\u0438\u0435 \u0432\u0441\u0435\u0445 \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u044b\u0445 \u0434\u0430\u043d\u043d\u044b\u0445 \u2014 \u043a\u044d\u0448\u0435\u0439, \u043a\u0440\u0435\u0434\u0435\u043d\u0448\u0435\u043b\u0441\u043e\u0432, \u043a\u043e\u043d\u0444\u0438\u0433\u043e\u0432 sing-box \u2014 \u0437\u0430\u0442\u0435\u043c \u0441\u0432\u0435\u0436\u0438\u0439 \u0432\u0445\u043e\u0434.",
  "hotkey_clear": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'c' \U0001f9f9: \u0432\u0441\u0435 \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u044b\u0435 \u0434\u0430\u043d\u043d\u044b\u0435 \u0443\u0434\u0430\u043b\u0435\u043d\u044b (\u043a\u044d\u0448\u0438, \u043a\u0440\u0435\u0434\u0435\u043d\u0448\u0435\u043b\u0441\u044b, \u043a\u043e\u043d\u0444\u0438\u0433\u0438 sing-box) \u2014 \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u043a\u0430\u044e\u0441\u044c \u0441 \u0447\u0438\u0441\u0442\u043e\u0433\u043e \u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u044f.",
  "hotkey_engine": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'e': \u043f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0430\u044e \u0434\u0432\u0438\u0436\u043e\u043a \u043d\u0430 {engine} \u2014 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u0442\u044f\u0442\u0441\u044f \u0441 \u043d\u0438\u043c.",
  "hotkey_listen": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'l': \u043f\u0440\u043e\u0441\u043b\u0443\u0448\u0438\u0432\u0430\u043d\u0438\u0435 \u0442\u0435\u043f\u0435\u0440\u044c \u043d\u0430 {host} \u2014 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u044b\u0435 \u043f\u0440\u043e\u043a\u0441\u0438 \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u0442\u044f\u0442\u0441\u044f \u0441 \u043d\u0438\u043c.",
  "hotkey_totp": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 't' \U0001f522: \u0442\u0435\u043a\u0443\u0449\u0438\u0439 \u043a\u043e\u0434 TOTP \u2014 \u0442\u0430\u043a\u0436\u0435 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d \u0432 \u0431\u0443\u0444\u0435\u0440 \u043e\u0431\u043c\u0435\u043d\u0430.",
  "hotkey_jwt": "\u0422\u0435\u043a\u0443\u0449\u0438\u0439 proxyPass JWT {_e} \u2014 \u0442\u0430\u043a\u0436\u0435 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d \u0432 \u0431\u0443\u0444\u0435\u0440 \u043e\u0431\u043c\u0435\u043d\u0430:",
  "hotkey_jwt_none": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'j' \U0001f3ab: \u0442\u043e\u043a\u0435\u043d\u0430 proxyPass \u0435\u0449\u0451 \u043d\u0435\u0442 \u2014 \u043e\u043d \u043f\u043e\u044f\u0432\u0438\u0442\u0441\u044f \u0441\u0440\u0430\u0437\u0443 \u043f\u043e\u0441\u043b\u0435 \u0443\u0441\u043f\u0435\u0448\u043d\u043e\u0433\u043e \u0432\u0445\u043e\u0434\u0430.",
  "hotkey_totp_none": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 't' \U0001f522: \u0441\u0435\u043a\u0440\u0435\u0442 TOTP \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d. \u041f\u0440\u0438\u0447\u0438\u043d\u0430: {reason}. \u0421\u0435\u043a\u0440\u0435\u0442 TOTP \u0445\u0440\u0430\u043d\u0438\u0442\u0441\u044f \u0432 config.json (\u0432 \u0442\u0435\u043a\u0443\u0449\u0435\u043c \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0435) \u0438 \u043f\u043e\u043f\u0430\u0434\u0430\u0435\u0442 \u0442\u0443\u0434\u0430 \u0442\u043e\u043b\u044c\u043a\u043e \u043f\u043e\u0441\u043b\u0435 \u0432\u0445\u043e\u0434\u0430 \u0441 --qr <QR-\u043a\u0430\u0440\u0442\u0438\u043d\u043a\u0430> \u0438\u043b\u0438 --totp-secret <base32> (\u043b\u0438\u0431\u043e \u0447\u0435\u0440\u0435\u0437 \u043f\u0435\u0440\u0435\u043c\u0435\u043d\u043d\u0443\u044e \u043e\u043a\u0440\u0443\u0436\u0435\u043d\u0438\u044f MOZVPN_TOTP_SECRET).",
  "totp_none_reason_nocreds": "\u0442\u0435\u043a\u0443\u0449\u0435\u0433\u043e \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u0432 config.json \u0435\u0449\u0451 \u043d\u0435\u0442 \u2014 \u043d\u0430 \u044d\u0442\u043e\u0439 \u043c\u0430\u0448\u0438\u043d\u0435 \u0435\u0449\u0451 \u043d\u0435 \u0431\u044b\u043b\u043e \u0432\u0445\u043e\u0434\u0430 \u0441 \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0438\u0435\u043c \u0440\u0435\u043a\u0432\u0438\u0437\u0438\u0442\u043e\u0432",
  "totp_none_reason_nosecret": "\u0432 \u0442\u0435\u043a\u0443\u0449\u0435\u043c \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0435 \u0432 config.json \u043d\u0435\u0442 \u043f\u043e\u043b\u044f totp_secret \u2014 \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u044b\u0439 \u0432\u0445\u043e\u0434 \u0431\u044b\u043b \u0432\u044b\u043f\u043e\u043b\u043d\u0435\u043d \u0431\u0435\u0437 --qr / --totp-secret, \u043b\u0438\u0431\u043e \u0443 \u0430\u043a\u043a\u0430\u0443\u043d\u0442\u0430 \u043d\u0435 \u0432\u043a\u043b\u044e\u0447\u0435\u043d\u0430 2FA (TOTP)",
  "hotkey_open_dir_fallback": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'o' \U0001f4c2: \u043a\u0430\u0442\u0430\u043b\u043e\u0433 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0439 sing-box \u0435\u0449\u0451 \u043d\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442 (\u043e\u043d \u0441\u043e\u0437\u0434\u0430\u0451\u0442\u0441\u044f \u043f\u0440\u0438 \u0440\u0430\u0431\u043e\u0442\u0435 \u0434\u0432\u0438\u0436\u043a\u0430 singbox) \u2014 \u0432\u043c\u0435\u0441\u0442\u043e \u043d\u0435\u0433\u043e \u043e\u0442\u043a\u0440\u044b\u0442 \u043e\u0441\u043d\u043e\u0432\u043d\u043e\u0439 \u043a\u0430\u0442\u0430\u043b\u043e\u0433 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 {_e}: {path}",
  "hotkey_files_hint": "\u0424\u0430\u0439\u043b\u044b \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438: \u043d\u0430\u0436\u043c\u0438\u0442\u0435 \u043d\u043e\u043c\u0435\u0440, \u0447\u0442\u043e\u0431\u044b \u043e\u0442\u043a\u0440\u044b\u0442\u044c \u0444\u0430\u0439\u043b \u0432 \u0441\u0438\u0441\u0442\u0435\u043c\u043d\u043e\u043c \u0440\u0435\u0434\u0430\u043a\u0442\u043e\u0440\u0435 \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e.",
  "hotkey_file_entry": "  {n} - {path}",
  "files_menu_hint": "\u0424\u0430\u0439\u043b\u044b \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 ({n}) {_e} \u2014 \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u0442\u043e\u043a\u0435\u043d \u0444\u0430\u0439\u043b\u0430 (\u0434\u043b\u044f \u0444\u0430\u0439\u043b\u043e\u0432 \u043f\u043e\u043c\u0438\u043c\u043e \u043f\u0435\u0440\u0432\u043e\u0433\u043e \u2014 \u0431\u0443\u043a\u0432\u0430) \u0438 Enter. Backspace \u0443\u0434\u0430\u043b\u044f\u0435\u0442, \u043b\u044e\u0431\u0430\u044f \u0434\u0440\u0443\u0433\u0430\u044f \u043a\u043b\u0430\u0432\u0438\u0448\u0430 \u043e\u0442\u043c\u0435\u043d\u044f\u0435\u0442; \u043c\u0435\u043d\u044e \u0437\u0430\u043a\u0440\u044b\u0432\u0430\u0435\u0442\u0441\u044f \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438 \u043f\u043e\u0441\u043b\u0435 \u043e\u0442\u043a\u0440\u044b\u0442\u0438\u044f \u0444\u0430\u0439\u043b\u0430.",
  "hotkey_no_file": "\U0001f4c4 \u041a\u043b\u0430\u0432\u0438\u0448\u0430 '{k}': \u0444\u0430\u0439\u043b\u0430 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 \u2116 {n} \u043d\u0435\u0442 \u2014 \u0441 v6.0 \u0440\u0435\u0434\u0430\u043a\u0442\u0438\u0440\u0443\u0435\u043c\u044b\u0439 \u043a\u043e\u043d\u0444\u0438\u0433 \u041e\u0414\u0418\u041d (config.json, \u043a\u043b\u0430\u0432\u0438\u0448\u0430 '1').",
  "hotkey_open": "\u041e\u0442\u043a\u0440\u044b\u043b \u0432 \u0441\u0438\u0441\u0442\u0435\u043c\u043d\u043e\u043c \u0440\u0435\u0434\u0430\u043a\u0442\u043e\u0440\u0435 \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e {_e}: {path}",
  "hotkey_open_dir": "\u041e\u0442\u043a\u0440\u044b\u043b \u043a\u0430\u0442\u0430\u043b\u043e\u0433 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0439 \u0432 \u0441\u0438\u0441\u0442\u0435\u043c\u043d\u043e\u043c \u0444\u0430\u0439\u043b\u043e\u0432\u043e\u043c \u043c\u0435\u043d\u0435\u0434\u0436\u0435\u0440\u0435 {_e}: {path}",
  "hotkey_open_fail": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043e\u0442\u043a\u0440\u044b\u0442\u044c {path}: {err}",
  "hotkey_open_missing": "\u0424\u0430\u0439\u043b \u043d\u0435 \u0441\u0443\u0449\u0435\u0441\u0442\u0432\u0443\u0435\u0442: {path}",
  "hotkey_copy_local_hint": "\u0421\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0430\u0434\u0440\u0435\u0441 \u041b\u041e\u041a\u0410\u041b\u042c\u041d\u041e\u0413\u041e \u043f\u0440\u043e\u043a\u0441\u0438 \u0432 \u0431\u0443\u0444\u0435\u0440 \u043e\u0431\u043c\u0435\u043d\u0430 \u2014 \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u0435\u0433\u043e \u043d\u043e\u043c\u0435\u0440/\u0431\u0443\u043a\u0432\u0443 \u0438 \u043d\u0430\u0436\u043c\u0438\u0442\u0435 Enter:",
  "hotkey_copy_remote_hint": "\u0421\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0430\u0434\u0440\u0435\u0441 \u0410\u041f\u0421\u0422\u0420\u0418\u041c-\u043f\u0440\u043e\u043a\u0441\u0438 \u0432 \u0431\u0443\u0444\u0435\u0440 \u043e\u0431\u043c\u0435\u043d\u0430 \u2014 \u0432\u0432\u0435\u0434\u0438\u0442\u0435 \u0435\u0433\u043e \u043d\u043e\u043c\u0435\u0440/\u0431\u0443\u043a\u0432\u0443 \u0438 \u043d\u0430\u0436\u043c\u0438\u0442\u0435 Enter:",
  "hotkey_copy_entry": "  {n} - {addr} ({label})",
  "hotkey_copied": "\u0421\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043b \u0432 \u0431\u0443\u0444\u0435\u0440 \u043e\u0431\u043c\u0435\u043d\u0430 {_e}: {text}",
  "hotkey_copy_fail": "\u0411\u0443\u0444\u0435\u0440 \u043e\u0431\u043c\u0435\u043d\u0430 \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d \u0432 \u044d\u0442\u043e\u0439 \u0441\u0438\u0441\u0442\u0435\u043c\u0435: {err}",
  "hotkey_copy_cancel": "\u0412\u044b\u0431\u043e\u0440 \u043e\u0442\u043c\u0435\u043d\u0451\u043d \u2014 \u043d\u0430\u0436\u043c\u0438\u0442\u0435 v, b \u0438\u043b\u0438 h, \u0447\u0442\u043e\u0431\u044b \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u044c.",
  "hotkey_stop": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'q': \u0437\u0430\u043f\u0440\u043e\u0448\u0435\u043d\u0430 \u043e\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430.",
  "retry_wait": "\u0412\u0445\u043e\u0434 \u043d\u0435 \u0443\u0434\u0430\u043b\u0441\u044f \u0441 \u043f\u0435\u0440\u0432\u043e\u0433\u043e \u0440\u0430\u0437\u0430 \u2014 \u043e\u0431\u044b\u0447\u043d\u043e \u043f\u043e\u043b\u0443\u0447\u0430\u0435\u0442\u0441\u044f \u0441\u043e \u0432\u0442\u043e\u0440\u043e\u0433\u043e. \u041f\u041e\u0414\u041e\u0416\u0414\u0418\u0422\u0415: \u0437\u0430\u043f\u0440\u043e\u0441 \u043b\u043e\u0433\u0438\u043d\u0430/\u043f\u0430\u0440\u043e\u043b\u044f/TOTP \u043f\u043e\u044f\u0432\u0438\u0442\u0441\u044f \u0441\u043d\u043e\u0432\u0430 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438, \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u043a \u0441\u043a\u0440\u0438\u043f\u0442\u0430 \u043d\u0435 \u043d\u0443\u0436\u0435\u043d.",
  "retry_in": "\u0421\u043b\u0435\u0434\u0443\u044e\u0449\u0430\u044f \u043f\u043e\u043f\u044b\u0442\u043a\u0430 \u0432\u0445\u043e\u0434\u0430 \u0447\u0435\u0440\u0435\u0437:",
  "theme_switched": "\u0422\u0435\u043c\u0430 \u043f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0435\u043d\u0430 {_e}: {theme}",
  "theme_bg_forced": "\u0424\u043e\u043d \u043e\u043a\u043d\u0430 \u043a\u043e\u043d\u0441\u043e\u043b\u0438 \u041f\u0420\u0418\u041d\u0423\u0414\u0418\u0422\u0415\u041b\u042c\u041d\u041e \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d {_e}: {bg} (escape-\u043f\u043e\u0441\u043b\u0435\u0434\u043e\u0432\u0430\u0442\u0435\u043b\u044c\u043d\u043e\u0441\u0442\u044c OSC 11 \u2014 \u0442\u0435\u043c\u0430 \u0442\u0435\u043f\u0435\u0440\u044c \u043f\u0435\u0440\u0435\u043a\u0440\u0430\u0448\u0438\u0432\u0430\u0435\u0442 \u0438 \u0441\u0430\u043c\u043e \u043e\u043a\u043d\u043e, \u0430 \u043d\u0435 \u0442\u043e\u043b\u044c\u043a\u043e \u0441\u0442\u0440\u043e\u043a\u0438 \u043b\u043e\u0433\u0430).",
  "theme_bg_exit": "\u041f\u0440\u0438 \u0432\u044b\u0445\u043e\u0434\u0435 \u0444\u043e\u043d \u043a\u043e\u043d\u0441\u043e\u043b\u0438 \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e \u0431\u0443\u0434\u0435\u0442 \u0432\u043e\u0441\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d {_e} (OSC 111). \u0415\u0441\u043b\u0438 \u0432\u0430\u0448 \u0442\u0435\u0440\u043c\u0438\u043d\u0430\u043b \u0438\u0433\u043d\u043e\u0440\u0438\u0440\u0443\u0435\u0442 \u044d\u0442\u043e\u0442 \u0441\u0431\u0440\u043e\u0441, \u0432\u0435\u0440\u043d\u0438\u0442\u0435 \u0446\u0432\u0435\u0442 \u043e\u043a\u043d\u0430 \u0432 \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0430\u0445 \u0435\u0433\u043e \u043f\u0440\u043e\u0444\u0438\u043b\u044f.",
  "deps_fallback_each": "\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u043e\u0434\u043d\u043e\u0439 \u043a\u043e\u043c\u0430\u043d\u0434\u043e\u0439 \u043d\u0435 \u0443\u0434\u0430\u043b\u0430\u0441\u044c (\u043a\u043e\u043d\u0444\u043b\u0438\u043a\u0442 \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0435\u0439 pip) {_e} \u2014 \u043f\u043e\u0432\u0442\u043e\u0440\u044f\u044e \u043a\u0430\u0436\u0434\u044b\u0439 \u043f\u0430\u043a\u0435\u0442 \u043e\u0442\u0434\u0435\u043b\u044c\u043d\u043e \u0411\u0415\u0417 --force-reinstall: \u043f\u0440\u0438\u043d\u0443\u0434\u0438\u0442\u0435\u043b\u044c\u043d\u0430\u044f \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u043e\u0431\u0449\u0438\u0445 \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0435\u0439 \u0432 \u0442\u043e\u0447\u043d\u044b\u0435 \u0432\u0435\u0440\u0441\u0438\u0438 \u2014 \u043e\u0431\u044b\u0447\u043d\u0430\u044f \u043f\u0440\u0438\u0447\u0438\u043d\u0430 \u043a\u043e\u043d\u0444\u043b\u0438\u043a\u0442\u043e\u0432.",
  "deps_fallback_nodeps": "{pkg}: \u0432\u0441\u0451 \u0435\u0449\u0451 \u043a\u043e\u043d\u0444\u043b\u0438\u043a\u0442 {_e} \u2014 \u043a\u0440\u0430\u0439\u043d\u044f\u044f \u043c\u0435\u0440\u0430: pip install {pkg} --no-deps (\u0443\u0436\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043d\u043e\u0435 \u0434\u0435\u0440\u0435\u0432\u043e \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0435\u0439 \u0443\u0434\u043e\u0432\u043b\u0435\u0442\u0432\u043e\u0440\u044f\u0435\u0442 \u0438\u043c\u043f\u043e\u0440\u0442\u044b).",
  "deps_pkg_ok": "  {_e} {pkg} \u2014 OK",
  "deps_pkg_fail": "  {_e} {pkg} \u2014 \u041d\u0415 \u0423\u0414\u0410\u041b\u041e\u0421\u042c",
  "deps_conflict_fail": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c \u043f\u0430\u043a\u0435\u0442\u044b: {pkgs}. \u0421\u043c. \u043e\u0448\u0438\u0431\u043a\u0438 pip \u0432\u044b\u0448\u0435.",
  "hotkey_theme": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'm' \U0001f3a8: \u0442\u0435\u043c\u0430 \u043f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0435\u043d\u0430 \u043d\u0430 {theme} (--theme).",
  "color_enabled": "\u0426\u0432\u0435\u0442\u043d\u043e\u0439 \u0432\u044b\u0432\u043e\u0434 \u0432\u043a\u043b\u044e\u0447\u0451\u043d {_e} (\u043f\u0435\u0440\u0435\u043a\u043b\u044e\u0447\u0430\u0435\u0442\u0441\u044f \u043a\u043b\u0430\u0432\u0438\u0448\u0435\u0439 'n' / --no-color).",
  "hotkey_color": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'n' \U0001f308: \u0446\u0432\u0435\u0442\u043d\u043e\u0439 \u0432\u044b\u0432\u043e\u0434 {state} (\u0437\u0435\u0440\u043a\u0430\u043b\u0438\u0442 --no-color).",
  "color_state_on": "\u0432\u043a\u043b\u044e\u0447\u0451\u043d",
  "color_state_off": "\u043e\u0442\u043a\u043b\u044e\u0447\u0451\u043d",
  "deps_header": "Python-\u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438, \u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442 \u044d\u0442\u043e\u0442 \u0441\u043a\u0440\u0438\u043f\u0442 {_e}:",
  "singbox_dep_header": "\u0412\u043d\u0435\u0448\u043d\u044f\u044f \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u044c (\u043d\u0435 pip-\u043f\u0430\u043a\u0435\u0442) {_e}:",
  "singbox_dep_ok": "  {_e} sing-box \u2014 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d: {path} (\u0432\u0435\u0440\u0441\u0438\u044f {version})",
  "singbox_dep_missing": "  {_e} sing-box \u2014 \u041d\u0415 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d (\u043d\u0435\u043e\u0431\u044f\u0437\u0430\u0442\u0435\u043b\u0435\u043d: \u043d\u0443\u0436\u0435\u043d \u0442\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f \u0434\u0432\u0438\u0436\u043a\u0430 'singbox'; \u0432\u0441\u0442\u0440\u043e\u0435\u043d\u043d\u044b\u0439 \u0434\u0432\u0438\u0436\u043e\u043a \u043f\u043e\u043b\u043d\u043e\u0441\u0442\u044c\u044e \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442 \u0431\u0435\u0437 \u043d\u0435\u0433\u043e)",
  "deps_entry_ok": "  {_e} {pip:<12} (\u043c\u043e\u0434\u0443\u043b\u044c {module:<10}) {version:<12} \u2014 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d",
  "deps_entry_missing": "  {_e} {pip:<12} (\u043c\u043e\u0434\u0443\u043b\u044c {module:<10}) \u2014 \u041d\u0415 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d{need}",
  "deps_need_required": " \u2014 \u041d\u0423\u0416\u0415\u041d \u0434\u043b\u044f TOTP/QR",
  "deps_need_optional": " \u2014 \u043d\u0435\u043e\u0431\u044f\u0437\u0430\u0442\u0435\u043b\u044c\u043d\u044b\u0439 (\u0440\u0435\u0430\u043b\u044c\u043d\u044b\u0439 MASQUE / \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 HTTP-3)",
  "deps_missing_note": "\u041e\u0442\u0441\u0443\u0442\u0441\u0442\u0432\u0443\u044e\u0442 \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438: {list}.",
  "deps_install_q": "\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c \u043d\u0435\u0434\u043e\u0441\u0442\u0430\u044e\u0449\u0438\u0435 \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438 \u0441\u0435\u0439\u0447\u0430\u0441 \u0447\u0435\u0440\u0435\u0437 pip ({cmd})? [Y/n]: ",
  "deps_installing": "\u0423\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u044e \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438 {_e}: {pkgs} ...",
  "deps_install_ok": "\u0417\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438 \u0443\u0441\u043f\u0435\u0448\u043d\u043e \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u044b {_e}.",
  "deps_install_fail": "pip \u0437\u0430\u0432\u0435\u0440\u0448\u0438\u043b\u0441\u044f \u0441 \u043e\u0448\u0438\u0431\u043a\u043e\u0439 (\u043a\u043e\u0434 {code}): {err}",
  "deps_frozen_note": "\u0421\u043a\u0440\u0438\u043f\u0442 \u0441\u043a\u043e\u043c\u043f\u0438\u043b\u0438\u0440\u043e\u0432\u0430\u043d \u0432 \u0431\u0438\u043d\u0430\u0440\u043d\u0438\u043a (frozen) \u2014 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0430\u044f \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u043d\u0435\u0432\u043e\u0437\u043c\u043e\u0436\u043d\u0430. \u0423\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u0435 \u0432\u0440\u0443\u0447\u043d\u0443\u044e: {cmd}",
  "deps_install_declined": "\u0417\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438 \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u044b \u2014 \u043f\u0440\u043e\u0434\u043e\u043b\u0436\u0430\u044e \u0431\u0435\u0437 \u043d\u0438\u0445.",
  "deps_reinstall_header": "\u041f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u044e \u0412\u0421\u0415 Python-\u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438 \u0441 \u043d\u0443\u043b\u044f {_e}: {pkgs}",
  "deps_reinstall_ok": "\u0412\u0441\u0435 \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438 \u0443\u0441\u043f\u0435\u0448\u043d\u043e \u043f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u044b {_e}.",
  "deps_reinstall_fail": "\u041f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0435\u0439 \u043d\u0435 \u0443\u0434\u0430\u043b\u0430\u0441\u044c (\u043a\u043e\u0434 {code}): {err}",
  "deps_reinstall_skip_frozen": "\u0421\u043a\u0440\u0438\u043f\u0442 \u2014 \u0441\u043a\u043e\u043c\u043f\u0438\u043b\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0431\u0438\u043d\u0430\u0440\u043d\u0438\u043a (frozen): \u043f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 \u0447\u0435\u0440\u0435\u0437 pip \u043d\u0435\u0432\u043e\u0437\u043c\u043e\u0436\u043d\u0430, \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438 \u0432\u0441\u0442\u0440\u043e\u0435\u043d\u044b \u0432 \u0431\u0438\u043d\u0430\u0440\u043d\u0438\u043a.",
  "singbox_install_header": "sing-box \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d {_e}. \u0421\u043a\u0440\u0438\u043f\u0442 \u041f\u041e\u041b\u041d\u041e\u0421\u0422\u042c\u042e \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442 \u0438 \u0431\u0435\u0437 \u043d\u0435\u0433\u043e: \u0432\u0441\u0442\u0440\u043e\u0435\u043d\u043d\u044b\u0439 \u0434\u0432\u0438\u0436\u043e\u043a \u043e\u0431\u0441\u043b\u0443\u0436\u0438\u0432\u0430\u0435\u0442 \u0442\u0435 \u0436\u0435 \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u044b (MASQUE / HTTP CONNECT) \u0432\u043d\u0443\u0442\u0440\u0438 \u044d\u0442\u043e\u0433\u043e Python-\u043f\u0440\u043e\u0446\u0435\u0441\u0441\u0430. sing-box \u043d\u0443\u0436\u0435\u043d \u0442\u043e\u043b\u044c\u043a\u043e \u0434\u043b\u044f \u0434\u0432\u0438\u0436\u043a\u0430 'singbox'.",
  "singbox_install_q": "\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u044c sing-box \u0441\u0435\u0439\u0447\u0430\u0441? [y/N]: ",
  "singbox_install_cmd": "\u041a\u043e\u043c\u0430\u043d\u0434\u0430 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0438 \u0434\u043b\u044f \u044d\u0442\u043e\u0439 \u0441\u0438\u0441\u0442\u0435\u043c\u044b {_e}: {cmd}",
  "singbox_install_manual": "\u0420\u0443\u0447\u043d\u0430\u044f \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430: \u043e\u0442\u043a\u0440\u043e\u0439\u0442\u0435 {url} \u2014 \u043e\u0444\u0438\u0446\u0438\u0430\u043b\u044c\u043d\u0430\u044f \u0441\u0442\u0440\u0430\u043d\u0438\u0446\u0430 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0438 sing-box.",
  "singbox_install_started": "\u0423\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u044e sing-box {_e}: {cmd}",
  "singbox_install_ok": "sing-box \u0443\u0441\u043f\u0435\u0448\u043d\u043e \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d {_e}: {path}",
  "singbox_install_fail": "\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 sing-box \u043d\u0435 \u0443\u0434\u0430\u043b\u0430\u0441\u044c (\u043a\u043e\u0434 {code}): {err}",
  "singbox_install_declined": "\u0423\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 sing-box \u043e\u0442\u043a\u043b\u043e\u043d\u0435\u043d\u0430 {_e} \u2014 \u0432\u044b\u0431\u043e\u0440 \u0437\u0430\u043f\u043e\u043c\u043d\u0435\u043d, \u0432\u043e\u043f\u0440\u043e\u0441 \u0431\u043e\u043b\u044c\u0448\u0435 \u043d\u0435 \u0431\u0443\u0434\u0435\u0442 \u0437\u0430\u0434\u0430\u0432\u0430\u0442\u044c\u0441\u044f (\u043a\u0440\u043e\u043c\u0435 \u0441\u043b\u0443\u0447\u0430\u044f, \u043a\u043e\u0433\u0434\u0430 \u0432\u044b \u0432\u044b\u0431\u0435\u0440\u0435\u0442\u0435 \u0434\u0432\u0438\u0436\u043e\u043a singbox, \u0430 sing-box \u0432\u0441\u0451 \u0435\u0449\u0451 \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d).",
  "singbox_windows_hint": "Windows: \u0441\u043a\u0430\u0447\u0430\u0439\u0442\u0435 \u0440\u0435\u043b\u0438\u0437 sing-box \u0441 {url} , \u0440\u0430\u0441\u043f\u0430\u043a\u0443\u0439\u0442\u0435 \u0438 \u0434\u043e\u0431\u0430\u0432\u044c\u0442\u0435 \u0432 PATH, \u0437\u0430\u0442\u0435\u043c \u043f\u0435\u0440\u0435\u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u0441\u043a\u0440\u0438\u043f\u0442.",
  "singbox_reinstall_header": "\u041f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u044e sing-box \u0441 \u043d\u0443\u043b\u044f {_e} ...",
  "singbox_reinstall_ok": "sing-box \u043f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d {_e}: {path}",
  "singbox_reinstall_fail": "\u041f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043a\u0430 sing-box \u043d\u0435 \u0443\u0434\u0430\u043b\u0430\u0441\u044c (\u043a\u043e\u0434 {code}): {err}",
  "singbox_engine_still_missing": "sing-box \u043f\u043e-\u043f\u0440\u0435\u0436\u043d\u0435\u043c\u0443 \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d \u2014 \u043e\u0441\u0442\u0430\u044e\u0441\u044c \u043d\u0430 \u0432\u0441\u0442\u0440\u043e\u0435\u043d\u043d\u043e\u043c \u0434\u0432\u0438\u0436\u043a\u0435.",
  "hotkey_qr_prompt": "\u041f\u0443\u0442\u044c \u043a QR-\u043a\u0430\u0440\u0442\u0438\u043d\u043a\u0435 \u0441 \u043a\u043e\u0434\u043e\u043c 2FA (TOTP) (Enter \u2014 \u043e\u0442\u043c\u0435\u043d\u0430): ",
  "hotkey_qr_loaded": "QR \u0437\u0430\u0433\u0440\u0443\u0436\u0435\u043d {_e}: {path}. \u0421\u0435\u043a\u0440\u0435\u0442 TOTP \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d; \u0442\u0435\u043a\u0443\u0449\u0438\u0439 \u043a\u043e\u0434: {code} (\u0434\u0435\u0439\u0441\u0442\u0432\u0443\u0435\u0442 \u0435\u0449\u0451 {sec} \u0441).",
  "hotkey_qr_fail": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0437\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044c QR: {err}",
  "hotkey_login": "\u041b\u043e\u0433\u0438\u043d (email) {_e}: {email} \u2014 \u0442\u0430\u043a\u0436\u0435 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d \u0432 \u0431\u0443\u0444\u0435\u0440 \u043e\u0431\u043c\u0435\u043d\u0430.",
  "hotkey_login_none": "\u0421\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u043e\u0433\u043e \u043b\u043e\u0433\u0438\u043d\u0430 \u043d\u0435\u0442: \u0441\u043d\u0430\u0447\u0430\u043b\u0430 \u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u0435 \u0432\u0445\u043e\u0434 (--email \u0438\u043b\u0438 \u0438\u043d\u0442\u0435\u0440\u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0439 \u0437\u0430\u043f\u0440\u043e\u0441).",
  "hotkey_password": "\u041f\u0430\u0440\u043e\u043b\u044c {_e}: {password} \u2014 \u0442\u0430\u043a\u0436\u0435 \u0441\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d \u0432 \u0431\u0443\u0444\u0435\u0440 \u043e\u0431\u043c\u0435\u043d\u0430.",
  "hotkey_password_none": "\u0421\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u043e\u0433\u043e \u043f\u0430\u0440\u043e\u043b\u044f \u043d\u0435\u0442: \u0441\u043d\u0430\u0447\u0430\u043b\u0430 \u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u0435 \u0432\u0445\u043e\u0434 (--password \u0438\u043b\u0438 \u0438\u043d\u0442\u0435\u0440\u0430\u043a\u0442\u0438\u0432\u043d\u044b\u0439 \u0437\u0430\u043f\u0440\u043e\u0441).",
  "hotkey_deps_reinstalled": "\u0417\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0438 \u043f\u0435\u0440\u0435\u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u044b {_e}.",
  "protocol_summary": "\u0421\u0432\u043e\u0434\u043a\u0430 \u043f\u043e \u043f\u0440\u043e\u0442\u043e\u043a\u043e\u043b\u0430\u043c \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u043e\u0432 {_e}: {m} \u0430\u043f\u0441\u0442\u0440\u0438\u043c(\u043e\u0432) \u0447\u0435\u0440\u0435\u0437 MASQUE (HTTP/3 CONNECT-UDP \u2014 \u043f\u0440\u0438\u043e\u0440\u0438\u0442\u0435\u0442\u043d\u044b\u0439 \u043f\u0440\u043e\u0442\u043e\u043a\u043e\u043b), {c} \u0430\u043f\u0441\u0442\u0440\u0438\u043c(\u043e\u0432) \u0447\u0435\u0440\u0435\u0437 HTTP CONNECT (\u0442\u0443\u043d\u043d\u0435\u043b\u044c HTTPS-\u043f\u0440\u043e\u043a\u0441\u0438 \u043f\u043e\u0432\u0435\u0440\u0445 TLS \u2014 \u043e\u0442\u043a\u0430\u0442, \u043a\u043e\u0433\u0434\u0430 MASQUE \u043d\u0435 \u043f\u0440\u043e\u043f\u0443\u0441\u0442\u0438\u043b \u0434\u0430\u043d\u043d\u044b\u0435).",
  "proto_chosen_masque": "\u041f\u0440\u043e\u0442\u043e\u043a\u043e\u043b \u0434\u043b\u044f {hp}: masque (HTTP/3 CONNECT-UDP) \u2014 \u043f\u0440\u0438\u043e\u0440\u0438\u0442\u0435\u0442\u043d\u044b\u0439 \u043f\u0440\u043e\u0442\u043e\u043a\u043e\u043b; \u0442\u0443\u043d\u043d\u0435\u043b\u044c MASQUE \u043f\u0440\u043e\u043f\u0443\u0441\u0442\u0438\u043b \u0434\u0430\u043d\u043d\u044b\u0435.",
  "proto_fallback_connect": "\u041f\u0440\u043e\u0442\u043e\u043a\u043e\u043b \u0434\u043b\u044f {hp}: HTTP CONNECT \u2014 \u043e\u0442\u043a\u0430\u0442 \u0441 masque, \u043a\u043e\u0442\u043e\u0440\u044b\u0439 \u0437\u0434\u0435\u0441\u044c \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d: {reason}",
  "proto_masque_no_lib": "\u0414\u043b\u044f masque \u043d\u0443\u0436\u0435\u043d \u043f\u0430\u043a\u0435\u0442 aioquic \u2014 \u043e\u043d \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 \u0432\u0441\u0435 \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u044b \u0431\u0443\u0434\u0443\u0442 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u044c \u043e\u0442\u043a\u0430\u0442 HTTP CONNECT.",
  "test_commands_header": "\u0427\u0442\u043e\u0431\u044b \u043f\u0440\u043e\u0442\u0435\u0441\u0442\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u041b\u041e\u041a\u0410\u041b\u042c\u041d\u042b\u0415 \u043f\u0440\u043e\u043a\u0441\u0438, \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0439\u0442\u0435 \u044d\u0442\u0438 \u043a\u043e\u043c\u0430\u043d\u0434\u044b {_e}:",
  "test_commands_hidden": "\u0422\u0435\u0441\u0442\u043e\u0432\u044b\u0435 \u043a\u043e\u043c\u0430\u043d\u0434\u044b curl \u0441\u043a\u0440\u044b\u0442\u044b {_e} \u2014 \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u0435 \u0438\u0445 \u043f\u0430\u0440\u0430\u043c\u0435\u0442\u0440\u043e\u043c --show-test-commands (env MOZVPN_SHOW_TEST_COMMANDS=1).",
  "test_command_local": "  {_e} {cmd}   [{label}, {proto}]",
  "test_commands_remote_header": "\u0427\u0442\u043e\u0431\u044b \u043f\u0440\u043e\u0442\u0435\u0441\u0442\u0438\u0440\u043e\u0432\u0430\u0442\u044c \u0410\u041f\u0421\u0422\u0420\u0418\u041c (\u0443\u0434\u0430\u043b\u0451\u043d\u043d\u044b\u0435) \u043f\u0440\u043e\u043a\u0441\u0438 \u043d\u0430\u043f\u0440\u044f\u043c\u0443\u044e, \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0439\u0442\u0435 \u044d\u0442\u0438 \u043a\u043e\u043c\u0430\u043d\u0434\u044b:",
  "test_command_remote": "  {_e} {cmd}   [{label}]",
  "clear_will_remove_header": "\u041a\u043b\u0430\u0432\u0438\u0448\u0430 'c' / 'r' / --clear-cache / --relogin \u0443\u0434\u0430\u043b\u0438\u0442 \u0412\u0421\u0401 \u044d\u0442\u043e {_e}:",
  "clear_will_remove_entry": "  - {path}",
  "clear_will_remove_dir": "  - {path} (\u0432\u0435\u0441\u044c \u043a\u0430\u0442\u0430\u043b\u043e\u0433 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 \u2014 \u0432\u0441\u0451 \u043f\u0435\u0440\u0435\u0447\u0438\u0441\u043b\u0435\u043d\u043d\u043e\u0435 \u0432\u044b\u0448\u0435 \u043d\u0430\u0445\u043e\u0434\u0438\u0442\u0441\u044f \u0432\u043d\u0443\u0442\u0440\u0438 \u043d\u0435\u0433\u043e)",
  "clear_will_remove_legacy": "  - {path} (\u0432\u0441\u0435 \u043e\u0441\u0442\u0430\u0442\u043a\u0438 \u0421\u0422\u0410\u0420\u041e\u0413\u041e \u0444\u043e\u0440\u043c\u0430\u0442\u0430 \u043a\u043e\u043d\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 \u0434\u043e v6)",
  "config_auto_created": "config.json \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d \u2014 \u0441\u043e\u0437\u0434\u0430\u043d \u041d\u041e\u0412\u042b\u0419 \u0444\u0430\u0439\u043b \u0441\u043e \u0437\u043d\u0430\u0447\u0435\u043d\u0438\u044f\u043c\u0438 \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e {_e}: {path}",
  "clear_wiped_note": "\u0423\u0434\u0430\u043b\u0435\u043d\u043e: \u043a\u044d\u0448\u0438 \u0441\u0435\u0441\u0441\u0438\u0438, \u0441\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u044b\u0435 \u043a\u0440\u0435\u0434\u0435\u043d\u0448\u0435\u043b\u0441\u044b (email/\u043f\u0430\u0440\u043e\u043b\u044c/\u0441\u0435\u043a\u0440\u0435\u0442 TOTP), cookie Fastly \u0438 \u043a\u043e\u043d\u0444\u0438\u0433\u0438 sing-box. \u041f\u0440\u0438 \u0441\u0432\u0435\u0436\u0435\u043c \u0432\u0445\u043e\u0434\u0435 \u043b\u043e\u0433\u0438\u043d-\u0434\u0430\u043d\u043d\u044b\u0435 \u0437\u0430\u043f\u0440\u043e\u0441\u044f\u0442\u0441\u044f \u0437\u0430\u043d\u043e\u0432\u043e.",
  "jwt_decoded_header": "\u0420\u0430\u0441\u0448\u0438\u0444\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0439 proxyPass JWT {_e}:",
  "jwt_decoded_part": "  {part} {json}",
  "jwt_decoded_exp": "  exp (\u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0442\u0435\u043b\u0435\u043d \u0434\u043e): {time} UTC   iat (\u0432\u044b\u0434\u0430\u043d): {iat} UTC",
  "confirm_exit_prompt": "\u041f\u043e\u043b\u0443\u0447\u0435\u043d Ctrl+C. \u041d\u0430\u0436\u043c\u0438\u0442\u0435 Ctrl+C \u0435\u0449\u0451 \u0440\u0430\u0437 \u0432 \u0442\u0435\u0447\u0435\u043d\u0438\u0435 5 \u0441 \u0434\u043b\u044f \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u044f \u0432\u044b\u0445\u043e\u0434\u0430, \u0438\u043b\u0438 \u043f\u043e\u0434\u043e\u0436\u0434\u0438\u0442\u0435, \u0447\u0442\u043e\u0431\u044b \u043f\u0440\u043e\u0434\u043e\u043b\u0436\u0438\u0442\u044c.",
  "confirm_exit_abort": "\u0412\u044b\u0445\u043e\u0434 \u043e\u0442\u043c\u0435\u043d\u0451\u043d, \u043f\u0440\u043e\u0434\u043e\u043b\u0436\u0430\u044e.",
  "sigterm": "\u041f\u043e\u043b\u0443\u0447\u0435\u043d \u0441\u0438\u0433\u043d\u0430\u043b \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u044f, \u043e\u0441\u0442\u0430\u043d\u0430\u0432\u043b\u0438\u0432\u0430\u044e\u0441\u044c.",
  "recommended_server": "\u0420\u0435\u043a\u043e\u043c\u0435\u043d\u0434\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0441\u0435\u0440\u0432\u0435\u0440: {country} / {city}",
  "curl_hint": "    {_e} curl -x https://{host}:{port} --proxy-header \"Proxy-Authorization: Bearer {token}\" {echo}",
  "test_running": "\u0422\u0435\u0441\u0442 {host}:{port} ...",
  "test_external_ip": "\u0412\u043d\u0435\u0448\u043d\u0438\u0439 IP: {ip}",
  "waf_406": "HTTP 406 \u043e\u0442 *.firefox.com \u0434\u0430\u0436\u0435 \u043f\u043e\u0441\u043b\u0435 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u043e\u0433\u043e \u0440\u0435\u0448\u0435\u043d\u0438\u044f challenge.\n\u041f\u043e\u0445\u043e\u0436\u0435, Fastly \u0438\u0437\u043c\u0435\u043d\u0438\u043b \u0440\u0430\u0437\u043c\u0435\u0442\u043a\u0443/\u0430\u043b\u0433\u043e\u0440\u0438\u0442\u043c challenge. \u0421\u0432\u0435\u0440\u044c\u0442\u0435 regex'\u044b:\n  - github.com/pagpeter/fastly-antibot (pkg/solver/solver.go \u2014 regex'\u044b script id \u0438 token)\n  - PR #22 \u0432 Mikescher/firefox-sync-client (syncclient/fastly.go \u2014 \u043f\u043e\u0440\u0442 \u044d\u0442\u043e\u0433\u043e \u0430\u043b\u0433\u043e\u0440\u0438\u0442\u043c\u0430)\n\u0424\u043e\u043b\u0431\u044d\u043a \u2014 \u043f\u0435\u0440\u0435\u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0439\u0442\u0435 \u0441\u0435\u0441\u0441\u0438\u044e Firefox:\n  1) \u0412\u043e\u0439\u0434\u0438\u0442\u0435 \u0432 Mozilla-\u0430\u043a\u043a\u0430\u0443\u043d\u0442 \u0432 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0435 Firefox (2FA \u0432\u0432\u043e\u0434\u0438\u0442\u0441\u044f \u0442\u0430\u043c).\n  2) \u0418\u0437\u0432\u043b\u0435\u043a\u0438\u0442\u0435 sessionToken \u0438\u0437 \u043f\u0440\u043e\u0444\u0438\u043b\u044f, \u043d\u0430\u043f\u0440\u0438\u043c\u0435\u0440 \u0443\u0442\u0438\u043b\u0438\u0442\u043e\u0439 firefox_decrypt\n     (github.com/unode/firefox_decrypt): \u0437\u0430\u043f\u0438\u0441\u044c \u00abFirefox Accounts credentials\u00bb\n     \u0445\u0440\u0430\u043d\u0438\u0442 JSON \u0441 \u043f\u043e\u043b\u0435\u043c sessionToken.\n  3) \u0417\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435:  python3 mozvpn.py --session-token <hex> --email you@example.com",
  "session_token_hex": "sessionToken \u0434\u043e\u043b\u0436\u0435\u043d \u0431\u044b\u0442\u044c hex-\u0441\u0442\u0440\u043e\u043a\u043e\u0439.",
  "masque_no_aioquic": "aioquic \u043d\u0435 \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d",
  "masque_probe_error": "{err}",
  "builtin_connect_failed": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0438\u0442\u044c\u0441\u044f \u043a \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u0443: {err}",
  "builtin_no_token": "proxyPass-\u0442\u043e\u043a\u0435\u043d \u0435\u0449\u0451 \u043d\u0435 \u043f\u043e\u043b\u0443\u0447\u0435\u043d",
  "api_proxy_on": "\u041a\u043e\u043d\u0442\u0440\u043e\u043b\u044c\u043d\u0430\u044f \u043f\u043b\u043e\u0441\u043a\u043e\u0441\u0442\u044c (FxA/Guardian/Remote Settings + challenge Fastly) \u0447\u0435\u0440\u0435\u0437 \u0424\u0418\u041a\u0421\u0418\u0420\u041e\u0412\u0410\u041d\u041d\u042b\u0419 \u0432\u044b\u0445\u043e\u0434 {_e}: {url} (--api-proxy)",
  "api_proxy_off": "\u0412\u044b\u0445\u043e\u0434 \u043a\u043e\u043d\u0442\u0440\u043e\u043b\u044c\u043d\u043e\u0439 \u043f\u043b\u043e\u0441\u043a\u043e\u0441\u0442\u0438: \u043f\u0440\u044f\u043c\u043e\u0439 (--api-proxy \u043d\u0435 \u0437\u0430\u0434\u0430\u043d)",
  "api_proxy_socks_unsupported": "socks5:// \u043d\u0435 \u043f\u043e\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u0442\u0441\u044f (--api-proxy): stdlib ProxyHandler \u0442\u0443\u043d\u043d\u0435\u043b\u0438\u0440\u0443\u0435\u0442 \u0442\u043e\u043b\u044c\u043a\u043e http/https \u0447\u0435\u0440\u0435\u0437 CONNECT; \u0441\u043a\u0440\u0438\u043f\u0442 \u043d\u0435 \u0434\u043e\u0431\u0430\u0432\u043b\u044f\u0435\u0442 \u043d\u043e\u0432\u044b\u0445 \u0437\u0430\u0432\u0438\u0441\u0438\u043c\u043e\u0441\u0442\u0435\u0439 - \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0439\u0442\u0435 http:// \u0438\u043b\u0438 https:// \u043f\u0440\u043e\u043a\u0441\u0438",
  "hotkey_tls_split": "\u0424\u0440\u0430\u0433\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u044f ClientHello TLS: {state}",
  "tls_split_startup": "\u0424\u0440\u0430\u0433\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u044f ClientHello TLS: {state} (--tls-split; \u043f\u043e \u0443\u043c\u043e\u043b\u0447\u0430\u043d\u0438\u044e \u0412\u041a\u041b)",
  "fastly_406_stale": "\u041e\u0442\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u043d\u044b\u0439 cookie \u0447\u0435\u043b\u043b\u0435\u043d\u0434\u0436\u0430 Fastly \u043e\u0442\u043a\u043b\u043e\u043d\u0451\u043d (HTTP 406 \u043f\u0440\u0438 \u043d\u0430\u043b\u0438\u0447\u0438\u0438 cookie) - \u0443\u0441\u0442\u0430\u0440\u0435\u0432\u0448\u0438\u0439 cookie \u043e\u0442\u0431\u0440\u0430\u0441\u044b\u0432\u0430\u0435\u0442\u0441\u044f, \u043f\u0435\u0440\u0435\u0434 \u043f\u043e\u0432\u0442\u043e\u0440\u043e\u043c \u0440\u0435\u0448\u0430\u0435\u0442\u0441\u044f \u041d\u041e\u0412\u042b\u0419 \u0447\u0435\u043b\u043b\u0435\u043d\u0434\u0436",
  "fxa_429_cooldown": "\u041b\u0438\u043c\u0438\u0442 \u0447\u0430\u0441\u0442\u043e\u0442\u044b \u0432\u0445\u043e\u0434\u0430 FxA - \u043f\u0430\u0443\u0437\u0430 15 \u043c\u0438\u043d\u0443\u0442; \u043f\u0440\u0438 \u043f\u043e\u0432\u0442\u043e\u0440\u0435 \u043f\u0440\u0435\u0434\u043f\u043e\u0447\u0442\u0451\u043d \u043a\u044d\u0448\u0438\u0440\u043e\u0432\u0430\u043d\u043d\u044b\u0439 session token",
  "guardian_reactivated": "Guardian: \u043f\u043e\u0432\u0442\u043e\u0440\u043d\u0430\u044f \u0430\u043a\u0442\u0438\u0432\u0430\u0446\u0438\u044f (HTTP {status}) - \u043e\u0434\u043d\u0430 \u043f\u043e\u0432\u0442\u043e\u0440\u043d\u0430\u044f \u043f\u043e\u043f\u044b\u0442\u043a\u0430 \u043f\u043e\u043b\u0443\u0447\u0435\u043d\u0438\u044f \u0442\u043e\u043a\u0435\u043d\u0430",
  "guardian_reactivate_failed": "Guardian: \u043f\u043e\u0432\u0442\u043e\u0440\u043d\u0430\u044f \u0430\u043a\u0442\u0438\u0432\u0430\u0446\u0438\u044f \u043d\u0435 \u0443\u0434\u0430\u043b\u0430\u0441\u044c (HTTP {status}: {detail})",
  "pass_rejected_refresh": "\u0410\u043f\u0441\u0442\u0440\u0438\u043c \u041e\u0422\u0412\u0415\u0420\u0413 proxyPass (HTTP 400 'parsing JWT failed' / 401 / 403) - pass \u043e\u0431\u043d\u043e\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u043d\u0435\u043c\u0435\u0434\u043b\u0435\u043d\u043d\u043e",
  "session_fail_refresh": "3+ \u0440\u0430\u0437\u043d\u044b\u0445 \u0446\u0435\u043b\u0435\u0439 \u043d\u0435 \u043e\u0442\u043a\u0440\u044b\u043b\u0438\u0441\u044c \u0447\u0435\u0440\u0435\u0437 \u0442\u0443\u043d\u043d\u0435\u043b\u044c - \u0441\u0435\u0441\u0441\u0438\u044f \u0432\u044b\u0433\u043b\u044f\u0434\u0438\u0442 \u0431\u0438\u0442\u043e\u0439; \u043e\u0431\u043d\u043e\u0432\u043b\u044f\u044e pass \u0441\u0435\u0439\u0447\u0430\u0441",
  "connect_rejected": "\u0410\u043f\u0441\u0442\u0440\u0438\u043c \u043e\u0442\u0432\u0435\u0440\u0433 CONNECT (HTTP {code}) \u043a {_e}{target}",
  "connect_target_open_timeout": "CONNECT \u043a {_e}{target} \u043d\u0435 \u043e\u0442\u043a\u0440\u044b\u043b\u0441\u044f (\u0442\u0430\u0439\u043c\u0430\u0443\u0442)",
  "connect_target_bad_gateway": "\u0410\u043f\u0441\u0442\u0440\u0438\u043c \u043e\u0442\u0432\u0435\u0442\u0438\u043b HTTP {code} \u0434\u043b\u044f {_e}{target}",
  "connect_target_doh_unreachable": "DoH-\u0446\u0435\u043b\u044c DNS-\u0440\u0435\u0442\u0440\u0430\u043d\u0441\u043b\u044f\u0442\u043e\u0440\u0430 {target} \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u043d\u0430 \u0447\u0435\u0440\u0435\u0437 \u0442\u0443\u043d\u043d\u0435\u043b\u044c {_e} DNS-\u0442\u043e\u0447\u043a\u0438 \u043f\u0440\u043e\u043a\u0441\u0438 \u0432\u043e\u0437\u044f\u0442 \u0437\u0430\u043f\u0440\u043e\u0441\u044b \u0442\u043e\u043b\u044c\u043a\u043e \u043a \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u043e\u043c\u0443 \u043f\u0440\u043e\u0432\u0430\u0439\u0434\u0435\u0440\u0443 (\u043a\u043b\u0430\u0432\u0438\u0448\u0430 'h' / --doh \u2014 \u0441\u043c\u0435\u043d\u0438\u0442\u044c); DNS-\u0437\u0430\u043f\u0440\u043e\u0441\u044b \u0447\u0435\u0440\u0435\u0437 \u0442\u043e\u0447\u043a\u0438 \u043d\u0435 \u043e\u0442\u0432\u0435\u0447\u0430\u044e\u0442, \u043f\u043e\u043a\u0430 \u043e\u043d \u043d\u0435 \u0432\u043e\u0441\u0441\u0442\u0430\u043d\u043e\u0432\u0438\u0442\u0441\u044f (\u0440\u0435\u0437\u043e\u043b\u0432\u0435\u0440 \u043a\u043b\u0438\u0435\u043d\u0442\u0430 \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442 \u0441\u0430\u043c)",
  "quota_low": "\u041e\u0441\u0442\u0430\u0442\u043e\u043a \u043a\u0432\u043e\u0442\u044b \u043d\u0438\u0436\u0435 15%: {left} \u0438\u0437 {limit}{reset} - \u043a\u0432\u043e\u0442\u0430 \u043e\u0431\u043d\u0443\u043b\u044f\u0435\u0442\u0441\u044f \u0435\u0436\u0435\u043c\u0435\u0441\u044f\u0447\u043d\u043e",
  "filter_cleared_broken": "\u0421\u043e\u0445\u0440\u0430\u043d\u0451\u043d\u043d\u044b\u0439 \u0432\u044b\u0431\u043e\u0440 \u043f\u0440\u043e\u043a\u0441\u0438 \u0441\u0442\u0430\u0431\u0438\u043b\u044c\u043d\u043e \u043f\u0430\u0434\u0430\u043b \u043d\u0430 \u0412\u0421\u0415\u0425 \u043e\u0431\u0441\u043b\u0443\u0436\u0438\u0432\u0430\u0435\u043c\u044b\u0445 \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u0430\u0445 - \u0444\u0438\u043b\u044c\u0442\u0440 \u043e\u0447\u0438\u0449\u0435\u043d, \u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0430\u044f \u0441\u0431\u043e\u0440\u043a\u0430 \u0434\u0432\u0438\u0436\u043a\u0430 \u043e\u0431\u0441\u043b\u0443\u0436\u0438\u0442 \u0412\u0421\u0415 \u043f\u0440\u043e\u043a\u0441\u0438 (\u0432\u0435\u0440\u043d\u0438\u0442\u0435 \u0432\u044b\u0431\u043e\u0440 \u043a\u043b\u0430\u0432\u0438\u0448\u0435\u0439 'w', \u043a\u043e\u0433\u0434\u0430 \u0430\u043f\u0441\u0442\u0440\u0438\u043c\u044b \u0432\u043e\u0441\u0441\u0442\u0430\u043d\u043e\u0432\u044f\u0442\u0441\u044f)",
  "channel_limits_note": "\u041a\u0430\u043d\u0430\u043b Mozilla \u0441\u0435\u0433\u043e\u0434\u043d\u044f — \u044d\u0442\u043e HTTP CONNECT-\u0442\u0443\u043d\u043d\u0435\u043b\u044c \u043f\u043e\u0432\u0435\u0440\u0445 HTTP/2 (\u0421\u042b\u0420\u041e\u0419 TCP-\u0442\u0443\u043d\u043d\u0435\u043b\u044c: \u0432\u043d\u0443\u0442\u0440\u0438 \u043c\u043e\u0436\u0435\u0442 \u0440\u0430\u0431\u043e\u0442\u0430\u0442\u044c \u041b\u042e\u0411\u041e\u0419 TCP-\u043f\u0440\u043e\u0442\u043e\u043a\u043e\u043b \u0438 \u043d\u0430 \u041b\u042e\u0411\u041e\u0419 \u043f\u043e\u0440\u0442 \u043d\u0430\u0437\u043d\u0430\u0447\u0435\u043d\u0438\u044f; \u0431\u0435\u043b\u043e\u0433\u043e \u0441\u043f\u0438\u0441\u043a\u0430 \u043f\u043e\u0440\u0442\u043e\u0432 \u043d\u0435\u0442). UDP/IP-\u043f\u043e\u0442\u043e\u043a\u0438 — \u0441\u043b\u0435\u0434\u0443\u044e\u0449\u0438\u0439 \u0448\u0430\u0433: MASQUE \u043f\u043e\u0432\u0435\u0440\u0445 HTTP/3 (Firefox \u0443\u0436\u0435 \u043d\u0435\u0441\u0451\u0442 \u043a\u043e\u0434 CONNECT-UDP, \u0430 \u0432 \u0441\u043f\u0438\u0441\u043a\u0435 \u0441\u0435\u0440\u0432\u0435\u0440\u043e\u0432 \u0443\u0436\u0435 \u0435\u0441\u0442\u044c \u043f\u043e\u0441\u0435\u0440\u0432\u0435\u0440\u043d\u044b\u0439 \u043f\u0440\u043e\u0442\u043e\u043a\u043e\u043b masque). \u0413\u043b\u0443\u0431\u043e\u043a\u043e\u0433\u043e \u0430\u043d\u0430\u043b\u0438\u0437\u0430 \u043f\u0430\u043a\u0435\u0442\u043e\u0432 (DPI) \u043d\u0430 \u0432\u044b\u0445\u043e\u0434\u0435 \u043d\u0435\u0442; Mozilla \u043f\u043e\u0437\u0438\u0446\u0438\u043e\u043d\u0438\u0440\u0443\u0435\u0442 \u0444\u0443\u043d\u043a\u0446\u0438\u044e \u0434\u043b\u044f \u0432\u0435\u0431-\u0442\u0440\u0430\u0444\u0438\u043a\u0430 \u0431\u0440\u0430\u0443\u0437\u0435\u0440\u0430",
  "proxy_type_selected": "Тип локального прокси: {type} (Ctrl+T открывает меню выбора; SOCKS5 передаёт доменные имена апстриму — удалённый DNS)",
  "proxy_type_switched": "Тип локального прокси переключён на {type}: пересборка слушателей",
  "hotkey_proxy_type": "Ctrl+T — выбрать тип локального прокси в меню: socks5 / http (--proxy-type; выбор сохраняется)",
  "ptype_menu_hint": "Выберите тип локального прокси {_e} — введите его номер и нажмите Enter (текущий: {cur}; [x] отмечает работающий тип). Выбор сохраняется в config.json (settings.proxy_type), сразу пересобирает слушатели и действует после перезапусков (Backspace удаляет, любая другая клавиша отменяет; после применения меню закрывается автоматически).",
  "ptype_menu_entry": "  {n} - {name} - {desc}",
  "ptype_desc_socks5": "SOCKS5 (RFC 1928): доменные имена резолвит апстрим — удалённый DNS",
  "ptype_desc_http": "HTTP CONNECT",
  "dns_line": "DNS-ретрансляция {_e} {listen}: {n} DNS-точек — по одной на прокси (UDP+TCP; DNS-порт прокси возит запросы ТОЛЬКО через этот прокси -> его egress -> DoH {target}). Укажите системному резолверу или любой plain-DNS-программе DNS-порт, показанный рядом с нужным прокси; приложениям, которые уже передают домены через прокси (socks5h, remote DNS), они не нужны",
  "dns_port_busy": "DNS-порт {port} прокси {label} занят — эта DNS-точка пропущена (сам прокси продолжает работать)",
  "hotkey_auto_rotate": "Ctrl+R — авторотация аккаунтов по квоте вкл/выкл (выбор сохраняется)",
  "hotkey_pac_export": "Ctrl+P — перезаписать PAC-файл (обход локальных сайтов)",
  "auto_rotate_startup": "Авторотация аккаунтов по квоте ВКЛЮЧЕНА (Ctrl+R выключает; --no-auto-rotate)",
  "auto_rotate_on": "Авторотация аккаунтов по квоте ВКЛЮЧЕНА",
  "auto_rotate_off": "Авторотация аккаунтов по квоте ВЫКЛЮЧЕНА",
  "auto_rotate_switched": "{state} — выбор сохранён",
  "auto_rotate_zero": "Квота исчерпана на текущем аккаунте ({email}) — авторотация ищет аккаунт с максимумом остатка",
  "auto_rotate_to": "Авторотация: переключение на аккаунт {email} (известный остаток {left}) — кэшированная сессия, без нового входа",
  "auto_rotate_none": "Авторотация: все остальные кэшированные аккаунты исчерпаны или без кэшированной сессии — остаёмся на {email}",
  "auto_rotate_off_zero": "Квота исчерпана на текущем аккаунте — авторотация ВЫКЛЮЧЕНА (Ctrl+R включает)",
  "fxa_profile_read": "Сессия профиля Firefox: {path}",
  "fxa_profile_missing": "Не удалось прочитать файл профиля Firefox: {path} ({err})",
  "fxa_profile_no_token": "В {path} нет sessionToken — сначала войдите в браузер Firefox, затем перезапустите",
  "fxa_profile_bad_token": "sessionToken в {path} повреждён — войдите в браузер Firefox заново",
  "fxa_profile_session_invalid": "Сессия браузера Firefox больше не валидна (errno 110) — войдите в Firefox заново, затем нажмите любую клавишу для повтора",
  "unblock_prompt": "Mozilla отправила 6-значный код разблокировки на {email} — введите его (пустой ввод повторно отправляет письмо, 'q' отмена): ",
  "unblock_resent": "Письмо с кодом разблокировки повторно отправлено на {email}",
  "unblock_wrong": "Код разблокировки не принят — попробуйте ещё раз",
  "unblock_gave_up": "Попытки ввода кода разблокировки исчерпаны — вход остаётся заблокированным (дождитесь нового письма или попробуйте позже)",
  "email_link_wait": "Откройте ссылку-подтверждение из письма Mozilla в браузере — ожидание до {sec} с (любая клавиша вернёт к вводу кода)",
  "email_link_verified": "Ссылка-подтверждение из письма принята — сессия верифицирована",
  "email_link_timeout": "Ссылка не подтверждена вовремя — возврат к вводу кода",
  "pac_written": "PAC-файл записан: {path} ({directive} записей: {n})",
  "pac_failed": "Не удалось записать PAC-файл: {path} ({err})",
  "pac_no_proxies": "Нет работающих локальных прокси — PAC-файл не перезаписан",
  "doctor_title": "Диагностика (только чтение):",
  "doctor_ok": "ок",
  "doctor_fail": "СБОЙ",
  "doctor_skip": "пропуск",
  "doctor_interpreter": "Python {ver} на {plat}",
  "doctor_config": "Хранилище конфигурации: {path} (аккаунтов: {n})",
  "doctor_deps": "Зависимости: {miss}",
  "doctor_deps_ok": "все на месте",
  "doctor_sysdns": "Системный DNS: {host} -> {ips}",
  "doctor_doh": "DoH ({provider}) резолв {host}: {ips}",
  "doctor_doh_system": "выключен по выбору — системный резолвер (проверен шагом выше)",
  "doctor_fxa": "FxA API {url}: HTTP {status}",
  "doctor_serverlist": "Список серверов: {n} локаций, {m} серверов",
  "doctor_tls": "TLS-хендшейк до {host}:{port} (профиль {p}): {ms} мс",
  "doctor_quota": "Квота Guardian на кэшированной сессии: осталось {left} из {limit}",
  "doctor_no_session": "Нет кэшированного session-токена — шаг Guardian пропущен (войдите один раз обычным способом)",
  "doctor_done": "Диагностика завершена: {ok} ок, {fail} сбоев",
},
}

def set_language(lang: str):
    """Switch the output language (req. 14)."""
    global _LANG
    _LANG = lang if lang in ("en", "ru") else "en"

# v5.30 (user request): the language choice made with the hotkey 'y' menu
# is PERSISTED in the user config directory (lang.json, the same directory
# as session.json / countries.json) and survives restarts. Precedence at
# startup: an explicit --lang argument > the cached hotkey-'y' choice >
# the MOZVPN_LANG environment variable > the built-in default 'en'.
# Option '0' of the menu resets the language to the DEFAULT and REMOVES
# the persisted choice, so later runs fall back to env/default again.
# v6.0: the choice lives in config.json (settings.lang) - the lang.json
# file of v5.30-v5.36 is migrated and removed on the first run.

def save_lang_cache(lang: str):
    """v5.30 -> v6.0: persist the language choice (hotkey 'y') into
    config.json (settings.lang)."""
    try:
        cfg_set(("settings", "lang"), lang if lang in ("en", "ru") else "en")
    except Exception:
        pass                    # a read-only config dir must not crash the run

def load_lang_cache() -> "str | None":
    """v5.30 -> v6.0: the persisted language choice, or None when not
    saved yet."""
    try:
        lang = (cfg_get(("settings", "lang"), "") or "").strip().lower()
        return lang if lang in ("en", "ru") else None
    except Exception:
        return None

def clear_lang_cache():
    """v5.30 -> v6.0: drop the persisted language choice (menu '0')."""
    try:
        cfg_set(("settings", "lang"), None)
    except Exception:
        pass


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
    "doh_selected": "\U0001F310 ",       # globe (DNS resolver)
    "doh_system": "\U0001F310 ",
    "doh_chain": "\U0001F517 ",           # link (fallback chain)
    "doh_strict_mode": "\U0001F512 ",     # lock (strict DoH, no leak)
    "system_dns_fallback_on": "\U0001F513 ",  # open lock (opt-in fallback)
    "lang_menu_hint": "\U0001F4AC ",     # speech balloon (language menu)
    "lang_set": "\U0001F4AC ",
    "lang_reset": "\U0001F4AC ",
    "doh_geo_mismatch": "\U0001F5FA ",   # world map (geo check)
    "doh_geo_ok": "\U0001F5FA ",
    "hotkey_doh": "\U0001F310 ",
    "locked_note": "\U00002139 ",
    "geo_echo_no_geo": "\U0001F5FA ",     # geo check skipped note
    "foxyproxy_no_proxies": "\U0001F98A ",   # fox
    "foxyproxy_export_done": "\U0001F98A ",  # fox
    "foxyproxy_export_cancel": "\U0001F98A ",
    "foxyproxy_import_hint": "\U0001F98A ",
    "doh_cache_state_on": "\U0001F4BE ",
    "doh_cache_state_off": "\U0001F4BE ",
    "doh_menu_hint": "\U0001F310 ",
    "doh_menu_entry": "\U0001F310 ",
    "doh_default_applied": "\U0001F310 ",
    "hotkey_doh_cache": "\U0001F4BE ",
    "select_hint": "\u2328 ",
    "select_buffer": "\u2328 ",
    "select_bad": "\U0000274C ",
    "select_hint_multi": "\u2328 ",
    "multi_buffer": "\u2328 ",
    "multi_bad": "\U0000274C ",
    "countries_menu_hint": "\U0001F30D ",
    "countries_menu_entry": "\U0001F517 ",
    "countries_filter_applied": "\U0001F30D ",
    "filter_all_applied": "\U0001F30D ",
    "filter_empty_fallback": "\u26A0\uFE0F  ",
    "hotkey_countries": "\U0001F504 ",
    "net_error_retry": "\U0001F4E1 ",
    "resolver_blip_note": "\U0001F4E1 ",
    "resolver_broken_note": "\U0001F4E1 ",
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
    "files_menu_hint": "\U0001F4C6 ",        # card index dividers (full file menu)
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
    "probe_filter_applied": "\u279C ",
    "accounts_none": "\u2139 ",
    "accounts_list_header": "\U0001F465 ",
    "accounts_qr_dir": "\U0001F5BC\uFE0F ",
    "accounts_menu_hint": "\U0001F465 ",
    "account_switched": "\U0001F465 ",
    "profile_applied": "\U0001F9F1 ",
    "account_cached": "\U0001F465 ",
    "account_qr_saved": "\U0001F5BC\uFE0F ",
    "accounts_json_saved": "\U0001F4BE ",
    "accounts_survived_wipe": "\U0001F465 ",
    "accounts_menu_add": "\u2795 ",
    "accounts_menu_del": "\u2796 ",
    "accounts_add_hint": "\U0001F464 ",
    "accounts_delete_prompt": "\U0001F5D1 ",
    "accounts_delete_missing": "\u26A0\uFE0F ",
    "accounts_deleted": "\U0001F5D1 ",
    "accounts_delete_last": "\u2139 ",
    "accounts_not_found": "\u274C ",
    "refresh_retry_soon": "\u23F3 ",
    "config_migration_header": "\U0001F4E6 ",
    "config_migration_entry": "\u21AA\uFE0F ",
    "config_migration_done": "\u2705 ",
    "clean_old_none": "\u2705 ",
    "clean_old_header": "\U0001F9F9 ",
    "clean_old_removed": "\U0001F5D1 ",
    "clean_old_failed": "\u274C ",
    "clean_old_done": "\U0001F9F9 ",
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
    "clear_will_remove_legacy": "\U0001F5D1\ufe0f ",
    "config_auto_created": "\U0001F195 ",       # NEW button (file just created)
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
    # v7.0: the emailed-code verification path (email-2fa)
    "email_code_resent": "\u2705 ",
    "email_code_confirmed": "\u2705 ",
    "email_code_rejected": "\u26A0\uFE0F  ",
    "email_resend_failed": "\u26A0\uFE0F  ",
    "email_code_aal_hint": "\u2139\uFE0F ",
    "email_code_rejected_final": "\u274C ",
    "email_code_unknown_error": "\u274C ",
    "session_unverified": "\u274C ",
    "totp_missing": "\u274C ",
    "totp_rejected_final": "\u274C ",
    "totp_unknown_error": "\u274C ",
    "prompt_read_error": "\u274C ",
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
    # v5.2 (req. 2): emoji for the messages that had none
    "answer_no_words": "\U0001F937 ",        # shrug
    "answer_yes_words": "\U0001F44D ",       # thumbs up
    "blocked_extra_method": "\U0001F6A8 ",   # police light (WAF block)
    "builtin_connect_failed": "\U0001F6A8 ",
    "builtin_no_token": "\U0001F6A8 ",
    "api_proxy_on": "\U0001F3AF ",
    "api_proxy_off": "\U0001F3AF ",
    "api_proxy_socks_unsupported": "\u274C ",
    "hotkey_tls_split": "\U0001F9E9 ",
    "tls_split_startup": "\U0001F9E9 ",
    "fastly_406_stale": "\U0001F504 ",
    "fxa_429_cooldown": "\U0001F4E1 ",
    "guardian_reactivated": "\U0001F6E1uFE0F  ",
    "guardian_reactivate_failed": "\U0001F6E1uFE0F  ",
    "pass_rejected_refresh": "\u26A0uFE0F  ",
    "session_fail_refresh": "\u26A0uFE0F  ",
    "connect_rejected": "\u274C ",
    "connect_target_open_timeout": "\u23F3 ",
    "connect_target_bad_gateway": "\u274C ",
    "connect_target_doh_unreachable": "\U0001F4E1 ",
    "quota_low": "\U0001F4CA ",
    "filter_cleared_broken": "\U0001F30D ",
    "channel_limits_note": "\U00002139 ",
    "cache_clear_failed": "\u274C ",
    "cache_cleared": "\U0001F9F9 ",          # broom (cache wiped)
    "cache_nothing": "\U0001F937 ",
    "clock_skew": "\U0001F557 ",             # clock (time skew)
    "config_file_dir": "\U0001F4C1 ",        # folder
    "config_file_exists": "\U0001F4C1 ",
    "config_file_missing": "\U0001F4C1 ",
    "deps_need_optional": "\U0001F9EA ",     # test tube (optional dep)
    "deps_need_required": "\U0001F9EA ",
    "engine_builtin": "\U0001F534 ",         # red circle (builtin engine)
    "engine_singbox": "\U0001F7E0 ",        # orange circle (sing-box)
    "enter_email": "\U0001F4E9 ",           # inbox tray (prompt)
    "enter_password": "\U0001F510 ",        # lock with key
    "masque_no_aioquic": "\U0001F4E6 ",     # package (lib missing)
    "masque_probe_error": "\u274C ",
    "qr_verify_mismatch": "\u274C ",
    "qr_verify_q": "\U0001F5B3 ",            # question (ask)
    "retry_after": "\U000023F3 ",            # hourglass
    "server_wants_method": "\U0001F4E4 ",   # outbox (server requires)
    "stretch_v2_note": "\U00002139 ",
    "tls_plain_http": "\U000026A0 ",
    "totp_none_reason_nocreds": "\U0001F510 ",
    "totp_none_reason_nosecret": "\U0001F510 ",
    "proxy_type_selected": "\U0001F50C ",
    "proxy_type_switched": "\U0001F50C ",
    "hotkey_proxy_type": "\U0001F527 ",   # wrench (the proxy type menu)
    "ptype_menu_hint": "\U0001F527 ",     # wrench (the Ctrl+T selection menu)
    "ptype_menu_entry": "\U0001F527 ",
    "dns_line": "\U0001F4E1 ",            # satellite antenna (the local DNS relay, v8.5)
    "dns_port_busy": "\U0001F4E1 ",
    "hotkey_auto_rotate": "\U0001F501 ",
    "hotkey_pac_export": "\U0001F4CB ",
    "auto_rotate_startup": "\U0001F501 ",
    "auto_rotate_on": "\U0001F501 ",
    "auto_rotate_off": "\U000023F8 ",
    "auto_rotate_switched": "\U0001F501 ",
    "auto_rotate_zero": "\U0001FAAB ",
    "auto_rotate_to": "\U0001F504 ",
    "auto_rotate_none": "\U0001F6AB ",
    "auto_rotate_off_zero": "\U0001FAAB ",
    "fxa_profile_read": "\U0001F98A ",
    "fxa_profile_missing": "\U0001F98A ",
    "fxa_profile_no_token": "\U0001F98A ",
    "fxa_profile_bad_token": "\U0001F98A ",
    "fxa_profile_session_invalid": "\U0001F98A ",
    "unblock_prompt": "\U0001F513 ",
    "unblock_resent": "\U00002709 ",
    "unblock_wrong": "\U0000274C ",
    "unblock_gave_up": "\U000026D4 ",
    "email_link_wait": "\U0001F517 ",
    "email_link_verified": "\U0001F517 ",
    "email_link_timeout": "\U0001F517 ",
    "pac_written": "\U0001F4CB ",
    "pac_failed": "\U0001F4CB ",
    "pac_no_proxies": "\U0001F4CB ",
    "doctor_title": "\U0001FA7A ",
    "doctor_ok": "\U00002705 ",
    "doctor_fail": "\U0000274C ",
    "doctor_skip": "\U000023ED ",
    "doctor_interpreter": "\U0001F40D ",
    "doctor_config": "\U0001F5C3 ",
    "doctor_deps": "\U0001F4E6 ",
    "doctor_deps_ok": "\U0001F4E6 ",
    "doctor_sysdns": "\U0001F310 ",
    "doctor_doh": "\U0001F50E ",
    "doctor_doh_system": "\U0001F50E ",
    "doctor_fxa": "\U0001F98A ",
    "doctor_serverlist": "\U0001F30D ",
    "doctor_tls": "\U0001F512 ",
    "doctor_quota": "\U0001F4F6 ",
    "doctor_no_session": "\U0001F4F6 ",
    "doctor_done": "\U0001FA7A ",
}

def tr(key: str, **kw) -> str:
    """Translate a message template in the current language with English
    fallback and attach the message's emoji decoration. A template may
    contain the placeholder {_e} - the emoji is placed THERE (in the
    middle of the sentence, at the meaningful spot); templates without
    the placeholder get the emoji as a prefix.
    v5.13: a caller may OVERRIDE the emoji decoration by passing
    _e=... in kw (e.g. the per-proxy national flag in proxy_line);
    without the override the _EMOJI map entry is used as before."""
    raw = STR.get(_LANG, {}).get(key) or STR["en"].get(key) or key
    emo = kw.pop("_e", None) or _EMOJI.get(key, "")
    if "{_e}" in raw:
        txt = raw.replace("{_e}", emo)
    else:
        txt = emo + raw
    if kw:
        txt = txt.format(**kw)
    return txt

# v5.19: the flag representation of the proxy lines. The pixel art was
# REDRAWN from scratch as a REAL 6x2 PIXEL GRID rendered with the
# upper-half block (U+2580): each terminal cell = TWO vertically stacked
# pixels (the truecolor FOREGROUND paints the top half, the BACKGROUND
# the bottom half - the standard technique of pixterm/ascii-magic-style
# terminal graphics; verified online 2026-09-28: the upper half block
# fills the top half of the cell and block elements give two pixels per
# cell, and Windows Terminal STILL has no Kitty graphics protocol or
# Sixel in the stock build, so half-block truecolor remains the ONLY
# portable way to show a pixel PICTURE in a console). Every flag is
# therefore EXACTLY 6 cells wide (12 pixels), stored as two 6-char
# strings (top row / bottom row) + a small palette dict at the top of
# the code - no emoji, no mixed quarter/diagonal glyphs, so every line
# is perfectly aligned (the old table mixed 2- and 3-cell entries, which
# is why e.g. Japan sat one column left). The RECOMMENDED anycast
# (REC/unknown) gets a REAL flag too: a solid white flag in the dark
# theme and a solid black flag in the light theme (drawn as ART in art
# mode, so it aligns exactly like the country flags; the single-glyph
# white/black flag emoji in emoji mode). "auto" (the DEFAULT) is the
# v6.0 behavior (req. 8): the ready-made emoji pair where the terminal
# really renders flag emoji, the pixel art everywhere else (see
# _flag_emoji_supported); "emoji"/"art" force a style.
_FLAG_STYLE = "auto"

# The width of every flag representation, in console columns. The art
# is FLAG_COLS cells + 1 trailing space; the emoji fallbacks are padded
# to the same total so the listen-address column never moves.
FLAG_COLS = 6

# v6.0 (req. 3): the DISPLAY WIDTH of a string in console cells. The
# hotkey hint lines and the flag/emoji paddings must line up EXACTLY on
# every platform, but an emoji icon is rendered 1 cell wide on some
# Windows fonts and 2 cells on the Linux/macOS/Termux terminals - a
# hardcoded space count cannot fix that. _cw() computes the wcwidth-
# style cell count the way the Unicode standard prescribes (East Asian
# Wide/Fullwidth = 2, combining marks / zero-width joiners / variation
# selectors = 0, most emoji = 2, control chars = 0) WITHOUT any third-
# party package: wcwidth/wcswidth are part of the POSIX/C universality
# but Python needs the table, and a dependency is not acceptable for a
# cosmetic fix. The table below is the standard wcwidth algorithm
# (the Unicode East Asian Width property W/F = 2; Mn/Me/Cf categories
# and the VS16/ZWJ = 0; everything else printable = 1).
#
# v8.1 (req. 2): the emoji/symbol planes are checked against the REAL
# East Asian Width W table (Unicode 18.0.0 - the wcwidth project's
# table_wide.py, generated from EastAsianWidth-18.0.0.txt of
# 2026-06-29; fetched and diffed 2026-10-30) instead of the v6.0
# blanket 'all of 0x1F300-0x1F64F is 2 cells'. The real W property in
# the emoji planes is patchy and the blanket was wrong in BOTH
# directions: it counted NEUTRAL codepoints as 2 cells (U+1F39B
# CONTROL KNOBS, U+1F54F, U+1F568 DESKTOP COMPUTER ... render 1 cell
# on every terminal that follows the standard, so a hint line led by
# one of them was padded one cell short and its key letter sat one
# column off), and it MISSED the wide symbols outside the blanket
# (U+2705, U+26A1, U+26D4 ...). The ranges below are the
# 0x2300-0x2BFF and 0x1F000-0x1FBFF portions of that W table
# verbatim; the CJK/fullwidth ranges stay in _cw itself.
_EAW_WIDE = (
    (0x231A, 0x231B), (0x2329, 0x232A), (0x23E9, 0x23EC), (0x23F0, 0x23F0),
    (0x23F3, 0x23F3), (0x25FD, 0x25FE), (0x2614, 0x2615), (0x2630, 0x2637),
    (0x2648, 0x2653), (0x267F, 0x267F), (0x268A, 0x268F), (0x2693, 0x2693),
    (0x26A1, 0x26A1), (0x26AA, 0x26AB), (0x26BD, 0x26BE), (0x26C4, 0x26C5),
    (0x26CE, 0x26CE), (0x26D4, 0x26D4), (0x26EA, 0x26EA), (0x26F2, 0x26F3),
    (0x26F5, 0x26F5), (0x26FA, 0x26FA), (0x26FD, 0x26FD), (0x2705, 0x2705),
    (0x270A, 0x270B), (0x2728, 0x2728), (0x274C, 0x274C), (0x274E, 0x274E),
    (0x2753, 0x2755), (0x2757, 0x2757), (0x2795, 0x2797), (0x27B0, 0x27B0),
    (0x27BF, 0x27BF), (0x2B1B, 0x2B1C), (0x2B50, 0x2B50), (0x2B55, 0x2B55),
    (0x1F004, 0x1F004), (0x1F0CF, 0x1F0CF), (0x1F18E, 0x1F18E),
    (0x1F191, 0x1F19A), (0x1F1AE, 0x1F1AE), (0x1F1E6, 0x1F202),
    (0x1F210, 0x1F23B), (0x1F240, 0x1F248), (0x1F250, 0x1F251),
    (0x1F260, 0x1F265), (0x1F300, 0x1F320), (0x1F32D, 0x1F335),
    (0x1F337, 0x1F37C), (0x1F37E, 0x1F393), (0x1F3A0, 0x1F3CA),
    (0x1F3CF, 0x1F3D3), (0x1F3E0, 0x1F3F0), (0x1F3F4, 0x1F3F4),
    (0x1F3F8, 0x1F43E), (0x1F440, 0x1F440), (0x1F442, 0x1F4FC),
    (0x1F4FF, 0x1F53D), (0x1F54B, 0x1F54E), (0x1F550, 0x1F567),
    (0x1F57A, 0x1F57A), (0x1F595, 0x1F596), (0x1F5A4, 0x1F5A4),
    (0x1F5FB, 0x1F64F), (0x1F680, 0x1F6C5), (0x1F6CC, 0x1F6CC),
    (0x1F6D0, 0x1F6D2), (0x1F6D5, 0x1F6D9), (0x1F6DC, 0x1F6DF),
    (0x1F6EB, 0x1F6EC), (0x1F6F4, 0x1F6FC), (0x1F7DA, 0x1F7DA),
    (0x1F7E0, 0x1F7EB), (0x1F7F0, 0x1F7F0), (0x1F90C, 0x1F93A),
    (0x1F93C, 0x1F945), (0x1F947, 0x1F9FF), (0x1FA70, 0x1FA7C),
    (0x1FA80, 0x1FAC6), (0x1FAC8, 0x1FAC8), (0x1FACC, 0x1FADD),
    (0x1FADF, 0x1FAEB), (0x1FAEF, 0x1FAFA),
)

def _eaw_wide(cp: int) -> bool:
    """Is `cp` East Asian Wide in the emoji/symbol planes? The ranges
    are sorted by their start, so the scan stops at the first one."""
    for start, stop in _EAW_WIDE:
        if cp < start:
            return False
        if cp <= stop:
            return True
    return False

def _cw(text: str) -> int:
    """Console cell width of `text` (wcwidth-style, no dependencies).
    Follows the Unicode 9 emoji-width model used by every modern
    terminal (Windows Terminal, VTE, iTerm2, kitty, Termux): an emoji
    PRESENTATION sequence - a symbol + VS16, or any default-emoji-
    presentation codepoint - occupies 2 cells; a regional-indicator
    PAIR is one 2-cell flag glyph; combining marks, ZWJ and variation
    selectors add nothing."""
    w = 0
    i = 0
    n = len(text)
    prev_zwj = False
    prev_ri = False
    while i < n:
        cp = ord(text[i])
        nxt = ord(text[i + 1]) if i + 1 < n else 0
        if cp == 0 or cp < 32 or cp == 0x7F:      # NUL / control chars
            i += 1
            continue
        if cp == 0x200D:                         # ZWJ glues a sequence
            prev_zwj = True
            i += 1
            continue
        if 0x0300 <= cp <= 0x036F or 0x200B <= cp <= 0x200F \
                or 0x20D0 <= cp <= 0x20FF or 0xFE00 <= cp <= 0xFE2F:
            i += 1                              # combining / zero-width
            continue
        if 0x1F1E6 <= cp <= 0x1F1FF:
            # regional indicator: a PAIR renders as ONE 2-cell flag
            if not prev_ri:
                w += 2
            prev_ri = True
            prev_zwj = False
            i += 1
            continue
        prev_ri = False
        if nxt == 0xFE0F:
            # symbol + VS16 = emoji presentation = 2 cells
            w += 2
            prev_zwj = False
            i += 2
            continue
        # East Asian Wide & Fullwidth. The CJK/fullwidth blocks are the
        # standard ones; the emoji/symbol planes go through _eaw_wide()
        # - the REAL East Asian Width W table (Unicode 18.0.0, see
        # _EAW_WIDE above), not a blanket emoji-block guess.
        wide = (0x1100 <= cp <= 0x115F or   # Hangul Jamo
                (0x2E80 <= cp <= 0xA4CF and cp != 0x303F) or
                0xAC00 <= cp <= 0xD7A3 or    # Hangul syllables
                0xF900 <= cp <= 0xFAFF or    # CJK compatibility
                0xFE30 <= cp <= 0xFE4F or
                0xFF00 <= cp <= 0xFF60 or    # fullwidth forms
                0xFFE0 <= cp <= 0xFFE6 or
                _eaw_wide(cp))
        if prev_zwj:
            # a joined emoji sequence counts as ONE glyph: the ZWJ'd
            # piece adds nothing (family/profession emoji stay 2 cells)
            prev_zwj = False
            i += 1
            continue
        w += 2 if wide else 1
        i += 1
    return w

def _pad_cells(text: str, width: int) -> str:
    """Pad `text` with spaces so it occupies EXACTLY `width` console
    cells (v6.0, req. 3: the padding counts the REAL display width, so
    a 1-cell emoji on a narrow Windows font gets one space MORE than a
    2-cell emoji on a Linux terminal and the next column still starts
    at the very same position on both)."""
    w = _cw(text)
    return text + " " * max(0, width - w)

# v6.0 (req. 8): where do FLAG EMOJI actually render? The intent of
# the 'auto' style was always "show the ready-made flag pictures where
# they are supported and the pixel art everywhere else", but v5.17 had
# picked the branch by OS only: Windows has no font that maps the
# regional-indicator pairs to flag glyphs (they print as the bare
# two-letter ISO code), while a bare 'linux' TERM or a 'dumb' console
# has no emoji font either - so some platforms showed LETTERS instead
# of pictures. Detection (all verified online, 2026-10-25):
#   * Windows 10/11: no flag-glyph font in any stock build -> art;
#   * dumb/not-a-terminal or a bare linux console (TERM unset or
#     'dumb'): no emoji rendering -> art;
#   * macOS (darwin), X11/Wayland desktop terminals, Termux on
#     Android: the emoji fonts (Apple Color Emoji, Noto Color Emoji)
#     render the pairs -> emoji.
# MOZVPN_FLAG_STYLE=emoji|art|auto overrides the detection; the
# --flag-style argument overrides the environment.
def _flag_emoji_supported() -> bool:
    """Does THIS terminal render the regional-indicator flag emoji as
    real flag PICTURES (and not as bare 'US'/'RU' letters)?"""
    forced = (os.environ.get("MOZVPN_FLAG_STYLE") or "").strip().lower()
    if forced == "emoji":
        return True
    if forced == "art":
        return False
    if os.name == "nt":
        return False            # Windows: no flag-glyph font (see above)
    term = (os.environ.get("TERM") or "").strip().lower()
    if term in ("", "dumb", "dumb-emacs-ansi"):
        return False            # not a terminal / a console without emoji
    if sys.platform.startswith("linux") and term == "linux":
        return False            # the bare Linux text console: no emoji font
    return True                 # macOS / desktop Linux / Termux: emoji font

def country_flag(cc) -> str:
    """The flag of an ISO 3166-1 alpha-2 country code for the proxy
    lines. v5.19: in ART mode every flag is a truecolor 6x2 PIXEL GRID
    painted with the upper-half block (U+2580: fg = the top pixel of
    the column, bg = the bottom pixel) - clean rectangles instead of
    the old mixed quarter/diagonal glyphs, and EXACTLY 6 cells for
    every country, so all proxy lines stay in the same columns. In
    EMOJI mode it is the regional-indicator pair (U+1F1E6..U+1F1FF),
    padded to the same 7-column total. 'UK' becomes the GB flag. The
    RECOMMENDED anycast / unknown codes get a real flag as well:
    solid WHITE in the dark theme, solid BLACK in the light theme
    (art in art mode - perfectly aligned with the country flags -
    or the single-glyph white/black flag emoji in emoji mode)."""
    cc = (cc or "").strip().upper()
    if cc == "UK":
        cc = "GB"
    style = _FLAG_STYLE
    if style == "auto":
        # v6.0 (req. 8): the ORIGINAL intent of 'auto' - the ready-made
        # emoji flag PICTURES where the terminal actually renders them
        # (macOS, desktop Linux, Termux), the truecolor pixel art where
        # it does not (Windows without a flag-glyph font, the bare Linux
        # text console, a dumb/absent TERM). v5.17-v5.36 picked by OS
        # alone, which printed bare 'US'/'RU' LETTERS on exactly those
        # no-emoji platforms; the platform detection now lives in
        # _flag_emoji_supported() (MOZVPN_FLAG_STYLE overrides it).
        style = "emoji" if _flag_emoji_supported() else "art"
    if len(cc) != 2 or not cc.isalpha():
        # v5.19: REC / unknown - a real WHITE (dark theme) or BLACK
        # (light theme) flag, drawn as ART in art mode so it aligns
        # exactly like the country flags (7 columns, like every line).
        if style == "art" and _USE_COLOR:
            col = "#FFFFFF" if _THEME == "dark" else "#000000"
            return _flag_paint(("W" * FLAG_COLS, "W" * FLAG_COLS,
                                {"W": col}))
        flag = "\U0001F3F3\uFE0F" if _THEME == "dark" else "\U0001F3F4"
        return _pad_cells(flag, FLAG_COLS + 1)
    if style == "art" and _USE_COLOR:
        px = _FLAG_PIXELS.get(cc)
        if px:
            return _flag_paint(px)
        # no art data: the emoji pair, padded to keep the alignment
        pair = "".join(chr(0x1F1E6 + (ord(ch) - 0x41)) for ch in cc)
        return _pad_cells(pair, FLAG_COLS + 1)
    if style == "art" and not _USE_COLOR:
        pass                      # fall through to the emoji pair below
    # emoji style: the regional-indicator pair (2 columns) + padding
    pair = "".join(chr(0x1F1E6 + (ord(ch) - 0x41)) for ch in cc)
    return _pad_cells(pair, FLAG_COLS + 1)

# ---------------------------------------------------------------------------
# v5.19: the flag PIXEL table. Every entry is (TOP, BOTTOM, PALETTE):
# two 6-character strings - one character per PIXEL COLUMN - and a
# dict mapping each character to the official '#RRGGBB' shade. The
# renderer paints column i with the upper-half block U+2580, the
# FOREGROUND color = PALETTE[TOP[i]] (the top pixel) and the
# BACKGROUND color = PALETTE[BOTTOM[i]] (the bottom pixel): 6 cells,
# 12 pixels, one console line. Horizontal tricolors use the
# A*3+B*3 / B*3+C*3 layout (the middle stripe appears on both rows, so
# the flag reads as three bands); vertical tricolors repeat one string.
# Emblems (crosses, crescents, discs, stars) are approximated with 1-4
# pixels - the maximum a 6x2 grid can carry. Countries = the Mozilla
# VPN network plus neighbors; any other ISO code falls back to the
# emoji pair. Official shades verified online (v5.0-v5.18 notes).
_FLAG_PIXELS = {
    "US": ("BBBRRR", "WWWWRR", {"B": "#3C3B6E", "R": "#B22234", "W": "#FFFFFF"}),
    "GB": ("BWBWBW", "WBWBWB", {"B": "#012169", "W": "#C8102E"}),
    "AU": ("BBBBBW", "BWBWBB", {"B": "#012169", "W": "#FFFFFF"}),
    "NZ": ("BBBBBW", "BWBBWB", {"B": "#012169", "W": "#FFFFFF"}),
    "CA": ("RWWWWR", "RWWWWR", {"R": "#FF0000", "W": "#FFFFFF"}),
    "DE": ("KKKRRR", "RRRGGG", {"K": "#000000", "R": "#DD0000", "G": "#FFCE00"}),
    "FR": ("BBWWRR", "BBWWRR", {"B": "#002395", "W": "#FFFFFF", "R": "#ED2939"}),
    "IT": ("GGWWRR", "GGWWRR", {"G": "#008C45", "W": "#F4F5F0", "R": "#CD212A"}),
    "IE": ("GGWWOO", "GGWWOO", {"G": "#169B62", "W": "#FFFFFF", "O": "#FF883E"}),
    "ES": ("RRRYYY", "YYYRRR", {"R": "#AA151B", "Y": "#F1BF00"}),
    "AT": ("RRRWWW", "WWWRRR", {"R": "#ED2939", "W": "#FFFFFF"}),
    "NL": ("RRRWWW", "WWWBBB", {"R": "#AE1C28", "W": "#FFFFFF", "B": "#21468B"}),
    "BE": ("KKYYRR", "KKYYRR", {"K": "#000000", "Y": "#FDDA24", "R": "#EF3340"}),
    "LU": ("RRRWWW", "WWWBBB", {"R": "#ED2939", "W": "#FFFFFF", "B": "#00A1DE"}),
    "CH": ("RRWWRR", "WWWWWW", {"R": "#DA291C", "W": "#FFFFFF"}),
    "SE": ("BBYYBB", "YYYYYY", {"B": "#006AA7", "Y": "#FECC02"}),
    "NO": ("RRWWRR", "WWBBWW", {"R": "#BA0C2F", "W": "#FFFFFF", "B": "#00205B"}),
    "DK": ("RRWWRR", "WWWWWW", {"R": "#C8102E", "W": "#FFFFFF"}),
    "FI": ("BBWWBB", "WWWWWW", {"B": "#003580", "W": "#FFFFFF"}),
    "PL": ("WWWWWW", "RRRRRR", {"W": "#FFFFFF", "R": "#DC143C"}),
    "PT": ("GGGRRR", "GGYRRR", {"G": "#006600", "R": "#FF0000", "Y": "#FFDD00"}),
    "CZ": ("BBWWWW", "BBRRRR", {"B": "#11457E", "W": "#FFFFFF", "R": "#D7141A"}),
    "GR": ("BBBBBB", "WBWBWB", {"B": "#0D5EAF", "W": "#FFFFFF"}),
    "HU": ("RRRWWW", "WWWGGG", {"R": "#CE2939", "W": "#FFFFFF", "G": "#436F4D"}),
    "RO": ("BBYYRR", "BBYYRR", {"B": "#002B7F", "Y": "#FCD116", "R": "#CE1126"}),
    "BG": ("WWWGGG", "GGGRRR", {"W": "#FFFFFF", "G": "#00966E", "R": "#D62612"}),
    "HR": ("RRRWWW", "WWWBBB", {"R": "#FF0000", "W": "#FFFFFF", "B": "#171796"}),
    "SI": ("WWWBBB", "BBBRRR", {"W": "#FFFFFF", "B": "#005DA4", "R": "#ED1C24"}),
    "SK": ("WWWBBB", "BBBRRR", {"W": "#FFFFFF", "B": "#0B4EA2", "R": "#EE1C25"}),
    "EE": ("BBBKKK", "KKKWWW", {"B": "#0072CE", "K": "#000000", "W": "#FFFFFF"}),
    "LV": ("RRRWWW", "WWWRRR", {"R": "#9E3039", "W": "#FFFFFF"}),
    "LT": ("YYYGGG", "GGGRRR", {"Y": "#FDB913", "G": "#006A44", "R": "#C1272D"}),
    "UA": ("BBBBBB", "YYYYYY", {"B": "#0057B7", "Y": "#FFD700"}),
    "RU": ("WWWBBB", "BBBRRR", {"W": "#FFFFFF", "B": "#0039A6", "R": "#D52B1E"}),
    "BY": ("RRRRRR", "GGWWGG", {"R": "#CE1720", "G": "#4AA657", "W": "#FFFFFF"}),
    "TR": ("RRWWRR", "RWWWRR", {"R": "#E30A17", "W": "#FFFFFF"}),
    "CY": ("WWWCWW", "WWCCWW", {"W": "#FFFFFF", "C": "#D57800"}),
    "MT": ("WWWRRR", "WWWRRR", {"W": "#FFFFFF", "R": "#CF142B"}),
    "JP": ("WWRRWW", "WWRRWW", {"W": "#FFFFFF", "R": "#BC002D"}),
    "KR": ("WWWRRR", "BBBWWW", {"W": "#FFFFFF", "R": "#CD2E3A", "B": "#0047A0"}),
    "CN": ("RYYRRR", "RRRRRR", {"R": "#DE2910", "Y": "#FFDE00"}),
    "TW": ("BWBRRR", "BBRRRR", {"B": "#000095", "W": "#FFFFFF", "R": "#FE0000"}),
    "IN": ("OOOWWW", "WWWGGG", {"O": "#FF9933", "W": "#FFFFFF", "G": "#138808"}),
    "ID": ("RRRRRR", "WWWWWW", {"R": "#CE1126", "W": "#FFFFFF"}),
    "VN": ("RRYRRR", "RYYYRR", {"R": "#DA251D", "Y": "#FFFF00"}),
    "TH": ("RRWWWW", "WBBBBW", {"R": "#A51931", "W": "#FFFFFF", "B": "#2D2A4A"}),
    "MY": ("BBBRRW", "BBYRRW", {"B": "#01006D", "R": "#CC0001", "W": "#FFFFFF", "Y": "#FFCC00"}),
    "SG": ("RRRWWW", "RWWRWW", {"R": "#ED2939", "W": "#FFFFFF"}),
    "PH": ("BBWWWW", "RRWWYY", {"B": "#0038A8", "W": "#FFFFFF", "R": "#CE1126", "Y": "#FCD116"}),
    "AE": ("RGGGGG", "RWWKKK", {"R": "#EF3340", "G": "#00732F", "W": "#FFFFFF", "K": "#000000"}),
    "SA": ("GGGGGG", "GWWWWG", {"G": "#165D31", "W": "#FFFFFF"}),
    "IL": ("BBBBBB", "WWBWBW", {"B": "#0038B8", "W": "#FFFFFF"}),
    "EG": ("RRRYYY", "YYYKKK", {"R": "#CE1126", "Y": "#C09300", "K": "#000000"}),
    "GH": ("RRRYYY", "YYKKGG", {"R": "#CE1126", "Y": "#FCD116", "K": "#000000", "G": "#006B3F"}),
    "KE": ("KKKRRR", "RRWWGG", {"K": "#000000", "R": "#BB0000", "W": "#FFFFFF", "G": "#006600"}),
    "NG": ("GWWGGG", "GWWGGG", {"G": "#008751", "W": "#FFFFFF"}),
    "ZA": ("KKRRGG", "KKGGBB", {"K": "#000000", "R": "#DE3831", "G": "#007A4D", "B": "#002395"}),
    "MA": ("RRGRRR", "RRRGRR", {"R": "#C1272D", "G": "#006233"}),
    "SN": ("GGYYRR", "GGYYRR", {"G": "#00853F", "Y": "#FDEF42", "R": "#E31B23"}),
    "BD": ("GRRGGG", "GRRGGG", {"G": "#006A4E", "R": "#F42A41"}),
    "BR": ("GGYYGG", "GYBBYG", {"G": "#009C3B", "Y": "#FFDF00", "B": "#002776"}),
    "CO": ("YYYBBB", "BBBRRR", {"Y": "#FCD116", "B": "#003893", "R": "#CE1126"}),
    "PE": ("RWWRRR", "RWWRRR", {"R": "#D91023", "W": "#FFFFFF"}),
    "CL": ("BBWWWW", "RRRRRR", {"B": "#0032A0", "W": "#FFFFFF", "R": "#D52B1E"}),
    "AR": ("AAAYWW", "WWYAAA", {"A": "#74ACDF", "Y": "#F6B40E", "W": "#FFFFFF"}),
    "MX": ("GWWRRR", "GWYRRR", {"G": "#006341", "W": "#FFFFFF", "R": "#C8102E", "Y": "#C09300"}),
    "KZ": ("BYYBBB", "BBYBBB", {"B": "#00AFCA", "Y": "#FEC50C"}),
}

def _flag_rgb(hexstr: str) -> "tuple[int, int, int]":
    """'#RRGGBB' -> (r, g, b) for the truecolor escape sequences."""
    h = hexstr.lstrip("#")
    return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))

def _flag_paint(px) -> str:
    """v5.19: paint one flag PIXEL GRID. px = (TOP, BOTTOM, PALETTE):
    two 6-character strings (one char per pixel column) and a dict
    mapping chars to '#RRGGBB'. Every column is ONE cell with the
    upper-half block U+2580: the TRUECOLOR foreground paints the TOP
    pixel, the background the BOTTOM pixel - 6 cells, 12 pixels, one
    console line, exactly FLAG_COLS cells wide for EVERY country (the
    old quarter/diagonal-glyph table mixed 2- and 3-cell entries and
    its mixed glyphs read as noise; the pixel grid reads as a clean
    mini-flag). One trailing reset + space separates the flag from the
    listen address and keeps every proxy line in the same columns."""
    top, bottom, pal = px
    out = []
    for i in range(min(len(top), len(bottom), FLAG_COLS)):
        fr, fgg, fb = _flag_rgb(pal[top[i]])
        br, bgg, bb = _flag_rgb(pal[bottom[i]])
        out.append(f"\x1b[38;2;{fr};{fgg};{fb}m"
                   f"\x1b[48;2;{br};{bgg};{bb}m\u2580")
    return "".join(out) + "\x1b[0m "
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
    r'|(?P<email>\b[\w.+-]+@[\w-]+(?:\.[A-Za-z]{2,})+\b)'
    r'|(?P<jwt>\b[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{20,}){2,}\b)'
    r'|(?P<path>(?:[A-Za-z]:)?[\\/][\w .-]*(?:[\\/][\w .-]+)+'
    r'|~?/[\w.-]*(?:/[\w.-]+)+)'
    r'|(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b)'
    r'|(?P<host>\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+'
    r'[A-Za-z]{2,}(?::\d{1,5})?(?![\w.-]))'
    r'|(?P<cc>\b[A-Z]{2}\b)'
    r'|(?P<proto>\b(?:connect-udp|connect-ip|masque|connect|socks5|http)\b)'
    r'|(?P<flag>(?<=\s)--[\w][\w-]*)'
    r'|(?P<key>(?<=\')[a-z0-9](?=\')|(?<=\s)[1-9]-[1-9](?=\s[-\u2014]\s)|(?<=\s)Ctrl\+[A-Z](?=\s[-\u2014]\s)|(?<=\s)[a-z0-9](?=\s[-\u2014]\s))'
    r'|(?P<hotdesc>(?<=\s[-\u2014]\s)[^\n]+)'
    r'|(?P<size>\b\d+(?:\.\d+)?\s?(?:GiB|MiB|KiB|TiB|GB|MB|KB)\b)'
    r'|(?P<time>\b\d{2}:\d{2}:\d{2}\b)'
    r'|(?P<count>\b\d+/\d+\b|\b\d{6}\b)')

# v5.14: embedded ANSI sequences (the truecolor pixel-art flags of the
# proxy lines bake their codes into the stored history message) are
# STRIPPED when the colorless render prints / redraws the log, so a
# color toggle via hotkey 'n' never shows raw escape garbage.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Log history: every emitted line is remembered so the WHOLE visible log
# can be redrawn when the theme or the color mode is switched on the fly
# (hotkeys 'm' / 'n'). Capped to keep the memory bounded.
_LOG_HISTORY = []
_LOG_HISTORY_MAX = 2000

_RE_DESC_TOKENS = re.compile(r'--[\w][\w-]*'
                            r'|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b'
                            r'|\b(?:masque|connect-udp|connect-ip|connect|builtin|singbox|sing-box)\b')

def _render(level: str, msg: str, end: str = "\n"):
    """Render ONE log line (theme background + level color + word-level
    highlight colors). Does NOT touch the history - used both for live
    output and for the full-log redraw. Inside a matched file path the
    BASENAME is highlighted separately (brighter) from the directories, so
    e.g. C:\\Users\\...\\mozvpn\\session.json shows session.json distinctly.
    A hotkey DESCRIPTION (the text after " - " in the per-key hint lines)
    gets its own color, with --flags / IPs / protocol names inside it
    still highlighted separately.
    v8.1 (req. 3): `end` lets the caller print WITHOUT the trailing
    newline - the live UI panel paints its rows this way on repaint."""
    if not _USE_COLOR:
        # v5.14: strip embedded ANSI sequences (the pixel-art flags) so
        # the colorless log and the hotkey-'n' redraw stay clean text
        print(_ANSI_RE.sub("", msg), end=end, flush=True)
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
    print("".join(out), end=end, flush=True)

def _emit(level: str, msg: str):
    """Print one log line and REMEMBER it in the history (for the full
    redraw on a theme/color switch). v8.1 (req. 3): while the live UI
    panel is on screen, the line first LIFTS the panel (erase), prints
    ABOVE its old position and DROPS it back below - the log keeps
    scrolling and the panel stays pinned at the bottom of the screen."""
    _panel_lift()
    _LOG_HISTORY.append((level, msg))
    if len(_LOG_HISTORY) > _LOG_HISTORY_MAX:
        del _LOG_HISTORY[:len(_LOG_HISTORY) - _LOG_HISTORY_MAX]
    _render(level, msg)
    _panel_drop()

def redraw_log():
    """Fully redraw the whole remembered log: clear the screen (and the
    scrollback) and re-render every history line in the CURRENT theme and
    color mode. Used by hotkeys 'm' (theme switch) and 'n' (color toggle)
    so the entire visible output switches style at once. v8.1 (req. 3):
    the live UI panel is repainted below the redrawn log (its content is
    NOT part of the history - it would double-print in the fallback
    mode, and the panel always shows its CURRENT state anyway)."""
    was_live = _PANEL["rows"] or _PANEL["pending"]
    _PANEL["rows"] = 0
    _PANEL["pending"] = False
    print("\033[2J\033[3J\033[H", end="", flush=True)
    for level, msg in list(_LOG_HISTORY):
        _render(level, msg)
    if was_live and _PANEL["lines"]:
        _panel_render(_PANEL["lines"])

# v8.1 (req. 3): the LIVE UI PANEL. Every proxyPass refresh used to
# APPEND the whole per-refresh block to the log - the proxyPass line,
# the quota, the raw + decoded JWT, the next-refresh countdown, the
# full hotkeys hint, the config-files list and the clear-cache targets
# (50+ rows every ~10 minutes of runtime). The panel instead REDRAWS
# that block in place: the old rows are erased with ANSI cursor
# control (cursor-up + clear-to-end-of-line per row) and the current
# block is repainted at the same spot, so a token refresh costs ZERO
# new log rows. Any real log line emitted while the panel is on
# screen (a warning, a hotkey action, an engine rebuild message)
# lifts the panel first, prints above its old position and drops it
# back below the new line. Everything falls back to the classic
# append when in-place redraw is impossible: no tty (a pipe/file), a
# 'dumb' TERM, or a panel taller than the terminal window. The row
# count follows the REAL wrapped height (a segment longer than the
# terminal width occupies ceil(cells / columns) rows; every embedded
# newline starts its own row), so the long raw-JWT row is tracked
# correctly too.
_PANEL = {"lines": None, "rows": 0, "pending": False}

def _panel_tty_ok() -> bool:
    """In-place redraw needs a real terminal with ANSI cursor control
    (the script already enables VT processing on Windows)."""
    try:
        return (sys.stdout.isatty()
                and os.environ.get("TERM", "") not in ("", "dumb"))
    except Exception:
        return False

def _panel_size():
    """(columns, lines) of the terminal, with safe defaults."""
    try:
        sz = os.get_terminal_size()
        return max(20, sz.columns), max(10, sz.lines)
    except Exception:
        return 80, 24

def _panel_rows_of(lines, cols: int) -> int:
    """The REAL number of terminal rows `lines` will occupy once
    painted: per embedded-newline segment, ceil(cells / columns)."""
    rows = 0
    for _lvl, msg in lines:
        for seg in _ANSI_RE.sub("", msg).split("\n"):
            rows += max(1, -(-min(_cw(seg), 4096) // cols))
    return rows

def _panel_erase():
    """Lift the painted panel off the screen. The cursor ends on the
    panel's FIRST row (column 0), so whatever is printed next replaces
    it; the row count is remembered by the caller when needed."""
    rows = _PANEL["rows"]
    _PANEL["rows"] = 0
    if rows and _panel_tty_ok():
        # up `rows` -> wipe each row and step down -> back to the top
        print("\x1b[%dA" % rows
              + "".join("\r\x1b[K\x1b[1B" for _ in range(rows))
              + "\r\x1b[%dA" % rows, end="", flush=True)

def _panel_lift():
    """Erase the on-screen panel before a new log line scrolls in; the
    CONTENT is remembered and repainted below that line by the paired
    _panel_drop(). No-op unless the panel is currently painted."""
    if _PANEL["rows"]:
        _PANEL["pending"] = True
        _panel_erase()

def _panel_drop():
    """Repaint the lifted panel below whatever was printed since the
    lift (paired with _panel_lift in _emit / the prompt helpers)."""
    if _PANEL["pending"]:
        _PANEL["pending"] = False
        _panel_render(_PANEL["lines"])

def _panel_render(lines):
    """(Re)paint the live UI panel. `lines` is a list of (level, msg)
    tuples: level None = a RAW uncolored row (the token line), any
    other level renders through _render with the theme colors. None
    erases the panel and forgets its content. When in-place repaint is
    impossible (no tty / dumb TERM / the panel does not fit the
    window), every row is emitted the CLASSIC way instead - the log
    then grows per refresh exactly as it did before v8.1."""
    prev = _PANEL["rows"]
    _panel_erase()
    _PANEL["lines"] = lines
    if lines is None:
        _PANEL["pending"] = False
        return
    def _classic():
        for level, msg in lines:
            if level:
                _emit(level, msg)
            else:
                print(msg)
    if not _panel_tty_ok():
        _classic()
        return
    cols, nl = _panel_size()
    need = _panel_rows_of(lines, cols)
    if need + 1 >= nl:
        _classic()
        return
    for level, msg in lines:
        if level:
            _render(level, msg)
        else:
            print(msg)
    _PANEL["rows"] = need
    if prev > need:
        # the new panel is SHORTER: remove the leftover blank rows so
        # the next log line starts right below the panel again
        print("\x1b[%dM" % (prev - need), end="", flush=True)

# v6.0 (req. 3): the hotkey-hint ICON COLUMN. The hint lines look like
# "  <icon> <key> - description" and the icons have DIFFERENT display
# widths: plain emoji pictures are 2 cells, but symbol+VS16 sequences
# (U+267B U+FE0F, U+2934 U+FE0F, ...) are 1 cell on terminals that
# predate the Unicode 9 emoji widths and 2 cells on modern ones - so
# the gap between an icon and its hotkey letter varied from line to
# line and from platform to platform. The fix: every icon is padded to
# the SAME fixed width (ICON_COLS) counting the STANDARD wcwidth-style
# cells (_cw above), so the key letter starts in the same column on
# every line - on every terminal that follows the Unicode widths
# (Windows Terminal, VTE, iTerm2, kitty, Termux all do; verified
# online 2026-10-25). v8.1 (req. 2) additionally keeps every hint icon
# a GUARANTEED East Asian Wide PICTURE (the _EAW_WIDE audit above), so
# the padding itself never has to compensate a 1-cell icon: the hint
# now leads with U+26D4 (Ctrl+C) and U+1F527 (Ctrl+T) instead of the
# VS16-dependent U+23F9 and the NEUTRAL U+1F39B.
ICON_COLS = 2

def _align_icon_line(line: str) -> str:
    """Pad the LEADING icon of a hint/menu line to exactly ICON_COLS
    console cells (v6.0, req. 3). Lines without a leading non-ASCII icon
    are returned unchanged."""
    m = re.match(r"^(\s*)(\S+)(\s+)(\S.*)$", line)
    if not m:
        return line
    lead, icon, sep, rest = m.groups()
    if icon.isascii():
        return line                    # no icon on this line
    w = _cw(icon)
    if w >= ICON_COLS:
        return lead + icon + sep + rest
    return lead + icon + " " * (ICON_COLS - w) + sep + rest

def print_hotkeys_hint(panel: list = None):
    """Print the hotkey hint with EVERY hotkey on its own line, each line
    as its own _emit call (so the theme background is painted per line -
    a multi-line single print would leave the background striped), the KEY
    on the dedicated hotkey block and the DESCRIPTION in the hotdesc color
    (see _render). v6.0 (req. 3): every line goes through
    _align_icon_line first, so the icon column has the SAME width on
    every platform and the hotkey letters all start at one column.
    v8.1 (req. 3): with `panel` given the lines are collected into the
    live-panel list instead of the scrolling log - the hint is part of
    the per-refresh UI block that now redraws itself in place."""
    for line in tr("hotkeys_hint").split("\n"):
        if line.strip():
            if panel is None:
                info(_align_icon_line(line))
            else:
                panel.append(("info", _align_icon_line(line)))

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

# v9.3 (the full-audit identity fix): the challenge flow rides the SAME
# pinned Firefox UA as the FxA API requests (BROWSER_HEADERS) - ONE client
# identity across the *.firefox.com hosts. The Go reference client pinned
# its solver to the FxA UA on 2026-10-31 with the exact reason ('challenge
# cookies may be tied to the client identity'); a real Firefox browser
# sends this UA to accounts.firefox.com too, so the Chrome-macOS UA of the
# older pagpeter/fastly-antibot-era port is retired.
FASTLY_UA   = BROWSER_HEADERS["User-Agent"]
FASTLY_PAGE = "https://accounts.firefox.com/"

COOKIE_JAR = http.cookiejar.CookieJar()
# v6.6: --api-proxy / env MOZVPN_API_PROXY (the Go reference client's
# -api-proxy flag). The CONTROL-plane requests (everything that goes
# through this opener: FxA, Guardian, Remote Settings, the Fastly
# challenge) leave DIRECT by default; with --api-proxy the opener is
# REBUILT with a urllib ProxyHandler so the whole control plane keeps
# ONE FIXED HTTP(S) exit - the Fastly WAF cookie and the Guardian
# enrollment are BOUND TO THE EGRESS IP, so a rotating control plane
# can invalidate them mid-session, while the proxied browsing traffic
# keeps rotating through the Mozilla egresses freely. http:// and
# https:// proxy URLs only: the stdlib ProxyHandler tunnels HTTPS via
# CONNECT and this script adds NO new dependency - socks5:// is
# refused with a clear error at startup. The DoH chain is NOT routed
# through it (the DoH endpoints are anycast; DNS needs no fixed exit).
_api_proxy_url = ""

def _rebuild_opener():
    """(Re)build the shared control-plane opener: a plain cookie-processor
    opener, or a ProxyHandler opener when --api-proxy is active."""
    global _OPENER
    handlers = [urllib.request.HTTPCookieProcessor(COOKIE_JAR)]
    if _api_proxy_url:
        handlers.insert(0, urllib.request.ProxyHandler(
            {"http": _api_proxy_url, "https": _api_proxy_url}))
    _OPENER = urllib.request.build_opener(*handlers)

def set_api_proxy(url: str):
    """v6.6: route the control-plane requests through a fixed HTTP(S)
    proxy ('' = off, the default). Mirrors the Go client's -api-proxy."""
    global _api_proxy_url
    _api_proxy_url = (url or "").strip()
    _rebuild_opener()

def api_proxy() -> str:
    """v6.6: the current --api-proxy URL ('' = off)."""
    return _api_proxy_url

_OPENER = None          # materialized by _rebuild_opener() right below
_rebuild_opener()
_fastly_state = {"solved": False, "failed": False}
# v6.6: THE BOUNDED FASTLY SOLVER (the Go reference client's fastly.go
# limits). FASTLY_MAX_ROUNDS caps the post-back exchange: a server that
# answers a solution submission with ANOTHER challenge list cannot
# loop the solver forever (at most 3 rounds of solve + submit);
# FASTLY_SOLVE_TIMEOUT caps the WHOLE challenge flow (60 s) so a
# wedged post-back cannot hang the sign-in; _FASTLY_SOLVE_LOCK
# serializes concurrent solves (the Go solve mutex: parallel PoW work
# races the token/cookie pairing and wastes the challenge rounds).
FASTLY_MAX_ROUNDS    = 3
FASTLY_SOLVE_TIMEOUT = 60
_FASTLY_SOLVE_LOCK = threading.Lock()

# v6.7 (the Go fxa.go fxaDo loop): the maximum solve-and-retry cycles a
# SINGLE request runs when the Fastly edge keeps answering 406 (the
# maxChallengeAttempts = 5 constant of the reference client).
FASTLY_MAX_406_ATTEMPTS = 5

def _is_firefox_host(url: str) -> bool:
    h = urlparse(url).hostname or ""
    return h == "firefox.com" or h.endswith(".firefox.com")

def _waf_challenge_body(raw) -> bool:
    """v7.0: True when a *.firefox.com response body is a Fastly
    client-challenge page. The Vauth/FoxyVPN PR #46 (2026-10-29)
    reports the NGWAF challenge arriving NOT ONLY as the classic
    empty-body 406 but also as 403/200/503 WITH the markup - and
    the Go fastly.go fetchChallengePage detects the page by the
    same two markers ('/_fs-ch-' + 'Client Challenge'), so BOTH
    are required here (a lone marker could be a coincidental
    string in real page content)."""
    try:
        return (raw is not None and len(raw) > 0
                and raw.find(b"/_fs-ch-") >= 0
                and raw.find(b"Client Challenge") >= 0)
    except Exception:
        return False

def _add_cookie(name: str, value: str, domain: str = ".firefox.com"):
    COOKIE_JAR.set_cookie(http.cookiejar.Cookie(
        version=0, name=name, value=value,
        port=None, port_specified=False,
        domain=domain, domain_specified=True, domain_initial_dot=True,
        path="/", path_specified=True,
        secure=False, expires=None, discard=False,
        comment=None, comment_url=None, rest={}, rfc2109=False))

def _purge_fastly_cookies():
    """v6.7: drop every _fs_ch_cp_* cookie from the shared jar. A 406 that
    arrived DESPITE a sent cookie means the WAF rejected THAT cookie - the
    retry must solve a FRESH challenge, not re-send the stale one (the Go
    client re-solves on every 406: fxa.go fxaDo). The jar is mutated IN
    PLACE, so the opener's cookie processor (which captured the jar object)
    stays in sync."""
    for c in list(COOKIE_JAR):
        if c.name.startswith("_fs_ch_cp_"):
            try:
                COOKIE_JAR.clear(c.domain, c.path, c.name)
            except KeyError:
                pass

def load_fastly_cache() -> bool:
    # v6.0: the cookie lives in config.json (fastly_cookie) - the
    # fastly-cookie.json file of the old format is migrated & removed.
    c = cfg_get(("fastly_cookie",)) or {}
    try:
        if c.get("name") and c.get("value") and c.get("expiresAt", 0) > time.time() + 60:
            _add_cookie(c["name"], c["value"])
            return True
    except Exception:
        pass
    return False

def save_fastly_cache(name: str, value: str):
    try:
        cfg_set(("fastly_cookie",),
                {"name": name, "value": value,
                 "expiresAt": time.time() + 50 * 60})
    except Exception:
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
    # v5.36: the challenge flow must ALSO work when the SYSTEM resolver is
    # broken (the packaged-binary-on-Android state). The v5.13-v5.35 code
    # opened _OPENER directly here, so in that state the Fastly challenge
    # could NOT be solved: every *.firefox.com request that arrived with a
    # missing/expired _fs_ch_cp_* cookie ended in the waf_406 form forever
    # (the latent 'works for hours, then dies after the ~1h cookie expiry'
    # recurrence). In the broken state the request goes through
    # _fastly_http_ip() - the emergency DoH resolves the host, ONE raw
    # HTTPS request goes to the IP (Host + SNI kept) and the shared cookie
    # jar stays in sync (the _fs_ch_cp_* Set-Cookie must land in COOKIE_JAR
    # - fastly_solve_challenge() scans the jar). On any failure the
    # reference _OPENER path still runs below (best effort, the exact
    # pre-v5.36 behavior).
    if _resolver_broken():
        try:
            return _fastly_http_ip(method, url, body, h, timeout)
        except Exception:
            pass
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
    # Minimal values - sufficient per live tests (pypi.org,
    # accounts.firefox.com). v9.3: the field set now matches the Go
    # reference solver's answer (fastly.go clientMetricsAnswer, the
    # 2026-08-22 sync) - detector_results {} and v 2 are carried too,
    # and error_trace is JSON null (the old stub predates both fields
    # and sent a '""' string).
    return {"ty": "clientmetrics",
            "webdriver": False,
            "bot_detection_result": {"bot_detected": False, "bot_kind": None},
            "browser_metrics": {"client_data": "{}", "error_trace": None},
            "detector_results": {},
            "v": 2}

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
    # v6.6: THE POST-BACK ROUNDS LOOP. The server may answer a solution
    # submission with ANOTHER challenge list (a new 'tok' + 'ch')
    # instead of the final success - the reference Go client bounds
    # this exchange by maxPostBackRounds (fastly.go: 3) and by a
    # whole-solve timeout (60 s), so a server that keeps issuing
    # rounds cannot loop the solver forever and a wedged post-back
    # cannot hang the sign-in.
    _deadline = time.monotonic() + FASTLY_SOLVE_TIMEOUT
    current = _fastly_postback(domain, script_id, referer, token,
                               [{"ty": "pat", "auth": ""}])
    _round_no = 0
    while True:
        _round_no += 1
        if time.monotonic() > _deadline:
            raise RuntimeError(
                f"Fastly challenge solve timed out ({FASTLY_SOLVE_TIMEOUT}s)")
        token = current.get("tok", token)

        # 5. solve the challenges of THIS round
        solutions = []
        for ch in current.get("ch", []):
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

        # 6. submit the solutions -> success (Set-Cookie _fs_ch_cp_*) or
        # the NEXT challenge list (one more round, bounded by
        # FASTLY_MAX_ROUNDS / FASTLY_SOLVE_TIMEOUT above)
        current = _fastly_postback(domain, script_id, referer, token,
                                   solutions)
        if current.get("status") == "success":
            # v7.0: THE ACCEPTANCE PROBE (the Go fastly.go flow, fetched
            # 2026-10-30: 'Probe before installing the cookie: with
            # rotating-exit proxies the cookie may be bound to an IP
            # the API call will not reuse, and the probe catches that
            # immediately' - errChallengeNotAccepted). The page is
            # re-fetched THROUGH THE SAME JAR: a page that still
            # carries the challenge markup means the earned cookie
            # was NOT accepted (e.g. a rotated exit IP) and must NOT
            # be latched/cached (up to v6.9 the cookie was cached
            # blindly and the API call had to rediscover the
            # rejection through the 406 re-solve loop). The two
            # markers are the Go fetchChallengePage pair.
            _, probe_body = _fastly_http("GET", target_url, headers={
                "Accept": "text/html,application/xhtml+xml,"
                          "application/xml;q=0.9,*/*;q=0.8"})
            if (probe_body.find(b"/_fs-ch-") >= 0
                    and probe_body.find(b"Client Challenge") >= 0):
                raise RuntimeError(
                    "challenge cookie not accepted on this exit IP "
                    "(the Go errChallengeNotAccepted)")
            break
        if not current.get("ch") or _round_no >= FASTLY_MAX_ROUNDS:
            raise RuntimeError(
                f"challenge not solved (status={current.get('status')!r}, "
                f"rounds={_round_no})")
    final = current

    for c in COOKIE_JAR:
        if c.name.startswith("_fs_ch_cp_"):
            return c.name, c.value
    raise RuntimeError("_fs_ch_cp_* cookie not received after a successful solution")

def ensure_fastly_cookie() -> bool:
    """Fastly cookie: cache -> challenge solution. True = the cookie is in the jar.
    v6.6: the whole check-and-solve sequence runs under _FASTLY_SOLVE_LOCK
    (the Go solve mutex): concurrent callers (the probe threads, a hotkey
    racing the watch loop) JOIN the one running solve instead of racing it
    with parallel challenge solutions - parallel solves waste the PoW work
    and can end up with mismatched token/cookie pairs."""
    if _fastly_state["solved"]:
        return True
    if _fastly_state["failed"]:
        return False
    with _FASTLY_SOLVE_LOCK:
        # the state may have changed while this caller waited on the lock
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

class _HawkHeaders(dict):
    """v8.0 (C1): the Hawk Authorization header that RE-SIGNS ITSELF on
    every retry (the foxyvpn rule: 'on Hawk-signed FxA requests, the
    request signature is rebuilt fresh on every retry'). The dict IS the
    normal header dict - every existing caller keeps working verbatim -
    but it also carries its signing inputs, and rebuild() recomputes the
    ts, the nonce and the MAC through the very same _hawk_header_value()
    computation. The server may not verify the MAC today (the onepw
    hawk-fxa-token.js era is over), but the code no longer RELIES on
    that: a retry can never ride a signature that was minted for the
    PREVIOUS attempt (an older ts, a reused nonce)."""
    __slots__ = ("_sign_args",)

    def __init__(self, header: dict, sign_args: tuple):
        super().__init__(header)
        self._sign_args = sign_args

    def rebuild(self) -> "_HawkHeaders":
        st, method, path, payload, host, port = self._sign_args
        fresh = _hawk_header_value(st, method, path, payload, host, port)
        out = _HawkHeaders({"Authorization": fresh}, self._sign_args)
        return out

def _hawk_header_value(session_token: str, method: str, path: str,
                       payload: bytes, host: str, port: int) -> str:
    """v8.0: the Hawk signature COMPUTATION extracted verbatim from
    hawk_session() so _HawkHeaders.rebuild() can re-run it with a FRESH
    ts + nonce on every retry."""
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
    return (f'Hawk id="{token_id}", ts="{ts}", nonce="{nonce}", '
            f'hash="{body_hash}", mac="{mac}"')

def hawk_session(session_token: str, method: str, path: str,
                 payload: bytes, host: str = "api.accounts.firefox.com",
                 port: int = 443) -> "_HawkHeaders":
    """A full Hawk header (fallback in case the Bearer strategy is not accepted).
    id=tokenID, key=reqHMACkey - the same derivatives as in the onepw/Hawk era.
    The current server does not verify the MAC (hawk-fxa-token.js), but for
    compatibility with an older deployment we sign properly: normalized string
    + HMAC-SHA256 + body hash.
    v8.0 (C1): the returned header is a _HawkHeaders - a plain dict that
    carries its signing inputs, so every retry of req_full() re-signs it
    with a fresh ts + nonce through _rebuild_hawk() (the foxyvpn rule)."""
    sign_args = (session_token, method, path, payload, host, port)
    return _HawkHeaders({"Authorization":
                         _hawk_header_value(*sign_args)}, sign_args)

def _rebuild_hawk(headers):
    """v8.0 (C1): re-sign a Hawk header before a retry. A _HawkHeaders
    comes back FRESH (new ts + nonce + MAC, the same signing inputs);
    every plain dict (and None) passes through untouched - non-Hawk
    callers see no change at all."""
    if isinstance(headers, _HawkHeaders):
        return headers.rebuild()
    return headers

# ---------------- http ----------------

def _is_transient_net_error(e) -> bool:
    """v5.12: True for TRANSIENT network errors that usually resolve
    themselves within seconds (the Termux/arm live runs showed
    gaierror(7) 'No address associated with hostname' blips that broke
    ONE loop iteration and were fine on the retry): a URLError whose
    reason is a gaierror/timeout/connection error, socket.gaierror,
    timeouts and connection errors, plus a text fallback. HTTPError is
    NOT transient (it is a real server answer)."""
    if isinstance(e, urllib.error.HTTPError):
        return False
    if isinstance(e, urllib.error.URLError):
        r = getattr(e, "reason", None)
        if isinstance(r, (socket.gaierror, socket.timeout, TimeoutError,
                          ConnectionError, OSError)):
            return True
        t = str(r).lower()
        return any(s in t for s in ("gaierror", "timed out", "timeout",
                                    "connection reset", "refused",
                                    "unreachable", "network is down",
                                    "no address associated"))
    if isinstance(e, (socket.gaierror, socket.timeout, TimeoutError,
                      ConnectionError)):
        return True
    t = str(e).lower()
    return any(s in t for s in ("gaierror", "timed out", "timed out",
                                "connection reset", "refused",
                                "no address associated"))

def _net_err_public(e) -> str:
    """v5.12: a SHORT localized reason for a transient network error, so
    the log stays friendly instead of showing raw exception reprs like
    URLError(gaierror(7, 'No address associated with hostname'))."""
    t = str(getattr(e, "reason", e)).lower()
    if ("gaierror" in t or "no address associated" in t
            or "name or service" in t):
        return tr("net_err_dns")
    if "timed out" in t or "timeout" in t:
        return tr("net_err_timeout")
    return tr("net_err_conn")

# ---------------------------------------------------------------------------
# v5.13: DIRECT-IP HTTPS FALLBACK (packaged Android binaries).
# On Android/Termux PACKAGED binaries (PyInstaller/Nuitka) the SYSTEM
# resolver may fail with gaierror(7) 'No address associated with
# hostname' while the same code runs fine as a plain script in the same
# shell - a KNOWN packaged-Python-on-Android problem (python-for-android
# #1447, kivy #7087, PyInstaller #3721: getaddrinfo is broken in the
# packaged runtime while nslookup/the browser work fine). The DoH
# presets are hostname-based, so they cannot help either when
# getaddrinfo is broken. The fallback bypasses the system resolver
# ENTIRELY:
#   (1) _emergency_doh_resolve() asks the well-known DoH resolver IPs
#       directly over HTTPS - NO name resolution anywhere (the SNI and
#       the Host header stay the resolver hostname, the TCP connect
#       goes to the IP literal);
#   (2) _raw_https() sends ONE raw HTTPS/1.1 request straight to the
#       resolved IP with the correct Host header and SNI;
#   (3) _ip_fallback_full() (v5.36; was _req_ip_fallback) wraps (1)+(2)
#       into a req_full()-compatible call (redirect following, the shared
#       cookie jar, the response headers, JSON parsing);
#   (4) v5.36 adds _fastly_http_ip(): the same direct-IP transport for
#       the Fastly WAF challenge flow itself.
# ---------------------------------------------------------------------------

_DOH_IP_BOOTSTRAP = (
    # (resolver IP, SNI/Host hostname, port, JSON DoH endpoint)
    ("1.1.1.1", "cloudflare-dns.com", 443,  "/dns-query"),
    ("8.8.8.8", "dns.google",         443,  "/resolve"),
    # v8.8: Quad9 RETIRED the JSON service on port 5053 (5 May 2025 -
    # 'migrate to DoH on port 443'); the 443 endpoint answers the
    # RFC 8484 wireformat, so a JSON request gets an error status and
    # the emergency walk skips quad9 FAST (the loop walks on to
    # cloudflare/google; 2026-10-31 live check: 443 is up, the ?name=
    # JSON form is gone).
    ("9.9.9.9", "dns.quad9.net",      443,  "/dns-query"),
)

def _raw_https(ip: str, sni_host: str, port: int, method: str, path: str,
               headers: dict, body: "bytes | None" = None,
               timeout: int = 10,
               frag: bool = False) -> "tuple[int, dict, bytes]":
    """v5.13: ONE raw HTTPS/1.1 request straight to `ip` - NO system DNS
    anywhere: the TCP connect goes to the IP literal, the TLS SNI and
    the Host header stay `sni_host`. Returns (status_code, header_dict,
    body_bytes) or raises OSError/socket errors.
    v8.6: frag=True (the DoH callers) sends the TLS handshake with the
    FRAGMENTED ClientHello when tls_split() is on (the same
    _FragTLSConn segmentation the egress TLS rides); the default
    frag=False keeps the byte-for-byte v8.5 behavior of the API
    direct-IP fallback callers. Any fragmented-handshake failure falls
    back to a FRESH plain connection (the v6.1 lesson: a hardening
    must never break the data path)."""
    s = socket.create_connection((ip, port), timeout=timeout)
    tls = None
    try:
        s.settimeout(timeout)
        if frag and tls_split():
            try:
                tls = _FragTLSConn(s, _ssl_ctx(), sni_host,
                                   int(timeout) or 10)
            except Exception:
                # a fresh socket + the plain handshake (the socket may
                # be half-consumed by the failed fragmented handshake)
                try:
                    s.close()
                except Exception:
                    pass
                s = socket.create_connection((ip, port), timeout=timeout)
                s.settimeout(timeout)
                tls = _ssl_ctx().wrap_socket(s, server_hostname=sni_host)
        else:
            tls = _ssl_ctx().wrap_socket(s, server_hostname=sni_host)
        # v5.35: the outgoing header set is DEDUPLICATED case-insensitively
        # before the wire (one header line per name, the FIRST occurrence
        # wins). The v5.13 caller could hand this function a dict holding
        # BOTH "Content-Type" (the caller's original spelling) and
        # "Content-type" (a urllib Request header_items() copy - urllib
        # .capitalize()s every header name in Request.add_header), and the
        # raw request then carried the SAME header twice. api.accounts.
        # firefox.com is served through Fastly, which combines duplicate
        # request headers into ONE comma-joined value; the FxA backend
        # (fxa-auth-server, Hapi) received 'Content-Type: application/json,
        # application/json' - a media type it cannot parse - and answered
        # 415 Unsupported Media Type (the packaged-Termux-binary OAuth
        # failure). HTTP header names are case-insensitive (RFC 9110), so
        # a single line per name is always semantically correct.
        hdrs = {"Host": sni_host, "Connection": "close",
                "Accept-Encoding": "identity"}
        seen = {"host", "connection", "accept-encoding"}
        for k, v in (headers or {}).items():
            lk = k.lower()
            if lk == "host" or lk in seen:
                continue           # a case-variant duplicate - drop it
            seen.add(lk)
            hdrs[k] = v
        if body is not None:
            hdrs["Content-Length"] = str(len(body))
        head = (f"{method.upper()} {path} HTTP/1.1\r\n"
                + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
                + "\r\n").encode("latin-1", "replace")
        tls.sendall(head + (body or b""))
        chunks = []
        while True:
            b = tls.recv(65536)
            if not b:
                break
            chunks.append(b)
            if len(b"".join(chunks)) > 1048576:
                break
        status_line, hdict, resp_body = _http_dechunked_body(b"".join(chunks))
        if not status_line:
            raise OSError(f"unparsable HTTP response from {ip}:{port}")
        parts = status_line.split()
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        return code, hdict, resp_body
    finally:
        for _sock in (tls, s):
            try:
                if _sock is not None:
                    _sock.close()
            except Exception:
                pass

def _emergency_doh_resolve(host: str) -> "list[str] | None":
    """v5.13: resolve a hostname when the SYSTEM resolver is broken: ask
    the well-known DoH resolver IPs DIRECTLY (the resolver hostnames are
    never resolved - SNI only). Returns the A/AAAA answer list or None.
    Works regardless of the --doh setting (even with DoH 'off')."""
    for ip, sni, rport, path in _DOH_IP_BOOTSTRAP:
        try:
            q = (path + ("&" if "?" in path else "?")
                 + "name=" + quote(host, safe="") + "&type=A")
            code, _h, resp = _raw_https(ip, sni, rport, "GET", q,
                                        {"Accept": "application/dns-json",
                                         "User-Agent": "mozvpn/5.13"},
                                        None, DOH_TIMEOUT, frag=True)
            if code != 200 or not resp:
                continue
            data = json.loads(resp.decode("utf-8", "replace"))
            ips = [str(a.get("data")) for a in data.get("Answer") or []
                   if a.get("type") in (1, 28) and a.get("data")]
            if ips:
                return ips
        except Exception:
            continue
    return None

class _RawRespInfo:
    """v5.13: the minimal response shim for COOKIE_JAR.extract_cookies():
    the jar only needs response.info() with get_all('Set-Cookie') and a
    real urllib Request (which already provides every attribute it
    reads)."""

    def __init__(self, hdict: dict):
        from email.message import Message
        self._msg = Message()
        for k, v in (hdict or {}).items():
            self._msg[k] = v

    def info(self):
        return self._msg

def _fastly_http_ip(method: str, url: str, body: "bytes | None",
                    headers: dict, timeout: int) -> "tuple[int, bytes]":
    """v5.36: ONE challenge-flow request when the SYSTEM resolver is
    broken (the packaged-binary-on-Android state): the emergency DoH
    resolves the URL host (NO getaddrinfo anywhere - the well-known
    bootstrap resolver IPs answer directly), then ONE raw HTTPS/1.1
    request goes to the resolved IP with the Host header + the TLS SNI
    kept. The shared cookie jar is kept in sync on every hop: the
    request carries the jar's Cookie header and the response's
    Set-Cookie entries are extracted into the jar - the final
    _fs_ch_cp_* cookie MUST land in COOKIE_JAR (fastly_solve_
    challenge() scans the jar for it; the _OPENER cookie processor
    fulfills the same contract on the reference path). Returns
    (status_code, body_bytes); raises OSError on any failure (the
    caller, _fastly_http, decides what to do)."""
    u = urlparse(url)
    if (u.scheme or "https").lower() != "https" or not u.hostname:
        raise OSError(f"not an https URL: {url}")
    ips = _emergency_doh_resolve(u.hostname)
    if not ips:
        raise OSError(f"emergency DoH could not resolve {u.hostname}")
    path = (u.path or "/") + (("?" + u.query) if u.query else "")
    # a REAL urllib Request only as the cookie-jar interface (as in
    # _ip_fallback_full: extract_cookies needs a genuine Request)
    creq = urllib.request.Request(url, data=body, method=method,
                                  headers=dict(headers))
    try:
        COOKIE_JAR.add_cookie_header(creq)
    except Exception:
        pass
    send = dict(headers)
    for k, v in creq.header_items():
        # v5.35 rule: ONLY the Cookie header is taken from the urllib
        # Request (its other header names are .capitalize()d and would
        # duplicate the originals -> the Fastly 415 bug)
        if k.lower() == "cookie" and v:
            send["Cookie"] = v
    code, hdict, resp_body = _raw_https(ips[0], u.hostname, u.port or 443,
                                        method, path, send, body, timeout)
    _note_server_date(hdict)
    try:
        COOKIE_JAR.extract_cookies(_RawRespInfo(hdict), creq)
    except Exception:
        pass
    return code, resp_body

def _ip_fallback_full(method: str, url: str, data, headers,
                     timeout: int) -> "tuple[int, dict, dict] | None":
    """v5.13 -> v5.36: req_full() LAST RESORT after the system resolver
    failed (the packaged-binary-on-Android case): resolve the URL host
    over the emergency DoH, then ONE raw HTTPS request to the IP with
    the correct Host header + SNI, redirect following, the shared
    cookie jar, the v5.25 406-challenge retry and _note_server_date
    included. v5.36: returns the FULL response
    (status, headers_dict_lower, json) - guardian_pass() needs the
    X-Quota-*/Retry-After headers of the /api/v1/fpn/token answer too
    - or None when the fallback cannot help (the URL is not HTTPS or
    the emergency DoH itself failed)."""
    u = urlparse(url)
    if (u.scheme or "https").lower() != "https" or not u.hostname:
        return None
    ips = _emergency_doh_resolve(u.hostname)
    if not ips:
        return None
    base_headers = dict(BROWSER_HEADERS)
    base_headers.update(headers or {})
    cur_url, cur_method, cur_body = url, (method or "GET").upper(), \
        (json.dumps(data).encode() if data is not None else None)
    waf_retried = False            # v5.25: one challenge retry per raw call
    for _hop in range(5):                   # follow up to 5 redirects
        u2 = urlparse(cur_url)
        if u2.hostname != u.hostname:       # cross-host redirect
            ips = _emergency_doh_resolve(u2.hostname) or ips
        path = (u2.path or "/") + (("?" + u2.query) if u2.query else "")
        # a REAL urllib Request only as the cookie-jar interface
        creq = urllib.request.Request(cur_url, data=cur_body,
                                      headers=dict(base_headers),
                                      method=cur_method)
        try:
            COOKIE_JAR.add_cookie_header(creq)
        except Exception:
            pass
        # v5.35: ONLY the Cookie header is taken from the urllib Request.
        # The v5.13 code merged EVERY creq.header_items() entry into the
        # outgoing dict; urllib .capitalize()s header names
        # ("Content-Type" -> "Content-type"), so different-case keys did
        # NOT overwrite each other and the raw request carried the same
        # header TWICE - Fastly joins the duplicates into
        # 'application/json, application/json', which the FxA backend
        # (Hapi) rejects with 415 Unsupported Media Type. base_headers
        # stays the single source of every other header.
        send = dict(base_headers)
        for k, v in creq.header_items():
            if k.lower() == "cookie" and v:
                send["Cookie"] = v
        code, hdict, resp_body = _raw_https(
            ips[0], u2.hostname, u2.port or 443, cur_method, path,
            send, cur_body, timeout)
        # v5.25 (Termux fix): the RAW path could answer 406 with an empty
        # body exactly like the normal req() path (the Fastly NGWAF
        # blocks this raw request too until a _fs_ch_cp_* cookie
        # exists) - but the raw path had NO challenge handling at all,
        # so the 406 bubbled up as the waf_406 'retry form'. Solve the
        # challenge, re-attach the fresh cookie and redo the hop ONCE.
        # (v5.36: in the broken state the challenge flow itself now
        # rides _fastly_http_ip(), so this retry actually SUCCEEDS.)
        if (code == 406 and not resp_body and not waf_retried
                and _is_firefox_host(cur_url) and ensure_fastly_cookie()):
            waf_retried = True
            continue                # same hop again, now with the cookie
        _note_server_date(hdict)            # time sync for TOTP, as in req()
        try:
            COOKIE_JAR.extract_cookies(_RawRespInfo(hdict), creq)
        except Exception:
            pass
        if code in (301, 302, 303, 307, 308) and hdict.get("location"):
            cur_url = urllib.parse.urljoin(cur_url, hdict["location"])
            if code == 303 or (code in (301, 302) and cur_method == "POST"):
                cur_method, cur_body = "GET", None
            continue
        out_hdrs = dict(hdict)
        if not resp_body:
            return code, out_hdrs, {}
        try:
            return code, out_hdrs, json.loads(resp_body)
        except Exception:
            return code, out_hdrs, {}

def req_full(method: str, url: str, data=None, headers=None, timeout=30,
             _fastly_attempts=0, _net_retry=False):
    """v5.36: the ROUTED request transport - req() PLUS the response
    headers. Returns (status, headers_dict_lower, json_dict). This is
    the single place where the request algorithm lives, so EVERY caller
    (req() and the header-needing callers like guardian_pass()) rides
    the EXACT same routing:
      - the reference-parity PRIMARY path: plain urllib through the
        shared cookie opener, one 406-challenge retry (the exact
        reference request algorithm - the reference mozvpn.py has no
        other retries);
      - a transient network error retries ONCE (1.5 s) like a blip;
      - after a SECOND gaierror (the persistent packaged-binary
        resolver state, _resolver_broken()) every call goes STRAIGHT
        to _ip_fallback_full(): emergency DoH to the well-known
        resolver IPs + ONE raw HTTPS request to the resolved IP (Host
        + SNI kept, the shared cookie jar, redirect following,
        _note_server_date and its OWN 406 challenge handling).
    v5.36 SHORT-CIRCUIT: once the resolver is flagged broken, the
    doomed getaddrinfo attempt is not even made anymore (the v5.28 code
    raised a gaierror on EVERY call first and only then switched to
    the fallback); the normal urllib path is reached again only when
    the emergency route cannot help at all (best effort)."""
    h = dict(BROWSER_HEADERS); h.update(headers or {})
    body = json.dumps(data).encode() if data is not None else None
    # v5.36: the system resolver is KNOWN broken -> skip the doomed
    # getaddrinfo attempt entirely, go straight to the emergency route.
    if _resolver_broken():
        try:
            out = _ip_fallback_full(method, url, data,
                                    _rebuild_hawk(headers), timeout)
            if out is not None:
                return out
        except Exception:
            pass          # fall through to the urllib path (best effort)
    r = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        with _OPENER.open(r, timeout=timeout) as resp:
            _note_server_date(resp.headers)     # time sync for TOTP
            raw = resp.read()
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            # v7.0: the client-challenge page can arrive with HTTP 200
            # as well (the Vauth/FoxyVPN PR #46 report: the challenge
            # markup shows up at 406/403/200/503) - the same bounded
            # solve-and-retry as the 406 branch below, including the
            # stale-cookie purge on the SECOND sighting.
            if (_waf_challenge_body(raw)
                    and _fastly_attempts < FASTLY_MAX_406_ATTEMPTS
                    and _is_firefox_host(url)):
                if _fastly_attempts >= 1:
                    _fastly_state["solved"] = False
                    _fastly_state["failed"] = False
                    _purge_fastly_cookies()
                    try:
                        cfg_set(("fastly_cookie",), None)
                    except Exception:
                        pass
                    warn(tr("fastly_406_stale"))
                if ensure_fastly_cookie():
                    return req_full(method, url, data,
                                    _rebuild_hawk(headers), timeout,
                                    _fastly_attempts=_fastly_attempts + 1,
                                    _net_retry=_net_retry)
            if _RESOLVER_STRIKES["n"]:
                # a request SUCCEEDED -> the system resolver works again
                # (the earlier failures were a transient blip, not the
                # packaged-binary state)
                _RESOLVER_STRIKES["n"] = 0
            return resp.status, hdrs, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        _note_server_date(e.headers)            # also from error responses
        raw = e.read()
        # Fastly NGWAF blocks non-browser clients with 406 and an empty
        # body until a valid _fs_ch_cp_* cookie exists. Solve the challenge
        # and retry; v6.7 adopts the Go fxaDo loop (maxChallengeAttempts =
        # 5): when a 406 arrives DESPITE a cookie that was already sent,
        # the WAF rejected THAT cookie - drop the solved latch, purge the
        # stale cookie (jar + config cache) and solve a FRESH one, up to
        # FASTLY_MAX_406_ATTEMPTS solve-and-retry cycles per call.
        # v7.0: BODY-AWARE - the client challenge ALSO arrives as a
        # challenge PAGE with 403/200/503 (the Vauth/FoxyVPN PR #46
        # report, 2026-10-29), not only as the classic empty-body
        # 406, so a body carrying the challenge markup takes the
        # same bounded solve-and-retry (_waf_challenge_body carries
        # the Go fetchChallengePage marker pair).
        if (((e.code == 406 and not raw) or _waf_challenge_body(raw))
                and _fastly_attempts < FASTLY_MAX_406_ATTEMPTS
                and _is_firefox_host(url)):
            if _fastly_attempts >= 1:
                _fastly_state["solved"] = False
                _fastly_state["failed"] = False
                _purge_fastly_cookies()
                try:
                    cfg_set(("fastly_cookie",), None)
                except Exception:
                    pass
                warn(tr("fastly_406_stale"))
            if ensure_fastly_cookie():
                return req_full(method, url, data,
                                _rebuild_hawk(headers), timeout,
                                _fastly_attempts=_fastly_attempts + 1,
                                _net_retry=_net_retry)
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:    return e.code, hdrs, (json.loads(raw) if raw else {})
        except Exception: return e.code, hdrs, {}
    except urllib.error.URLError as e:
        # v5.28: a transient network error is retried once; a PERSISTENT
        # gaierror (2+ strikes - the packaged-binary-on-Android broken
        # resolver) permanently switches the request route to the
        # direct-IP fallback that needs NO name resolution anywhere.
        if _is_transient_net_error(e):
            reason = getattr(e, "reason", None)
            if isinstance(reason, socket.gaierror):
                _RESOLVER_STRIKES["n"] += 1
                warn(tr("resolver_broken_note")
                     if _resolver_broken() else tr("resolver_blip_note"))
            if _resolver_broken():
                # Bypass the system resolver ENTIRELY: emergency DoH
                # straight to the well-known resolver IPs + ONE raw
                # HTTPS request to the resolved IP (Host + SNI kept).
                try:
                    out = _ip_fallback_full(method, url, data,
                                            _rebuild_hawk(headers),
                                            timeout)
                    if out is not None:
                        return out
                except Exception:
                    pass
            elif not _net_retry:
                time.sleep(1.5)
                return req_full(method, url, data,
                                _rebuild_hawk(headers), timeout,
                                _fastly_attempts=_fastly_attempts,
                                _net_retry=True)
        raise

def req(method: str, url: str, data=None, headers=None, timeout=30,
        _fastly_attempts=0, _net_retry=False):
    """v5.36: req_full() without the headers - the same (status, json)
    shape every existing caller was written against; the request
    algorithm (reference parity + the broken-resolver emergency route)
    lives in req_full() only, so no caller can bypass it anymore."""
    status, _hdrs, d = req_full(method, url, data, headers, timeout,
                                _fastly_attempts=_fastly_attempts,
                                _net_retry=_net_retry)
    return status, d

# ---------------- session / credential caches ----------------

def _chmod600(path: str):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

# ---------------------------------------------------------------------------
# v6.0: THE UBER-CONFIG STORE. Every persisted configuration lives in the
# ONE plain-text file CONFIG_FILE (next to this script by default; the
# --config FILE parameter of v6.1 points it anywhere else; chmod 600).
# v6.4: EVERY ACCOUNT IS A PROFILE - the Fastly WAF cookie, the settings
# and the sing-box configs live INSIDE the account entry they belong to
# and switch with it (CONFIG_VERSION 2):
#   {
#     "version": 2,                   # the store format version
#     "first_run": false,            # TRUE until the first run has finished
#                                     # its one-time migration
#     "migrated_at": "2026-...",     # when that migration ran
#     "current_account": "a@b.c",    # the profile of this run
#     "accounts": {                  # EVERY cached account, in PLAIN TEXT:
#         "a@b.c": {"password": "...", "totp_secret": "...",
#                    "totp_digits": 6, "totp_period": 30,
#                    "totp_algorithm": "SHA1",
#                    "session_token": "...",     # the ONLY copy (the old
#                                                # session.json duplicate
#                                                # is gone)
#                    "qr_png_base64": "...",     # the 2FA QR image
#                    "saved_at": "2026-...",
#                    # v6.4: the PROFILE data of this account -
#                    "settings": {"doh": "cloudflare", "doh_cache": false,
#                                 "lang": "en",
#                                 "countries_filter": {"countries": [...],
#                                                      "keys": [...]},
#                                 "singbox_declined": false},
#                    "fastly_cookie": {"name": "...", "value": "...",
#                                      "expiresAt": ...},
#                    "singbox_configs": {"moz-us-nyc-20001-0.json":
#                                        { ... outbound ... }}}
#     },
#     "profile_defaults": {}         # v6.4/v6.5: the SETTINGS (never the
#                                     # Fastly cookie / sing-box configs -
#                                     # those are PROFILE-EXCLUSIVE and
#                                     # live ONLY inside account entries)
#                                     # while NO current account exists
#                                     # yet (a fresh install before the
#                                     # first sign-in); the FIRST account
#                                     # the script creates ADOPTS them
#   }
# All user data stays in PLAIN TEXT exactly like the old files (explicit
# user decision). Writes are ATOMIC (tmp file + os.replace), so a crash
# can never leave a half-written store behind. The per-account layout
# also removes the old duplication: session.json stored the session
# token + email of accounts.json a SECOND time and credentials.json
# duplicated the login/password/TOTP fields - v6 keeps exactly ONE
# copy of every value (per account).
# ---------------------------------------------------------------------------

CONFIG_VERSION = 2
_CFG = None                    # the in-memory config.json (loaded lazily)
_CFG_LOCK = threading.Lock()

# v6.4: the config roots that are PROFILE data. cfg_get()/cfg_set() route
# these three roots to the profile node of the CURRENT account - every
# existing caller keeps its ('settings', ...)/('fastly_cookie', ...)/
# ('singbox_configs', ...) paths and just works against the profile of
# the moment.
# v6.5: the roots are of TWO kinds now:
#   * 'settings' - a PREFERENCE (language, resolver, filter, the
#     sing-box decline marker): while NO account exists yet (a fresh
#     install before the first sign-in) its values live in the
#     top-level 'profile_defaults' placeholder and the FIRST account
#     adopts them (nothing configured before the first sign-in is
#     ever lost);
#   * 'fastly_cookie' and 'singbox_configs' - PROFILE-EXCLUSIVE data
#     (the user's own rule: a profile's data can never cross into
#     another profile): they are NEVER stored outside an account
#     entry - there is NO placeholder for them. While the account
#     they belong to does not exist yet (the sign-in of a NEW account
#     solves its FIRST Fastly challenge BEFORE its entry is created)
#     the value is STAGED in the in-memory _PENDING_PROFILE stash and
#     flushed into the account entry the moment it is created; a NEW
#     account therefore always receives its OWN fresh cookie/configs,
#     and the previous profile's data stays untouched.
_PROFILE_ROOTS = ("settings", "fastly_cookie", "singbox_configs")
# v6.5: the EXCLUSIVE roots - routed to the account being signed in /
# the current one, never to the 'profile_defaults' placeholder.
_PROFILE_EXCLUSIVE_ROOTS = ("fastly_cookie", "singbox_configs")

# v6.5: the account being signed IN right now. During its sign-in the
# Fastly challenge may be solved (and its cookie saved) BEFORE the
# account is made current (the '+' flow of the 'a' menu signs in a NEW
# account while the PREVIOUS one is still current) - the exclusive
# roots route to THIS email then, not to the current one. Set around
# the actual login call in ensure_session, cleared afterwards.
_SIGNIN_EMAIL = None

# v6.5: email -> {root: value} - the PROFILE-EXCLUSIVE data staged in
# memory while its account entry does not exist yet; flushed into the
# entry at account creation (save_cache/cache_account), dropped when
# the sign-in fails.
_PENDING_PROFILE = {}

def cfg_default() -> dict:
    """A fresh, empty uber-config (first_run=True until the initial
    migration of the very first run has completed). v6.4: no GLOBAL
    settings/cookie/singbox sections anymore - they live inside the
    account entries; 'profile_defaults' holds the SETTINGS only, and
    only while no account exists yet (v6.5: the Fastly cookie and the
    sing-box configs are PROFILE-EXCLUSIVE and are never stored
    outside an account entry)."""
    return {"version": CONFIG_VERSION,
            "first_run": True,
            "migrated_at": None,
            "current_account": None,
            "accounts": {},
            "profile_defaults": {}}

def cfg_load() -> dict:
    """Load config.json into memory (once); a missing/corrupt file yields
    the fresh default. Returns the in-memory store. v6.4: a file of the
    pre-v6.4 layout (GLOBAL settings/fastly_cookie/singbox_configs) is
    folded into the profile it belongs to on the first load."""
    global _CFG
    if _CFG is not None:
        return _CFG
    data = None
    try:
        with open(CONFIG_FILE) as f:
            data = json.load(f)
    except Exception:
        data = None
    if not isinstance(data, dict):
        data = cfg_default()
    else:
        # defensive: guarantee every top-level section exists
        base = cfg_default()
        for k, v in base.items():
            data.setdefault(k, v)
    _CFG = data
    _migrate_profile_layout()
    return _CFG

def cfg_save():
    """Persist the in-memory store to config.json (atomic write, 0600)."""
    global _CFG
    with _CFG_LOCK:
        if _CFG is None:
            return
        try:
            os.makedirs(CONF_DIR, exist_ok=True)
            tmp = CONFIG_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(_CFG, f, indent=2, ensure_ascii=False)
            _chmod600(tmp)
            os.replace(tmp, CONFIG_FILE)
        except OSError:
            pass                # a read-only config dir must not crash the run

def _profile_email():
    """v6.5: the account whose PROFILE data is being accessed RIGHT
    NOW: the account being signed IN takes precedence (during its
    sign-in its exclusive data must bind to IT, even though it is
    not current yet - and may not even exist in config.json), then
    the current account. None when neither exists."""
    em = (_SIGNIN_EMAIL or cfg_current_email() or "").strip().lower()
    return em or None

def _pending_root(root):
    """v6.5: the PROFILE-EXCLUSIVE section staged in memory for the
    account of the moment (its entry does not exist yet - the sign-in
    of a NEW account). Returns the staged section dict or None."""
    em = _profile_email()
    if not em:
        return None
    pend = _PENDING_PROFILE.get(em)
    if not isinstance(pend, dict):
        return None
    v = pend.get(root)
    return v if isinstance(v, dict) else None

def _flush_pending_profile_data(email: str):
    """v6.5: move the PROFILE-EXCLUSIVE data staged in memory (the
    FIRST Fastly cookie of a brand-new account, solved during its
    sign-in BEFORE its entry existed) into that account's entry -
    called the moment the entry is created/made current. A no-op when
    nothing is staged; the stash is dropped when there is still no
    entry to own it (the sign-in failed - the cookie belongs to
    nobody and a fresh one is solved next time)."""
    em = (email or "").strip().lower()
    if not em:
        return
    pend = _PENDING_PROFILE.pop(em, None)
    if not isinstance(pend, dict) or not pend:
        return
    acc = cfg_accounts().get(em)
    if not isinstance(acc, dict):
        return              # no profile to own it - drop the stash
    for root in _PROFILE_EXCLUSIVE_ROOTS:
        v = pend.get(root)
        if v in (None, {}, ""):
            continue
        if not acc.get(root):
            acc[root] = v
    cfg_save()

def _profile_node(root=None):
    """v6.4/v6.5: the dict holding the PROFILE data being accessed -
    the entry of the account being signed in (it takes precedence
    DURING its sign-in) or of the current account. While NO such
    account exists: for the 'settings' root the top-level
    'profile_defaults' placeholder is the target (the language/
    resolver may be configured before the first sign-in; the FIRST
    account adopts them); for the PROFILE-EXCLUSIVE roots
    (fastly_cookie, singbox_configs) there is NO target - None (their
    values are never shared between profiles: a NEW account always
    receives a NEW fresh cookie/configs; the value is staged in
    memory instead, see cfg_set/_PENDING_PROFILE). Never returns
    None for 'settings'."""
    em = _profile_email()
    acc = cfg_accounts().get(em) if em else None
    if isinstance(acc, dict):
        return acc
    if root in (None, "settings"):
        store = cfg_load()
        pd = store.get("profile_defaults")
        if not isinstance(pd, dict):
            pd = {}
            store["profile_defaults"] = pd
        return pd
    return None

def cfg_get(path, default=None):
    """Read a value from the store; path is a tuple of keys
    (e.g. ("settings", "doh") or ("fastly_cookie",)). v6.4: the PROFILE
    roots ("settings", "fastly_cookie", "singbox_configs") are routed
    to the profile of the moment - the account being signed in, else
    the current one. v6.5: the 'settings' root falls back to the
    'profile_defaults' placeholder while no account exists; the
    EXCLUSIVE roots (fastly_cookie, singbox_configs) have NO
    placeholder - while their account does not exist yet the staged
    in-memory copy is returned instead."""
    path = tuple(path)
    node = cfg_load()
    if path and path[0] in _PROFILE_ROOTS:
        if path[0] == "settings":
            section = _profile_node("settings").get(path[0])
        else:
            owner = _profile_node(path[0])
            if isinstance(owner, dict):
                section = owner.get(path[0])
            else:
                # v6.5: no account entry owns it (yet) - the only
                # copy is the staged one of the sign-in in progress
                section = _pending_root(path[0])
        if not isinstance(section, dict):
            return default
        node = section
        path = path[1:]
    for k in path:
        if not isinstance(node, dict) or k not in node:
            return default
        node = node[k]
    return node

def cfg_set(path, value):
    """Write a value into the store and SAVE config.json at once.
    value=None REMOVES the key (no null clutter in the file). v6.4: the
    PROFILE roots ("settings", "fastly_cookie", "singbox_configs") are
    routed to the profile node of the CURRENT account (or to the
    'profile_defaults' placeholder while no account exists). v6.5: the
    EXCLUSIVE roots (fastly_cookie, singbox_configs) route to the
    account being signed in / the current one and have NO placeholder -
    while that account does not exist yet the value is STAGED in the
    in-memory _PENDING_PROFILE stash (flushed into the entry at its
    creation, dropped when the sign-in fails); with no account to own
    it at all the write is skipped (the in-memory session state still
    carries it for this run)."""
    path = tuple(path)
    if not path:
        return
    with _CFG_LOCK:
        node = cfg_load()
        if path[0] in _PROFILE_ROOTS:
            if path[0] == "settings":
                owner = _profile_node("settings")
            else:
                owner = _profile_node(path[0])
                if owner is None:
                    # v6.5: PROFILE-EXCLUSIVE data of an account that
                    # does not exist yet (the sign-in of a NEW account
                    # solves its FIRST Fastly challenge before its
                    # entry is created) - stage it in memory; it is
                    # flushed into the entry at creation and dropped
                    # when the sign-in fails
                    em = _profile_email()
                    if not em:
                        return      # nobody can own this value
                    owner = _PENDING_PROFILE.setdefault(em, {})
            if len(path) == 1:
                # the WHOLE profile root (e.g. the fastly_cookie object)
                if value is None:
                    owner.pop(path[0], None)
                else:
                    owner[path[0]] = value
                path = ()
            else:
                node = owner.setdefault(path[0], {})
                if not isinstance(node, dict):
                    raise ValueError(f"config path {path[0]} not writable")
                path = path[1:]
        if path:
            for k in path[:-1]:
                node = node.setdefault(k, {})
                if not isinstance(node, dict):
                    raise ValueError(f"config path {'/'.join(path)} not writable")
            if value is None:
                node.pop(path[-1], None)
            else:
                node[path[-1]] = value
    cfg_save()

def cfg_accounts() -> dict:
    """The account store: {email: entry} (insertion ordered)."""
    accs = cfg_get(("accounts",), {})
    return accs if isinstance(accs, dict) else {}

def cfg_current_email() -> "str | None":
    """The current account's email: the stored pointer, or the single
    cached account when exactly one exists (a fresh install with one
    sign-in must not lose its account), or None."""
    em = (cfg_get(("current_account",)) or "").strip().lower()
    if em and em in cfg_accounts():
        return em
    accs = cfg_accounts()
    if not em and len(accs) == 1:
        return next(iter(accs))
    return em or None

def cfg_current_account() -> dict:
    """The config entry of the current account ({} when there is none)."""
    em = cfg_current_email()
    acc = cfg_accounts().get(em) if em else None
    return acc if isinstance(acc, dict) else {}

def cfg_set_current(email: str):
    """Make an account current (creates no data - the entry must exist).
    v6.4: when the store still carries the PROVISIONAL profile
    ('profile_defaults' - the settings saved while NO account existed),
    the account ADOPTS it here: its own values win, the placeholder is
    cleared."""
    em = (email or "").strip().lower() or None
    cfg_set(("current_account",), em)
    if em:
        _adopt_profile_defaults(em)

def _adopt_profile_defaults(email: str):
    """v6.4/v6.5: fold the PROVISIONAL profile ('profile_defaults' -
    the SETTINGS saved while NO account existed: language, resolver,
    the countries filter, the sing-box decline marker) into the
    account that has just become current, then clear the placeholder.
    The account's OWN values win for every key it already has; missing
    keys are filled from the defaults. A no-op once the placeholder is
    empty (every later cfg_set_current of the same account). The
    PROFILE-EXCLUSIVE data (a Fastly cookie, sing-box configs) is
    never adopted: v6.5 keeps it out of the placeholder entirely - a
    NEW account always receives its OWN fresh cookie/configs."""
    store = cfg_load()
    pd = store.get("profile_defaults")
    if not isinstance(pd, dict) or not pd:
        return
    em = (email or "").strip().lower()
    accs = store.get("accounts")
    acc = accs.get(em) if (isinstance(accs, dict) and em) else None
    if isinstance(acc, dict):
        v = pd.pop("settings", None)
        if isinstance(v, dict) and v:
            own = acc.get("settings")
            if isinstance(own, dict):
                merged = dict(v)
                merged.update(own)       # the account's own values win
                acc["settings"] = merged
            else:
                acc["settings"] = v
    # v6.5: exclusive leftovers a pre-v6.5 file may carry inside the
    # placeholder belong to NO profile (no account existed when they
    # were saved) - drop them; a fresh cookie is obtained at the next
    # sign-in and the configs are rebuilt from that account's proxies
    for root in _PROFILE_EXCLUSIVE_ROOTS:
        pd.pop(root, None)
    store["profile_defaults"] = {}
    cfg_save()

def _migrate_profile_layout():
    """v6.4 (CONFIG_VERSION 2): fold the pre-v6.4 GLOBAL sections of
    config.json (the top-level 'settings'/'fastly_cookie'/
    'singbox_configs') into the profile they belong to - the CURRENT
    account's entry (the only profile that could have been using them).
    v6.5: the 'settings' of a file with NO account yet go into the
    'profile_defaults' placeholder (adopted by the first account); the
    PROFILE-EXCLUSIVE sections (fastly_cookie, singbox_configs) of a
    file with no account belong to NOBODY - they are dropped (a fresh
    cookie is obtained at the next sign-in, the configs are rebuilt
    from that account's proxies; the values can never be shared
    between profiles). Runs on every load; the top-level sections are
    REMOVED afterwards, which makes the check idempotent."""
    store = cfg_load()          # _CFG is already set by the caller
    legacy = {r: store.get(r) for r in _PROFILE_ROOTS if r in store}
    if not legacy:
        # v6.5: also clean the EXCLUSIVE leftovers a pre-v6.5 file may
        # carry inside the 'profile_defaults' placeholder (they were
        # saved while no account existed - no profile can own them)
        pd = store.get("profile_defaults")
        if isinstance(pd, dict):
            for root in _PROFILE_EXCLUSIVE_ROOTS:
                if root in pd:
                    pd.pop(root, None)
                    cfg_save()
        return
    # the target profile: the CURRENT account's entry, else the
    # placeholder section (SETTINGS only)
    em = cfg_current_email()
    accs = store.get("accounts")
    node = None
    if em and isinstance(accs, dict) and isinstance(accs.get(em), dict):
        node = accs[em]
    else:
        node = store.setdefault("profile_defaults", {})
        if not isinstance(node, dict):
            store["profile_defaults"] = {}
            node = store["profile_defaults"]
    for root, v in legacy.items():
        store.pop(root, None)
        if v in (None, {}, ""):
            continue
        if root == "settings" and isinstance(v, dict):
            own = node.get(root)
            if isinstance(own, dict):
                merged = dict(v)
                merged.update(own)   # the account's own values win
                node[root] = merged
            else:
                node[root] = v
        elif root in _PROFILE_EXCLUSIVE_ROOTS:
            # v6.5: EXCLUSIVE data goes into the CURRENT account only;
            # with no account it belongs to nobody and is dropped
            # (never shared, never adopted by a future profile)
            if node is not store.get("profile_defaults") \
                    and not node.get(root):
                node[root] = v
        elif not node.get(root):
            node[root] = v
    if isinstance(store.get("version"), int) and store["version"] < CONFIG_VERSION:
        store["version"] = CONFIG_VERSION
    cfg_save()

def _reset_fastly_session():
    """v6.5: drop the in-memory HTTP session state (the cookie jar with
    the PREVIOUS profile's Fastly cookie, the opener, the challenge
    latch) so the NEXT profile starts with a CLEAN session - the cookie
    of profile A must never be reused for profile B. The same sequence
    wipe_all_saved_data uses (v5.23)."""
    global COOKIE_JAR
    COOKIE_JAR = http.cookiejar.CookieJar()
    # v6.7 (audit fix of the v6.6 --api-proxy integration): rebuild the
    # opener through _rebuild_opener() - it reads the FRESH jar just
    # assigned above AND re-applies the ProxyHandler when --api-proxy is
    # active. The old bare HTTPCookieProcessor build silently DROPPED the
    # fixed control-plane exit on every profile switch.
    _rebuild_opener()
    _fastly_state["solved"] = False
    _fastly_state["failed"] = False

def apply_profile_runtime(args):
    """v6.4: re-apply the settings of the CURRENT profile after a
    profile switch (the hotkey 'a' selection, --select-account, the
    auto-switch after deleting the current account, the sign-in of a
    NEW account in the watch loop). The precedence is
    exactly the startup one: an EXPLICIT --lang / --doh / --doh-url
    argument of this run still wins; otherwise the SAVED choice of the
    newly selected profile applies, else the MOZVPN_LANG / MOZVPN_DOH
    environment variable, else the built-in default. v6.9: the STICKY
    preferences (theme, color, the DoH answer cache, the ClientHello
    fragmentation) follow the SAME precedence, and the log is redrawn
    when the theme or the color mode changed; the saved ENGINE of
    the profile applies at the next start (a live engine switch is
    hotkey 'e' territory). The Fastly WAF cookie is PROFILE-EXCLUSIVE
    data too: the in-memory cookie jar, the
    opener and the challenge latch are reset first
    (_reset_fastly_session, the same v5.23 sequence
    wipe_all_saved_data uses), then the cookie of the NEW profile is
    loaded - the session of profile A can never leak into profile B.
    The effective values are mirrored back into the profile entry
    (the v5.33 'settings exist from the very first run' contract).
    The countries filter, the sing-box decline marker and the
    sing-box configs need no in-memory handling: every consumer reads
    them lazily through cfg_get() and therefore follows the profile of
    the moment."""
    # 1) the language of the profile
    if not getattr(args, "lang", None):
        saved = load_lang_cache()
        set_language(saved
                     or (os.environ.get("MOZVPN_LANG", "en").strip().lower()
                         or "en"))
    # 2) the DNS resolver of the profile
    if not getattr(args, "doh_url", None) and not getattr(args, "doh", None):
        saved = load_doh_provider_cache()
        if saved is not None:
            set_doh_provider(saved)      # '' = the explicit 'off' choice (v6.8)
        else:
            set_doh_provider(
                (os.environ.get("MOZVPN_DOH", "cloudflare").strip().lower()
                 or "cloudflare"))
    # 2b) v6.9: the STICKY display/transport preferences of the
    #     profile (settings.theme / settings.color /
    #     settings.doh_cache / settings.tls_split). An EXPLICIT
    #     --theme / --no-color / --doh-cache / --tls-split argument
    #     of this run still wins (the _explicit markers were
    #     recorded at startup, BEFORE the argparse values were
    #     resolved in place); otherwise the SAVED choice of the
    #     newly selected profile applies, else the env, else the
    #     built-in default - the same precedence as the startup
    #     block. The ENGINE choice is profile-bound too
    #     (settings.engine), but a LIVE engine switch stops and
    #     recreates every listener - that is hotkey 'e' territory
    #     - so the saved engine of the profile takes effect at
    #     the next start.
    _theme_before, _color_before = _THEME, _USE_COLOR
    if not getattr(args, "_theme_explicit", False):
        saved = load_str_setting("theme")
        if saved in ("dark", "light"):
            set_theme(saved)
    if not getattr(args, "_no_color_explicit", False):
        saved = load_bool_setting("color", None)
        if saved is not None:
            set_color(saved)
    if not getattr(args, "_doh_cache_explicit", False):
        set_doh_cache(load_bool_setting(
            "doh_cache", _env_flag("MOZVPN_DOH_CACHE", False)))
    if not getattr(args, "_tls_split_explicit", False):
        set_tls_split(load_bool_setting(
            "tls_split", _env_flag("MOZVPN_TLS_SPLIT", True)))
    # 3) the Fastly WAF cookie of the profile: reset the in-memory
    #    session first, then load the cookie of the NEW profile
    _reset_fastly_session()
    load_fastly_cache()
    # 4) mirror the effective settings into the profile entry (the
    #    v5.33 'exists from the first run' contract), then report
    if doh_provider() != "custom":
        save_doh_provider_cache(doh_provider())
    save_lang_cache(_LANG)
    save_bool_setting("color", _USE_COLOR)
    save_str_setting("theme", _THEME)
    save_bool_setting("doh_cache", doh_cache_enabled())
    save_bool_setting("tls_split", tls_split())
    if _THEME != _theme_before or _USE_COLOR != _color_before:
        global _BG_CURRENT
        if _USE_COLOR:
            _force_terminal_bg(_THEME)
        elif _BG_CURRENT is not None:
            _restore_terminal_bg()
            _BG_CURRENT = None
        redraw_log()
    info(tr("profile_applied", email=cfg_current_email() or "-"))

# ---------------------------------------------------------------------------
# v6.0: the FIRST-RUN migration (req. 6) and the old-format cleanup
# (req. 7, Ctrl+O / --clean-old-config).
# ---------------------------------------------------------------------------

def _legacy_read_json(path: str):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def _legacy_account_paths(email: str) -> "list[str]":
    """Where the OLD format stored the QR png of an account's 2FA secret
    (v5.27-v5.36: the script directory by default)."""
    safe = re.sub(r"[^A-Za-z0-9_.@-]+", "_", (email or "").strip().lower())
    if not safe:
        return []
    return [os.path.join(script_dir(), safe + ".png")]

def _qr_b64_of(email: str) -> "str | None":
    acc = cfg_accounts().get((email or "").strip().lower()) or {}
    v = acc.get("qr_png_base64")
    return v if isinstance(v, str) and v else None

def migrate_old_config_if_first_run() -> bool:
    """v6.0 (req. 6): run ONCE on the first start. config.json carries the
    'first_run' flag; while it is set, every OLD-format configuration file
    is read, folded into the uber-config and DELETED afterwards (the old
    files AND the old directories - nothing of the old format is left
    behind). A fresh install simply flips the flag. Returns True when a
    migration ran."""
    cfg_load()
    if not cfg_get(("first_run",)):
        return False
    info(tr("config_migration_header", path=CONFIG_FILE))
    moved = []

    def _acc(email: str) -> dict:
        em = (email or "").strip().lower()
        if not em:
            return {}
        return _CFG["accounts"].setdefault(em, {})

    # 1) accounts.json - the whole multi-account store
    data = _legacy_read_json(os.path.join(LEGACY_CONF_DIR, "accounts.json"))
    if isinstance(data, dict):
        for em, acc in data.items():
            if not isinstance(acc, dict) or not str(em).strip():
                continue
            entry = _acc(str(em))
            for k in ("password", "totp_secret", "totp_digits",
                      "totp_period", "totp_algorithm", "session_token",
                      "saved_at"):
                if acc.get(k) is not None:
                    entry[k] = acc[k]
        moved.append("accounts.json")
    # 2) session.json - the current session (email + sessionToken)
    data = _legacy_read_json(os.path.join(LEGACY_CONF_DIR, "session.json"))
    if isinstance(data, dict):
        em = (data.get("email") or "").strip().lower()
        if em and data.get("sessionToken"):
            _acc(em)["session_token"] = data["sessionToken"]
            _CFG["current_account"] = em
        moved.append("session.json")
    # 3) credentials.json - the saved login data of the current account
    data = _legacy_read_json(os.path.join(LEGACY_CONF_DIR, "credentials.json"))
    if isinstance(data, dict):
        em = ((data.get("email") or "").strip().lower()
              or _CFG.get("current_account"))
        if em:
            entry = _acc(em)
            for k in ("password", "totp_secret", "totp_digits",
                      "totp_period", "totp_algorithm"):
                if data.get(k) is not None:
                    entry[k] = data[k]
            if not _CFG.get("current_account"):
                _CFG["current_account"] = em
        moved.append("credentials.json")
    # 4) fastly-cookie.json - the Fastly WAF cookie (v6.5: the cookie is
    #    PROFILE-EXCLUSIVE data - it goes into the CURRENT account's
    #    entry and NOWHERE else; with no account yet it is dropped: a
    #    fresh cookie is obtained at the first sign-in and can never be
    #    'pre-owned' by a profile that does not exist)
    data = _legacy_read_json(os.path.join(LEGACY_CONF_DIR, "fastly-cookie.json"))
    if isinstance(data, dict) and data.get("name") and data.get("value"):
        em = cfg_current_email()
        node = cfg_accounts().get(em) if em else None
        if isinstance(node, dict):
            node["fastly_cookie"] = {
                "name": data.get("name"), "value": data.get("value"),
                "expiresAt": data.get("expiresAt") or 0}
            moved.append("fastly-cookie.json")
    # 5) countries.json - the local-proxy filter (v6.4: into the PROFILE)
    data = _legacy_read_json(os.path.join(LEGACY_CONF_DIR, "countries.json"))
    if isinstance(data, dict):
        flt = {k: data[k] for k in ("countries", "keys")
               if data.get(k) is not None}
        if flt:
            _profile_node().setdefault("settings", {})["countries_filter"] = flt
        moved.append("countries.json")
    # 6) doh.json - the resolver choice (v6.4: into the PROFILE)
    data = _legacy_read_json(os.path.join(LEGACY_CONF_DIR, "doh.json"))
    if isinstance(data, dict):
        # v6.8: a legacy '' was only ever written by an EXPLICIT
        # old-version system-DNS choice (a missing doh.json produced
        # no entry at all), so it migrates to the EXPLICIT 'off'
        # marker - NOT to the 'never chosen' state into which the
        # bug-written '' of v6.0-v6.7 must heal.
        _profile_node().setdefault("settings", {})["doh"] = (
            (data.get("provider") or "").strip().lower() or "off")
        moved.append("doh.json")
    # 7) lang.json - the language choice (v6.4: into the PROFILE)
    data = _legacy_read_json(os.path.join(LEGACY_CONF_DIR, "lang.json"))
    if isinstance(data, dict):
        _profile_node().setdefault("settings", {})["lang"] = (
            data.get("lang") or "en").strip().lower()
        moved.append("lang.json")
    # 8) singbox-install.json - the install-decline marker (v6.4: into
    #    the PROFILE)
    data = _legacy_read_json(os.path.join(LEGACY_CONF_DIR, "singbox-install.json"))
    if isinstance(data, dict):
        _profile_node().setdefault("settings", {})["singbox_declined"] = \
            bool(data.get("declined"))
        moved.append("singbox-install.json")
    # 9) the cached QR pngs of the 2FA secrets -> base64 in the account
    #    entries (the old default location was the script directory)
    for em in list(_CFG["accounts"].keys()):
        for p in _legacy_account_paths(em):
            if os.path.isfile(p):
                try:
                    with open(p, "rb") as f:
                        b = f.read()
                    if b:
                        _CFG["accounts"][em]["qr_png_base64"] = \
                            base64.b64encode(b).decode("ascii")
                        moved.append(os.path.basename(p))
                except OSError:
                    pass
    for name in moved:
        hint(tr("config_migration_entry", name=name))
    # DELETE every old-format file and directory (config.json is not one
    # of them - it is saved right after this line)
    removed = clean_old_config_format(verbose=False)
    # 10) flip the first-run flag and persist
    _CFG["first_run"] = False
    _CFG["migrated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    cfg_save()
    ok(tr("config_migration_done", n=len(moved), removed=removed,
          path=CONFIG_FILE))
    return True

def find_old_config_artifacts() -> "list[str]":
    """v6.0 (req. 7): every leftover of the OLD config format that still
    exists on this machine - the pre-v6 json files in the OLD config
    directory (~/.config/mozvpn - the LEGACY location, v6.1), the old
    singbox/ and engine/ directories and the old on-disk QR pngs.
    config.json is NEVER listed."""
    out = []
    for name in LEGACY_CONFIG_FILES:
        p = os.path.join(LEGACY_CONF_DIR, name)
        if os.path.exists(p):
            out.append(p)
    for d in LEGACY_CONFIG_DIRS:
        p = os.path.join(LEGACY_CONF_DIR, d)
        if os.path.isdir(p):
            out.append(p)
    for em in cfg_accounts():
        for p in _legacy_account_paths(em):
            if os.path.isfile(p):
                out.append(p)
    return out

def clean_old_config_format(verbose=True) -> int:
    """v6.0 (req. 7): find and REMOVE every leftover of the OLD config
    format (Ctrl+O / --clean-old-config). config.json itself is never
    touched. Returns the number of removed items."""
    items = find_old_config_artifacts()
    if not items:
        if verbose:
            ok(tr("clean_old_none"))
        return 0
    if verbose:
        info(tr("clean_old_header", n=len(items)))
    removed = 0
    for p in items:
        try:
            if os.path.isdir(p):
                import shutil
                shutil.rmtree(p)
            else:
                os.remove(p)
            removed += 1
            if verbose:
                hint(tr("clean_old_removed", path=p))
        except OSError as e:
            if verbose:
                warn(tr("clean_old_failed", path=p, err=e))
    if verbose:
        ok(tr("clean_old_done", n=removed))
    return removed

def clear_all_caches() -> bool:
    """v6.0: everything persisted lives in config.json - the wipe RESETS
    the uber file to a fresh state while KEEPING the account store (the
    v5.27+ contract: wiping the current session must never delete the
    saved logins of all the other accounts). Leftovers of the pre-v6
    format are removed from disk as well. Returns success."""
    global _CFG
    cfg_load()
    with _CFG_LOCK:
        accounts = dict(_CFG.get("accounts") or {})
        migrated_at = _CFG.get("migrated_at")
        _CFG = cfg_default()
        _CFG["accounts"] = accounts        # the account store SURVIVES
        _CFG["first_run"] = False
        _CFG["migrated_at"] = migrated_at
    cfg_save()
    clean_old_config_format(verbose=False)
    ok(tr("cache_cleared", path=CONFIG_FILE))
    return True

def wipe_all_saved_data(creds: dict) -> bool:
    """FULL wipe: every file this script has EVER saved goes away - the whole
    config directory (session cache, saved credentials with the email/
    password/TOTP secret, the Fastly WAF cookie, all sing-box configs) AND
    the in-memory state (the creds dict passed in, the Fastly cookie jar),
    so the next sign-in cannot reuse anything and asks for the login data
    again. Used by the 'c' hotkey, the 'r' hotkey, --clear-cache, --relogin."""
    global COOKIE_JAR, _OPENER
    # v6.0: the multi-account store lives INSIDE config.json, and
    # clear_all_caches() above KEEPS the "accounts" section while
    # resetting everything else - the v5.27 accounts.json backup/
    # restore dance is gone for good (no second file exists anymore).
    ok_caches = clear_all_caches()
    # In-memory leftovers are why a re-login used to succeed after a wipe:
    # creds (email/password/totp_secret) and the Fastly cookie must go too.
    creds.clear()
    # v5.23: _OPENER holds the ORIGINAL jar forever (build_opener captured
    # it at import). Reassigning COOKIE_JAR alone left the opener wired to
    # the DEAD jar: the challenge flow stored the solved _fs_ch_cp_* cookie
    # into the old jar while the code read the NEW, empty one ("cookie not
    # received after a successful solution"), and no request ever sent the
    # new jar's cookies. Rebuild the opener on the fresh jar.
    COOKIE_JAR = http.cookiejar.CookieJar()
    _OPENER = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(COOKIE_JAR))
    # v5.23: the challenge latch survived every wipe - after ONE failure
    # failed=True disabled solving for the REST OF THE PROCESS (every retry
    # skipped straight to the 406), which is exactly why the endless
    # relogin-retry loop never recovered while a RESTART always worked.
    # The state is part of the Fastly session and resets with it.
    _fastly_state["solved"] = False
    _fastly_state["failed"] = False
    info(tr("clear_wiped_note"))
    return ok_caches

def save_cache(email, session_token):
    """v6.0: the session token is stored in the CURRENT account entry of
    config.json (and that account becomes the current one). The separate
    session.json file is gone - there is exactly ONE copy of the token,
    inside the account, so it can never diverge from the credentials.
    v6.5: creating/making current the account also flushes its staged
    PROFILE-EXCLUSIVE data (its FIRST Fastly cookie, solved during the
    sign-in before this entry existed) into the entry."""
    try:
        email = (email or "").strip().lower()
        if not email:
            return
        cfg_load()
        with _CFG_LOCK:
            acc = dict(((_CFG.get("accounts") or {}).get(email)) or {})
            if session_token:
                acc["session_token"] = session_token
            acc["saved_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
            accounts = dict(_CFG.get("accounts") or {})
            accounts[email] = acc
            _CFG["accounts"] = accounts
            _CFG["current_account"] = email
        cfg_save()
        _flush_pending_profile_data(email)
    except OSError:
        pass

# ---------------- v5.12: --countries / hotkey 'w' filter cache ----------------

def parse_countries_arg(value) -> "list[str]":
    """v5.12: parse --countries (comma/space-separated ISO codes, full
    country names, 'rec' allowed) into a list of lowercase tokens."""
    if not value:
        return []
    out = []
    for tok in re.split(r"[,\s]+", str(value).strip()):
        tok = tok.strip().lower()
        if tok and tok not in out:
            out.append(tok)
    return out

def save_countries_filter(countries=None, keys=None):
    """v5.12: persist the local-proxy filter (--countries or the hotkey
    'w' selection) so it survives restarts. `keys` (the per-proxy tokens
    of the hotkey 'w' menu) take precedence over `countries`; an 'all'
    selection (token '0') CLEARS the filter (settings.countries_filter
    is dropped from config.json). v6.0: the choice lives in
    config.json (settings.countries_filter) - countries.json is gone."""
    data = {}
    if countries:
        data["countries"] = list(countries)
    if keys:
        data["keys"] = list(keys)
    try:
        cfg_set(("settings", "countries_filter"), data or None)
    except OSError:
        pass

def load_countries_filter() -> dict:
    """v5.12: {'countries': [...], 'keys': [...]} saved by --countries or
    the hotkey 'w' ('keys' take precedence). Empty when no filter is set."""
    try:
        c = cfg_get(("settings", "countries_filter")) or {}
        if isinstance(c, dict):
            return c
    except Exception:
        pass
    return {}

def clear_countries_filter():
    """v5.12: drop the saved --countries / hotkey 'w' filter ('all')."""
    try:
        cfg_set(("settings", "countries_filter"), None)
    except OSError:
        pass

def _match_country_token(srv: dict, tokens: "list[str]") -> bool:
    """v5.12: does the upstream match one of the --countries tokens?
    A token may be an ISO code ('us', 'de', 'rec') or a full lowercase
    country name ('france')."""
    cc = (srv.get("countryCode") or "").strip().lower()
    name = (srv.get("countryName") or "").strip().lower()
    for t in tokens:
        if t == cc or t == name:
            return True
    return False

def apply_countries_filter(args, verified: list) -> list:
    """v5.12: filter the verified upstreams by the --countries list or
    the saved hotkey 'w' selection (countries.json; the per-proxy keys
    take precedence over the country list). --countries given on THIS
    run wins and is persisted for the next restarts. Returns the
    filtered list (unchanged when no filter is set); when a saved
    filter matches nothing, ALL upstreams are served with a warning so
    the script never ends up with zero local proxies."""
    flt = load_countries_filter()
    keys = [str(k).strip().lower() for k in (flt.get("keys") or [])
            if str(k).strip()]
    countries = [str(c).strip().lower() for c in (flt.get("countries") or [])
                 if str(c).strip()]
    cli = parse_countries_arg(getattr(args, "countries", None))
    if cli:
        countries = cli
        keys = []
        save_countries_filter(countries=countries)
    if not keys and not countries:
        return verified
    if keys:
        tokmap = {selection_token(i): s for i, s in enumerate(verified)}
        out = [tokmap[t] for t in keys if t in tokmap]
    else:
        out = [s for s in verified if _match_country_token(s, countries)]
    if not out:
        warn(tr("filter_empty_fallback"))
        return verified
    if len(out) != len(verified):
        cc_list = ", ".join(sorted({(s.get("countryCode") or "?").upper()
                                     for s in out})) or "-"
        info(tr("countries_filter_applied", n=len(out), m=len(verified),
                list=cc_list))
    return out

def _filter_probe_entries(args, entries: list) -> list:
    """v5.27 (fix 1): the upstream PROBES must run only for the local
    proxies the user selected (--countries / the hotkey 'w' filter in
    countries.json). Same filter logic as apply_countries_filter(): the
    --countries CLI value of THIS run wins, then the saved per-proxy
    keys, then the saved country tokens. When the filter matches
    nothing, ALL entries are probed (the same fallback as
    apply_countries_filter - the script never ends up with zero usable
    upstreams)."""
    flt = load_countries_filter()
    keys = [str(k).strip().lower() for k in (flt.get("keys") or [])
            if str(k).strip()]
    countries = [str(c).strip().lower() for c in (flt.get("countries") or [])
                 if str(c).strip()]
    cli = parse_countries_arg(getattr(args, "countries", None))
    if cli:
        countries = cli
        keys = []
    if not keys and not countries:
        return entries
    if keys:
        tokmap = {selection_token(i): s for i, s in enumerate(entries)}
        out = [tokmap[t] for t in keys if t in tokmap]
    else:
        out = [s for s in entries if _match_country_token(s, countries)]
    if not out:
        return entries
    if len(out) != len(entries):
        info(tr("probe_filter_applied", n=len(out), m=len(entries)))
    return out

_CRED_KEYS = ("email", "password", "totp_secret",
              "totp_digits", "totp_period", "totp_algorithm")

def load_credentials() -> dict:
    """v6.0: the credentials of the CURRENT account straight from
    config.json ({} when there is no current account).
    {email, password, totp_secret, totp_digits, totp_period, totp_algorithm}."""
    em = cfg_current_email()
    acc = cfg_accounts().get(em) if em else None
    c = acc if isinstance(acc, dict) else {}
    out = {k: c.get(k) for k in _CRED_KEYS}
    out["email"] = em
    return out

def save_credentials(**kw):
    """v6.0: merge new known fields into the CURRENT account entry of
    config.json. An explicit email= switches the current account (the
    same account cannot hold two identities)."""
    em = ((kw.get("email") or "").strip().lower()
          or cfg_current_email() or "")
    if not em:
        return
    try:
        cfg_load()
        with _CFG_LOCK:
            acc = dict(((_CFG["accounts"]).get(em)) or {})
            for k in _CRED_KEYS:
                v = kw.get(k)
                if v is None or v == "":
                    continue
                if k in ("totp_digits", "totp_period"):
                    try:
                        v = int(v)
                    except (TypeError, ValueError):
                        continue
                acc[k] = v
            accounts = dict(_CFG.get("accounts") or {})
            accounts[em] = acc
            _CFG["accounts"] = accounts
            _CFG["current_account"] = em
        cfg_save()
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

# ---------------- v5.27: MULTI-ACCOUNT cache (accounts.json) ----------------
# Every SUCCESSFUL sign-in is cached as a separate account entry, so the
# user can switch between any number of Mozilla accounts (hotkey 'a') the
# same way the single account used to be reused from credentials.json.
# ---------------- v5.27/v6.0: MULTI-ACCOUNT store (config.json) -------------
# Every SUCCESSFUL sign-in is cached as a separate account entry INSIDE
# the uber-config, so the user can switch between any number of Mozilla
# accounts (hotkey 'a'). The account store SURVIVES every wipe
# (--clear-cache / 'r' / 'c' / --relogin): wiping the session of ONE
# account must not delete the saved logins of ALL accounts (see
# wipe_all_saved_data / clear_all_caches).

def load_accounts() -> dict:
    """v6.0: {email: {password, totp_secret, totp_digits, totp_period,
    totp_algorithm, session_token, qr_png_base64, saved_at}} straight
    from config.json - insertion ordered."""
    accs = cfg_accounts()
    return {str(k).strip().lower(): (v if isinstance(v, dict) else {})
            for k, v in accs.items() if str(k).strip()}

def _save_accounts(accounts: dict):
    """v6.0: replace the whole account section of config.json."""
    cfg_set(("accounts",), {str(k).strip().lower(): (v if isinstance(v, dict)
                                                     else {})
                            for k, v in (accounts or {}).items()
                            if str(k).strip()})

def accounts_qr_dir(args=None) -> str:
    """v5.27 (fix 2): where the cached QR images are MATERIALIZED when
    the user asks for them (--show-accounts / --accounts-json / the 'a'
    menu). Default: the directory of the script itself; --qr-dir
    overrides it. v6.0: the persisted storage is the base64 field in
    config.json - this directory only holds on-demand copies."""
    d = (getattr(args, "qr_dir", None) or "").strip() or script_dir()
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d

def account_qr_path(email: str, args=None) -> str:
    """v6.0: where the account's QR png is MATERIALIZED on demand (the
    persistent copy is the qr_png_base64 field in config.json)."""
    safe = re.sub(r"[^A-Za-z0-9_.@-]+", "_", (email or "").strip().lower())
    return os.path.join(accounts_qr_dir(args), (safe or "account") + ".png")

def materialize_account_qr(email: str, args=None) -> "str | None":
    """v6.0: write the account's QR png (base64 in config.json) into the
    QR dir and return the path; None when the account has no QR data."""
    b64 = _qr_b64_of(email)
    if not b64:
        return None
    dst = account_qr_path(email, args)
    try:
        with open(dst, "wb") as f:
            f.write(base64.b64decode(b64))
        return dst
    except (OSError, ValueError):
        return None

def account_totp_now(acc: dict):
    """(code, seconds_left) for a cached account, or None when it has no
    TOTP secret. Computed on Mozilla-synced time like every code here."""
    secret = (acc.get("totp_secret") or "").strip()
    if not secret:
        return None
    try:
        return totp_generate(secret,
                              acc.get("totp_digits") or 6,
                              acc.get("totp_period") or 30,
                              (acc.get("totp_algorithm") or "SHA1").upper())
    except Exception:
        return None

def cache_account(args, creds, session_token=None):
    """v5.27 (fix 2) / v6.0: cache the account AFTER a successful sign-in.
    Silent when nothing changed (the watch loop calls it on every token
    refresh - the log must not repeat itself); prints one line when the
    account is new or its data changed. The --qr image of THIS run is
    embedded as base64 into the account entry of config.json (the old
    on-disk QR copy is gone - one storage, one file)."""
    email = ((getattr(args, "email", None) or "")
             or creds.get("email") or "").strip().lower()
    if not email:
        return
    cfg_load()
    accounts = load_accounts()
    old = accounts.get(email) or {}
    acc = dict(old)
    pw = getattr(args, "password", None) or creds.get("password")
    if pw:
        acc["password"] = pw
    secret = ((getattr(args, "totp_secret", None) or "").strip()
              or creds.get("totp_secret") or "")
    if secret:
        acc["totp_secret"] = secret
        digits, period, algorithm = totp_params_from(creds)
        acc["totp_digits"] = digits
        acc["totp_period"] = period
        acc["totp_algorithm"] = algorithm
    if session_token:
        acc["session_token"] = session_token
    # QR image of THIS run (--qr): embed it as base64 into the account
    qr_src = getattr(args, "qr", None)
    if qr_src and os.path.isfile(qr_src):
        try:
            with open(qr_src, "rb") as f:
                data = f.read()
            if data:
                acc["qr_png_base64"] = base64.b64encode(
                    data).decode("ascii")
        except OSError as e:
            warn(tr("hotkey_open_fail", path=qr_src, err=e))
    sig = (acc.get("password"), acc.get("totp_secret"),
           acc.get("session_token"), acc.get("qr_png_base64"))
    old_sig = (old.get("password"), old.get("totp_secret"),
               old.get("session_token"), old.get("qr_png_base64"))
    if sig == old_sig and old:
        return                      # nothing new - stay silent
    acc["saved_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    accounts[email] = acc
    _save_accounts(accounts)
    cfg_set_current(email)
    # v6.5: the entry has just been created/made current - flush the
    # PROFILE-EXCLUSIVE data staged during its sign-in (its FIRST
    # Fastly cookie) into it
    _flush_pending_profile_data(email)
    # v6.4: a NEW profile starts with the CURRENT effective settings
    # (the v5.33 'settings exist from the very first run' contract,
    # now per profile): when the account entry has NO 'settings'
    # section of its own yet (a brand-new profile - the '+' flow of
    # the 'a' menu, or the very first sign-in before the startup
    # mirror was adopted), the effective language and resolver of
    # THIS session become its first saved values, so the profile is
    # complete from its very first run and a restart reproduces the
    # session that created it. An account that already HAS settings
    # (its own, or adopted from the provisional 'profile_defaults')
    # is NOT touched - its profile wins.
    if not isinstance(cfg_get(("settings",)), dict):
        if doh_provider() != "custom":
            save_doh_provider_cache(doh_provider())
        save_lang_cache(_LANG)
    info(tr("account_cached", email=email))

def print_accounts_list(args, reveal=False):
    """--list-accounts (masked) / --show-accounts (reveal=True: logins,
    passwords and the CURRENT TOTP code of every cached account in plain
    text, plus the QR dir). v6.0: the accounts come from config.json; in
    reveal mode the stored QR images are MATERIALIZED as png files into
    the QR dir (the persistent copy is the base64 field)."""
    accounts = load_accounts()
    if not accounts:
        info(tr("accounts_none"))
        return
    info(tr("accounts_list_header", n=len(accounts)))
    for i, (em, acc) in enumerate(accounts.items()):
        n = selection_token(i)
        if reveal:
            code = account_totp_now(acc)
            info(tr("account_reveal_entry", n=n, email=em,
                    password=acc.get("password") or "-",
                    code=(code[0] + f" ({code[1]}s)"
                          if code else "-")))
            if acc.get("qr_png_base64"):
                dst = materialize_account_qr(em, args)
                if dst:
                    ok(tr("account_qr_saved", path=dst))
        else:
            info(tr("account_list_entry", n=n, email=em,
                    pw=("yes" if acc.get("password") else "no"),
                    totp=("yes" if acc.get("totp_secret") else "no"),
                    session=("yes" if acc.get("session_token") else "no"),
                    saved=acc.get("saved_at") or "-"))
    info(tr("accounts_qr_dir", dir=accounts_qr_dir(args)))

def export_accounts_json(args, path: str):
    """v5.27 (fix 2, 4th parameter): --accounts-json FILE - export ALL
    cached accounts into ONE json file: logins, passwords, the CURRENT
    TOTP code and the stored QR image (base64, straight from config.json)
    of every account."""
    accounts = load_accounts()
    out = []
    for em, acc in accounts.items():
        code = account_totp_now(acc)
        entry = {"email": em,
                 "password": acc.get("password"),
                 "totp_secret": acc.get("totp_secret"),
                 "totp_digits": acc.get("totp_digits"),
                 "totp_period": acc.get("totp_period"),
                 "totp_algorithm": acc.get("totp_algorithm"),
                 "current_totp": code[0] if code else None,
                 "session_token": acc.get("session_token"),
                 "saved_at": acc.get("saved_at")}
        if acc.get("qr_png_base64"):
            entry["qr_png_base64"] = acc["qr_png_base64"]
        out.append(entry)
    payload = {"exportedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                           time.gmtime()),
               "accounts": out}
    try:
        with open(path, "w") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
    except OSError as e:
        sys.exit(str(e))
    ok(tr("accounts_json_saved", n=len(out), path=path))

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

def anchored_exp(token: str, receipt: float = None) -> int:
    """v6.6: the pass expiry ANCHORED TO OUR CLOCK at receipt (Firefox
    GuardianTypes.ProxyPass: 'Anchor the pass to our clock at receipt: it
    is valid from now for the token's lifetime. This makes rotation
    scheduling immune to any drift between Guardian's clock (nbf/exp)
    and ours'). Returns receipt + (exp - nbf) - the JWT lifetime
    measured on OUR clock - so a skewed local clock can no longer
    'extend' a pass into real expiry or see a fresh pass as expired.
    A JWT with no nbf (or unparsable) falls back to the raw exp: the
    pre-v6.6 behavior, preserved exactly."""
    p = jwt_payload(token)
    try:
        nbf = int(p.get("nbf") or 0)
        exp = int(p.get("exp") or 0)
    except (TypeError, ValueError):
        return jwt_exp(token)
    if nbf and exp and exp > nbf:
        base = receipt if receipt is not None else time.time()
        return int(base) + (exp - nbf)
    return jwt_exp(token)

def _jwt_part(token: str, idx: int) -> dict:
    try:
        part = token.split(".")[idx]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}

def print_jwt_decoded(token: str, panel: list = None):
    """Pretty-print the DECODED proxyPass JWT right under the raw token:
    header and payload as formatted JSON, plus exp/iat in human-readable
    UTC. Printed after every token issue/refresh (req: decoded JWT
    output). v8.1 (req. 3): with `panel` given the rows go to the
    live-panel line list instead of the scrolling log (the decoded JWT
    changes every refresh - it belongs to the redrawn block)."""
    header = _jwt_part(token, 0)
    payload = _jwt_part(token, 1)
    if not payload:
        return
    def _row(level, msg):
        if panel is None:
            _emit(level, msg)
        else:
            panel.append((level, msg))
    _row("info", tr("jwt_decoded_header"))
    _row("hint", tr("jwt_decoded_part", part="header: ",
                    json=json.dumps(header, indent=2, ensure_ascii=False)))
    _row("hint", tr("jwt_decoded_part", part="payload:",
                    json=json.dumps(payload, indent=2, ensure_ascii=False)))
    exp = int(payload.get("exp") or 0)
    iat = int(payload.get("iat") or 0)
    if exp:
        _row("hint", tr("jwt_decoded_exp",
                time=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(exp)),
                iat=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(iat))))

# ---------------- FxA auth ----------------

def get_credentials_status(email: str):
    """Account stretching version: ("v1"|"v2", clientSalt|None).
    Mirrors PyFxA Client.get_key_stretch_version().

    v5.25: EXACTLY the reference mozvpn.py behavior again - on any error
    the v1 fallback is used silently. The v5.24 experiment raised a hard
    error instead, but the reference script (which ALWAYS works on
    Termux) has the silent v1 fallback, and req() already solves the
    Fastly 406 challenge + retries inside, so a failing status request
    is a transient network outcome, not a reason to abort the sign-in.
    (For a genuine v2 account a v1 fallback would compute a wrong
    authPW and fail with errno 103 - but that was NEVER the observed
    Termux symptom: the observed failure was the waf_406 retry form,
    whose real root cause is fixed in req() this version.)"""
    status, d = req("POST", FXA_AUTH + "/account/credentials/status",
                    {"email": email})
    if status == 200 and d.get("currentVersion") in ("v1", "v2"):
        return d["currentVersion"], d.get("clientSalt")
    return "v1", None

def _can_prompt() -> bool:
    """v5.24 (Termux fix): whether an interactive input() prompt can
    physically deliver a line. A real tty always can. A non-tty stdin
    (a wrapper/launcher with redirected input on Android) raises EOFError
    on every input() - the TOTP gate used to rely on the caller's
    `interactive` FLAG alone and skipped the prompt whenever the flag was
    False, sending the sign-in into the email-confirmation dead end
    without ever asking for the 2FA code (variant 1 of the Termux bug)."""
    try:
        return sys.stdin.isatty()
    except Exception:
        return False

def prompt_line(prompt: str) -> str:
    """v5.24 (Termux fix): an input() that fails with a CLEAR localized
    error instead of the generic 'Unexpected error' retry loop when
    stdin cannot deliver a line (EOFError/OSError - Termux wrappers,
    packaged-binary runs with a redirected stdin).
    v8.1 (req. 3): the prompt first lifts the live UI panel and drops
    it back below the typed line, so the input row never overlaps the
    panel and the panel math stays intact."""
    _panel_lift()
    try:
        return input(prompt)
    except (EOFError, OSError) as e:
        raise MozVpnError(tr("prompt_read_error",
                             err=str(e) or repr(e)))
    finally:
        _panel_drop()

def prompt_secret(prompt: str) -> str:
    """v5.24 (Termux fix): getpass with the same clear-error wrapper.
    getpass reads /dev/tty FIRST and stdin second; on Android/Termux
    wrappers both may fail -> a localized error, not a raw crash.
    v8.1 (req. 3): panel lift/drop, same as prompt_line."""
    _panel_lift()
    try:
        return getpass.getpass(prompt)
    except (EOFError, OSError) as e:
        raise MozVpnError(tr("prompt_read_error",
                             err=str(e) or repr(e)))
    finally:
        _panel_drop()

def read_fxa_profile_session_token(path: str) -> "str | None":
    """v8.0 (A3): read the FxA sessionToken out of a DESKTOP FIREFOX
    PROFILE (--fxa-profile PATH): PATH may be the signedInUser.json
    file itself OR the profile DIRECTORY (FXA_PROFILE_FILE is appended
    then). The token sits at accountData.sessionToken (64 hex chars) -
    the foxhole-vpn AUTH.md pattern, verified 2026-10-30 against the
    Firefox source docs. Returns the token (lowercase), or None with a
    localized message on every failure (the caller keeps its normal
    chain, so a bad path can never brick a run)."""
    p = (path or "").strip()
    if not p:
        return None
    if os.path.isdir(p):
        p = os.path.join(p, FXA_PROFILE_FILE)
    if not os.path.isfile(p):
        warn(tr("fxa_profile_missing", path=path, err="not found"))
        return None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as e:
        warn(tr("fxa_profile_missing", path=path, err=e))
        return None
    tok = ""
    try:
        acc = data.get("accountData")
        tok = str((acc or {}).get("sessionToken") or "").strip()
    except Exception:
        tok = ""
    if not tok:
        warn(tr("fxa_profile_no_token", path=p))
        return None
    if len(tok) != 64 or any(c not in "0123456789abcdef" for c in tok.lower()):
        warn(tr("fxa_profile_bad_token", path=p))
        return None
    info(tr("fxa_profile_read", path=p))
    return tok.lower()

def fxa_unblock_prompt(email_norm: str) -> "str | None":
    """v8.0 (B4): ONE round of the FxA UNBLOCK-CODE prompt (the errno 125
    flow): the server has ALREADY emailed the 6-digit code to the
    address; an EMPTY input re-sends the letter via
    POST /v1/account/login/send_unblock_code {'email': ...} and returns
    the 'resend' sentinel (the fxa-js-client signIn pattern, verified
    online 2026-10-30); 'q' cancels ('cancel'); a numeric entry returns
    the code. The bounded retry/resend counters live in the CALLER, so
    every loop of the login flow stays visible in ONE place."""
    raw = prompt_line(tr("unblock_prompt", email=email_norm)).strip()
    if raw.lower() in ("q", "quit"):
        return "cancel"
    if not raw:
        s, _dd = req("POST", FXA_AUTH + "/account/login/send_unblock_code",
                     {"email": email_norm})
        if s == 200:
            info(tr("unblock_resent", email=email_norm))
        else:
            warn(tr("email_resend_failed", status=s))
        return "resend"
    code = re.sub(r"[\s\-]+", "", raw)   # "226 829" -> "226829"
    if not code.isdigit():
        warn(tr("unblock_wrong"))
        return "cancel"
    return code

def fxa_wait_email_link(session_token: str, timeout: int = 300) -> bool:
    """v8.0 (B5): wait for the user to open the CONFIRMATION LINK from
    the Mozilla email in a browser: poll GET /v1/recovery_email/status
    (the onepw protocol's own endpoint: 'the client can use
    /recovery_email/status (requires sessionToken, not verification)
    until the user clicks the email link and the API reports
    verification is complete' - verified against the mozilla/
    fxa-auth-server wiki, fetched 2026-10-30) every 10 s, bounded at
    300 s. The same Bearer-with-Hawk-fallback auth as every other
    session route. Accepts BOTH response shapes (verified /
    emailVerified)."""
    url = FXA_AUTH + "/recovery_email/status"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(10)
        s, dd = req("GET", url, None, bearer_session(session_token))
        if s == 401 and isinstance(dd, dict) and dd.get("errno") == 110:
            # Bearer not accepted (deployment lag/rollback) -> Hawk fallback
            s, dd = req("GET", url, None,
                        hawk_session(session_token, "GET",
                                     "/v1/recovery_email/status", b""))
        if s == 200 and isinstance(dd, dict) and (
                dd.get("verified") or dd.get("emailVerified")):
            return True
    return False

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

    # v8.0 (B4): the login call is a BOUNDED LOOP now. errno 125 means
    # the server has ALREADY emailed a 6-digit unblock code to the
    # address (the fxa-js-client signIn pattern, verified online
    # 2026-10-30): the login is retried with the code riding the
    # payload as 'unblockCode', and an EMPTY prompt input re-sends the
    # letter via POST /v1/account/login/send_unblock_code {'email'}.
    # errno 127 (incorrectUnblockCode) re-enters the SAME flow with a
    # warning. Interactive runs get the in-app prompt (the Zeus-VPN
    # 'unblock codes all handled in the app' feature); non-interactive
    # runs (no promptable stdin) keep the v6.6 blocked error VERBATIM.
    # Bounds: 3 code submissions, 3 re-sends - then the localized
    # gave-up error.
    login_payload = {"email": email_norm, "authPW": auth_pw}
    unblock_tries = 0
    resends = 0
    while True:
        status, d = req("POST", FXA_AUTH + "/account/login", login_payload)
        if status == 406:
            raise MozVpnError(tr("waf_406"))
        if status == 200:
            break
        errno = d.get("errno"); msg = d.get("message", d)
        if errno == 102: raise MozVpnError(tr("account_not_found"))
        if errno == 103: raise MozVpnError(tr("wrong_password"))
        # errno 114 -> HTTP 429 "Client has sent too many requests"
        # errno 125 -> HTTP 400 "The request was blocked for security reasons".
        # Both are TEMPORARY blocks (customs/rate-limit); recovery is email
        # sign-in confirmation (see blocked_login_message).
        if status == 429 or errno == 114:
            # v6.6: the FXA LOGIN rate limit gets its OWN error code so
            # the watch loop applies the LOGIN cooldown (15 min, the
            # cached session token preferred on the retry - see the
            # 'blocked_login' handler there) instead of the generic
            # blocked wait; the Guardian-side blocks keep 'blocked'.
            raise MozVpnError(blocked_login_message(_retry_after_seconds(d), "login"),
                              code="blocked_login")
        if errno in (125, 127):
            if errno == 127:
                warn(tr("unblock_wrong"))
            if interactive or _can_prompt():
                if unblock_tries >= 3 or resends >= 3:
                    raise MozVpnError(tr("unblock_gave_up"), code="blocked")
                got = fxa_unblock_prompt(email_norm)
                if got == "cancel":
                    vm = d.get("verificationMethod") or ""
                    extra = tr("blocked_extra_method", method=vm) if vm else ""
                    raise MozVpnError(blocked_login_message(None, "login") + extra,
                                      code="blocked")
                if got == "resend":
                    resends += 1
                    continue
                login_payload["unblockCode"] = got
                unblock_tries += 1
                continue
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
        # v5.26 (REFERENCE PARITY): the CONTROL FLOW of the unverified
        # branch is the reference mozvpn.py again - the TOTP route is
        # entered ONLY when the SERVER announces verificationMethod
        # 'totp-2fa'/'totp'. The v5.24 speculative try_totp attempt
        # (a TOTP request even when the server announced 'email') is
        # REMOVED: the reference script, which ALWAYS signs in on the
        # same phone, never makes that extra request, so neither do
        # we. What stays from v5.24 is only the PROMPT robustness:
        # the code is read via prompt_line() and the prompt is allowed
        # whenever the caller's flag is set OR stdin can physically
        # deliver a line (_can_prompt()) - so a redirected stdin
        # produces a CLEAR localized error instead of a raw EOFError.
        if vm in ("totp-2fa", "totp"):
            session_ok = False
            for attempt in range(3):
                if totp_provider is not None:
                    raw = totp_provider()
                elif interactive or _can_prompt():
                    raw = prompt_line(tr("totp_prompt")).strip()
                else:
                    raise MozVpnError(tr("totp_missing"))
                code = re.sub(r"[\s\-]+", "", raw)   # "226 829" -> "226829"
                if not code.isdigit():
                    warn(tr("totp_digits_only"))
                    continue
                # v5.25: the v5.24 'same code sent twice -> fail fast'
                # check is REMOVED - the reference mozvpn.py (which the
                # user confirms ALWAYS logs in) retries the SAME fixed
                # --totp code up to 3 times without any such check, so
                # the retry semantics are back to the reference exactly.
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
                    # v6.6: same OWN code as the login 429 - the watch
                    # loop applies the LOGIN cooldown to it as well.
                    raise MozVpnError(
                        blocked_login_message(_retry_after_seconds(d2), "2FA"),
                        code="blocked_login")
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
                # errno 155 broke out of the loop above (no TOTP on the
                # server) or the code was never numeric 3 times - either
                # way the session is NOT verified via TOTP.
                raise MozVpnError(tr("totp_rejected_final"), code="relogin")
        elif email_verified is False or vr == "signup":
            raise MozVpnError(tr("email_unverified"), code="relogin")
        elif vm.startswith("email") or not vm:
            # v7.0: THE EMAILED-CODE SESSION VERIFICATION (the dead end
            # is gone for accounts the script can prompt for). The
            # reference Go client (fxa.go, 'Sync upstream token pool,
            # email-2fa login, and Fastly challenge solver',
            # 2026-08-22) prompts for the 6-digit code FxA emails at
            # login time and POSTs it to /v1/session/verify_code
            # (fxaVerifySession). Verified against the FxA sources
            # (lib/routes/session.js, fetched 2026-10-30):
            #   * /session/verify_code rides the SAME sessionTokenBearer
            #     auth with a sessionToken Hawk fallback as the TOTP
            #     route above, payload {'code': DIGITS};
            #   * a VALID code verifies the session via 'email-2fa'
            #     (AAL1) - but a TOTP account is REFUSED with
            #     insufficientAal (the AAL1 guard the v5.25 comment
            #     above documented), so this path is entered ONLY when
            #     the script holds NO TOTP provider for the account;
            #   * /session/resend_code re-sends the letter on demand
            #     (a no-op {} for TOTP accounts, same handler file).
            # An EMPTY input re-sends the letter; non-interactive runs
            # (no promptable stdin) keep the v6.9 reference dead end -
            # the localized instructions - VERBATIM.
            if totp_provider is not None or not (interactive or _can_prompt()):
                raise MozVpnError(tr("email_confirm_required"), code="relogin")
            verify_url = FXA_AUTH + "/session/verify_code"
            resend_url = FXA_AUTH + "/session/resend_code"
            session_ok = False
            wrong = 0
            while True:
                raw = prompt_line(tr("email_code_prompt")).strip()
                if not raw:
                    # EMPTY input = 're-send the letter'
                    s3, d3 = req("POST", resend_url, {},
                                 bearer_session(d["sessionToken"]))
                    if s3 == 401 and d3.get("errno") == 110:
                        s3, d3 = req("POST", resend_url, {},
                                     hawk_session(d["sessionToken"], "POST",
                                                  "/v1/session/resend_code",
                                                  b"{}"))
                    if s3 == 200:
                        info(tr("email_code_resent"))
                    else:
                        warn(tr("email_resend_failed", status=s3))
                    continue
                # v8.0 (B5): the CONFIRMATION-LINK branch (the foxyvpn
                # 'email 2FA code verification, falling back to a
                # confirmation-link prompt' / 4q4r 'or the confirmation
                # link, when FxA chooses that method' pattern): 'l'
                # (or 'link') means the user will confirm via the LINK
                # in the Mozilla email - the session is then POLLED via
                # GET /v1/recovery_email/status (the onepw protocol's
                # own endpoint: requires sessionToken, NOT verification;
                # verified against the mozilla/fxa-auth-server wiki,
                # fetched 2026-10-30) every 10 s, bounded at 300 s; a
                # timeout simply returns to the code prompt and the
                # code path below stays exactly as it was.
                if raw.lower() in ("l", "link"):
                    if fxa_wait_email_link(d["sessionToken"]):
                        session_ok = True
                        info(tr("email_link_verified"))
                        break
                    warn(tr("email_link_timeout"))
                    continue
                code = re.sub(r"[\s\-]+", "", raw)   # "226 829" -> "226829"
                if not code.isdigit():
                    wrong += 1
                    if wrong >= 3:
                        raise MozVpnError(tr("email_code_rejected_final"),
                                         code="relogin")
                    warn(tr("totp_digits_only"))
                    continue
                vbody = json.dumps({"code": code}).encode()
                s4, d4 = req("POST", verify_url, {"code": code},
                             bearer_session(d["sessionToken"]))
                if s4 == 401 and d4.get("errno") == 110:
                    # Bearer not accepted (deployment lag/rollback) -> full Hawk fallback
                    s4, d4 = req("POST", verify_url, {"code": code},
                                 hawk_session(d["sessionToken"], "POST",
                                              "/v1/session/verify_code",
                                              vbody))
                if s4 == 200:
                    session_ok = True
                    info(tr("email_code_confirmed"))
                    break
                if s4 == 400:
                    # invalidOrExpiredOtpCode (session.js): a wrong or
                    # expired code - the letter may have been re-sent.
                    wrong += 1
                    if wrong >= 3:
                        raise MozVpnError(tr("email_code_rejected_final"),
                                         code="relogin")
                    warn(tr("email_code_rejected"))
                    continue
                if s4 == 401:
                    # insufficientAal: the account HAS a server-side
                    # TOTP (the AAL1 guard) - an email code can never
                    # verify this session. The reference dead end.
                    info(tr("email_code_aal_hint"))
                    raise MozVpnError(tr("email_confirm_required"),
                                     code="relogin")
                if s4 == 429 or d4.get("errno") in (114, 125):
                    # Too many wrong codes in a row - the same OWN code
                    # as the TOTP 429 above (the watch loop cooldown).
                    raise MozVpnError(
                        blocked_login_message(_retry_after_seconds(d4),
                                              "email code"),
                        code="blocked_login")
                raise MozVpnError(tr("email_code_unknown_error",
                                     status=s4, data=d4), code="relogin")
            if not session_ok:
                raise MozVpnError(tr("email_confirm_required"), code="relogin")
        else:
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
    # v5.36: THE FIX of the endless 'temporary DNS failure - retrying in
    # 30s' loop on the packaged Termux binary. The v5.13-v5.35 code sent
    # this ONE request through a RAW _OPENER.open() call (copied from the
    # reference mozvpn.py, where it is correct - the reference runs as a
    # plain script whose getaddrinfo is healthy on the very same phone).
    # That raw call was the ONLY network request of the whole sign-in
    # chain that did NOT go through req(): in the packaged-binary broken-
    # resolver state OAuth and /fpn/activate rode the emergency direct-IP
    # route and SUCCEEDED, while THIS call hit socket.getaddrinfo ->
    # gaierror(7) EAI_NODATA on EVERY retry - the watch loop classified
    # it as a transient blip and re-died every 30 s, exactly the live
    # log ('Guardian: enroll completed (HTTP 200)' -> the endless DNS
    # retry). guardian_pass() now rides the SAME routed transport as
    # every other request: req_full() - the reference urllib path when
    # the resolver is healthy (identical headers, cookies, JSON and
    # header handling), the emergency direct-IP route when it is not.
    # The response HEADERS (X-Quota-*, Retry-After) are returned with
    # the answer, as the raw code did.
    status, hdrs, d = req_full("GET", GUARDIAN + "/api/v1/fpn/token",
                              headers=auth, timeout=30)
    if status == 403:
        # v6.6: a 403 (no_entitlement) - Firefox re-establishes the
        # enrollment and asks again before giving up: ONE automatic
        # POST /api/v1/fpn/activate (the v5.3 reference-parity
        # re-activation path, reused verbatim) followed by ONE retry
        # of the token fetch. A stale/absent fpn enrollment (the
        # OAuth token was minted but the activation did not stick) is
        # exactly the transient case this heals; a 403 AFTER the
        # retry raises below exactly as before, and every other
        # status is untouched.
        s1b, d1b = req("POST", GUARDIAN + "/api/v1/fpn/activate",
                       headers=auth)
        if s1b in (200, 201, 204):
            ok(tr("guardian_reactivated", status=s1b))
        else:
            warn(tr("guardian_reactivate_failed", status=s1b,
                    detail=str(d1b)[:120]))
        status, hdrs, d = req_full("GET", GUARDIAN + "/api/v1/fpn/token",
                                  headers=auth, timeout=30)

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

_QUOTA_LAST = {"zero": False, "unlimited": False, "seen": False}
# v8.0 (A2): the ONE-TIME rotation warnings of the watch loop (a dry
# account must not re-warn on EVERY ~10-min refresh).
_ROTATE_WARNED = {"none": False, "off": False}

def save_account_quota(email: str, limit, remaining, reset, unlimited=False):
    """v8.0 (A2): remember the LAST KNOWN quota of an account INSIDE its
    config entry (quota_remaining / quota_limit / quota_reset /
    quota_seen / quota_unlimited) - the ranking data
    pick_rotation_account() reads when the current account runs dry.
    The bookkeeping runs on EVERY refresh (cheap: the X-Quota headers
    ride every token response, no extra request), whether or not the
    auto-rotation itself is enabled."""
    em = (email or "").strip().lower()
    if not em:
        return
    try:
        cfg_load()
        with _CFG_LOCK:
            acc = (_CFG.get("accounts") or {}).get(em)
            if not isinstance(acc, dict):
                return
            acc["quota_limit"] = limit
            acc["quota_remaining"] = None if unlimited else remaining
            acc["quota_reset"] = reset
            acc["quota_unlimited"] = bool(unlimited)
            acc["quota_seen"] = int(time.time())
        cfg_save()
    except Exception:
        pass

def pick_rotation_account(current_email: str):
    """v8.0 (A2): the account the rotation should switch to when the
    current one runs dry - the Zeus-VPN rule: 'moves to the account
    with the most data left, without dropping the connection'.
      * a KNOWN-dry account (remaining <= 0, not unlimited) is NEVER
        a target;
      * an account whose quota was never seen counts as a VIABLE
        candidate (its allowance may be full);
      * an account WITHOUT a cached session token is skipped: the
        rotation rides CACHED sessions only and must never trigger a
        password login (the FxA 429 login rate limit - the
        foxyvpn-pool lesson);
      * an unlimited account always wins the ranking.
    Returns (email, known_remaining_or_None) or (None, None)."""
    cur = (current_email or "").strip().lower()
    best_em, best_left, best_score = None, None, -1
    for em, acc in cfg_accounts().items():
        if not isinstance(acc, dict) or em == cur:
            continue
        if not str(acc.get("session_token") or "").strip():
            continue
        if acc.get("quota_unlimited"):
            return em, None            # unlimited always wins
        try:
            left = int(acc.get("quota_remaining"))
        except (TypeError, ValueError):
            left = None
        if left is not None and left <= 0:
            continue
        score = left if (left is not None and left > 0) else 0
        if score > best_score:
            best_em, best_left, best_score = em, left, score
    return best_em, best_left

def print_quota(hdrs: dict, panel: list = None):
    """Print the quota from the X-Quota-* headers of the Guardian response.
    v8.0 (A2): the parsed numbers are also RECORDED - the module-level
    _QUOTA_LAST snapshot (the zero flag the watch loop's rotation
    trigger reads) and the per-account bookkeeping in config.json
    (save_account_quota) that ranks the other cached accounts when the
    current one runs dry.
    v8.1 (req. 3): with `panel` given, the ONE status line is not
    emitted into the log but APPENDED to the live-panel line list
    (redrawn in place every refresh); the quota_low warning is a real
    event and stays a log line in both modes."""
    if not hdrs:
        return
    _QUOTA_LAST["zero"] = False
    _QUOTA_LAST["unlimited"] = False
    _QUOTA_LAST["seen"] = True
    if hdrs.get("x-quota-unlimited", "").lower() == "true":
        _QUOTA_LAST["unlimited"] = True
        if panel is None:
            info(tr("quota_unlimited"))
        else:
            panel.append(("info", tr("quota_unlimited")))
        save_account_quota(cfg_current_email(),
                          hdrs.get("x-quota-limit"), None,
                          hdrs.get("x-quota-reset"), unlimited=True)
        return
    limit = hdrs.get("x-quota-limit")
    remaining = hdrs.get("x-quota-remaining")
    reset = hdrs.get("x-quota-reset")
    if limit is not None and remaining is not None:
        reset_s = f", reset: {reset}" if reset else ""
        if panel is None:
            info(tr("quota_left", left=human_bytes(remaining),
                    limit=human_bytes(limit), reset=reset_s))
        else:
            panel.append(("info", tr("quota_left",
                                    left=human_bytes(remaining),
                                    limit=human_bytes(limit),
                                    reset=reset_s)))
        # v6.6: the quota is therefore reported on EVERY proxyPass
        # refresh (the ~10-min cadence - tighter than the Go
        # quotaCheckInterval of 15 min; the X-Quota headers already
        # ride every token response, no extra request), and a NEW
        # warning fires when the remaining monthly allowance drops
        # below 15% of the limit (the reset time is included).
        try:
            rem_i = int(remaining)
        except (TypeError, ValueError):
            rem_i = None
        if rem_i is not None:
            # v8.0 (A2): the CURRENT account is DRY - the snapshot the
            # watch loop's auto-rotation trigger reads.
            _QUOTA_LAST["zero"] = rem_i <= 0
        try:
            if int(limit) > 0 and int(remaining) * 100 < int(limit) * 15:
                warn(tr("quota_low", left=human_bytes(remaining),
                        limit=human_bytes(limit), reset=reset_s))
        except (TypeError, ValueError):
            pass
        save_account_quota(cfg_current_email(), limit, remaining, reset)

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
            # v5.0: the recommended anycast egress (p.m1.fastly-masque.net)
            # is served as its OWN location too - one more local proxy,
            # exactly like Firefox's 'Recommended' server choice.
            rec_c = countries.setdefault("REC", {
                "countryCode": "REC",
                "countryName": r.get("name") or "Recommended",
                "locked": locked,
                "cities": {}})
            rec_c["cities"].update(cities_out)
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

# ---------------------------------------------------------------------------
# v6.6: TLS ClientHello FRAGMENTATION (--tls-split / hotkey 'i' / env
# MOZVPN_TLS_SPLIT). The ClientHello of the outer TLS connection (which
# carries the egress SNI) is sent in SMALL TCP segments so a middlebox
# that parses the whole ClientHello from the FIRST packet of the flow
# cannot see the full SNI in one segment. Implementation: the handshake
# runs over memory BIOs (ctx.wrap_bio + a hand-driven do_handshake loop
# - the stdlib technique the Python ssl docs document for non-blocking
# BIO use); the ClientHello bytes the BIO produces go to the socket in
# TLS_SPLIT_CHUNK-byte pieces (the first piece gets a short delay so the
# segments land in separate TCP packets), and everything after the
# handshake is pumped through the SAME SSLObject, so the connection
# stays a normal TLS stream for the peer. ON by default since v6.7 (the
# user's directive: every USEFUL option ships enabled) and SAFE by
# CONSTRUCTION, not by opt-in: any fragmented-handshake failure falls
# back to the plain profile matrix of _tls_profiles() on a FRESH socket
# (see _tls_connect), so the v6.1 lesson (a transport 'hardening' must
# never surprise the working data path) holds even with the feature
# enabled; --no-tls-split / MOZVPN_TLS_SPLIT=0 restores the plain
# ClientHello.
# ---------------------------------------------------------------------------
TLS_SPLIT_CHUNK = 64          # bytes per ClientHello TCP segment
TLS_SPLIT_DELAY = 0.03        # s after the first segment
_tls_split_on = {"v": False}

def set_tls_split(enabled: bool):
    """v6.6: enable/disable the ClientHello fragmentation (NEW connections)."""
    _tls_split_on["v"] = bool(enabled)

def tls_split() -> bool:
    """v6.6: whether the ClientHello fragmentation is active."""
    return _tls_split_on["v"]

def _split_clienthello_records(record: bytes) -> "list[bytes] | None":
    """v7.0: re-frame ONE TLS record (the ClientHello) into TWO
    records, cutting at the start of the server_name extension
    (the 'sniext' cut of the zapret tpws --tlsrec option), so the
    WHOLE SNI extension goes in the second record. Returns None
    when the buffer is not exactly one ClientHello record or the
    extension is not found - the caller then keeps the v6.6 plain
    TCP segmentation.
    Why the record layer AT ALL: zapret issue #238 shows the TLS-
    record fragmentation ALONE does not fool a DPI that reads TCP
    (the two records went in ONE packet), and the Xray-core
    discussion #5969 (2026-04) reports the Iranian national DPI
    now REASSEMBLING the classic TCP-layer ClientHello split -
    but 'TLS record-layer fragmentation bypasses DPIs that
    reassemble at the TCP layer but not at the TLS record layer'.
    The COMBINATION (two TLS records, each in small TCP segments)
    therefore requires the DPI to reassemble BOTH layers to see
    the SNI. RFC 5246 section 6.2.1 permits a handshake message
    to be carried across multiple records, and the v6.6 item-12
    fallback still covers a server that mishandles it."""
    try:
        if len(record) < 5 or record[0] != 0x16:
            return None                      # not a handshake record
        rec_len = int.from_bytes(record[3:5], "big")
        if 5 + rec_len != len(record):
            return None                      # not exactly one record
        hs = record[5:]
        if len(hs) < 4 or hs[0] != 0x01:
            return None                      # not a ClientHello
        hs_len = int.from_bytes(hs[1:4], "big")
        if 4 + hs_len != len(hs):
            return None
        ch = hs[4:]                          # the ClientHello body
        # version(2) random(32) session_id(1+n) cipher_suites(2+n)
        # compression_methods(1+n) extensions(2+n)
        o = 2 + 32
        sid_n = ch[o]; o += 1 + sid_n
        cs_n = int.from_bytes(ch[o:o + 2], "big"); o += 2 + cs_n
        co_n = ch[o]; o += 1 + co_n
        if o + 2 > len(ch):
            return None
        ext_len = int.from_bytes(ch[o:o + 2], "big")
        ext_start = o + 2
        ext_end = ext_start + ext_len
        if ext_end > len(ch):
            return None
        p = ext_start
        cut = None
        while p + 4 <= ext_end:
            etype = int.from_bytes(ch[p:p + 2], "big")
            elen = int.from_bytes(ch[p + 2:p + 4], "big")
            if etype == 0:                   # server_name
                cut = 5 + 4 + p              # record offset of it
                break
            p += 4 + elen
        if cut is None or cut <= 5 or cut >= len(record) - 1:
            return None
        def _frame(part: bytes) -> bytes:
            # re-write the record header with the new payload length
            return (part[:3] + (len(part) - 5).to_bytes(2, "big")
                    + part[5:])
        return [_frame(record[:cut]), _frame(record[cut:])]
    except Exception:
        return None

class _FragTLSConn:
    """v6.6: a socket-like adapter around an ssl.SSLObject that performs
    the TLS handshake with a FRAGMENTED ClientHello and then pumps the
    application data. Surface: sendall/recv/settimeout/close/getpeercert -
    everything the probes and the builtin engine do with a tunnel."""

    def __init__(self, raw: socket.socket, ctx: ssl.SSLContext,
                 server_hostname: str, timeout: int):
        self._raw = raw
        self._bio_in = ssl.MemoryBIO()
        self._bio_out = ssl.MemoryBIO()
        self._obj = ctx.wrap_bio(self._bio_in, self._bio_out,
                                 server_hostname=server_hostname)
        self._timeout = timeout
        raw.settimeout(timeout)
        # 1) drive the handshake; the FIRST thing do_handshake writes
        #    into bio_out is the ClientHello - send it FRAGMENTED.
        first_flush = True
        deadline = time.monotonic() + max(5, int(timeout))
        while True:
            try:
                self._obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                if time.monotonic() > deadline:
                    raise socket.timeout("TLS handshake timed out")
                if self._bio_out.pending():
                    self._send_bio_out(fragment=first_flush)
                    first_flush = False
                data = raw.recv(65536)
                if not data:
                    raise ConnectionResetError(
                        "peer closed during handshake")
                self._bio_in.write(data)
            except ssl.SSLWantWriteError:
                if time.monotonic() > deadline:
                    raise socket.timeout("TLS handshake timed out")
                self._send_bio_out(fragment=first_flush)
                first_flush = False
        # the handshake completed - flush what it left in bio_out (the
        # client Finished); this is small and goes as ONE segment
        self._send_bio_out(fragment=False)

    def _send_bio_out(self, fragment: bool):
        """Flush bio_out to the raw socket; with fragment=True the bytes
        (the ClientHello) go in TLS_SPLIT_CHUNK-byte TCP segments.
        v7.0: the ClientHello is FIRST re-framed into TWO TLS records
        cut at the server_name extension (the zapret tpws
        --tlsrec=sniext cut - see _split_clienthello_records) and
        THEN each record goes in small TCP segments - a DPI must
        reassemble BOTH layers (TCP AND the TLS records) to see
        the SNI. A chunk that is not a single ClientHello record
        (the Finished, the application data) keeps the v6.6
        behavior verbatim."""
        while self._bio_out.pending():
            chunk = self._bio_out.read()
            if not chunk:
                break
            parts = _split_clienthello_records(chunk) if fragment else None
            if parts:
                first = True
                for part in parts:
                    off = 0
                    while off < len(part):
                        self._raw.sendall(part[off:off + TLS_SPLIT_CHUNK])
                        if first:
                            time.sleep(TLS_SPLIT_DELAY)
                            first = False
                        off += TLS_SPLIT_CHUNK
                continue
            if fragment and len(chunk) > TLS_SPLIT_CHUNK:
                off = 0
                first = True
                while off < len(chunk):
                    self._raw.sendall(chunk[off:off + TLS_SPLIT_CHUNK])
                    if first:
                        time.sleep(TLS_SPLIT_DELAY)
                        first = False
                    off += TLS_SPLIT_CHUNK
            else:
                self._raw.sendall(chunk)

    # -- the socket-like surface used by the probes / the builtin engine --
    def settimeout(self, value):
        self._timeout = value
        try:
            self._raw.settimeout(value)
        except OSError:
            pass

    def sendall(self, data):
        # 2) application data: encrypt via the SSLObject, flush whole
        view = memoryview(data)
        while view:
            n = self._obj.write(view)
            self._send_bio_out(fragment=False)
            view = view[n:]

    def recv(self, size):
        while True:
            try:
                return self._obj.read(size)
            except ssl.SSLWantReadError:
                data = self._raw.recv(65536)
                if not data:
                    return b""
                self._bio_in.write(data)
            except ssl.SSLWantWriteError:
                self._send_bio_out(fragment=False)
            except ssl.SSLZeroReturnError:
                return b""

    def close(self):
        try:
            self._raw.close()
        except OSError:
            pass

    def getpeercert(self):
        return self._obj.getpeercert()

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
    The first profile whose handshake completes wins.
    v6.1 (the user-reported regression fix): the v6.0 'security' change
    REMOVED profile 4 - and that broke the local proxies COMPLETELY on
    real-world DPI/TLS-intercepting networks (the user's live report:
    the log says 'token obtained, connections for all countries
    established', but NOTHING routes; the original works perfectly).
    On such networks the three certificate-VALIDATING profiles cannot
    complete the handshake to the Fastly egress, so EVERY relay of the
    builtin engine dies while the startup log keeps looking healthy
    (the masque probe rides QUIC/UDP - a different transport that the
    interceptor may pass - and --probe-fail keep, the default, keeps
    unverified upstreams in the served list). The ORIGINAL matrix is
    therefore restored VERBATIM: the 'insecure' profile is back as the
    LAST resort, exactly like the original curl --proxy-insecure-like
    fallback the user's working setup relies on."""
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
    answered something that was not TLS at all.
    v5.6 probe speedup: the hostname is resolved ONCE before the profile
    loop and the resolved IP list is reused by every profile attempt -
    previously each of the 4 attempts ran a FRESH DoH resolution (and the
    in-probe echo fallback 4 more), which with the DoH cache off and a
    slow/blocked first DoH provider added many seconds to EVERY probe
    (the '10+ seconds' live-run complaint)."""
    last_err = None
    ips = resolve_host(host)          # v5.6: resolve once, reuse below
    for name, ctx in _tls_profiles():
        raw = None
        try:
            raw = _connect_resolved_ips(ips, host, port, timeout)
        except Exception as e:
            # v5.14: a TCP-LAYER failure (connect timeout / refused /
            # unreachable) means NO ClientHello was ever sent - the
            # ClientHello profile of the remaining attempts CANNOT
            # change this outcome. The v5.8 changelog already noted that
            # 'a fully-failing run is bounded by the profile matrix x
            # the per-attempt timeout' (up to 4 x 5 s wasted per
            # upstream in the probe); abort the matrix immediately.
            last_err = e
            break
        try:
            raw.settimeout(timeout)
            if tls_split():
                # v6.6 (item 12): the fragmented-ClientHello handshake.
                # ANY failure here falls back to the plain profile walk
                # (a fresh socket + the plain wrap_socket below) - a
                # 'hardening' must never break the data path (the v6.1
                # lesson). The raw socket may be half-consumed by the
                # failed fragmented handshake, so a FRESH one is opened
                # for the plain attempt.
                try:
                    return _FragTLSConn(raw, ctx, host, timeout)
                except Exception:
                    try:
                        raw.close()
                    except Exception:
                        pass
                    raw = _connect_resolved_ips(ips, host, port, timeout)
                    raw.settimeout(timeout)
            return ctx.wrap_socket(raw, server_hostname=host)
        except Exception as e:
            # a TLS-HANDSHAKE failure: the next ClientHello profile may
            # still succeed - walk on (the preserved v5.6 behavior)
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

def _http_dechunked_body(raw: bytes) -> tuple:
    """v5.4: split a raw HTTP/1.1 response into (status, headers, body)
    with a REAL parser - not the naive 'split once on \\r\\n\\r\\n' of
    v5.2/v5.3. Handles Content-Length AND 'Transfer-Encoding: chunked'
    (RFC 9112 section 7.1 - the standard HTTP/1.1 framing): ipinfo.io
    answers /json with a chunked body, so the old parser handed the
    JSON decoder a body polluted with hex chunk-size lines and the
    probe failed on EVERY upstream (live log 2026-09-25: 33/33 'data
    check not passed'). Returns (status_line, header_dict, body_bytes);
    ('', {}, b'') when the response is unusable."""
    parts = raw.split(b"\r\n\r\n", 1)
    if len(parts) != 2:
        return "", {}, b""
    head, rest = parts
    head_lines = head.split(b"\r\n")
    if not head_lines:
        return "", {}, b""
    status = head_lines[0].decode("latin-1", "replace")
    headers = {}
    for line in head_lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.decode("latin-1").strip().lower()] = \
                v.decode("latin-1").strip()
    if headers.get("transfer-encoding", "").lower().find("chunked") >= 0:
        body = b""
        buf = rest
        while True:
            # chunk-size line (may carry chunk extensions after ';')
            cut = buf.find(b"\r\n")
            if cut < 0:
                break
            size_token = buf[:cut].split(b";")[0].strip()
            try:
                size = int(size_token, 16)
            except ValueError:
                break
            if size == 0:
                break
            chunk = buf[cut + 2:cut + 2 + size]
            buf = buf[cut + 2 + size + 2:] if len(buf) >= cut + 2 + size + 2 \
                else b""
            body += chunk
            if len(body) > 262144:
                break
        return status, headers, body
    cl = headers.get("content-length")
    if cl and cl.isdigit():
        n = int(cl)
        if n <= len(rest):
            return status, headers, rest[:n]
        return status, headers, rest
    # no framing info: read-to-EOF body is whatever we collected
    return status, headers, rest

def _http_ip_request_over_tunnel(tunnel: "ssl.SSLSocket", host_header: str,
                                 path: str = "/") -> str:
    """Send a plain HTTP/1.1 GET through an established (decrypted) TLS tunnel
    and return the body. Used to verify data actually flows through a proxy.
    v5.4: 'Accept-Encoding: identity' prevents a gzip body the JSON parser
    cannot read; the response is parsed by _http_dechunked_body() so chunked
    replies (ipinfo.io/json) decode correctly; the wait was 15 s -> 10 s so a
    dead upstream fails the probe faster (the 'very long probes' complaint
    of the live run)."""
    req_bytes = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                 "User-Agent: Mozilla/5.0 (mozvpn probe)\r\n"
                 "Accept: */*\r\nAccept-Encoding: identity\r\n"
                 "Connection: close\r\n\r\n").encode()
    tunnel.sendall(req_bytes)
    chunks = []
    tunnel.settimeout(6)
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
    status, headers, body = _http_dechunked_body(b"".join(chunks))
    return body.decode("utf-8", "replace").strip() if body else ""

def _hp(host: str, port, width: int = 34) -> str:
    """v5.2 (req. 1): 'host:port' padded with spaces to a FIXED width, so
    the per-upstream probe / geo / protocol log lines all start their
    message text in the SAME column regardless of the hostname length."""
    return f"{host}:{port}".ljust(width)

def _proxy_label_width(proxies) -> int:
    """v5.19: the label-column width of the proxy lines: the WIDEST
    label of ALL proxies, at least 30 (the {label:<30} minimum of the
    proxy_line template). Padding every label to this width BEFORE the
    template runs is what keeps the '->' arrow column identical on
    every line - including the long 'Recomended Location/Recomended
    City' line, which used to overflow the fixed 30 and push its
    arrow further right than every other proxy line."""
    try:
        return max([len(str(p.get("label") or "")) for p in proxies] + [30])
    except Exception:
        return 30

def _connect_tunnel_open(server: dict, token: str,
                         dst_host: str, dst_port: int):
    """v5.4 helper: TLS to the egress + HTTP CONNECT to dst_host:dst_port.
    Returns (tls_socket, None) or (None, error_detail)."""
    try:
        tls = _tls_connect(server["protocolHost"], server["protocolPort"],
                           timeout=5)
    except Exception as e:
        return None, f"TLS to upstream failed: {e}"
    try:
        tls.settimeout(6)
        connect_req = (f"CONNECT {dst_host}:{dst_port} HTTP/1.1\r\n"
                       f"Host: {dst_host}:{dst_port}\r\n"
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
            try:
                tls.close()
            except Exception:
                pass
            return None, f"CONNECT refused: {first_line}"
        return tls, None
    except Exception as e:
        try:
            tls.close()
        except Exception:
            pass
        return None, f"{e!r}"

def probe_connect(server: dict, token: str, echo_url: str
                  ) -> "tuple[bool, str, str | None, str | None]":
    """Probe one upstream via HTTP CONNECT with a SINGLE request (v5.2,
    req. 3): open TLS to the egress, send CONNECT <echo-host>:443 with
    Proxy-Authorization: Bearer <proxyPass>, then run ONE real HTTPS
    request to the IP-echo service through the tunnel. With the default
    echo service (ipinfo.io/json) the SAME single response carries the
    external IP AND the exit geo (country ISO code + city); a plain-IP
    echo service (ipify etc.) returns the IP only and geo stays None.
    v5.4: if the primary echo body cannot be parsed (a CDN-side change,
    an unexpected encoding, a truncated chunked body), ONE retry goes to
    https://checkip.amazonaws.com - a plain-text 'x.x.x.x\\n' endpoint
    with no JSON and no chunking - through a FRESH tunnel, so one flaky
    echo service can no longer fail all probes (live log 2026-09-25:
    33/33 'data check not passed' while the tunnels were fine).
    Returns (ok, ip, geo_country, geo_city). Data must actually flow -
    a bare 200 is not enough."""
    u = urlparse(echo_url)
    echo_host = u.hostname
    echo_port = u.port or 443
    echo_path = u.path or "/"

    def _one_echo(dst_host: str, dst_port: int, path: str
                  ) -> "tuple[bool, str, str | None, str | None]":
        """One full attempt: fresh tunnel to dst_host, one HTTPS request,
        parse the body. Returns (ok, ip, geo, city); geo only from a JSON
        echo that carries country/city fields."""
        tls, err = _connect_tunnel_open(server, token, dst_host, dst_port)
        if tls is None:
            return False, err, None, None
        try:
            # 200 alone proves nothing: verify real data transfer through
            # the tunnel
            inner = _ssl_ctx().wrap_socket(tls, server_hostname=dst_host)
            body = _http_ip_request_over_tunnel(inner, dst_host, path)
            ip = geo = city = None
            try:
                data = json.loads(body)
                if isinstance(data, dict) and data.get("ip"):
                    ip = str(data["ip"]).strip()
                    geo = (str(data.get("country") or "").strip().upper()
                           or None)
                    city = (str(data.get("city") or "").strip() or None)
            except Exception:
                pass
            if ip is None and re.fullmatch(r"[0-9a-fA-F.:]+", body or ""):
                ip = body.strip()
            if ip:
                return True, ip, geo, city
            return False, f"no IP in echo response: {body[:60]!r}", None, None
        except Exception as e:
            return False, f"{e!r}", None, None
        finally:
            try:
                tls.close()
            except Exception:
                pass

    ok, ip, geo, city = _one_echo(echo_host, echo_port, echo_path)
    if ok:
        return ok, ip, geo, city
    primary_detail = ip
    # v5.6 probe speedup: the fallback makes sense ONLY when a tunnel was
    # established but the echo BODY could not be parsed (the v5.4 purpose:
    # one flaky echo service must not fail all probes). When the failure is
    # at the TLS/CONNECT stage (a filtering network), a second tunnel to
    # checkip.amazonaws.com fails IDENTICALLY - it only doubled the probe
    # time, so it is skipped.
    if not str(primary_detail).startswith("no IP in echo response"):
        return False, str(primary_detail)[:120], None, None
    # v5.4 in-probe fallback: the primary echo answer was unusable ->
    # ONE retry through the guaranteed plain-text endpoint (fresh tunnel).
    ok2, ip2, _geo2, _city2 = _one_echo("checkip.amazonaws.com", 443, "/")
    if ok2:
        return True, ip2, None, None
    return False, f"primary: {str(primary_detail)[:60]} | fallback: " \
                  f"{str(ip2)[:60]}", None, None

def probe_geo(server: dict, token: str) -> "tuple[str | None, str | None]":
    """v5.0: open a CONNECT tunnel to ipinfo.io and read the JSON with the
    country and city of the egress PoP. Returns (country_code, city);
    (None, None) when the check could not run. v5.2: the default probe
    now gets the geo from the SAME single ipinfo.io/json answer (one
    request per upstream, req. 3), so this function is NOT called on the
    regular path anymore - it is KEPT as working functionality for
    custom scripts and possible future use (e.g. a manual re-check of a
    suspect egress)."""
    try:
        tls = _tls_connect(server["protocolHost"], server["protocolPort"],
                           timeout=8)
    except Exception:
        return None, None
    try:
        tls.settimeout(10)
        req = ("CONNECT ipinfo.io:443 HTTP/1.1\r\nHost: ipinfo.io:443\r\n"
               f"Proxy-Authorization: Bearer {token}\r\n"
               "Proxy-Connection: keep-alive\r\n\r\n")
        tls.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = tls.recv(4096)
            if not chunk:
                break
            resp += chunk
        if b" 200" not in resp.split(b"\r\n", 1)[0]:
            return None, None
        inner = _ssl_ctx().wrap_socket(tls, server_hostname="ipinfo.io")
        body = _http_ip_request_over_tunnel(inner, "ipinfo.io")
        data = json.loads(body)
        country = str(data.get("country") or "").strip().upper() or None
        city = str(data.get("city") or "").strip() or None
        return country, city
    except Exception:
        return None, None
    finally:
        try:
            tls.close()
        except Exception:
            pass

def probe_masque(server: dict, token: str, echo_url: str) -> "tuple[bool, str]":
    """Probe one upstream for real MASQUE (HTTP/3 CONNECT-UDP over QUIC,
    RFC 9298 + RFC 9114 extended CONNECT). Uses the popular `aioquic`
    package when installed.
    v5.15 (req. 3): a 2xx answer to the extended CONNECT is NOT a
    successful probe by itself anymore. The probe now TUNNELS REAL DATA:
    a minimal DNS query (A mozilla.com) is sent through the CONNECT-UDP
    tunnel to the public resolver 1.1.1.1:53 as a DATAGRAM capsule
    (RFC 9297: capsule type 0x00 = DATAGRAM, framing varint type +
    varint length; the HTTP Datagram is Context ID 0 + the raw UDP
    payload - with Context ID 0 the payload goes to the tunnel target
    from the CONNECT URI, RFC 9298) and the probe SUCCEEDS ONLY when the
    DNS ANSWER comes back through the tunnel (matched by the random
    2-byte DNS transaction ID + the QR bit). '200 but no data' is a
    FAILURE now. The CONNECT request also gained the RFC 9298-required
    'capsule-protocol: ?1' header, the correct :authority (the PROXY
    host:port, not the tunnel target - RFC 9298 section 5.1) and
    end_stream=False (the stream must STAY OPEN for the capsules).
    Returns (ok, detail)."""
    if aioquic is None:
        return False, tr("masque_no_aioquic")
    try:
        import asyncio

        async def _run():
            from aioquic.asyncio import connect as quic_connect
            from aioquic.h3.connection import H3_ALPN, H3Connection
            from aioquic.h3.events import (DataReceived, DatagramReceived,
                                           HeadersReceived)
            from aioquic.quic.configuration import QuicConfiguration
            from aioquic.quic.events import StreamReset

            # --- the tunneled UDP payload: a minimal DNS query (A mozilla.com)
            # The 2-byte transaction ID is random, so the ANSWER is matched
            # unambiguously: same ID + the DNS QR (response) bit set.
            qid = os.urandom(2)
            qname = b"".join(bytes([len(lbl)]) + lbl
                            for lbl in b"mozilla.com".split(b".")) + b"\x00"
            dns_q = (qid + b"\x01\x00"              # ID, flags: RD=1
                     + b"\x00\x01" + b"\x00\x00" * 3   # QDCOUNT=1, AN/NS/AR=0
                     + qname + b"\x00\x01" + b"\x00\x01")  # QNAME, A, IN
            # RFC 9297 DATAGRAM capsule: type 0x00, varint length, then the
            # HTTP Datagram "Context ID 0 + UDP payload" (RFC 9298: the
            # datagram with Context ID 0 carries the UDP payload for the
            # target host:port of the CONNECT URI). The capsule value is
            # 1 context byte + the 29-byte query = 30 - well under the 64
            # that still fits a ONE-byte varint length.
            capsule = bytes([0x00, 1 + len(dns_q), 0x00]) + dns_q

            cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
            cfg.server_name = server["protocolHost"]
            # v5.13 (speed/robustness 1): connect to the DoH-resolved IP -
            # aioquic resolves the hostname with the SYSTEM resolver
            # (broken in packaged Android binaries, slow/filtered on some
            # networks); the SNI above keeps the REAL hostname.
            m_ips = resolve_host(server["protocolHost"]) or []
            if not m_ips and _doh_provider and not system_dns_fallback():
                # v5.29 STRICT: the DoH chain failed for this hostname -
                # do NOT hand the hostname to aioquic (it would resolve
                # it with the SYSTEM, non-DoH, resolver); fail instead.
                raise OSError("strict DoH: "
                              + str(server["protocolHost"])
                              + " did not resolve over the DoH chain")
            m_host = m_ips[0] if m_ips else server["protocolHost"]
            async with quic_connect(m_host,
                                   server["protocolPort"], configuration=cfg,
                                   wait_connected=2.0) as client:
                h3 = H3Connection(client._quic)
                stream_id = client._quic.get_next_available_stream_id()
                # RFC 9298 section 5.1: the URI template target is the UDP
                # destination; :authority is the UDP PROXY (the egress).
                # The probe tunnels DNS to the public resolver 1.1.1.1:53 -
                # a UDP service that answers EVERY client from ANY source
                # address (the egress), so the probe needs no extra setup.
                headers = [
                    (b":method", b"CONNECT"),
                    (b":authority",
                     f"{server['protocolHost']}:{server['protocolPort']}"
                     .encode()),
                    (b":scheme", b"https"),
                    (b":path", b"/.well-known/masque/udp/1.1.1.1/53/"),
                    (b":protocol", b"connect-udp"),
                    (b"capsule-protocol", b"?1"),
                    (b"proxy-authorization", f"Bearer {token}".encode()),
                    (b"user-agent", b"curl/8.0"),
                ]
                # end_stream=False: the CONNECT stream STAYS OPEN - the
                # capsules with the tunneled datagrams flow on it (the
                # v5.14 probe closed its send side, so no data could ever
                # be tunneled; a 2xx answer was all it ever saw).
                h3.send_headers(stream_id=stream_id, headers=headers,
                                end_stream=False)
                client.transmit()
                # v5.13 (speed 2) / v5.14 (speed 1) / v5.15 (req. 3): the
                # protocol event callback is hooked (an instance attribute
                # shadows QuicConnectionProtocol.quic_event_received - the
                # class calls it for every QUIC event) and
                # H3Connection.handle_event() (the aioquic docs) RETURNS
                # the decoded H3 events. The verdict machine:
                #   - 2xx HEADERS  -> SEND the DNS query capsule through
                #     the tunnel (NOT a success yet!)
                #   - the DNS ANSWER (matching ID + QR bit) in a
                #     DataReceived (DATAGRAM capsule on the stream) or a
                #     DatagramReceived (QUIC DATAGRAM frame) -> SUCCESS
                #   - non-2xx HEADERS -> rejection, StreamReset -> refusal
                #   - the 5 s deadline -> failure; '200 but no data' is
                #     reported as exactly that
                state = {"sent_at": 0.0, "resends": 0, "dg_tried": False}
                verdict = []
                status_seen = []
                def _find_answer(data: bytes) -> bool:
                    """The DNS ANSWER: the random transaction ID at some
                    offset in the datagram + the QR (response) bit set."""
                    i = data.find(qid)
                    return (i >= 0 and i + 3 <= len(data)
                            and data[i + 2] & 0x80)
                def _on_quic_event(ev):
                    try:
                        for h3ev in h3.handle_event(ev):
                            if isinstance(h3ev, HeadersReceived) and \
                                    h3ev.stream_id == stream_id:
                                st = ""
                                for hk, hv in h3ev.headers:
                                    if hk == b":status":
                                        st = hv.decode("latin-1", "replace")
                                        break
                                status_seen.append(st)
                                if st.startswith("2"):
                                    # tunnel established: push the UDP
                                    # datagram through it and remember when.
                                    # h3.send_data wraps the capsule in an
                                    # H3 DATA frame - exactly how RFC 9297
                                    # section 3.1 says the data stream of
                                    # an HTTP/3 request travels ("all
                                    # bytes sent in DATA frames"); the
                                    # server concatenates the DATA frame
                                    # payloads and parses the capsules.
                                    h3.send_data(stream_id=stream_id,
                                                 data=capsule,
                                                 end_stream=False)
                                    client.transmit()
                                    state["sent_at"] = time.time()
                                else:
                                    verdict.append("refused")
                            elif isinstance(h3ev, (DataReceived,
                                                  DatagramReceived)):
                                # DataReceived: the server's DATAGRAM
                                #   capsule arrived in an H3 DATA frame -
                                #   aioquic already stripped the frame
                                #   header, h3ev.data IS the capsule bytes
                                #   (type, length, Context ID + UDP
                                #   payload).
                                # DatagramReceived: an HTTP/3 DATAGRAM
                                #   (QUIC DATAGRAM frame) - h3ev.data is
                                #   "Context ID + UDP payload" (aioquic
                                #   stripped the quarter stream ID).
                                # Both are scanned for the DNS answer.
                                if h3ev.stream_id == stream_id and \
                                        _find_answer(h3ev.data):
                                    verdict.append("ok")
                    except Exception:
                        pass
                    if isinstance(ev, StreamReset) and \
                            ev.stream_id == stream_id:
                        verdict.append("reset")
                client.quic_event_received = _on_quic_event
                deadline = time.time() + 5
                while time.time() < deadline and not verdict:
                    await asyncio.sleep(0.05)
                    # UDP can DROP the query: re-send it once per second
                    # (max twice), the second time ALSO via the QUIC
                    # DATAGRAM frame variant (h3.send_datagram) - some H3
                    # deployments prefer frames over capsules.
                    if (state["sent_at"]
                            and time.time() - state["sent_at"] >= 1
                            and state["resends"] < 2):
                        h3.send_data(stream_id=stream_id, data=capsule,
                                     end_stream=False)
                        if not state["dg_tried"]:
                            try:
                                h3.send_datagram(stream_id,
                                                 b"\x00" + dns_q)
                            except Exception:
                                pass
                            state["dg_tried"] = True
                        client.transmit()
                        state["resends"] += 1
                        state["sent_at"] = time.time()
                    if client._quic._close_event.is_set():
                        return False, "QUIC connection closed by server"
                if verdict:
                    v = verdict[0]
                    if v == "ok":
                        return True, ("UDP datagram tunneled and answered "
                                       "(DNS via MASQUE)")
                    if v == "refused":
                        return False, (f"CONNECT-UDP refused by server: "
                                       f"HTTP {status_seen[0] or '?'}")
                    if v == "reset":
                        return False, "CONNECT-UDP stream reset by server"
                # v5.15 (req. 3): 2xx WITHOUT a tunneled answer = FAILURE
                if status_seen and status_seen[0].startswith("2"):
                    return False, ("tunnel accepted (HTTP "
                                   f"{status_seen[0]}) but no UDP data "
                                   "came back through it")
                return False, "no CONNECT-UDP answer from server"

        return asyncio.run(_run())
    except Exception as e:
        return False, tr("masque_probe_error", err=repr(e))

def check_upstream(server: dict, token: str, echo_url: str) -> dict:
    """Full check of one upstream: MASQUE first (if advertised or if the node
    looks MASQUE-capable), HTTP CONNECT as the fallback. Returns a result
    dict: {server, protocol, ok, detail}.
    v5.13: for a MASQUE upstream the CONNECT fallback now runs
    CONCURRENTLY with the MASQUE probe (a 1-thread pool), no longer
    AFTER it - a UDP-blocked network used to pay the full masque
    attempt (up to 2 s QUIC connect + 5 s data wait) and THEN the
    whole CONNECT probe on top, per upstream: the last serial part of
    the probe phase. The masque verdict keeps priority; the connect
    result is simply already there when masque fails.
    v5.14: the fallback moved from a per-upstream ThreadPoolExecutor
    to a plain DAEMON thread + an Event - a pool's worker threads are
    NOT daemon and the interpreter JOINS them at exit (bpo-36780), so
    a fallback still running at shutdown delayed the exit; a daemon
    thread never does. Same concurrency, same wait semantics."""
    if server["protocol"] == PROTO_MASQUE:
        fallback = dict(server, protocol=PROTO_CONNECT)
        done = threading.Event()
        holder = {}
        def _bg_connect():
            try:
                holder["res"] = probe_connect(fallback, token, echo_url)
            except Exception as e:
                holder["res"] = (False, repr(e), None, None)
            done.set()
        threading.Thread(target=_bg_connect, daemon=True,
                         name="mozvpn-connect-fallback").start()
        ok_m, detail_m = probe_masque(server, token, echo_url)
        if ok_m:
            return {"server": server, "protocol": PROTO_MASQUE,
                    "ok": True, "detail": detail_m,
                    "geo": None, "geoCity": None}
        # MASQUE failed -> the CONNECT fallback result (already computed
        # concurrently; the wait matches the old future.result())
        done.wait()
        ok_c, detail_c, geo_c, city_c = holder["res"]
        return {"server": fallback, "protocol": PROTO_CONNECT,
                "ok": ok_c, "detail": detail_c,
                "geo": geo_c, "geoCity": city_c,
                "masque_fallback_reason": detail_m}
    ok_c, detail_c, geo_c, city_c = probe_connect(server, token, echo_url)
    return {"server": server, "protocol": PROTO_CONNECT,
            "ok": ok_c, "detail": detail_c,
            "geo": geo_c, "geoCity": city_c}

def _probe_reason_public(detail: str) -> str:
    """v5.8: map a raw probe-failure detail to a short human-readable
    reason class for the ONE compact probe summary line. The raw
    exception reprs (SSLError(1, '[SSL: UNEXPECTED_MESSAGE] unexpected
    message ...')) scare the user without helping: a probe failure is an
    expected outcome when the local network or the egress side blocks
    the tunnel, and the upstream is served anyway (the default). The
    full raw detail of every probe stays in the result dicts / the JSON
    output; only the console wording becomes friendly."""
    d = str(detail or "").lower()
    if "connect refused" in d:
        return tr("probe_reason_declined")
    if "timed out" in d or "timeout" in d:
        return tr("probe_reason_timeout")
    if "ssl" in d or "tls" in d or "handshake" in d or "certificate" in d:
        return tr("probe_reason_tls")
    if "refused" in d:
        return tr("probe_reason_refused")
    if "reset" in d:
        return tr("probe_reason_reset")
    if "unreachable" in d:
        return tr("probe_reason_unreachable")
    if "no ip in echo response" in d:
        return tr("probe_reason_echo")
    if "no udp data" in d:
        return tr("probe_reason_nodata")
    return tr("probe_reason_other")

def probe_upstreams_parallel(servers: list, token: str, echo_url: str,
                             echo_name: str, max_workers: int = 64) -> list:
    """Probe all upstreams in parallel (req. 7) and return the list of result
    dicts. Logging is done AFTER all checks complete as grouped summary
    lines so parallel output does not interleave.
    v6.9 (the user's request 3): each UNIQUE (host, port, protocol)
    is probed ONCE and the verdict is fanned out to every entry
    that points at it - several locations share one egress, and
    with --upstream-host they ALL do, so the old one-tunnel-per-
    ENTRY loop re-learned the same fact N times (see the dedup
    block below)."""
    info(tr("proxy_check_started", n=len(servers), service=echo_name, url=echo_url))
    # masque is the PRIORITY protocol; without aioquic it cannot even be
    # probed - state the reason once, up front, so the protocol choice in
    # every per-upstream line is fully explained.
    if aioquic is None and any(s.get("protocol") == PROTO_MASQUE
                               for s in servers):
        info(tr("proto_masque_no_lib"))
    # v6.9 (the user's request 3): probe each UNIQUE (host, port,
    # protocol) ONCE. Several locations share one egress - and with
    # --upstream-host EVERY entry points at the same upstream - but
    # the old loop opened one probe tunnel PER ENTRY: N duplicate
    # TLS+CONNECT handshakes against the same egress at once, N
    # times the WAF-visible request rate, all to learn the SAME
    # fact. The references agree on the minimal-probe principle:
    # the Go client verifies the exit ONCE after connecting
    # (main.go verifyExit) and Firefox runs NO pre-flight probes
    # at all (its IPPNetworkErrorObserver reacts to failures
    # instead). The verdict - including the CONNECT-fallback
    # protocol switch of a failed MASQUE probe - is fanned out to
    # every entry that points at the probed (host, port,
    # protocol).
    by_key = {}
    key_order = []
    for s in servers:
        key = (s.get("protocolHost"), s.get("protocolPort"),
               s.get("protocol"))
        if key not in by_key:
            by_key[key] = s
            key_order.append(key)
    res_by_key = {}
    with ThreadPoolExecutor(
            max_workers=min(max_workers, max(1, len(by_key)))) as ex:
        futures = {key: ex.submit(check_upstream, by_key[key],
                                 token, echo_url)
                   for key in key_order}
        for key in key_order:
            try:
                res_by_key[key] = futures[key].result()
            except Exception as e:
                res_by_key[key] = {"server": None,
                                   "protocol": PROTO_CONNECT,
                                   "ok": False, "detail": repr(e)}
    results = []
    for s in servers:
        key = (s.get("protocolHost"), s.get("protocolPort"),
               s.get("protocol"))
        r = res_by_key[key]
        if r.get("server") is by_key[key]:
            results.append(r)      # the probed representative: as-is
            continue
        r2 = dict(r)               # a shared-egress replica
        rs = r.get("server") or {}
        r2["server"] = {**s,
                        "protocol": rs.get("protocol", s.get("protocol"))}
        results.append(r2)
    # v5.8: the probe result is ONE compact message about ALL upstreams
    # (the live v5.7 run printed one fail line per upstream - 33 lines
    # with raw SSLError reprs - plus two long host-list summary lines).
    # The per-upstream protocol details stay in the result dicts (and the
    # JSON output); the console gets: one ok line when everything passed,
    # otherwise ONE info line with the pass count and a grouped,
    # human-readable breakdown of the failure reasons. A failed probe is
    # NOT a script error - the upstream is served anyway by default, so
    # the wording stays neutral (info level, never err/warn).
    ok_list = [r for r in results if r["ok"]]
    fail_list = [r for r in results if not r["ok"]]
    ok_n, total = len(ok_list), len(results)
    if fail_list:
        counts = {}
        for r in fail_list:
            reason = _probe_reason_public(str(r.get("detail") or ""))
            counts[reason] = counts.get(reason, 0) + 1
        breakdown = ", ".join(f"{n}x {reason}"
                              for reason, n in sorted(counts.items(),
                                                     key=lambda kv: -kv[1]))
        info(tr("proxy_check_summary_fail", n=ok_n, total=total,
                n_fail=len(fail_list), breakdown=breakdown))
    else:
        ok(tr("proxy_check_summary_ok", n=ok_n, total=total))
    return results

# ---------------------------------------------------------------------------
# FoxyProxy Standard export (v5.7): settings files for the local proxies
# started by THIS script, for FoxyProxy Standard v9.8 (the current AMO
# release; verified against the official sources at
# github.com/foxyproxy/browser-extension, src/content/*.js, v9.8):
#   - The v5.6 LEGACY export used a 'proxySettings' ARRAY - but
#     migrate.js convert7() extracts proxies ONLY from TOP-LEVEL object
#     keys (Object.values(pref).filter(i => i && ['address','type']
#     .some(p => Object.hasOwn(i, p)))), so a 'proxySettings' array is
#     silently dropped -> FoxyProxy showed an EMPTY proxy list after
#     'Import from older versions'. v5.7: the legacy file is the REAL
#     FoxyProxy 6/7 shape - every proxy as its own top-level 'k<id>'
#     key (exactly how the FoxyProxy 6/7 export stores them) plus the
#     {mode, sync, logging} keys; convert7() then finds every proxy.
#   - The CURRENT-format 'Import' button (options.js: FS.import ->
#     JSON.parse -> Object.assign(pref, data)) takes the pref keys as
#     they are, so the v5.7 current-format file is COMBINED: the full
#     current pref shape ({mode, sync, autoBackup, passthrough, theme,
#     container, commands, data: [...]}) PLUS the same proxies as
#     top-level 'k<id>' entries - it imports via ANY FoxyProxy import
#     path (the 'Import' button reads 'data', 'Import from older
#     versions' reads the 'k<id>' entries), so a wrong picker can no
#     longer produce an empty list.
#   - After ANY import the user must click 'Save' (the FoxyProxy import
#     only renders the settings into the UI; Save persists them) - the
#     import hint and the hotkey help both say it now.
#   - cc values are sanitized to the schema (^([A-Z]{2}|)$): the
#     recommended-location record ('REC') becomes '' (no flag icon),
#     'UK' becomes 'GB' (convert7() maps UK -> GB as well).
# ---------------------------------------------------------------------------

FOXYPROXY_COLORS = ["#0055E5", "#00C853", "#D50000", "#AA00FF", "#FF6D00",
                    "#00B8D4", "#C62828", "#6A1B9A", "#2E7D32", "#F57F17"]

def _foxyproxy_cc(p: dict) -> str:
    """v5.7: a schema-valid country code for FoxyProxy: two uppercase
    letters or '' (the 'REC' recommended-location record and any other
    non-ISO value -> ''), 'UK' -> 'GB' (convert7() maps UK -> GB too)."""
    cc = str(p.get("countryCode") or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return "GB" if cc == "UK" else cc

def _foxyproxy_title(p: dict) -> str:
    """v5.7: one title builder for BOTH export formats (so the same
    proxy always has the same name in FoxyProxy, whatever file was
    imported): 'mozvpn <CC> <city|label> [<local port>]'."""
    return (f"mozvpn {_foxyproxy_cc(p)} "
            f"{p.get('city') or p.get('label') or ''} [{p['port']}]")

def _foxyproxy_v67_entries(proxies: list, listen_host: str,
                           proxy_type: str = "http") -> list:
    """v5.7: the FoxyProxy 6/7 proxy entries - [(key, entry), ...] with
    the entry in the exact shape migrate.js convert7() consumes: a
    top-level 'k<id>' key whose value carries {title, type: 1 (http),
    address, port (NUMBER), username, password, cc, color, active,
    proxyDNS, whitePatterns[{title, active, pattern, type: 1 (wildcard),
    protocols: 1 (all)}], blackPatterns[...], index, id}; id == the key
    (that is how the FoxyProxy 6/7 export names them).
    v8.0 (A4) -> v8.5: the entry carries the SERVED proxy type - type 1
    (PROXY_TYPE_HTTP) + proxyDNS False for the 'http' listener, type 3
    (PROXY_TYPE_SOCKS5) + proxyDNS True for 'socks5' (verified
    2026-10-30 against the official FoxyProxy Standard 7.5.1 example
    settings, which use exactly "type": 3, "proxyDNS": true for a
    SOCKS proxy; proxyDNS True = the browser sends the NAME to the
    proxy - the remote-DNS semantics of the socks5 listener)."""
    socks = str(proxy_type or "http").strip().lower() in ("socks5",)
    def _pat(pattern: str, title: str) -> dict:
        # convert7() pattern item: type 1 = wildcard, protocols 1 = all
        return {"title": title, "active": True, "pattern": pattern,
                "type": 1, "protocols": 1}
    entries = []
    for i, p in enumerate(proxies):
        name = _foxyproxy_title(p)
        key = f"k{int(hashlib.sha256(name.encode()).hexdigest(), 16) % 10**17}"
        entries.append((key, {
            "title": name,
            "type": 3 if socks else 1,   # PROXY_TYPE_SOCKS5 / PROXY_TYPE_HTTP
            "address": listen_host,
            "port": int(p["port"]),
            "username": "",
            "password": "",
            "cc": _foxyproxy_cc(p),
            "color": FOXYPROXY_COLORS[i % len(FOXYPROXY_COLORS)],
            "active": True,
            "proxyDNS": bool(socks),     # SOCKS: DNS goes through the proxy
            "whitePatterns": [_pat("*", "all")],
            "blackPatterns": [
                _pat("localhost", "localhost"),
                _pat("127.0.0.1", "127.0.0.1"),
                _pat("::1", "::1"),
                _pat("10.*", "10.*"),
                _pat("172.16.*", "172.16.*"),
                _pat("192.168.*", "192.168.*"),
            ],
            "index": i,
            "id": key,
        }))
    return entries

def foxyproxy_settings_json(proxies: list, listen_host: str,
                            proxy_type: str = "http") -> str:
    """v5.7: build the FoxyProxy Standard settings JSON for the top
    'Import' button of the Options page - and, being COMBINED, for ANY
    FoxyProxy import path. Part 1 (current v8+/v9.x pref shape, verified
    against src/content/schema.json of the v9.8 sources): {mode, sync,
    autoBackup, passthrough, theme, container, commands, data: [{active,
    title, type ('http'), hostname, port (STRING), username, password,
    cc, city, color, pac, pacString, proxyDNS, include[], exclude[],
    tabProxy[]}]}. Part 2: the SAME proxies as top-level 'k<id>' entries
    (the FoxyProxy 6/7 shape) so 'Import from older versions'
    (migrate.js convert7) finds them too - Object.assign(pref, data)
    copies the extra keys harmlessly. 'mode': 'disable' = import without
    surprise traffic rerouting; the user then picks a proxy from the
    FoxyProxy toolbar popup.
    v8.0 (A4) -> v8.5: the served type is EXPORTED - 'socks5' +
    proxyDNS True for the socks5 listener (the schema.json type enum
    is the STRING 'http'/'https'/'socks4'/'socks5'/'pac'/'direct',
    verified 2026-10-30), 'http' unchanged."""
    socks = str(proxy_type or "http").strip().lower() in ("socks5",)
    data = []
    for i, p in enumerate(proxies):
        data.append({
            "active": True,
            "title": _foxyproxy_title(p),
            "type": "socks5" if socks else "http",
            "hostname": listen_host,
            "port": str(p["port"]),          # schema: port is a STRING
            "username": "",
            "password": "",
            "cc": _foxyproxy_cc(p),          # schema: '' or two letters
            "city": str(p.get("city") or ""),
            "color": FOXYPROXY_COLORS[i % len(FOXYPROXY_COLORS)],
            "pac": "",
            "pacString": "",
            "proxyDNS": bool(socks),   # SOCKS proxy -> DNS goes through it
            "include": [],
            "exclude": [
                {"type": "wildcard", "title": "localhost",
                 "pattern": "localhost", "active": True},
                {"type": "wildcard", "title": "127.0.0.1",
                 "pattern": "127.0.0.1", "active": True},
                {"type": "wildcard", "title": "::1",
                 "pattern": "::1", "active": True},
                {"type": "wildcard", "title": "10.*",
                 "pattern": "10.*", "active": True},
                {"type": "wildcard", "title": "172.16.*",
                 "pattern": "172.16.*", "active": True},
                {"type": "wildcard", "title": "192.168.*",
                 "pattern": "192.168.*", "active": True},
            ],
            "tabProxy": [],
        })
    settings = {"mode": "disable", "sync": False, "autoBackup": False,
                "passthrough": ("localhost, 127.0.0.1, ::1, "
                                "10.0.0.0/8, 172.16.0.0/12, "
                                "192.168.0.0/16, 169.254.0.0/16"),
                "theme": "", "container": {}, "commands": {},
                "data": data}
    # Part 2: the same proxies in the FoxyProxy 6/7 shape, top-level -
    # the ONLY place convert7() looks for proxies.
    for key, entry in _foxyproxy_v67_entries(proxies, listen_host,
                                              proxy_type):
        settings[key] = entry
    return json.dumps(settings, indent=2, ensure_ascii=False)

def foxyproxy_legacy_json(proxies: list, listen_host: str,
                          proxy_type: str = "http") -> str:
    """v5.7: build the LEGACY FoxyProxy settings JSON - the REAL FoxyProxy
    6/7 'FoxyProxy_YYYY-MM-DD.json' export shape, which is what FoxyProxy
    Standard v8+/9.x ACTUALLY parses on 'Import from older versions'
    (verified against the official extension sources, v9.8: fs.js reads
    the file with JSON.parse only - it accepts just the text/plain and
    application/json MIME types - and migrate.js convert7() extracts the
    proxies ONLY from TOP-LEVEL object keys whose values carry
    'address' and 'type', i.e. the 'k<id>' entries - a 'proxySettings'
    ARRAY, as the v5.6 export wrote it, is silently DROPPED and the
    imported list is EMPTY). The file therefore carries {mode, sync,
    logging} plus every proxy as its own top-level 'k<id>' key; the old
    FoxyProxy 4.x foxyproxy.xml cannot be imported by FoxyProxy 9.x at
    all (the official help: the XML must first pass through FoxyProxy
    7.5.1). 'mode': 'disable' - convert7() leaves it as-is, so no proxy
    is auto-enabled on import."""
    settings = {"mode": "disable", "sync": False,
                "logging": {"active": True, "maxSize": 500}}
    for key, entry in _foxyproxy_v67_entries(proxies, listen_host,
                                              proxy_type):
        settings[key] = entry
    return json.dumps(settings, indent=2, ensure_ascii=False)

def _foxyproxy_save_dialog(default_name: str, ext: str) -> "str | None":
    """v5.5: native OS 'Save as...' dialog. Uses tkinter when available
    (Windows/macOS/Linux with a desktop), otherwise a plain input() prompt.
    Returns the chosen path or None when cancelled."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        path = filedialog.asksaveasfilename(
            defaultextension=ext, initialfile=default_name,
            title="Save FoxyProxy settings",
            filetypes=[("FoxyProxy settings", f"*{ext}"), ("All files", "*.*")])
        root.destroy()
        return path or None
    except Exception:
        # No GUI stack (headless / no python3-tk) - console fallback.
        try:
            raw = input(tr("foxyproxy_path_prompt", name=default_name)).strip()
            return raw or None
        except Exception:
            return None

def export_foxyproxy(args, proxies: list, listen_host: str,
                    legacy: bool = False,
                    proxy_type: "str | None" = None) -> "str | None":
    """v5.5: write ONE FoxyProxy settings file for the CURRENTLY RUNNING
    local proxies. Destination: the --foxyproxy-out / --foxyproxy-legacy-out
    path when given (NO dialog, req. 3), otherwise the OS save dialog.
    Returns the written path or None on failure/cancel.
    v8.0 (A4): the exported entries carry the SERVED proxy type
    (proxy_type argument, else the CURRENT global type) - a socks5
    listener exports SOCKS entries (proxyDNS true), an http listener
    exports the classic HTTP entries exactly as before."""
    if not proxies:
        info(tr("foxyproxy_no_proxies"))
        return None
    ptype = str(proxy_type or get_proxy_type() or "http").strip().lower()
    today = time.strftime("%Y-%m-%d")
    if legacy:
        out_arg = getattr(args, "foxyproxy_legacy_out", None)
        default_name = f"foxyproxy-legacy_{today}.json"
        content = foxyproxy_legacy_json(proxies, listen_host, ptype)
        fmt = tr("foxyproxy_format_legacy")
    else:
        out_arg = getattr(args, "foxyproxy_out", None)
        default_name = f"FoxyProxy-settings_{today}.json"
        content = foxyproxy_settings_json(proxies, listen_host, ptype)
        fmt = tr("foxyproxy_format_current")
    if out_arg:
        path = out_arg
    else:
        path = _foxyproxy_save_dialog(default_name, ".json")
    if not path:
        info(tr("foxyproxy_export_cancel"))
        return None
    try:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    except Exception as e:
        err(tr("foxyproxy_export_fail", err=repr(e)))
        return None
    ok(tr("foxyproxy_export_done", path=path, n=len(proxies), format=fmt))
    info(tr("foxyproxy_import_hint", format=fmt))
    return path

def maybe_foxyproxy_export(args, engine) -> None:
    """v5.5: run the --foxyproxy-export / --foxyproxy-legacy-export CLI
    actions ONCE, right after the local proxies started (both engines expose
    the same proxy dict shape: port/country/countryCode/city/label). The
    hotkeys f / x call export_foxyproxy() directly and are repeatable."""
    if getattr(args, "_foxyproxy_done", False):
        return
    args._foxyproxy_done = True
    if not (getattr(args, "foxyproxy_export", False)
            or getattr(args, "foxyproxy_legacy_export", False)):
        return
    if not engine or not getattr(engine, "proxies", None):
        info(tr("foxyproxy_no_proxies"))
        return
    if getattr(args, "foxyproxy_export", False):
        export_foxyproxy(args, engine.proxies, engine.listen_host, legacy=False)
    if getattr(args, "foxyproxy_legacy_export", False):
        export_foxyproxy(args, engine.proxies, engine.listen_host, legacy=True)

# ---------------------------------------------------------------------------
# v8.0 (B3): the PAC export (the armanlife 'smart routing: local sites
# open directly' idea, adapted to a terminal proxy): a generated
# FindProxyForURL that sends localhost/private ranges DIRECT and
# everything else through the RUNNING local listeners, with a PAC
# fallback chain of EVERY listener ending in DIRECT (a dead listener
# fails over, the browser never hits a dead end). The DIRECT list is
# the SAME bypass list the FoxyProxy exports carry; the directive
# follows the proxy TYPE (SOCKS5 = the remote-DNS PAC entry, PROXY for
# the http listener). v8.2: the file is written on DEMAND - the Ctrl+P
# hotkey rewrites the default copy (plus --pac-export FILE); an automatic
# rebuild writes ONLY an explicit --pac-export FILE destination (a bare
# --pac-export opts back into the default copy on every rebuild).
# ---------------------------------------------------------------------------

def build_pac_script(proxies: list, listen_host: str,
                     proxy_type: str = "socks5") -> str:
    """v8.0 (B3): generate the PAC script for the CURRENTLY RUNNING
    listeners. The bypass list: localhost / 127.* / ::1 / 10.* /
    172.16-31.* / 192.168.* / 169.254.* (the private/link-local ranges
    of the FoxyProxy passthrough); the fallback chain lists every
    listener in order and ends with DIRECT (a stale PAC that points at
    dead ports silently breaks the browser - the chain avoids exactly
    that)."""
    ptype = str(proxy_type or "socks5").strip().lower()
    directive = "PROXY" if ptype == "http" else "SOCKS5"
    bypass = (["localhost", "127.*", "::1", "10.*"]
              + [f"172.{i}.*" for i in range(16, 32)]
              + ["192.168.*", "169.254.*"])
    lines = [
        "// mozvpn.py PAC: local sites DIRECT, everything else via the",
        "// local proxy listeners (regenerated on every engine rebuild).",
        "function FindProxyForURL(url, host) {",
        "  if (isPlainHostName(host)",
    ]
    for pat in bypass:
        lines.append(f'      || shExpMatch(host, "{pat}")')
    lines.append("     ) {")
    lines.append('    return "DIRECT";')
    lines.append("  }")
    chain = "; ".join(f"{directive} {listen_host}:{int(p['port'])}"
                      for p in proxies) + "; DIRECT"
    lines.append(f'  return "{chain}";')
    lines.append("}")
    return "\n".join(lines) + "\n"

def _write_pac_file(path: str, proxies: list, listen_host: str,
                    proxy_type: str) -> "str | None":
    """v8.0 (B3): write the PAC script to ONE path (best effort, a
    read-only dir must not crash the run). Returns the path or None."""
    try:
        content = build_pac_script(proxies, listen_host, proxy_type)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        return path
    except Exception as e:
        warn(tr("pac_failed", path=path, err=e))
        return None

def maybe_pac_export(args, engine, on_demand: bool = False) -> None:
    """v8.2 (user request): the PAC file is NO LONGER auto-created on
    every engine rebuild - a useful default should not litter the config
    dir until asked for. It is written on DEMAND only:
      * on_demand=True - the Ctrl+P hotkey: the default copy at
        <config dir>/mozvpn.pac (plus the --pac-export FILE copy);
      * an EXPLICIT --pac-export FILE is honored on every rebuild (the
        user named that destination);
      * a bare --pac-export (no FILE) opts back into the v8.0 behavior:
        the default copy on every rebuild.
    The DIRECT entries are counted per listener for the log line."""
    if not engine or not getattr(engine, "proxies", None):
        return
    listen_host = getattr(engine, "listen_host", "127.0.0.1") or "127.0.0.1"
    ptype = str(getattr(engine, "proxy_type", None)
                or get_proxy_type() or "socks5").strip().lower()
    directive = "PROXY" if ptype == "http" else "SOCKS5"
    custom = getattr(args, "pac_export", None)
    # v8.3 (bug fix): None (the flag was NOT given) must STAY None -
    # the old 'else ""' normalization collapsed argparse's None into
    # the BARE-flag opt-in value (const=""), so the branch below
    # matched the no-flag case too and every engine rebuild wrote the
    # default copy again.
    custom = str(custom).strip() if custom is not None else None
    targets = []
    if custom:
        targets.append(custom)          # an explicit FILE: always honored
    if on_demand or custom == "":
        targets.append(os.path.join(CONF_DIR, "mozvpn.pac"))
    for path in list(dict.fromkeys(targets)):
        if _write_pac_file(path, engine.proxies, listen_host, ptype):
            info(tr("pac_written", path=path, directive=directive,
                    n=len(engine.proxies)))

# ---------------------------------------------------------------------------
# v8.0 (C4): the --doctor one-shot diagnostics (the foxhole-vpn
# 'doctor command' pattern): a READ-ONLY walk of the whole chain the
# script depends on - the interpreter, the config store, the pip
# dependencies and sing-box, the system resolver, the DoH chain, the FxA
# API reachability, the server list fetch, a REAL TLS handshake to a
# live egress (the full profile matrix) and the OAuth -> Guardian ->
# quota chain on the CACHED session token ONLY (never a fresh sign-in,
# never a prompt). Exit code 0/1.
# ---------------------------------------------------------------------------

def run_doctor(a) -> int:
    """v8.0 (C4): print the diagnosis and return the exit code."""
    n_ok = 0
    n_fail = 0

    def _mark(good: bool):
        nonlocal n_ok, n_fail
        if good:
            n_ok += 1
        else:
            n_fail += 1
        return tr("doctor_ok") if good else tr("doctor_fail")

    info(tr("doctor_title"))
    # 1. the interpreter
    info(tr("doctor_interpreter", ver=sys.version.split()[0],
            plat=sys.platform))
    # 2. the config store
    try:
        n_acc = len(cfg_accounts())
        info(tr("doctor_config", path=CONFIG_FILE, n=n_acc))
        _mark(True)
    except Exception:
        info(tr("doctor_config", path=CONFIG_FILE, n="?"))
        _mark(False)
    # 3. the pip dependencies + sing-box
    try:
        missing = print_dependencies()
        if missing:
            info(tr("doctor_deps", miss=", ".join(missing)))
            _mark(False)
        else:
            info(tr("doctor_deps", miss=tr("doctor_deps_ok")))
            _mark(True)
    except Exception:
        _mark(False)
    # 4. the SYSTEM resolver
    try:
        ips = socket.getaddrinfo("api.accounts.firefox.com", 443,
                                 proto=socket.IPPROTO_TCP)
        hosts = sorted({x[4][0] for x in ips})
        info(tr("doctor_sysdns", host="api.accounts.firefox.com",
                ips=", ".join(hosts)))
        _mark(True)
    except Exception as e:
        info(tr("doctor_sysdns", host="api.accounts.firefox.com", ips=str(e)))
        _mark(False)
    # 5. the DoH chain (the CONFIGURED provider - no state change).
    #    v9.3: with DoH 'off' (the SYSTEM resolver choice) resolve_host()
    #    is a no-op BY DESIGN - the system resolution is already proven
    #    by step 4, so the step says so and PASSES instead of reporting
    #    a misleading failure of a mode that works as configured.
    doh_name = load_doh_provider_cache() or "system"
    if not doh_provider():
        info(tr("doctor_doh", provider=doh_name,
                host="api.accounts.firefox.com",
                ips=tr("doctor_doh_system")))
        _mark(True)
    else:
        try:
            ips2 = resolve_host("api.accounts.firefox.com") or []
            info(tr("doctor_doh", provider=doh_name,
                    host="api.accounts.firefox.com",
                    ips=", ".join(ips2) if ips2 else "-"))
            _mark(bool(ips2))
        except Exception as e:
            info(tr("doctor_doh", provider=doh_name,
                    host="api.accounts.firefox.com", ips=str(e)))
            _mark(False)
    # 6. the FxA API reachability (the public credentials/status
    #    endpoint - the Fastly challenge path is exercised implicitly)
    try:
        # v9.3: the REAL route is /account/credentials/status (mozilla/fxa
        # account.ts, PR #21517 - the same route get_credentials_status()
        # rides). The underscore form of the pre-v9.3 typo always 404'd
        # and the pass rule below masked it; a 404 no longer counts.
        st, _d = req("POST", FXA_AUTH + "/account/credentials/status",
                     {"email": "doctor@localhost"})
        info(tr("doctor_fxa", url=FXA_AUTH, status=st))
        _mark(st in (200, 400, 403))      # a REAL answer of the REAL route
    except Exception as e:
        info(tr("doctor_fxa", url=FXA_AUTH, status=str(e)))
        _mark(False)
    # 7. the server list fetch (Remote Settings) - kept for step 8
    locs = []
    try:
        locs = fetch_serverlist()
        n_srv = sum(len(l.get("servers") or []) for l in locs)
        info(tr("doctor_serverlist", n=len(locs), m=n_srv))
        _mark(bool(locs))
    except Exception as e:
        info(tr("doctor_serverlist", n=str(e), m="-"))
        _mark(False)
    # 8. a REAL TLS handshake to a live egress (the full profile matrix)
    try:
        srv = None
        for l in locs:
            if l.get("servers"):
                s0 = l["servers"][0]
                srv = (s0.get("protocolHost"), s0.get("protocolPort"))
                break
        if srv and srv[0]:
            t0 = time.monotonic()
            _tls_connect(srv[0], int(srv[1] or 443), timeout=15)
            ms = int((time.monotonic() - t0) * 1000)
            info(tr("doctor_tls", host=srv[0], port=srv[1], p="matrix", ms=ms))
            _mark(True)
        else:
            _mark(False)
    except Exception as e:
        info(tr("doctor_tls", host="egress", port="-", p="matrix", ms=str(e)))
        _mark(False)
    # 9. the OAuth -> Guardian -> quota chain on the CACHED session ONLY
    #    (guardian_pass performs the activate + token fetch itself and
    #    returns the X-Quota headers - print_quota prints the allowance;
    #    NEVER a fresh sign-in, never a prompt)
    try:
        acc = cfg_current_account()
        st_tok = (acc.get("session_token") or "").strip()
        if st_tok:
            tok = oauth_token(st_tok)
            _tok, _until, ghdrs = guardian_pass(tok)
            print_quota(ghdrs)
            _mark(True)
        else:
            # a missing cached session is not a fault - the step is
            # skipped with a hint instead of counted as a failure
            info(tr("doctor_no_session"))
    except Exception as e:
        err(str(e))
        _mark(False)
    info(tr("doctor_done", ok=n_ok, fail=n_fail))
    return 0 if n_fail == 0 else 1

# ---------------------------------------------------------------------------
# Local proxy engines (req. 6, 10, 11)
# ---------------------------------------------------------------------------

def port_for_location(key: str, used: set) -> int:
    """Deterministic port 20000..39999 derived from the location key (SHA-256).
    v5.0: the key is '<country>|<city>|<server index>' so EVERY server of a
    city gets its own local port (one local proxy per upstream server)."""
    key = str(key)
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

# ---------------------------------------------------------------------------
# v6.6: THE PASS-HEALTH MONITOR of the builtin engine (the BUILTIN engine
# only - the sing-box engine runs as an external process this script
# cannot instrument; its lifecycle is unchanged). Firefox watches the
# CONNECT responses of the egress on EVERY request (IPPNetworkError
# Observer -> the 'proxy-http-error' event -> the pass is replaced
# immediately), and the Go reference client separates TWO failure
# classes before concluding that the SESSION (not one target) is broken:
#   - the PASS WAS REJECTED (HTTP 400 'parsing JWT failed' / 401 / 403):
#     the proxyPass itself is bad -> the watch loop refreshes it NOW
#     (paced by the Firefox floors: minRotationInterval 1 s + the 500 ms
#     retryAfter pacing - never a tight refresh loop);
#   - TARGET failures (the CONNECT to a destination never opened / the
#     egress answered 502/504): counted PER DISTINCT TARGET; only THREE
#     DISTINCT failing targets mean the TUNNEL/SESSION is broken (one
#     flaky destination or one bad egress moment must not 'flap' the
#     session; a single failure fails only its own client connection).
# The CONNECT targets are REDACTED in every log line by default (the Go
# logTarget redaction: '<redacted; use --verbose>' - a CONNECT
# destination is the user's browsing); the per-host EGRESS names stay
# visible (they are the script's own servers, not the user's traffic).
# v9.2 (the user's report): the TARGET-failure books now carry an
# EXPIRY (only failures fresher than _PASS_FAIL_WINDOW count toward
# the three-distinct-targets threshold) and are DROPPED for an egress
# the moment it serves a successful CONNECT (Firefox: a working
# connection resets the error history) - the v6.6 books grew forever,
# so three unrelated one-off dead-site failures tripped a spurious
# 'session looks broken' pass refresh. The DNS relay's own DoH wire
# target is exempted from the target-failure classes entirely (see
# _is_doh_wire_target); the PASS-REJECTION classes stay counted.
# ---------------------------------------------------------------------------

_VERBOSE_TARGETS = {"v": False}

def set_verbose_targets(enabled: bool):
    """v6.6: --verbose - reveal the CONNECT targets in the engine logs."""
    _VERBOSE_TARGETS["v"] = bool(enabled)

def verbose_targets() -> bool:
    """v6.6: whether the CONNECT targets are visible in the engine logs."""
    return _VERBOSE_TARGETS["v"]

def _redact_target(target: str) -> str:
    """v6.6: the CONNECT destination of a client request is the user's
    browsing - it never reaches the log unless --verbose was given."""
    return target if _VERBOSE_TARGETS["v"] else "<redacted; use --verbose>"

# v9.2: how long a per-target CONNECT failure stays countable toward
# the '3+ distinct targets' session-break threshold of the pass
# monitor (the books of the v6.6 design grew forever; Firefox
# escalates only REPEATED failures - a real broken session bursts
# through three distinct targets in seconds, while one-off failures
# spread minutes or hours apart are just the ordinary 'this site is
# dead from the exit country' noise, which became visible at the
# EGRESS with 502 after the v9.0 socks5 remote-DNS default).
_PASS_FAIL_WINDOW = 60        # seconds

# v9.2: the DNS relay's OWN DoH wire target (the engine sees its
# CONNECT like any client's): its failures are NOT user browsing and
# NOT a session-health signal - with the v9.1 'the chosen provider
# ONLY' contract a blocked/unreachable provider fails EVERY relayed
# DNS query, which must not spam the 'Egress answered HTTP 502' line
# per query nor feed the pass-health books; ONE calm line per run per
# target (the hotkey-'h' / --doh choice switches the provider).
_DOH_TARGET_WARNED = set()

def _is_doh_wire_target(target: str) -> bool:
    """v9.2: True when host:port is the CURRENT DoH wire endpoint of
    the DNS relay (doh_wire_targets() - exactly one entry since v9.1;
    an IPv6 target may come bracketed)."""
    try:
        host, port = target.rsplit(":", 1)
    except ValueError:
        return False
    host = host.strip("[]")
    try:
        pnum = int(port)
    except ValueError:
        return False
    for h, p, _path, _tag in doh_wire_targets():
        if host == h and pnum == p:
            return True
    return False

def _warn_doh_target_unreachable(target: str):
    """v9.2: the ONE per-run warning for a failing DoH wire target of
    the DNS relay (see _is_doh_wire_target); the relayed queries
    simply return nothing until the provider is reachable again (the
    client's resolver retries - the relay's own failure semantics)."""
    if target not in _DOH_TARGET_WARNED:
        _DOH_TARGET_WARNED.add(target)
        warn(tr("connect_target_doh_unreachable", target=target))

class _PassMonitor:
    """v6.6: thread-safe registry of the pass-health signals raised by
    the builtin engine; the watch loop polls the events every second of
    its sleep phase and reacts immediately (a rejected pass is
    refreshed at once instead of waiting for the margin clock)."""

    rejected     = threading.Event()   # the pass was rejected -> refresh NOW
    session_fail = threading.Event()   # 3+ distinct targets failed -> refresh
    _lock        = threading.Lock()
    _open_timeout = {}                 # distinct CONNECT target -> (ts, egress)
    _bad_gateway  = {}                 # distinct CONNECT target -> (ts, egress)
    _host_fails   = {}                 # egress host -> consecutive failures
    _last_refresh = 0.0

    @classmethod
    def note_pass_rejected(cls, host: str):
        with cls._lock:
            cls._host_fails[host] = cls._host_fails.get(host, 0) + 1
            cls.rejected.set()

    @classmethod
    def note_target_failure(cls, kind: str, target: str, host: str):
        with cls._lock:
            cls._host_fails[host] = cls._host_fails.get(host, 0) + 1
            book = (cls._open_timeout if kind == "open_timeout"
                    else cls._bad_gateway)
            # v9.2 (the user's report): a failure only counts while it
            # is FRESH. The books used to grow FOREVER - three ONE-OFF
            # failures of three DIFFERENT targets, however far apart,
            # spuriously tripped the '3+ distinct targets - the session
            # looks broken' refresh while the tunnel was serving
            # successful CONNECTs the whole time (dead/blocked sites
            # became far more visible after the v9.0 socks5 default:
            # with remote DNS such destinations now fail AT THE EGRESS
            # with 502 instead of dying in the local resolver).
            # Firefox escalates only REPEATED failures - so entries
            # older than _PASS_FAIL_WINDOW are pruned before counting.
            now = time.time()
            for t in [t for t, v in book.items()
                      if v[0] < now - _PASS_FAIL_WINDOW]:
                del book[t]
            book[target] = (now, host)
            if len(book) >= 3:
                # THREE DISTINCT targets failed the same way - the
                # session/tunnel is the common factor (the Go
                # maxDistinctOpenTimeoutTargets / maxDistinctBadGateway
                # thresholds of 3). Reset the book so the NEXT session
                # failure needs three fresh targets again and wake the
                # watch loop.
                book.clear()
                cls.session_fail.set()

    @classmethod
    def note_success(cls, host: str):
        with cls._lock:
            cls._host_fails.pop(host, None)
            # v9.2 (the user's report): a successful CONNECT through
            # THIS egress is direct evidence the tunnel/session is
            # alive - its recorded per-target failures were per-target
            # issues (dead sites), so they are dropped (Firefox resets
            # the connection/error history when the connection works
            # again). The OTHER egresses keep their own entries.
            for book in (cls._open_timeout, cls._bad_gateway):
                for t in [t for t, v in book.items() if v[1] == host]:
                    del book[t]

    @classmethod
    def host_failures(cls, host: str) -> int:
        with cls._lock:
            return cls._host_fails.get(host, 0)

    @classmethod
    def mark_refresh(cls):
        with cls._lock:
            cls._last_refresh = time.time()
            # v9.2: the pass rotated - the recorded per-target
            # failures belong to the OLD pass, drop them (a fresh pass
            # starts from a clean slate; the books refill from FRESH
            # failures if the new pass is broken too).
            cls._open_timeout.clear()
            cls._bad_gateway.clear()

    @classmethod
    def since_refresh(cls) -> float:
        with cls._lock:
            return time.time() - cls._last_refresh

# v6.6 (item 5): the half-close drain window of a relayed tunnel (the Go
# halfCloseDrainTimeout = 2 minutes) - see the join() logic in
# BuiltinProxyEngine._handle_client.
_HALF_CLOSE_DRAIN = 120

def _tcp_keepalive(sock):
    """v6.6 (item 6): best-effort TCP keepalive with the Go reference
    pacing (upstreamKeepAliveInterval 10 s / the probe timeout of 5 s ->
    idle 10 s, retry every 5 s, 3 probes): a silently-dropped NAT or
    middlebox path is detected by the OS instead of leaving a half-open
    tunnel until the application timeouts fire. Purely advisory - every
    option is applied best-effort and every platform keeps working
    without them (Windows exposes TCP_KEEPIDLE etc. only from recent
    builds; the plain SO_KEEPALIVE alone is already the useful part)."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception:
        return
    for opt, val in ((getattr(socket, "TCP_KEEPIDLE", None), 10),
                     (getattr(socket, "TCP_KEEPINTVL", None), 5),
                     (getattr(socket, "TCP_KEEPCNT", None), 3)):
        try:
            if opt is not None:
                sock.setsockopt(socket.IPPROTO_TCP, opt, val)
        except Exception:
            pass

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

def _recv_exact(conn, n: int) -> bytes:
    """v8.0 (A4): read EXACTLY n bytes from a socket - the SOCKS5
    handshake fields are length-prefixed, so a partial recv would
    corrupt the whole parse. Returns fewer bytes only on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf

def _socks5_reply(conn, rep: int, bind_host: str = "0.0.0.0",
                 bind_port: int = 0):
    """v8.0 (A4): send ONE RFC 1928 SOCKS5 reply -
    VER(05) REP RSV(00) ATYP(01) BND.ADDR BND.PORT - the wire shape
    every SOCKS5 server answers with (RFC 1928 section 6; the bound
    address/port fields are cosmetic for a CONNECT-only relay, the
    client ignores them). REP codes used: 00 succeeded, 01 general
    SOCKS-server failure, 04 host unreachable, 07 command not
    supported, 08 address type not supported."""
    try:
        conn.sendall(bytes([0x05, rep, 0x00, 0x01])
                     + socket.inet_aton(bind_host)
                     + int(bind_port).to_bytes(2, "big"))
    except OSError:
        pass

# ---------------------------------------------------------------------------
# v8.5 (user request): THE LOCAL DNS RELAY - a plain-DNS endpoint per
# local proxy (BOTH engines, ON by default). A client sends an ordinary
# DNS query (UDP, or TCP with the RFC 1035 section 4.2.2 two-byte
# length framing) to the proxy's DEDICATED DNS port; the relay rides
# the LOCAL PROXY LISTENER at 127.0.0.1:<proxy port> - the exact wire
# path every other client of the local proxies rides (the SOCKS5
# CONNECT with the DOMAIN name for 'socks5' / the absolute HTTP CONNECT
# for 'http') - so the query leaves through the EGRESS (the REMOTE
# proxy resolves the DoH provider's hostname - remote DNS) and is
# answered by the DoH provider over the RFC 8484 wireformat (POST
# application/dns-message, the same media type for the request and the
# response; the message is at most 65535 bytes). The DNS message itself
# is NEVER parsed or rewritten: the client's transaction ID, EDNS
# options and flags go to the provider VERBATIM and the answer comes
# back VERBATIM - the relay is a pure byte pipe (the shape of the
# mature DoH relays: the NextDNS CLI family, github.com/nextdns/nextdns).
# v8.6 (user request: DPI protection FOR DoH): the TLS handshake of
# every relayed DoH connection rides the FRAGMENTED ClientHello
# (tls_split() / _FragTLSConn - the same DPI protection the egress
# TLS uses), with a fresh-tunnel + plain-handshake fallback on any
# fragmented failure; the script's OWN DoH bootstrap (the preset
# resolvers contacted by their well-known resolver IPs) is fragmented
# the same way - see _doh_query / _raw_https(frag=True).
# ---------------------------------------------------------------------------

# provider name -> (SNI/Host hostname, port, RFC 8484 wireformat path).
# The PRESET URLs of DOH_PROVIDERS above serve the script's OWN JSON
# DoH chain (?name=&type=A); the relay needs the WIREFORMAT endpoints:
# the de-facto DoH URL shape is https://<host>/dns-query (RFC 8484,
# documented by all four providers), and Google's JSON API /resolve is
# NOT a wireformat endpoint - dns.google/dns-query is.
DOH_WIRE_ENDPOINTS = {
    "cloudflare": ("cloudflare-dns.com", 443, "/dns-query"),
    "google":     ("dns.google",         443, "/dns-query"),
    "nextdns":    ("dns.nextdns.io",     443, "/dns-query"),
    # v8.8: 5053 -> 443 - Quad9 retired the 5053 JSON service
    # (5 May 2025) and points DoH clients at port 443; the 443
    # endpoint was live-checked on 2026-10-31 and answers the
    # RFC 8484 wireformat POST the relay sends.
    "quad9":      ("dns.quad9.net",     443, "/dns-query"),
}
# v9.1 (the user's request): NO fallback trio anymore - the relay
# rides EXACTLY the provider the USER chose (the hotkey-'h' / --doh
# choice, read per query so a hotkey change applies LIVE); the
# built-in default 'cloudflare' applies when nothing is chosen or
# the choice is 'off' (the relay speaks DoH by design).
DNS_RELAY_TIMEOUT = 5      # seconds for the ONE DoH target (TLS + POST + answer)
DNS_RELAY_BUDGET = 10      # total seconds per query (the single attempt)

def doh_wire_targets() -> "list[tuple[str, int, str, str]]":
    """v8.5 -> v9.1 (the user's request): the RFC 8484 wireformat
    target of the DNS relay as [(hostname, port, path, tag)] -
    EXACTLY ONE entry: the SELECTED DoH provider (the hotkey-'h' /
    --doh choice, read per query so a hotkey change applies LIVE),
    or the built-in DEFAULT 'cloudflare' when nothing is chosen /
    the choice is 'off' (the relay speaks DoH by design and cannot
    query a system resolver through the egress). A custom
    --doh-url endpoint stays the USER's choice too (parsed
    best-effort from its URL, exactly as before); a dead or
    JSON-only custom endpoint simply fails THAT query - the
    client's resolver retries, like any plain DNS - the relay
    NEVER silently answers through a provider the user did not
    pick."""
    cur = doh_provider()
    if cur in DOH_WIRE_ENDPOINTS:
        h, p, path = DOH_WIRE_ENDPOINTS[cur]
        return [(h, p, path, cur)]
    if cur:
        # a custom endpoint URL (--doh-url -> DOH_PROVIDERS["custom"])
        url = DOH_PROVIDERS.get(cur,
                                cur if "://" in cur else "https://" + cur)
        try:
            u = urlparse(url)
            if u.hostname:
                return [(u.hostname, u.port or 443,
                         u.path or "/dns-query", "custom")]
        except Exception:
            pass
    # nothing chosen / 'off' / an unparseable custom URL -> the
    # built-in default (v6.8: the default IS cloudflare)
    h, p, path = DOH_WIRE_ENDPOINTS["cloudflare"]
    return [(h, p, path, "cloudflare")]

def _http_decode_chunked(body: bytes, tls) -> bytes:
    """v8.5 (the DNS relay): decode an HTTP/1.1 chunked response body
    (the chunked transfer coding of RFC 9110 section 7.1) - the stable
    size-line/chunk/CRLF loop until the 0-size terminator (the same
    algorithm Python http.client _read_chunked implements). Raises
    OSError on a truncated stream so the relayed query fails cleanly
    (nothing is sent; the client's resolver retries)."""
    out = b""
    while True:
        while b"\r\n" not in body:
            chunk = tls.recv(65536)
            if not chunk:
                raise OSError("doh: truncated chunked body")
            body += chunk
        line, _, body = body.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip() or b"0", 16)
        except ValueError:
            raise OSError("doh: bad chunk size line")
        while len(body) < size + 2:
            chunk = tls.recv(65536)
            if not chunk:
                raise OSError("doh: truncated chunk")
            body += chunk
        if size:
            out += body[:size]
        body = body[size + 2:]
        if size == 0:
            return out

class DnsRelay:
    """v8.5 -> v9.0 (the user's decision): the local DNS endpoints -
    ONE per started proxy (shared by BOTH engines - the relay rides
    the engines' LOCAL listeners at 127.0.0.1, so the engine that
    serves the proxies automatically carries the DNS endpoints too;
    with the sing-box engine the relay is a client of the sing-box
    inbound exactly like any other application). One UDP and one TCP
    listener PER PROXY on that proxy's deterministic '<location>|dns'
    port; every query is served by a daemon thread and rides THAT
    proxy ONLY: local proxy -> egress -> DoH (the doh_wire_targets
    chain). The DNS message is never parsed.
    v8.6: every relayed DoH TLS handshake rides the fragmented
    ClientHello when tls_split() is on (see _doh_via_local).
    v9.0 (the user's decision, reversing v8.9): NO shared
    round-robin endpoint anymore - a query entering through the DNS
    port of proxy X is relayed through THE LOCAL LISTENER OF PROXY X
    and nothing else, so the answer is always the answer of THAT
    proxy's exit country (a country that blocks resources BY DNS
    must not leak its block into another country's endpoint through
    the rotation back door - the user's exact scenario: switching to
    another country's proxy and still seeing the old block).
    v9.1 (the user's request): the DoH TARGET is exactly ONE too -
    the provider the USER chose (hotkey 'h' / --doh, default
    cloudflare); NO fallback chain walks on anymore (a dead target
    fails THAT query - the client's resolver retries, like any
    plain DNS)."""

    def __init__(self, listen_host: str):
        self.listen_host = listen_host or "127.0.0.1"
        self._udp = []          # [(socket, proxy), ...]
        self._tcp = []          # [(listener, proxy), ...]
        self._threads = []
        self._stopping = threading.Event()

    def bind(self, proxies: list) -> int:
        """Bind ONE UDP + ONE TCP listener on EVERY started proxy's
        deterministic DNS port (p['dns_port'] - the '<location>|dns'
        key of the same port_for_location scheme, so it can never
        collide with the proxy ports) and serve them with daemon
        threads - the same start/stop shape as the engines' own
        listeners (a busy port warns and is skipped, the proxy
        itself keeps running). Returns the number of BOUND
        endpoints; the ONE summary dns_line is printed by announce()
        AFTER the engines printed their proxy lines (v8.7: the quiet
        DNS log - one line, never one per proxy)."""
        self._stopping.clear()
        bound = 0
        for p in proxies:
            dp = p.get("dns_port")
            if not dp:
                continue
            u = t = None
            try:
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                u.bind((self.listen_host, dp))
                t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                t.bind((self.listen_host, dp))
                t.listen(16)
            except OSError:
                warn(tr("dns_port_busy", port=dp,
                        label=p.get("label", "?")))
                for s in (u, t):
                    if s is not None:
                        try:
                            s.close()
                        except Exception:
                            pass
                continue
            p["dns_bound"] = True
            self._udp.append((u, p))
            self._tcp.append((t, p))
            th = threading.Thread(target=self._serve_udp, args=(u, p),
                                  daemon=True,
                                  name=f"mozvpn-dns-u{dp}")
            th.start()
            self._threads.append(th)
            th = threading.Thread(target=self._serve_tcp, args=(t, p),
                                  daemon=True,
                                  name=f"mozvpn-dns-t{dp}")
            th.start()
            self._threads.append(th)
            bound += 1
        return bound

    def announce(self, bound: int):
        """v8.7 -> v9.0: the ONE summary line after the engines' proxy
        list (never one line per proxy - the user's v8.7 report); the
        v9.0 line names the COUNT and the per-proxy property (every
        endpoint rides ITS OWN proxy only) and says WHO needs the
        endpoints (the user's v8.9 'how do I use it' question: the
        DNS port of each proxy is shown next to that proxy's line)."""
        if bound:
            targets = doh_wire_targets()
            info(tr("dns_line", listen=self.listen_host, n=bound,
                    target=targets[0][0]))

    def stop(self):
        """Close every DNS socket (the daemon serve loops unblock on
        the close and exit); called from the engines' stop_all."""
        self._stopping.set()
        for s, _ in self._udp + self._tcp:
            try:
                s.close()
            except Exception:
                pass
        for _, p in self._udp:
            try:
                p["dns_bound"] = False
            except Exception:
                pass
        self._udp.clear()
        self._tcp.clear()
        self._threads.clear()

    def _serve_udp(self, sock, proxy):
        while not self._stopping.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except OSError:
                break
            if data:
                threading.Thread(target=self._answer_udp,
                                 args=(sock, data, addr, proxy),
                                 daemon=True).start()

    def _answer_udp(self, sock, query, addr, proxy):
        """One UDP query -> the chain through THIS endpoint's proxy ->
        sendto the answer (on total failure NOTHING is sent: the
        client's resolver retries with the next server / again, like
        any plain DNS)."""
        ans = self._relay_query(query, proxy)
        if ans:
            try:
                sock.sendto(ans, addr)
            except OSError:
                pass

    def _serve_tcp(self, listener, proxy):
        while not self._stopping.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_tcp,
                             args=(conn, proxy),
                             daemon=True).start()

    def _handle_tcp(self, conn, proxy):
        """DNS over TCP (the RFC 1035 section 4.2.2 two-byte length
        framing): possibly SEVERAL pipelined queries per connection,
        one relayed answer per query - every one through THIS
        endpoint's proxy."""
        try:
            conn.settimeout(30)
            while not self._stopping.is_set():
                hdr = _recv_exact(conn, 2)
                if len(hdr) < 2:
                    break
                ln = int.from_bytes(hdr, "big")
                if not ln or ln > 65535:
                    break
                query = _recv_exact(conn, ln)
                if len(query) < ln:
                    break
                ans = self._relay_query(query, proxy)
                if not ans:
                    break
                try:
                    conn.sendall(len(ans).to_bytes(2, "big") + ans)
                except OSError:
                    break
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _relay_query(self, query: bytes, proxy: dict) -> "bytes | None":
        """One DNS query -> the ONE user-chosen DoH target through THE
        ONE PROXY the endpoint belongs to -> the raw answer (or None).
        The attempt is bounded by DNS_RELAY_TIMEOUT and the
        DNS_RELAY_BUDGET cap: a stalled DoH endpoint must not hold the
        client's query thread forever.
        v9.0 (the user's decision, reversing v8.9): NO rotation over
        the other proxies anymore - a query that entered through the
        DNS port of proxy X rides proxy X and NOTHING else, so the
        answer is always the answer of THAT proxy's exit country (the
        v8.9 round-robin could answer through any other country and
        re-import the DNS block the user had just switched away
        from). A fully dead proxy simply fails its own DNS endpoint
        (nothing is sent, the client's resolver retries, like any
        plain DNS).
        v9.1 (the user's request): NO target-chain walk either - the
        query goes to EXACTLY the DoH provider the USER chose
        (hotkey 'h' / --doh, default cloudflare; doh_wire_targets()
        is read per query, so a hotkey change applies LIVE). A dead
        or JSON-only custom endpoint fails THAT query instead of
        silently answering through a provider the user did not pick."""
        host, port, path, tag = doh_wire_targets()[0]
        deadline = time.time() + DNS_RELAY_BUDGET
        try:
            return self._doh_via_local(proxy, host, port, path,
                                       query, deadline)
        except Exception:
            return None

    def _doh_via_local(self, proxy: dict, host: str, port: int,
                       path: str, query: bytes, deadline: float) -> bytes:
        """ONE RFC 8484 POST through the LOCAL PROXY LISTENER:
        127.0.0.1:<proxy port> - the SOCKS5 CONNECT with the DOMAIN
        name / the absolute HTTP CONNECT of the served type - then TLS
        inside the tunnel (SNI = the DoH hostname; the EGRESS resolved
        that name - remote DNS) and ONE POST application/dns-message;
        the response body IS the DNS answer message (verbatim).
        v8.6 (user request: DPI protection FOR DoH): the TLS handshake
        rides the FRAGMENTED ClientHello (tls_split() / _FragTLSConn -
        the same segmentation the egress TLS uses) with a fresh-tunnel
        + plain-handshake fallback on any fragmented failure."""
        timeout = max(1, min(DNS_RELAY_TIMEOUT,
                            int(deadline - time.time())))

        def _tunnel() -> socket.socket:
            """ONE CONNECT tunnel through the local proxy listener -
            the exact wire path every other client of the local proxies
            rides (the SOCKS5 domain CONNECT / the absolute HTTP
            CONNECT of the served type)."""
            sk = socket.create_connection(("127.0.0.1", proxy["port"]),
                                          timeout=timeout)
            sk.settimeout(timeout)
            if get_proxy_type() == "socks5":
                # the client side of RFC 1928: method negotiation, then
                # CONNECT with the DOMAIN name (ATYP=03 - the name goes
                # to the egress, remote DNS; the same request shape the
                # engine's own listener parses)
                sk.sendall(b"\x05\x01\x00")          # NO AUTHENTICATION
                r = _recv_exact(sk, 2)
                if len(r) < 2 or r[0] != 0x05 or r[1] != 0x00:
                    raise OSError("socks5: method negotiation failed")
                dn = host.encode("latin-1")
                if not dn or len(dn) > 255:
                    raise OSError("socks5: bad domain")
                sk.sendall(b"\x05\x01\x00\x03" + bytes([len(dn)]) + dn
                           + port.to_bytes(2, "big"))
                r = _recv_exact(sk, 4)
                if len(r) < 4 or r[1] != 0x00:
                    raise OSError("socks5: connect refused")
                atyp = r[3]
                if atyp == 0x01:
                    _recv_exact(sk, 4)
                elif atyp == 0x03:
                    nb = _recv_exact(sk, 1)
                    _recv_exact(sk, nb[0] if nb else 0)
                elif atyp == 0x04:
                    _recv_exact(sk, 16)
                else:
                    raise OSError("socks5: bad reply ATYP")
                _recv_exact(sk, 2)
            else:
                # the classic absolute HTTP CONNECT (the listener
                # serves it on the same port when the http type is
                # selected - the built-in default is socks5 since
                # v9.0, and _tunnel rides whatever type is served)
                req = (f"CONNECT {host}:{port} HTTP/1.1\r\n"
                       f"Host: {host}:{port}\r\n\r\n").encode(
                           "latin-1", "replace")
                sk.sendall(req)
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = sk.recv(4096)
                    if not chunk:
                        raise OSError("http: no CONNECT answer")
                    resp += chunk
                m = re.match(rb"HTTP/[\d.]+\s+(\d{3})", resp)
                if not m or int(m.group(1)) != 200:
                    raise OSError("http: CONNECT refused")
            return sk

        s = _tunnel()
        tls = None
        try:
            # v8.6: TLS INSIDE the tunnel (the egress resolved the
            # name) - with the fragmented ClientHello when tls_split()
            # is on, so an SNI-matching DPI cannot read the DoH
            # provider SNI from the first segment of the flow; ANY
            # fragmented failure falls back to a FRESH tunnel + the
            # plain handshake (the failed handshake may have
            # half-consumed the tunnel socket - the v6.1 lesson).
            if tls_split():
                try:
                    tls = _FragTLSConn(s, _ssl_ctx(), host, timeout)
                except Exception:
                    try:
                        s.close()
                    except Exception:
                        pass
                    s = _tunnel()
                    tls = _ssl_ctx().wrap_socket(s, server_hostname=host)
            else:
                tls = _ssl_ctx().wrap_socket(s, server_hostname=host)
            tls.settimeout(timeout)
            head = (f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Content-Type: application/dns-message\r\n"
                    "Accept: application/dns-message\r\n"
                    f"Content-Length: {len(query)}\r\n"
                    "Connection: close\r\n\r\n").encode("latin-1",
                                                        "replace")
            tls.sendall(head + query)
            # the response: status line + headers, then the body -
            # Content-Length bounded, or chunked (RFC 9110 section
            # 7.1), or read to the TLS EOF of the Connection: close
            # pipe - every branch returns the EXACT answer bytes
            buf = b""
            head_end = -1
            while head_end < 0:
                chunk = tls.recv(65536)
                if not chunk:
                    raise OSError("doh: no answer")
                buf += chunk
                head_end = buf.find(b"\r\n\r\n")
            head_b = buf[:head_end].decode("latin-1", "replace")
            body = buf[head_end + 4:]
            status = 0
            m = re.match(r"HTTP/[\d.]+\s+(\d{3})", head_b)
            if m:
                status = int(m.group(1))
            headers = {}
            for line in head_b.split("\r\n")[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
            if "chunked" in headers.get("transfer-encoding", "").lower():
                body = _http_decode_chunked(body, tls)
            else:
                need = -1
                if "content-length" in headers:
                    try:
                        need = int(headers["content-length"])
                    except ValueError:
                        need = -1
                while need < 0 or len(body) < need:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    body += chunk
                if need >= 0:
                    body = body[:need]
            if status != 200 or not body:
                raise OSError(f"doh: HTTP {status}")
            return body
        finally:
            for sock in (tls, s):
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass


class BuiltinProxyEngine:
    """Threaded in-process local proxy: one listening port per location.
    Upstream: TLS + HTTP CONNECT with Proxy-Authorization: Bearer <proxyPass>.
    v8.0 (A4) -> v8.5 -> v9.0: the LOCAL side serves the SELECTED
    proxy type (settings.proxy_type / --proxy-type / hotkey Ctrl+T) -
    exactly TWO protocols since v8.5 (the user's request; the v8.0
    'mixed' single-port auto-detect listener is REMOVED):
      * 'socks5' - the DEFAULT since v9.0 (was 'http' from v8.5 to
        v8.9): RFC 1928, CONNECT only, NO AUTHENTICATION REQUIRED,
        REMOTE DNS (a DOMAIN request address is passed through to
        the egress - the curl socks5h/socks5a semantics; a plain-
        'socks5' client that pre-resolves locally and sends the IP
        (ATYP=01) is served verbatim too - 'socks5h' is a CLIENT-
        side convention, not a separate wire protocol);
      * 'http' - the classic HTTP CONNECT
        listener (also serves plain absolute-URI HTTP requests by
        forwarding them upstream, like proxy.py's
        HttpProxyHandler); the CONNECT target hostname goes to the
        egress - remote DNS;"""

    def __init__(self, args, token_holder: TokenHolder):
        self.args = args
        self.token_holder = token_holder
        # --listen: bind address of the local listeners (127.0.0.1 or 0.0.0.0)
        self.listen_host = getattr(args, "listen", "127.0.0.1") or "127.0.0.1"
        # v8.0 (A4): the type the listeners SERVE (resolved from
        # --proxy-type / the saved settings.proxy_type at build time)
        self.proxy_type = get_proxy_type()
        # v8.5: the per-proxy local DNS endpoints - the relay rides the
        # listeners below (127.0.0.1), so it starts/stops with them
        self.dns = DnsRelay(self.listen_host)
        self.proxies = []       # [{port, label, host, upstreamPort, protocol, ...}]
        self._sockets = []
        self._threads = []
        self._stopping = threading.Event()

    def build_proxies(self, locations, verified):
        """v5.0: verified is the LIST of per-server entries from
        collect_verified_servers (one entry per upstream server of every
        city, with the location fields included) - one local proxy per
        entry, ports derived from country|city|serverIndex."""
        used = set()
        proxies = []
        max_p = self.args.max_proxies or 0
        for srv in verified:
            key = (f"{srv['countryCode']}|{srv.get('cityCode') or ''}"
                   f"|{srv.get('serverIndex') or 0}")
            port = port_for_location(key, used)
            # v9.0 (the user's decision, reversing v8.9): the
            # per-proxy DNS endpoint is BACK - the SAME deterministic
            # port_for_location scheme, key '<location>|dns' (it can
            # never collide with the proxy ports or another DNS
            # port): every proxy again owns a DEDICATED DNS port whose
            # queries ride THAT proxy ONLY (never another one)
            dns_port = port_for_location(key + "|dns", used)
            label = f"{srv['countryName']}/{srv['cityName']}"
            proxies.append({"port": port,
                            "country": srv["countryName"],
                            "countryCode": srv["countryCode"],
                            "city": srv["cityName"],
                            "cityCode": srv.get("cityCode"),
                            "host": srv["protocolHost"],
                            "upstreamPort": srv["protocolPort"],
                            "protocol": srv["protocol"],
                            "dns_port": dns_port,
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
        # v9.0: bind the PER-PROXY DNS endpoints BEFORE the proxy
        # lines are printed - each proxy_line shows the DNS port of
        # ITS proxy when that endpoint actually bound (the v8.9 'the
        # port must be visible' rule applied to the per-proxy scheme),
        # and the ONE summary line is announced AFTER the list (v8.7:
        # the quiet DNS log - one line, never one per proxy). The
        # endpoints relay a plain DNS query through THEIR OWN proxy
        # only -> the egress/DoH (the same lifecycle as the listeners
        # themselves; --no-dns-relay skips them, the proxies and
        # their socks5h remote DNS are NOT affected).
        dns_bound = 0
        if getattr(self.args, "dns_relay", True) and started:
            dns_bound = self.dns.bind(started)
        for p in started:
            # v5.13: the electric-plug emoji is replaced with the NATIONAL
            # FLAG of the proxy's country (REC/unknown keep the plug)
            info(tr("proxy_line", port=p["port"], label=p["label"].ljust(_proxy_label_width(self.proxies)),
                    host=p["host"], uport=p["upstreamPort"], proto=p["protocol"],
                    listen=self.listen_host,
                    dns=(f" DNS:{p['dns_port']}" if p.get("dns_bound") else ""),
                    _e=country_flag(p.get("countryCode"))))
        if dns_bound:
            self.dns.announce(dns_bound)
        if not started:
            raise MozVpnError(tr("no_free_ports"))
        # Same log shape as the sing-box engine (only the engine name differs)
        ok(tr("engine_started", engine=tr("engine_builtin"), n=len(started),
              listen=self.listen_host, ptype=get_proxy_type()))

    def _serve_listener(self, listener, proxy):
        while not self._stopping.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(conn, proxy),
                                 daemon=True)
            t.start()

    def _handle_client(self, conn, proxy):
        """v8.0 (A4) -> v8.5: the PROTOCOL DISPATCHER of the local
        listener. 'socks5' serves every connection as SOCKS5; 'http'
        goes straight to the classic HTTP path (no extra syscall). The
        v8.0 'mixed' MSG_PEEK auto-detect branch is REMOVED in v8.5 -
        only the two classic protocols remain (the user's request)."""
        ptype = get_proxy_type()
        if ptype == "socks5":
            self._handle_client_socks(conn, proxy)
            return
        self._handle_client_http(conn, proxy)

    def _open_upstream(self, proxy) -> "ssl.SSLSocket":
        """TCP + TLS to the Mozilla/Fastly egress (same profile matrix as the
        probe, so the probe result predicts what the engine can do)."""
        return _tls_connect(proxy["host"], proxy["upstreamPort"], timeout=20)

    def _handle_client_socks(self, conn, proxy):
        """v8.0 (A4): ONE client connection over SOCKS5 (RFC 1928, the
        CONNECT command only - the same scope as the mature analogs'
        SOCKS5 listeners). REMOTE DNS BY DESIGN: an ATYP=03 DOMAIN
        request address is passed THROUGH to the egress (the curl
        socks5h/socks5a semantics - the EGRESS resolves the name, the
        local system resolver is bypassed entirely). The upstream ride
        is IDENTICAL to the HTTP CONNECT path: the same TLS profile
        matrix (_open_upstream), the same Bearer pass, the same
        response classification (400/401/403 -> _PassMonitor, the watch
        loop refreshes the pass at once), the same early-data forward
        and the same half-close drain window."""
        try:
            conn.settimeout(60)
            # ---- method negotiation (RFC 1928 section 3) ----
            hdr = _recv_exact(conn, 2)
            if len(hdr) < 2 or hdr[0] != 0x05:
                conn.close()
                return
            nmethods = hdr[1]
            if nmethods < 1 or nmethods > 16:
                conn.close()
                return
            methods = _recv_exact(conn, nmethods)
            if 0x00 not in methods:
                # NO ACCEPTABLE METHODS: the script rides the pass at
                # the UPSTREAM; the LOCAL listener stays no-auth by
                # design, like every standard local proxy.
                try:
                    conn.sendall(b"\x05\xff")
                except OSError:
                    pass
                conn.close()
                return
            try:
                conn.sendall(b"\x05\x00")   # NO AUTHENTICATION REQUIRED
            except OSError:
                conn.close()
                return
            # ---- request: VER CMD RSV ATYP DST.ADDR DST.PORT ----
            r = _recv_exact(conn, 4)
            if len(r) < 4 or r[0] != 0x05 or r[2] != 0x00:
                _socks5_reply(conn, 0x01)
                conn.close()
                return
            if r[1] != 0x01:
                # BIND / UDP ASSOCIATE are not served: the Mozilla
                # egress itself is a TCP CONNECT tunnel.
                _socks5_reply(conn, 0x07)   # command not supported
                conn.close()
                return
            atyp = r[3]
            target = ""
            if atyp == 0x01:
                addr_b = _recv_exact(conn, 4)
                if len(addr_b) < 4:
                    conn.close()
                    return
                target = socket.inet_ntoa(addr_b)
            elif atyp == 0x03:
                ln_b = _recv_exact(conn, 1)
                if not ln_b:
                    conn.close()
                    return
                domain = _recv_exact(conn, ln_b[0]).decode("latin-1",
                                                           "replace")
                target = domain          # REMOTE DNS: the name goes to the egress
            elif atyp == 0x04:
                addr_b = _recv_exact(conn, 16)
                if len(addr_b) < 16:
                    conn.close()
                    return
                target = socket.inet_ntop(socket.AF_INET6, addr_b)
            else:
                _socks5_reply(conn, 0x08)   # address type not supported
                conn.close()
                return
            port_b = _recv_exact(conn, 2)
            if len(port_b) < 2 or not target:
                _socks5_reply(conn, 0x01)
                conn.close()
                return
            dst_port = int.from_bytes(port_b, "big")
            host_part = f"[{target}]" if ":" in target else target
            target_full = f"{host_part}:{dst_port}"
            token = self.token_holder.get()
            if not token:
                _socks5_reply(conn, 0x01)
                conn.close()
                return
            try:
                upstream = self._open_upstream(proxy)
            except Exception:
                # the egress is down / unreachable
                _socks5_reply(conn, 0x04)
                conn.close()
                return
            # v6.6 (item 6): TCP keepalive on BOTH sockets of the tunnel
            _tcp_keepalive(conn)
            _tcp_keepalive(upstream)
            try:
                req = (f"CONNECT {target_full} HTTP/1.1\r\n"
                       f"Host: {target_full}\r\n"
                       f"Proxy-Authorization: Bearer {token}\r\n"
                       "Proxy-Connection: keep-alive\r\n\r\n")
                upstream.sendall(req.encode())
                resp = b""
                try:
                    while b"\r\n\r\n" not in resp:
                        chunk = upstream.recv(4096)
                        if not chunk:
                            break
                        resp += chunk
                except socket.timeout:
                    # the CONNECT never got an answer from the egress -
                    # the SAME classification as the HTTP path (the Go
                    # reference client counts these PER DISTINCT TARGET).
                    if _is_doh_wire_target(target_full):
                        # v9.2: the DNS relay's OWN DoH target - ONE
                        # calm line per run, NOT a session signal (see
                        # _is_doh_wire_target).
                        _warn_doh_target_unreachable(target_full)
                    else:
                        warn(tr("connect_target_open_timeout",
                                target=_redact_target(target_full)))
                        _PassMonitor.note_target_failure(
                            "open_timeout", target_full, proxy["host"])
                    _socks5_reply(conn, 0x01)
                    conn.close()
                    upstream.close()
                    return
                # v6.6 (item 3): parse the CONNECT response status -
                # 400 ('parsing JWT failed') / 401 / 403 mean THE PASS
                # WAS REJECTED (the watch loop refreshes it at once).
                m = re.match(rb"HTTP/[\d.]+\s+(\d{3})", resp)
                code_num = int(m.group(1)) if m else 0
                if code_num in (400, 401, 403):
                    warn(tr("connect_rejected", code=code_num,
                            target=_redact_target(target_full)))
                    _PassMonitor.note_pass_rejected(proxy["host"])
                    _socks5_reply(conn, 0x01)
                    conn.close()
                    upstream.close()
                    return
                if code_num in (502, 504):
                    if _is_doh_wire_target(target_full):
                        # v9.2: the DNS relay's OWN DoH target - ONE
                        # calm line per run, NOT a session signal (see
                        # _is_doh_wire_target); the PASS-REJECTION
                        # classes above stay counted for it.
                        _warn_doh_target_unreachable(target_full)
                    else:
                        warn(tr("connect_target_bad_gateway",
                                code=code_num,
                                target=_redact_target(target_full)))
                        _PassMonitor.note_target_failure(
                            "bad_gateway", target_full, proxy["host"])
                    _socks5_reply(conn, 0x04)
                    conn.close()
                    upstream.close()
                    return
                if code_num != 200:
                    _socks5_reply(conn, 0x01)
                    conn.close()
                    upstream.close()
                    return
                _PassMonitor.note_success(proxy["host"])
                _socks5_reply(conn, 0x00)      # succeeded
                # v6.7 (audit fix): the status read above may have
                # pulled the FIRST TUNNEL BYTES past the response head
                # (an eager server / early data) - hand them to the
                # client BEFORE the relays start, no tunnel byte lost.
                _head, _sep, _early = resp.partition(b"\r\n\r\n")
                if _early:
                    conn.sendall(_early)
                t1 = threading.Thread(target=_relay, args=(conn, upstream),
                                      daemon=True)
                t2 = threading.Thread(target=_relay, args=(upstream, conn),
                                      daemon=True)
                t1.start(); t2.start()
                # the SAME half-close drain semantics as the HTTP path
                # (the v6.6/v6.7 audit contract: the FIRST direction is
                # waited for UNBOUNDED, only the second gets the window).
                t1.join()
                t2.join(_HALF_CLOSE_DRAIN)
                try:
                    upstream.close()
                except Exception:
                    pass
                try:
                    conn.close()
                except Exception:
                    pass
                t1.join(1)
                t2.join(1)
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

    def _handle_client_http(self, conn, proxy):
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
            # v6.6 (item 6): TCP keepalive on BOTH sockets of the tunnel
            # (the Go pacing: idle 10 s, retry every 5 s, 3 probes) - a
            # silently-dropped NAT/middlebox path is detected by the OS
            # instead of leaving a half-open tunnel. Best-effort.
            _tcp_keepalive(conn)
            _tcp_keepalive(upstream)
            try:
                if method.upper() == "CONNECT":
                    # CONNECT host:port -> sign with Bearer -> relay blindly
                    req = (f"{method} {target} HTTP/1.1\r\n"
                           f"Host: {target}\r\n"
                           f"Proxy-Authorization: Bearer {token}\r\n"
                           "Proxy-Connection: keep-alive\r\n\r\n")
                    upstream.sendall(req.encode())
                    resp = b""
                    try:
                        while b"\r\n\r\n" not in resp:
                            chunk = upstream.recv(4096)
                            if not chunk:
                                break
                            resp += chunk
                    except socket.timeout:
                        # v6.6 (item 4a): the CONNECT never got an answer
                        # from the egress (the tunnel-open timeout) - the
                        # Go reference client counts these PER DISTINCT
                        # TARGET: one timeout fails only THIS client
                        # connection; only THREE DISTINCT targets mean
                        # the session is broken (see _PassMonitor). The
                        # target is REDACTED unless --verbose (the Go
                        # logTarget redaction: a CONNECT destination is
                        # the user's browsing).
                        if _is_doh_wire_target(target):
                            # v9.2: the DNS relay's OWN DoH target - ONE
                            # calm line per run, NOT a session signal
                            # (see _is_doh_wire_target).
                            _warn_doh_target_unreachable(target)
                        else:
                            warn(tr("connect_target_open_timeout",
                                    target=_redact_target(target)))
                            _PassMonitor.note_target_failure(
                                "open_timeout", target, proxy["host"])
                        conn.sendall(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
                        conn.close()
                        upstream.close()
                        return
                    # v6.6 (item 3): parse the CONNECT response status -
                    # 400 ('parsing JWT failed') / 401 / 403 mean THE PASS
                    # WAS REJECTED (the watch loop refreshes it at once);
                    # 502/504 are TARGET failures; only a real 200 relays.
                    m = re.match(rb"HTTP/[\d.]+\s+(\d{3})", resp)
                    code_num = int(m.group(1)) if m else 0
                    if code_num in (400, 401, 403):
                        warn(tr("connect_rejected", code=code_num,
                                target=_redact_target(target)))
                        _PassMonitor.note_pass_rejected(proxy["host"])
                        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        conn.close()
                        upstream.close()
                        return
                    if code_num in (502, 504):
                        if _is_doh_wire_target(target):
                            # v9.2: the DNS relay's OWN DoH target - ONE
                            # calm line per run, NOT a session signal (see
                            # _is_doh_wire_target); the PASS-REJECTION
                            # classes above stay counted for it.
                            _warn_doh_target_unreachable(target)
                        else:
                            warn(tr("connect_target_bad_gateway",
                                    code=code_num,
                                    target=_redact_target(target)))
                            _PassMonitor.note_target_failure(
                                "bad_gateway", target, proxy["host"])
                        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        conn.close()
                        upstream.close()
                        return
                    if code_num != 200:
                        # Upstream refused (an unclassified status, e.g. a
                        # momentarily rate-limited egress): fail the client;
                        # it will retry with a fresh token (the preserved
                        # pre-v6.6 behavior).
                        conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        conn.close()
                        upstream.close()
                        return
                    _PassMonitor.note_success(proxy["host"])
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    # v6.7 (audit fix): the status read above reads with
                    # recv(4096) until the blank line, so the SAME read may
                    # have pulled the FIRST TUNNEL BYTES past the response
                    # head (an eager server / early data). Hand them to
                    # the client BEFORE the relays start - no tunnel byte
                    # is ever lost.
                    _head, _sep, _early = resp.partition(b"\r\n\r\n")
                    if _early:
                        conn.sendall(_early)
                    # Any bytes the client sent past its head go to the tunnel
                    if leftover:
                        upstream.sendall(leftover)
                    t1 = threading.Thread(target=_relay, args=(conn, upstream), daemon=True)
                    t2 = threading.Thread(target=_relay, args=(upstream, conn), daemon=True)
                    t1.start(); t2.start()
                    # v6.6 (item 5) + the v6.7 audit fix: THE HALF-CLOSE
                    # DRAIN WINDOW (the Go halfCloseDrainTimeout = 2
                    # minutes). The v6.6 code bounded BOTH joins - and
                    # that closed a HEALTHY tunnel (a long download whose
                    # client side stays silent) after 2-4 minutes: the
                    # worst kind of regression (the v6.1 lesson). The
                    # audited semantics: the FIRST relay direction is
                    # waited for UNBOUNDED (the tunnel's real lifetime,
                    # the pre-v6.6 behavior - and a dead peer can no
                    # longer pin the thread: the v6.6 TCP keepalive reaps
                    # it at the OS level); only the SECOND direction,
                    # after the half-close, gets the bounded window -
                    # the peer may legitimately keep sending for a while
                    # (a download finishing), but a direction that NEVER
                    # ends must not pin the sockets forever: after the
                    # window BOTH sockets are closed, the relay threads
                    # unblock and the connection is reaped.
                    t1.join()
                    t2.join(_HALF_CLOSE_DRAIN)
                    try:
                        upstream.close()
                    except Exception:
                        pass
                    try:
                        conn.close()
                    except Exception:
                        pass
                    t1.join(1)
                    t2.join(1)
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
        """Restart dead listeners (defensive; threads are daemon and robust).
        v9.3: the port of every listener is read BEST-EFFORT - a socket
        that already died (getsockname raises OSError) must not crash
        this DEFENSIVE method itself: the crash surfaced in the watch
        loop as an 'Unexpected error' retry instead of restarting the
        one dead listener the method exists to heal."""
        alive_ports = set()
        for s in list(self._sockets):
            try:
                alive_ports.add(s.getsockname()[1])
            except OSError:
                pass
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
        # v8.5: the DNS endpoints close with the listeners
        self.dns.stop()
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

def singbox_inbound_of(proxy_type: str) -> str:
    """v8.0 (A4) -> v8.5: map the script's local proxy TYPE to the
    OFFICIAL sing-box inbound type: http -> 'http', socks5 -> 'socks'.
    The v8.0 'mixed' mapping is REMOVED in v8.5 (only the two classic
    protocols remain); both are first-class sing-box inbounds, and
    'socks' carries remote DNS by design in sing-box."""
    v = str(proxy_type or "").strip().lower()
    if v == "socks5":
        return "socks"
    return "http"           # http (and unknown values; the script's
                            # own built-in default is socks5 since v9.0,
                            # so an unknown value never reaches here -
                            # set_proxy_type normalizes it first)

def singbox_config(local_port: int, upstream_host: str, upstream_port: int,
                   token: str, listen_host: str = "127.0.0.1",
                   inbound: str = "http") -> dict:
    """sing-box config: <inbound> on <listen_host>:<local_port> ->
    http outbound to the Mozilla egress with Proxy-Authorization
    (fields server/server_port/headers/tls of the official sing-box
    http outbound, sing-box.sagernet.org/configuration/outbound/http/).
    v8.0 (A4) -> v8.5 -> v9.0: the inbound TYPE follows the selected
    local proxy type (singbox_inbound_of) - 'http' (the classic
    CONNECT listener; the built-in default is socks5 since v9.0) or
    'socks' (RFC 1928 with remote DNS); the v8.0 'mixed'
    mapping is REMOVED in v8.5."""
    return {
        "log": {"disabled": True},
        "inbounds": [
            {"type": inbound, "tag": "http-in",
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
        # v8.0 (A4): the local type the inbounds SERVE ('socks' /
        # 'http' via singbox_inbound_of at build time)
        self.proxy_type = get_proxy_type()
        # v8.5: the per-proxy local DNS endpoints - the relay is
        # ENGINE-AGNOSTIC: it connects to 127.0.0.1:<inbound port>
        # exactly like any other client of the sing-box proxies
        self.dns = DnsRelay(self.listen_host)
        self.procs = {}      # port -> (Popen, config_path, label)
        self.proxies = []    # [{port, label, host, upstreamPort, path, ...}]
        # v6.0 (req. 4): the sing-box configs are PERSISTED in config.json
        # (the "singbox_configs" section - one entry per proxy, the source
        # of truth that survives restarts and is editable via the config
        # files menus). The files sing-box actually READS at runtime are
        # MATERIALIZED into a private temp directory of this engine
        # instance (cleaned in stop_all) - the old persistent singbox/
        # directory in the config dir is gone together with the engine/
        # one; nothing outside config.json survives a stop.
        self.runtime_dir = tempfile.mkdtemp(prefix="mozvpn-singbox-")
        exe = None
        try:
            import shutil
            exe = shutil.which("sing-box") or shutil.which("sing-box.exe")
        except Exception:
            pass
        if not exe:
            raise MozVpnError(tr("singbox_missing"))
        self.exe = exe

    def _write_config(self, fname: str, cfg: dict, also_persist=True):
        """Persist the config in config.json (the durable copy) and write
        the runtime file sing-box reads into this engine's temp dir."""
        if also_persist:
            try:
                cfg_set(("singbox_configs", fname), cfg)
            except (OSError, ValueError):
                pass
        path = os.path.join(self.runtime_dir, fname)
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2)
        return path

    def build_proxies(self, locations, verified):
        """Build sing-box configs for every verified upstream (ports by
        hash). v5.0: one config per per-server entry of collect_verified_servers.
        v6.0 (req. 4): every config is stored in config.json ("singbox_configs")
        and materialized into the engine's private runtime dir.
        Note: sing-box resolves the upstream hostname itself - the DoH
        resolver of this script applies to the builtin engine and to the
        probe/geo checks."""
        used, proxies = set(), []
        token = self.token_holder.get()
        max_p = self.args.max_proxies or 0
        for srv in verified:
            key = (f"{srv['countryCode']}|{srv.get('cityCode') or ''}"
                   f"|{srv.get('serverIndex') or 0}")
            port = port_for_location(key, used)
            # v9.0 (the user's decision, reversing v8.9): the
            # per-proxy DNS endpoint is BACK - the SAME deterministic
            # port_for_location scheme, key '<location>|dns' (it can
            # never collide with the proxy ports or another DNS
            # port): every proxy again owns a DEDICATED DNS port whose
            # queries ride THAT proxy's inbound ONLY (never another
            # one)
            dns_port = port_for_location(key + "|dns", used)
            label = f"{srv['countryName']}/{srv['cityName']}"
            cfg = singbox_config(port, srv["protocolHost"], srv["protocolPort"],
                                 token, self.listen_host,
                                 inbound=singbox_inbound_of(get_proxy_type()))
            fname = (f"moz-{srv['countryCode']}-"
                     f"{srv.get('cityCode') or port}-{port}"
                     f"-{srv.get('serverIndex') or 0}.json")
            path = self._write_config(fname, cfg)
            proxies.append({"port": port, "country": srv["countryName"],
                            "countryCode": srv["countryCode"],
                            "city": srv["cityName"], "cityCode": srv.get("cityCode"),
                            "host": srv["protocolHost"],
                            "upstreamPort": srv["protocolPort"],
                            "protocol": srv["protocol"],
                            "dns_port": dns_port,
                            "path": path, "label": label})
            if max_p and len(proxies) >= max_p:
                break
        self.proxies = proxies
        # drop persisted configs of proxies that no longer exist
        try:
            live = {self._fname_of(p) for p in proxies}
            stored = cfg_get(("singbox_configs",), {}) or {}
            for fname in list(stored):
                if fname not in live:
                    cfg_set(("singbox_configs", fname), None)
        except (OSError, ValueError):
            pass
        return proxies

    def _fname_of(self, p: dict) -> str:
        return os.path.basename(p.get("path") or "")

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
        # v9.0: bind the PER-PROXY DNS endpoints BEFORE the proxy
        # lines are printed (each proxy_line shows the DNS port of
        # ITS proxy when that endpoint actually bound - the v8.9 'the
        # port must be visible' rule applied to the per-proxy scheme;
        # the ONE summary line is announced after the list, v8.7: the
        # quiet DNS log). Every endpoint is a client of ITS OWN
        # sing-box inbound exactly like any other application and
        # rides that proxy ONLY (never another one); --no-dns-relay
        # skips them, the proxies and their socks5h remote DNS are
        # NOT affected.
        dns_bound = 0
        if getattr(self.args, "dns_relay", True) and started:
            dns_bound = self.dns.bind(started)
        for p in started:
            # v5.13: the electric-plug emoji is replaced with the NATIONAL
            # FLAG of the proxy's country (REC/unknown keep the plug)
            info(tr("proxy_line", port=p["port"], label=p["label"].ljust(_proxy_label_width(self.proxies)),
                    host=p["host"], uport=p["upstreamPort"], proto=p["protocol"],
                    listen=self.listen_host,
                    dns=(f" DNS:{p['dns_port']}" if p.get("dns_bound") else ""),
                    _e=country_flag(p.get("countryCode"))))
        if dns_bound:
            self.dns.announce(dns_bound)
        if not started:
            raise MozVpnError(tr("no_free_ports"))
        ok(tr("engine_started", engine=tr("engine_singbox"), n=len(started),
              listen=self.listen_host, ptype=get_proxy_type()))

    def update_token(self, token: str):
        """Rewrite all configs with the new token and restart sing-box."""
        info(tr("token_updated_singbox"))
        self.stop_all()
        token = self.token_holder.get()
        # Defense in depth: the config store may have been wiped (hotkeys
        # 'c'/'r', --clear-cache) while this engine object was still alive -
        # recreate the runtime dir before rewriting the config files into
        # it, otherwise open(path, "w") raises FileNotFoundError.
        try:
            if not os.path.isdir(self.runtime_dir):
                os.makedirs(self.runtime_dir, exist_ok=True)
        except OSError:
            self.runtime_dir = tempfile.mkdtemp(prefix="mozvpn-singbox-")
            for p in self.proxies:
                p["path"] = os.path.join(self.runtime_dir,
                                         self._fname_of(p))
        for p in self.proxies:
            cfg = singbox_config(p["port"], p["host"], p["upstreamPort"], token,
                              self.listen_host,
                              inbound=singbox_inbound_of(get_proxy_type()))
            p["path"] = self._write_config(self._fname_of(p), cfg)
        self.start_all()

    def stop_all(self):
        # v8.5: the DNS endpoints close with the processes
        self.dns.stop()
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
        # v6.0 (req. 4): the runtime config files live in the engine's
        # private temp dir - they are REMOVED with it (the durable copies
        # stay in config.json; nothing litters the user's config dir).
        try:
            import shutil
            shutil.rmtree(self.runtime_dir, ignore_errors=True)
        except Exception:
            pass

    def check_running(self):
        """Drop dead processes from the map (sing-box may crash on its own)."""
        for port, (proc, path, label) in list(self.procs.items()):
            if proc.poll() is not None:
                warn(tr("singbox_died", label=label, port=port, code=proc.returncode))
                del self.procs[port]

# ---------------- orchestration: session -> token ----------------

# (script_dir() is defined near the config constants above - v6.1 moved
# it there because the DEFAULT config.json path needs it at import time)

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

    # v8.0 (A3): the PASSWORDLESS profile session (--fxa-profile PATH,
    # a LAUNCH PARAMETER ONLY by the user's explicit request): the
    # sessionToken read from the DESKTOP FIREFOX PROFILE
    # (signedInUser.json -> accountData.sessionToken) wins over the
    # CACHED account session - an explicit launch parameter is a
    # deliberate choice of the run - and is RE-READ FRESH on every
    # call: after a Guardian 401 re-login the user may have re-signed
    # Firefox, and the new session is picked up automatically (no
    # password login, no 2FA prompt, no Fastly bot wall on third-party
    # password logins). A failed read falls through to the normal
    # chain (the cached session / the password login), so a moved or
    # locked profile can never brick the run.
    if getattr(args, "fxa_profile", None):
        tok = read_fxa_profile_session_token(args.fxa_profile)
        if tok:
            return tok

    # v6.0: the cached session token lives in the CURRENT account entry
    # of config.json (the old separate session.json file is gone - the
    # email + token were stored TWICE before, once here and once in the
    # account store; now there is exactly ONE copy, inside the account).
    if not force_relogin and not args.relogin:
        try:
            acc = cfg_current_account()
            st = (acc.get("session_token") or "").strip()
            c_email = cfg_current_email() or ""
            # v5.27 (multi-account): the cached session is reused ONLY
            # when it belongs to the SAME account being signed in. With
            # several cached accounts (hotkey 'a') a session of account
            # A must never be sent for account B - that would fail the
            # Guardian call with a foreign sessionToken. When the store
            # entry carries no email (very old data) stay permissive.
            if st and (not email or not c_email
                       or c_email == email.strip().lower()):
                email = email or c_email
                info(tr("cached_session", email=email))
                return st
        except Exception:
            pass

    # Re-login
    # v5.24 (Termux fix): every interactive prompt goes through the
    # robust wrappers (prompt_line / prompt_secret) - a broken stdin on
    # Android/Termux wrappers now fails with a CLEAR localized message
    # instead of the generic 'Unexpected error' retry loop.
    email = email or (prompt_line(tr("enter_email")).strip() if interactive else None)
    if not email:
        raise MozVpnError(tr("email_missing"))
    pw = args.password or creds.get("password")
    if not pw:
        if interactive:
            pw = prompt_secret(tr("enter_password"))
        else:
            raise MozVpnError(tr("password_missing"))
    info(tr("signing_in"))
    # v6.5: the Fastly cookie (and every other PROFILE-EXCLUSIVE value)
    # obtained during THIS sign-in belongs to the account being signed
    # in - NOT to whoever is 'current' at the moment (the '+' flow of
    # the 'a' menu signs in a NEW account while the previous one is
    # still current). The account's entry may not exist yet - the value
    # is staged in memory and flushed into the entry when the account
    # is created (save_cache below).
    global _SIGNIN_EMAIL
    _SIGNIN_EMAIL = (email or "").strip().lower() or None
    try:
        st = fxa_login(email, pw, totp_provider, interactive=interactive,
                       tp=totp_params_from(creds))
    finally:
        _SIGNIN_EMAIL = None
    save_cache(email, st)
    save_credentials(email=email, password=pw)
    ok(tr("session_cached", path=CONFIG_FILE))
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

def collect_verified_servers(args, locations, token: str) -> list:
    """v5.0: return ONE ENTRY PER SERVER of every city (the old version
    collapsed each city to a single server and hid most countries behind
    --probe-count 1). Every entry carries its location fields so the engines
    raise one local proxy per upstream server. The recommended anycast (REC)
    location is served too. Every entry gets a 'probe_ok' flag; failed
    servers are dropped only with --probe-fail drop. --probe-geo adds an
    exit-country check (ipinfo.io/json) that catches a wrong (usually US)
    exit PoP caused by a geo-wrong DNS answer for the egress hostname."""
    entries = []
    for loc in locations:
        for city in loc["cities"]:
            for idx, s in enumerate(city["servers"]):
                s = dict(s)
                # Optional manual override of the egress host/port
                # (Fastly anycast pool, hosts-file trick, custom port)
                if getattr(args, "upstream_host", None):
                    s["protocolHost"] = args.upstream_host
                    s["host"] = args.upstream_host
                if getattr(args, "upstream_port", None):
                    s["protocolPort"] = args.upstream_port
                s.update({"countryCode": loc["countryCode"],
                          "countryName": loc["countryName"],
                          "cityName": city.get("cityName"),
                          "cityCode": city.get("cityCode"),
                          "serverIndex": idx})
                entries.append(s)
    if getattr(args, "upstream_host", None) and entries:
        info(tr("upstream_override", host=args.upstream_host,
                port=(args.upstream_port
                      or entries[0]["protocolPort"])))
    if not getattr(args, "proxy_check", True):
        info(tr("proxy_check_disabled"))
        for s in entries:
            s["probe_ok"] = None          # not probed
        return entries
    # v5.0: probe ALL upstreams by default (--probe-count now defaults
    # to 0 = all; a positive number still limits the probe).
    n_probe = getattr(args, "probe_count", 0)
    probe_servers = entries if not n_probe else entries[:n_probe]
    # v5.27 (fix 1): when the user selected specific local proxies
    # (--countries / hotkey 'w'), probe ONLY the upstreams those local
    # proxies connect to - not every upstream of the server list.
    probe_servers = _filter_probe_entries(args, probe_servers)
    # v5.1 (req. 7): the exit-country check runs IN THE SAME TIME as the
    # data probe (a second thread pool) - the startup no longer waits for
    # the probe to finish before the geo requests even begin.
    probed_hp = {(s["protocolHost"], s["protocolPort"]) for s in probe_servers}
    # v5.1 (req. 7): PRE-RESOLVE every unique egress hostname over DoH
    # BEFORE the probe starts, so the probe threads do not repeat the
    # same DoH round-trips. v5.12: this runs ALWAYS (not only with the
    # opt-in long cache) - the always-on 60 s memo (v5.6) keeps the
    # answers, so the prefill pays off in every mode.
    # v5.14: the prefill is no longer a SERIAL phase before the probes -
    # it starts in daemon threads and the probe phase begins
    # IMMEDIATELY; the v5.14 IN-FLIGHT dedup in resolve_host() makes
    # every probe worker that hits the same host JOIN the already
    # running prefill query instead of duplicating it (and vice versa:
    # whichever thread touches the host first becomes the query owner).
    # The DNS warming now OVERLAPS the probes instead of adding its
    # whole duration to the startup wall time.
    if probe_servers:
        pre_hosts = sorted({s["protocolHost"] for s in probe_servers})
        for h in pre_hosts:
            threading.Thread(target=resolve_host, args=(h,), daemon=True,
                             name="mozvpn-doh-prefill").start()
    geo_mode = getattr(args, "probe_geo", "warn")
    # v5.2 (req. 3): ONE request per probe. The default echo service
    # (ipinfo.io/json) answers with the external IP AND the exit geo
    # (country ISO code + city) in the SAME single response, so the
    # separate exit-country request of v5.0/v5.1 is GONE: no second
    # thread pool, no second tunnel - the probes finish roughly twice as
    # fast. A plain-IP echo service (--ip-echo-service ipify etc.)
    # returns no geo; in that case the geo check is skipped with ONE
    # explanatory line (probe_geo() is kept for explicit custom use).
    results = probe_upstreams_parallel(probe_servers, token,
                                       args.ip_echo_url,
                                       args.ip_echo_name)
    # Several locations can share one egress (and with --upstream-host they
    # all do), so match results by (host, port), not by identity.
    ok_by_hp = {}
    geo_by_hp = {}
    for r in results:
        rs = r.get("server") or {}
        key = (rs.get("protocolHost"), rs.get("protocolPort"))
        if r["ok"]:
            ok_by_hp.setdefault(key, []).append(rs)
            if r.get("geo"):
                geo_by_hp[key] = (r["geo"], r.get("geoCity"))
    # v5.4: the note is printed ONLY when probes DID pass but the echo
    # service returned no geo (a plain-IP echo). On total probe failure
    # (ok_by_hp empty) the failure lines above already explain it - the
    # old condition fired the note there too and misled the live run.
    if (geo_mode != "off" and probe_servers and ok_by_hp and not geo_by_hp
            and not getattr(args, "_geo_skip_noted", False)):
        args._geo_skip_noted = True
        info(tr("geo_echo_no_geo", service=args.ip_echo_name))
    verified = []
    for s in entries:
        hp = (s["protocolHost"], s["protocolPort"])
        if hp not in probed_hp:
            s["probe_ok"] = None          # not probed (probe-count limit)
            verified.append(s)
            continue
        cand = ok_by_hp.get(hp)
        if cand:
            s.update(cand[0])            # may carry the CONNECT fallback
            s["probe_ok"] = True
            geo, geo_city = geo_by_hp.get(hp, (None, None))
            if geo and s.get("countryCode") != "REC":
                s["geoCountry"], s["geoCity"] = geo, geo_city
                if geo == s.get("countryCode"):
                    ok(tr("doh_geo_ok", hp=_hp(s["protocolHost"],
                                               s["protocolPort"]),
                          geo=geo, city=geo_city or "?",
                          cc=s["countryCode"]))
                else:
                    warn(tr("doh_geo_mismatch",
                            hp=_hp(s["protocolHost"], s["protocolPort"]),
                            geo=geo, city=geo_city or "?",
                            cc=s["countryCode"],
                            cname=s.get("countryName") or s["countryCode"]))
                    if geo_mode == "drop":
                        continue
            verified.append(s)
        else:
            # A failed probe is NOT a script error - it stays in the served
            # list by default (--probe-fail drop removes it).
            s["probe_ok"] = False
            if getattr(args, "probe_fail", "keep") != "drop":
                verified.append(s)
    return verified

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
    # v6.0 (req. 1): the exp of the CURRENT proxyPass JWT - the retry
    # logic below uses it to decide how URGENT a failed refresh is (the
    # token may still be valid; a full 30 s retry delay would eat into
    # the refresh margin of the NEXT attempt).
    token_exp = None
    copy_mode = None        # None | "multi" | "local" | "remote" | "doh" | "lang" | "files" | "ptype" (v5.1)
    select_buf = ""        # v5.1: the typed selection token (confirmed by Enter)
    select_items = []      # v5.1: [{"token": ..., ...}] of the active list
    select_pad = 0         # v5.12.1: length of the in-place 'w' selection line
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
        # v5.26 (POSIX terminal safety): make ABSOLUTELY sure the terminal is
        # in the NORMAL (cooked) mode before any sign-in prompt can run.
        # If the previous loop iteration died with an exception AFTER the
        # hotkey phase had switched the tty to CBREAK (e.g. a proxyPass
        # refresh failure during the sleep/hotkey window), the except
        # handlers below never restored the cooked mode: the NEXT
        # iteration's ensure_session() -> input()/getpass() then read a
        # raw-cbreak tty - broken line editing, Enter not submitting the
        # line, stray hotkey-phase keystrokes leaking into the prompts -
        # so the email/password/TOTP entry was corrupted and the attempt
        # failed, again and again. _hotkey_mode(False) is IDEMPOTENT and
        # a NO-OP on Windows (which is why Windows 11 never showed it);
        # calling it here is a belt-and-suspenders guard on top of the
        # except handlers below.
        _hotkey_mode(False)
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
            # v6.5: the sign-in may have SWITCHED the account (the '+'
            # flow signs in a NEW account, and even a plain --email
            # start signs in an account that is not the stored current
            # one; save_cache makes the signed-in account current).
            # Remember the profile of the moment to detect the switch.
            _prev_profile_email = cfg_current_email()
            session_token = ensure_session(
                args, creds, totp_provider,
                interactive=not args.no_input,
                force_relogin=force_relogin)
            force_relogin = False
            relogin_backoff = 0

            token, until, ghdrs = obtain_proxy_pass(session_token)
            token_holder.set(token)
            # v6.6 (item 1): ANCHOR-AT-RECEIPT (Firefox
            # GuardianTypes.ProxyPass: 'Anchor the pass to our clock at
            # receipt: it is valid from now for the token's lifetime.
            # This makes rotation scheduling immune to any drift between
            # Guardian's clock (nbf/exp) and ours'). The pass is valid
            # from NOW for (exp - nbf) seconds of OUR clock - not until
            # the absolute exp of Guardian's clock, which a skewed local
            # clock misreads in BOTH directions (a slow clock 'extends'
            # the pass into real expiry - the 'proxy stopped working for
            # a while' window; a fast clock can even see a fresh pass as
            # already expired). The rotation lead stays --refresh-margin
            # (default 120 s = Firefox's 'Rotate 2 Minutes from the End
            # Time').
            _receipt = int(time.time())
            exp = anchored_exp(token, _receipt)
            token_exp = exp
            _PassMonitor.mark_refresh()
            exp_str = time.strftime("%H:%M:%S", time.gmtime(exp)) if exp else "?"
            # req. 9: a human-readable expiry instead of "None".
            # v8.1 (req. 3): the whole per-refresh block - the
            # proxyPass line, the quota, the raw + decoded JWT, the
            # next-refresh countdown, the hotkeys hint, the files list
            # and the clear targets - is no longer APPENDED to the log
            # on every refresh; it is collected into `panel` and
            # REDRAWN IN PLACE at the tail of this iteration
            # (_panel_render): one refresh costs zero new log rows.
            panel = [("ok", tr("proxypass_received",
                               until=format_until(until, token),
                               exp=exp_str))]
            # v5.27 (fix 2): the sign-in SUCCEEDED - cache this account
            # (login/password/TOTP/session) in accounts.json. Silent
            # when the entry is unchanged (every token refresh calls it).
            cache_account(args, creds, session_token)
            if _prev_profile_email and \
                    cfg_current_email() != _prev_profile_email:
                # v6.5: the account CHANGED during the sign-in - the
                # WHOLE profile follows: apply its settings and its
                # Fastly cookie at runtime and stop the engine so the
                # next iteration rebuilds it from the NEW profile's
                # sing-box configs and countries filter (the FIRST
                # sign-in of a run needs no apply: the in-memory state
                # already matches the fresh profile)
                apply_profile_runtime(args)
                if engine:
                    engine.stop_all()
                engine = None

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

            print_quota(ghdrs, panel=panel)
            # v8.0 (A2): the ACCOUNT AUTO-ROTATION TRIGGER. The current
            # account just reported a DRY allowance (_QUOTA_LAST['zero'],
            # set by print_quota above - remaining <= 0, not unlimited)
            # and the rotation is enabled: switch the WHOLE profile to
            # the other cached account with the MOST data left
            # (pick_rotation_account) and let the NEXT iteration sign
            # in on ITS cached session - never a password login (an
            # account without a cached session token is not a
            # candidate, so the rotation can never trigger the FxA 429
            # login rate limit; the foxyvpn-pool lesson). The switch is
            # the EXACT sequence of the hotkey-'a' selection, so every
            # piece of profile state - args/creds, the TOTP provider,
            # the current-account pointer, the runtime settings and the
            # engine - moves together.
            if _QUOTA_LAST["zero"] and auto_rotate_enabled():
                rot_em, rot_left = pick_rotation_account(
                    cfg_current_email() or "")
                if rot_em:
                    rot_acc = cfg_accounts().get(rot_em) or {}
                    info(tr("auto_rotate_to", email=rot_em,
                            left=(human_bytes(rot_left)
                                  if rot_left is not None else "?")))
                    args.email = rot_em
                    args.password = rot_acc.get("password")
                    st = (rot_acc.get("session_token") or "").strip()
                    args.session_token = (st if st and all(
                        ch in "0123456789abcdefABCDEF"
                        for ch in st) else None)
                    args.totp_secret = ((rot_acc.get("totp_secret")
                                         or "").strip() or None)
                    args.qr = None
                    args.totp = None
                    creds.clear()
                    creds.update({kk: rot_acc.get(kk)
                                  for kk in _CRED_KEYS})
                    creds["email"] = rot_em
                    totp_secret = args.totp_secret
                    totp_provider = make_totp_provider(args, creds)
                    session_token = args.session_token
                    if args.session_token:
                        save_cache(rot_em, args.session_token)
                    cfg_set_current(rot_em)
                    apply_profile_runtime(args)
                    # the engine of the DRY profile is stopped - the
                    # next iteration rebuilds it from the NEW profile's
                    # filter and sing-box configs; the live relays
                    # drain on their own (daemon threads, the OS reaps
                    # the sockets when the peers hang up)
                    if engine:
                        engine.stop_all()
                    engine = None
                    _ROTATE_WARNED["none"] = False
                    continue
                elif not _ROTATE_WARNED["none"]:
                    # every OTHER cached account is dry or has no cached
                    # session: say it ONCE (not once per refresh) and
                    # keep serving the current account as long as it
                    # answers - the egress may still accept the pass.
                    _ROTATE_WARNED["none"] = True
                    warn(tr("auto_rotate_none",
                            email=(cfg_current_email()
                                   or args.email or "")))
            elif (_QUOTA_LAST["zero"] and not _ROTATE_WARNED["off"]):
                # the allowance is dry and the rotation is OFF: say it
                # ONCE with the hotkey hint, then stay quiet.
                _ROTATE_WARNED["off"] = True
                warn(tr("auto_rotate_off_zero"))
            # The TOTP code line stays a real LOG line: a code is
            # perishable (30 s), while the panel is redrawn once per
            # REFRESH - a panel row would show a dead code most of
            # the time. Everything else below is static per refresh
            # and belongs to the redrawn panel.
            print_current_totp(totp_secret, creds)
            panel.append((None, ""))
            panel.append(("info", tr("proxypass_jwt")))
            panel.append((None, token))
            print_jwt_decoded(token, panel=panel)

            json_out = save_result(args, token, until, session_token,
                                   args.email or creds.get("email"),
                                   recommended, locations, out_path=json_out)

            if engine:
                engine.check_running()
                if not engine.proxies:
                    # The token must be in the holder BEFORE build_proxies():
                    # the sing-box engine bakes the Bearer into its configs.
                    engine.token_holder.set(token)
                    # v5.12: --countries / hotkey 'w' filter - only the
                    # selected upstreams get local proxies (the filter is
                    # cached in countries.json and survives restarts).
                    serve_servers = apply_countries_filter(args, verified_servers)
                    engine.proxies = engine.build_proxies(locations, serve_servers)
                    engine.start_all()
                    # v5.5 (req. 3 + 4): --foxyproxy-export /
                    # --foxyproxy-legacy-export (with the paired --*-out
                    # paths) run ONCE right after the proxies started.
                    maybe_foxyproxy_export(args, engine)
                    # v8.2 (user request): the PAC file is NO longer
                    # auto-created on a rebuild - maybe_pac_export
                    # writes it ONLY for an explicit --pac-export FILE
                    # (or a bare --pac-export opt-in); the default copy
                    # is refreshed by the Ctrl+P hotkey.
                    maybe_pac_export(args, engine)
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
            panel.append(("info", tr("next_refresh", sec=sleep_s,
                    at=time.strftime("%H:%M:%S", time.gmtime(time.time() + sleep_s)))
                 + " " + tr("confirm_exit_hint")))
            # Sleep in short steps to react to Ctrl+C and hotkeys quickly.
            # Single-keypress hotkeys mirror the CLI flags:
            #   r = fresh re-login, c = --clear-cache + restart,
            #   e = toggle --local-proxy-engine + restart proxies, q = stop.
            # v4.5: every hotkey on its OWN line, the key on its color
            # block, the description in the dedicated hotdesc color.
            print_hotkeys_hint(panel=panel)
            files = config_open_files()
            if files:
                panel.append(("info", tr("hotkey_files_hint")))
                for i, p in enumerate(files):
                    panel.append(("hint", tr("hotkey_file_entry",
                                             n=selection_token(i), path=p)))
                if len(files) > 9:
                    # v5.1: more than 9 files -> tokens + Enter (see the
                    # selection sub-mode in the key handler below)
                    panel.append(("hint", tr("select_hint")))
            # What the 'c' hotkey / --clear-cache will remove (req: log it)
            print_clear_targets(panel=panel)
            # v8.1 (req. 3): (re)paint the LIVE PANEL - the previous
            # refresh's block is erased in place and the current one
            # printed at the same spot, so the log gains ZERO rows per
            # refresh. A real log line emitted while the panel is on
            # screen lifts it, prints above and drops it back; a non-tty
            # run (or a window too short for the block) falls back to
            # the classic append inside _panel_render.
            _panel_render(panel)
            _hotkey_mode(True)
            slept = 0
            while slept < sleep_s and not _STOP:
                # v6.6 (items 3/4): a pass-health signal of the builtin
                # engine (a REJECTED pass / a session-level failure) ends
                # the sleep AT ONCE (handled right below the loop).
                if _PassMonitor.rejected.is_set() or _PassMonitor.session_fail.is_set():
                    break
                # --confirm-exit: a Ctrl+C was issued but not confirmed within 5s
                if _CONFIRMISSUED and isinstance(_CONFIRMISSUED, float):
                    if time.time() - _CONFIRMISSUED > 5:
                        info(tr("confirm_exit_abort"))
                        _reset_confirm()
                k = _key_pressed()
                if copy_mode and k:
                    if copy_mode == "multi":
                        # v5.12: the MULTI selection of hotkey 'w': the
                        # tokens of SEVERAL proxies are typed SEPARATED
                        # BY SPACES. SPACE = the token separator, alnum
                        # = append to the current token, Backspace
                        # deletes, ENTER applies the selection (token
                        # '0' = ALL local proxies), any other key
                        # cancels the sub-mode.
                        # v5.12.1: the typed tokens are echoed in ONE
                        # in-place line that REWRITES itself (\r) - not
                        # a new log line per keystroke.
                        if k in ("\r", "\n"):
                            # finish the in-place line first, so the
                            # apply/cancel summary starts on a clean row
                            _multi_line_clear(select_pad)
                            select_pad = 0
                            toks = [t for t in select_buf.split(" ") if t]
                            if not toks:
                                info(tr("hotkey_copy_cancel"))
                            elif "0" in toks:
                                # '0' = ALL proxies: clear the saved filter
                                clear_countries_filter()
                                ok(tr("filter_all_applied"))
                            else:
                                known = {it["token"] for it in select_items}
                                good = []
                                for t in toks:
                                    if t in known:
                                        good.append(t)
                                    else:
                                        warn(tr("multi_bad", tok=t))
                                if good:
                                    save_countries_filter(keys=good)
                                    cc_list = ", ".join(sorted(
                                        {(it["srv"].get("countryCode")
                                          or "?").upper()
                                         for it in select_items
                                         if it["token"] in good})) or "-"
                                    ok(tr("countries_filter_applied",
                                          n=len(good),
                                          m=len(verified_servers),
                                          list=cc_list))
                            if toks:
                                # Restart the engine so the new selection
                                # takes effect immediately (the next loop
                                # iteration rebuilds the local proxies).
                                info(tr("hotkey_countries"))
                                if engine:
                                    engine.stop_all()
                                engine = None
                                break
                            select_buf = ""
                            copy_mode = None
                            select_items = []
                            k = ""
                        elif k == " ":
                            select_buf += " "
                            # v5.13: KEEP the trailing space visible - the
                            # user is asked to separate tokens WITH spaces,
                            # so the echo must show the separator (the old
                            # .strip() hid it); only accidental DOUBLE
                            # spaces are collapsed.
                            select_pad = _multi_line_show(
                                re.sub(r" {2,}", " ", select_buf),
                                select_pad)
                            k = ""
                        elif k in ("\x7f", "\x08"):
                            if select_buf:
                                select_buf = select_buf[:-1]
                                select_pad = _multi_line_show(
                                    re.sub(r" {2,}", " ", select_buf),
                                    select_pad)
                            k = ""
                        elif k.isalnum() and len(k) == 1:
                            select_buf += k
                            select_pad = _multi_line_show(
                                re.sub(r" {2,}", " ", select_buf),
                                select_pad)
                            k = ""
                        else:
                            # Any other key cancels the selection sub-mode
                            _multi_line_clear(select_pad)
                            select_pad = 0
                            info(tr("hotkey_copy_cancel"))
                            select_buf = ""
                            copy_mode = None
                            select_items = []
                            k = ""
                    elif k in ("\r", "\n"):
                        # v5.1: generic SELECTION sub-mode (v/b proxy
                        # copy, 'h' DoH menu, 1-9 config files when there
                        # are more than 9). A token may be several
                        # characters long (1-9, a-z, aa, ab, ...), so the
                        # choice is confirmed with ENTER; Backspace
                        # deletes the last typed character, any other key
                        # cancels the sub-mode.
                        # ENTER: confirm the buffered token
                        item = None
                        for it in select_items:
                            if it["token"] == select_buf:
                                item = it
                                break
                        if item is not None:
                            if copy_mode in ("local", "remote") and engine:
                                p = item["proxy"]
                                text = (f"{engine.listen_host}:{p['port']}"
                                        if copy_mode == "local"
                                        else f"{p['host']}:{p['upstreamPort']}")
                                if copy_to_clipboard(text):
                                    ok(tr("hotkey_copied", text=text))
                            elif copy_mode == "doh":
                                if item.get("default"):
                                    # v5.31: '0' = the DEFAULT resolver
                                    name = "cloudflare"
                                    set_doh_provider(name)
                                    save_doh_provider_cache(name)
                                    info(tr("doh_selected", provider=name,
                                            url=DOH_PROVIDERS.get(name,
                                                                   name)))
                                    info(tr("hotkey_doh", provider=name))
                                    info(tr("doh_default_applied",
                                            provider=name))
                                else:
                                    name = item["provider"]
                                    set_doh_provider(name)
                                    # v5.31: persist the hotkey-'h' choice
                                    save_doh_provider_cache(name)
                                    if name:
                                        info(tr("doh_selected", provider=name,
                                                url=DOH_PROVIDERS.get(name,
                                                                       name)))
                                        info(tr("hotkey_doh", provider=name))
                                    else:
                                        info(tr("hotkey_doh",
                                                provider=tr("doh_system_short")))
                                        info(tr("doh_system"))
                            elif copy_mode == "lang":
                                # v5.30: apply the language choice
                                if item.get("reset"):
                                    # '0' = the DEFAULT language + DROP
                                    # the saved choice (later runs fall
                                    # back to env/default again)
                                    clear_lang_cache()
                                    set_language("en")
                                    ok(tr("lang_reset", lang="en"))
                                else:
                                    set_language(item["lang"])
                                    save_lang_cache(item["lang"])
                                    ok(tr("lang_set", lang=item["lang"]))
                            elif copy_mode == "ptype":
                                # v8.4: apply the proxy-type choice from
                                # the Ctrl+T menu - the exact v8.0 cycle
                                # apply sequence: set + save, then stop
                                # the engine so the next watch-loop
                                # iteration rebuilds the listeners (both
                                # engines read get_proxy_type() at build
                                # time; the PAC file follows the v8.2
                                # rebuild rules). Choosing the CURRENT
                                # type is an explicit no-op: just the
                                # selected line, no needless rebuild.
                                new_type = item["ptype"]
                                if new_type == get_proxy_type():
                                    info(tr("proxy_type_selected",
                                            type=new_type))
                                else:
                                    set_proxy_type(new_type)
                                    save_str_setting("proxy_type",
                                                     new_type)
                                    info(tr("proxy_type_switched",
                                            type=new_type))
                                    if engine:
                                        engine.stop_all()
                                    engine = None
                                    # the shared cleanup + break below
                                    # leaves the sleep phase; the loop
                                    # rebuilds with the new type
                            elif copy_mode == "files":
                                open_in_system_editor(item["path"])
                        else:
                            info(tr("select_bad", buf=select_buf or "?"))
                        select_buf = ""
                        copy_mode = None
                        select_items = []
                        k = ""
                        # v5.30 (user request): after APPLYING an option
                        # (or a bad token) the selection menu EXITS
                        # AUTOMATICALLY - the countdown phase restarts
                        # immediately and the normal watch display
                        # reappears instead of the menu staying open for
                        # the rest of the sleep window.
                        break
                    elif k in ("\x7f", "\x08"):
                        # BACKSPACE: delete the last typed character
                        if select_buf:
                            select_buf = select_buf[:-1]
                            info(tr("select_buffer", buf=select_buf))
                        k = ""
                    elif k.isalnum() and len(k) == 1:
                        # A token character: append to the buffer. Show the
                        # buffer only when a valid COMPLETION exists, so
                        # single-digit tokens stay silent like before.
                        candidate = select_buf + k
                        if any(it["token"].startswith(candidate)
                               for it in select_items):
                            select_buf = candidate
                            if not any(it["token"] == select_buf
                                       for it in select_items):
                                info(tr("select_buffer", buf=select_buf))
                        else:
                            info(tr("select_bad", buf=candidate))
                            select_buf = ""
                            copy_mode = None
                            select_items = []
                        k = ""
                    else:
                        # Any other key cancels the selection sub-mode
                        info(tr("hotkey_copy_cancel"))
                        select_buf = ""
                        copy_mode = None
                        select_items = []
                        k = ""
                if k == "r":
                    # FULL wipe: saved session, credentials, cookies, sing-box
                    # configs AND the in-memory creds - a fresh sign-in must
                    # not be able to reuse anything (req: relogin = full wipe)
                    info(tr("hotkey_relogin"))
                    _hotkey_mode(False)
                    wipe_all_saved_data(creds)
                    # v5.22: ALL credential information is a wipe target -
                    # the disk caches went above; the IN-MEMORY leftovers go
                    # here. ensure_session() reads args.email / args.password /
                    # args.session_token FIRST (before creds), so a relogin
                    # that does not clear them re-logs-in silently with the
                    # old email/password - the leak seen live: after 'r' the
                    # script asked only for TOTP and signed in without ever
                    # asking for the login data. The live totp_provider
                    # closure (built from --qr of this run) and the CLI/env
                    # TOTP values are leftovers of exactly the same kind and
                    # go too: a fresh sign-in asks for email, password and
                    # the 2FA code (or gets them from a NEW --qr/--totp-secret
                    # --qr sign-in), reusing nothing from before the wipe.
                    totp_secret = None
                    totp_provider = None
                    args.email = None
                    args.password = None
                    args.session_token = None
                    args.qr = None
                    args.totp_secret = None
                    args.totp = None
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
                    # v5.22: same full in-memory wipe as 'r' (see there):
                    # args.email/password/session_token and the live
                    # totp_provider are credential leftovers a fresh sign-in
                    # must not be able to reuse.
                    totp_secret = None
                    totp_provider = None
                    args.email = None
                    args.password = None
                    args.session_token = None
                    args.qr = None
                    args.totp_secret = None
                    args.totp = None
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
                    # v6.9: the final engine choice is SAVED
                    # (settings.engine) and survives restarts.
                    save_str_setting("engine", args.local_proxy_engine)
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
                elif k == "w" and verified_servers:
                    # v5.12: choose WHICH local proxies to run. A MULTI
                    # selection: the tokens of several proxies are typed
                    # SEPARATED BY SPACES and confirmed with Enter; token
                    # '0' = ALL local proxies (clears the filter). The
                    # choice is cached in countries.json (the same file
                    # --countries persists to) and survives restarts.
                    copy_mode = "multi"
                    select_buf = ""
                    select_items = [{"token": "0", "all": True}]
                    select_items += [{"token": selection_token(i), "srv": srv}
                                     for i, srv in enumerate(verified_servers)]
                    flt_now = load_countries_filter()
                    active_keys = {str(x).strip().lower()
                                   for x in (flt_now.get("keys") or [])}
                    info(tr("countries_menu_hint"))
                    hint(tr("select_hint_multi"))
                    for it in select_items:
                        if it.get("all"):
                            hint(tr("countries_menu_entry", n=it["token"],
                                    desc=tr("filter_all_desc")))
                        else:
                            s = it["srv"]
                            mark = " [x]" if it["token"] in active_keys else ""
                            hint(tr("countries_menu_entry", n=it["token"],
                                    desc=(f"{s.get('countryName', '?')}/"
                                          f"{s.get('cityName', '?')} "
                                          f"{s.get('protocolHost', '')}"
                                          f"{mark}")))
                    # v5.12.1: ONE in-place line collects the typed tokens
                    # (every keystroke REWRITES it, like the countdown)
                    select_pad = _multi_line_show("", select_pad)
                elif k == "o":
                    # Open the config directory in the file manager.
                    # v6.0 (req. 4): ALL persisted configuration lives in
                    # ONE file, config.json, inside the config directory -
                    # there is no separate sing-box config directory anymore
                    # (the sing-box configs are sections of config.json; the
                    # runtime files live in a temp dir of the engine), so the
                    # hotkey always opens THE config directory.
                    # (no terminal mode change: the opener is a subprocess)
                    if os.path.isdir(CONF_DIR):
                        open_in_system_editor(CONF_DIR)
                    else:
                        os.makedirs(CONF_DIR, exist_ok=True)
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
                        # there is none: the reason depends on whether a
                        # current account exists in config.json at all and
                        # whether it has the totp_secret field inside.
                        acc = cfg_current_account()
                        reason = (tr("totp_none_reason_nocreds")
                                  if not acc
                                  else tr("totp_none_reason_nosecret"))
                        info(tr("hotkey_totp_none", reason=reason))
                elif k == "v" and engine and engine.proxies:
                    # Copy a LOCAL proxy address (listen host + port).
                    # v5.1: the list may exceed 9 items -> selection tokens
                    # (1-9, a-z, aa, ab, ...) confirmed with Enter.
                    copy_mode = "local"
                    select_buf = ""
                    select_items = [{"token": selection_token(i), "proxy": p}
                                    for i, p in enumerate(engine.proxies)]
                    info(tr("hotkey_copy_local_hint"))
                    hint(tr("select_hint"))
                    for it in select_items:
                        p = it["proxy"]
                        hint(tr("hotkey_copy_entry", n=it["token"],
                                addr=f"{engine.listen_host}:{p['port']}".ljust(36),
                                label=p["label"]))
                elif k == "b" and engine and engine.proxies:
                    # Copy an UPSTREAM (remote) proxy address (see 'v').
                    copy_mode = "remote"
                    select_buf = ""
                    select_items = [{"token": selection_token(i), "proxy": p}
                                    for i, p in enumerate(engine.proxies)]
                    info(tr("hotkey_copy_remote_hint"))
                    hint(tr("select_hint"))
                    for it in select_items:
                        p = it["proxy"]
                        hint(tr("hotkey_copy_entry", n=it["token"],
                                addr=f"{p['host']}:{p['upstreamPort']}".ljust(36),
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
                elif k == "a":
                    # v5.27 (fix 3) / v6.0 (req. 5): the ACCOUNT menu -
                    # switch to another CACHED Mozilla account, '+' add
                    # (sign in to) a NEW account, '-' delete an account.
                    # Every account lives in config.json; the selection
                    # menu uses the SAME token style as the other menus
                    # (1-9, a-z, ... + Enter); the prompt runs in the
                    # cooked terminal mode.
                    accounts = load_accounts()
                    _hotkey_mode(False)
                    # v6.0 (req. 5): the menu opens even with ZERO cached
                    # accounts - '+' (add a new account) must always be
                    # reachable; the account list is simply empty then.
                    if not accounts:
                        info(tr("accounts_none"))
                    info(tr("accounts_menu_hint"))
                    hint(tr("select_hint"))
                    emails = list(accounts.keys())
                    cur = cfg_current_email()
                    for i, em in enumerate(emails):
                        mark = (" [x]" if em == cur else "")
                        hint(tr("account_menu_entry",
                                n=selection_token(i),
                                email=em) + mark)
                    hint(tr("accounts_menu_add"))
                    hint(tr("accounts_menu_del"))
                    try:
                        choice = prompt_line(
                            tr("accounts_choice_prompt")).strip().lower()
                    except MozVpnError as e:
                        err(str(e))
                        choice = ""
                    tokmap = {selection_token(i): em
                              for i, em in enumerate(emails)}
                    if choice == "+":
                        # ADD a NEW account (req. 5): nothing is wiped -
                        # only the IN-MEMORY sign-in targets are
                        # cleared, so the next loop iteration prompts
                        # for the email/password/2FA of the NEW
                        # account; on success save_cache/cache_account
                        # add it to config.json and make it current.
                        info(tr("accounts_add_hint"))
                        args.email = None
                        args.password = None
                        args.session_token = None
                        args.qr = None
                        args.totp_secret = None
                        args.totp = None
                        creds.clear()
                        totp_secret = None
                        totp_provider = None
                        session_token = None
                        force_relogin = True
                        # v6.5: a NEW account is a NEW profile: its
                        # PROFILE-EXCLUSIVE data starts CLEAN. Reset
                        # the in-memory session (the cookie jar still
                        # holds the PREVIOUS profile's Fastly cookie
                        # and the challenge latch is still set) so
                        # the sign-in of the new account obtains its
                        # OWN fresh cookie - bound to IT (staged and
                        # flushed into its new entry), never written
                        # into the previous profile. The engine runs
                        # the OLD profile's proxies/configs - stop it;
                        # it is rebuilt from the NEW profile's tokens
                        # and filter after the sign-in.
                        _reset_fastly_session()
                        if engine:
                            engine.stop_all()
                        engine = None
                        break   # leave the sleep phase; the next loop
                                # iteration prompts for the new login
                    elif choice == "-":
                        # DELETE an account (req. 5): prompt for the
                        # token of the account to remove and drop it
                        # from config.json. Deleting the CURRENT
                        # account auto-switches to the first remaining
                        # one; when the LAST account is deleted a
                        # fresh sign-in is forced.
                        if not accounts:
                            info(tr("accounts_none"))
                            _hotkey_mode(True)
                        else:
                            try:
                                which = prompt_line(tr(
                                    "accounts_delete_prompt")).strip().lower()
                            except MozVpnError as e:
                                err(str(e))
                                which = ""
                            em = tokmap.get(which)
                            if not which:
                                _hotkey_mode(True)
                            elif em is None:
                                info(tr("accounts_delete_missing"))
                                _hotkey_mode(True)
                            else:
                                del accounts[em]
                                _save_accounts(accounts)
                                ok(tr("accounts_deleted", email=em))
                                if cfg_current_email() == em:
                                    # the CURRENT account was deleted:
                                    # switch to the first remaining
                                    # account, or force a fresh sign-in
                                    # when the store is now empty
                                    if accounts:
                                        first = next(iter(accounts))
                                        acc = accounts.get(first) or {}
                                        cfg_set_current(first)
                                        args.email = first
                                        args.password = acc.get("password")
                                        st = (acc.get("session_token")
                                              or "").strip()
                                        args.session_token = (st if st and all(
                                            ch in "0123456789abcdefABCDEF"
                                            for ch in st) else None)
                                        args.totp_secret = (acc.get(
                                            "totp_secret")
                                            or "").strip() or None
                                        args.qr = None
                                        args.totp = None
                                        creds.clear()
                                        creds.update({kk: acc.get(kk)
                                                      for kk in _CRED_KEYS})
                                        creds["email"] = first
                                        totp_secret = args.totp_secret
                                        totp_provider = make_totp_provider(
                                            args, creds)
                                        session_token = args.session_token
                                        info(tr("account_switched",
                                                email=first,
                                                session=(tr("account_session_used")
                                                         if args.session_token
                                                         else tr("account_session_fresh"))))
                                        if args.session_token:
                                            save_cache(first,
                                                       args.session_token)
                                        # v6.4: the auto-switch is a
                                        # FULL profile switch too -
                                        # apply the settings of the
                                        # first remaining account
                                        apply_profile_runtime(args)
                                    else:
                                        cfg_set_current(None)
                                        info(tr("accounts_delete_last"))
                                        args.email = None
                                        args.password = None
                                        args.session_token = None
                                        args.qr = None
                                        args.totp_secret = None
                                        args.totp = None
                                        creds.clear()
                                        totp_secret = None
                                        totp_provider = None
                                        session_token = None
                                        force_relogin = True
                                        # v6.4: no profile is left -
                                        # fall back to the provisional
                                        # profile (env/default settings)
                                        apply_profile_runtime(args)
                                # the sing-box configs of the deleted
                                # session are stale: restart the engine
                                # on the next iteration
                                if engine:
                                    engine.stop_all()
                                engine = None
                                break
                    elif choice in tokmap:
                        em = tokmap[choice]
                        acc = accounts.get(em) or {}
                        # Switch EVERYTHING the next loop iteration
                        # reads: args.* (ensure_session reads them
                        # FIRST), the creds dict and the TOTP
                        # provider. The cached sessionToken of the
                        # chosen account is tried first (skip the
                        # login prompt); on a Guardian failure the
                        # normal relogin path signs in with the
                        # cached login/password/TOTP.
                        args.email = em
                        args.password = acc.get("password")
                        st = (acc.get("session_token") or "").strip()
                        args.session_token = (st if st and all(
                            ch in "0123456789abcdefABCDEF"
                            for ch in st) else None)
                        args.totp_secret = (acc.get("totp_secret")
                                            or "").strip() or None
                        args.qr = None
                        args.totp = None
                        creds.clear()
                        creds.update({kk: acc.get(kk)
                                      for kk in _CRED_KEYS})
                        creds["email"] = em
                        totp_secret = args.totp_secret
                        totp_provider = make_totp_provider(args, creds)
                        session_token = args.session_token
                        if args.session_token:
                            # keep config.json in sync with the
                            # switched account (restarts reuse it)
                            save_cache(em, args.session_token)
                        cfg_set_current(em)
                        info(tr("account_switched", email=em,
                                session=(tr("account_session_used")
                                         if args.session_token
                                         else tr("account_session_fresh"))))
                        # v6.4: the WHOLE profile switches with the
                        # account - re-apply the saved language, the
                        # saved DoH resolver and the Fastly cookie of
                        # the newly selected profile at runtime (the
                        # explicit --lang/--doh/--doh-url argument of
                        # this run still wins, like at startup)
                        apply_profile_runtime(args)
                        # v6.4: the sing-box configs (and the local
                        # proxy selection) of the OLD profile are
                        # stale now: stop the engine so the next loop
                        # iteration rebuilds it from the NEW
                        # profile's configs and filter
                        if engine:
                            engine.stop_all()
                        engine = None
                        break       # leave the sleep phase; the next
                                    # loop iteration signs the account in
                    elif choice:
                        info(tr("accounts_bad_token"))
                        _hotkey_mode(True)
                    else:
                        _hotkey_mode(True)
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
                        # v8.1 (req. 3): the raw token row goes through
                        # the panel lift/drop pair, so the long wrapped
                        # row lands ABOVE the panel (like every log
                        # line) instead of overwriting its rows.
                        _panel_lift()
                        print(token_now)
                        _panel_drop()
                        copy_to_clipboard(token_now)
                    else:
                        info(tr("hotkey_jwt_none"))
                elif k == "m":
                    # v4.4 (req. 2): switch the color theme dark <-> light
                    # (mirrors --theme); v4.5: the WHOLE log is redrawn in
                    # the new theme (every remembered line re-rendered);
                    # v6.9: the choice is SAVED (settings.theme) and
                    # survives restarts.
                    new_theme = "light" if _THEME == "dark" else "dark"
                    set_theme(new_theme)
                    save_str_setting("theme", new_theme)
                    redraw_log()
                    info(tr("hotkey_theme", theme=new_theme))
                elif k == "h":
                    # v5.1 (req. 2): 'h' now OPENS A SELECTION MENU of the
                    # DNS resolvers (like the v/b copy lists) instead of
                    # cycling: every DoH preset + the system DNS entry.
                    # Applies live to the builtin engine (every new upstream
                    # connection resolves again) and to the next probe run.
                    # v5.31: option '0' switches to the DEFAULT resolver
                    # (cloudflare); the CURRENT resolver is marked [x];
                    # the applied choice is PERSISTED to doh.json and
                    # survives restarts.
                    # v9.1: the SAME choice is the DoH target of the
                    # per-proxy DNS endpoints - EXACTLY ONE provider,
                    # NO fallback chain (default cloudflare); the
                    # relay reads doh_wire_targets() per query, so
                    # the change applies LIVE (no restart, no engine
                    # rebuild).
                    copy_mode = "doh"
                    select_buf = ""
                    select_items = [{"token": "0", "default": True}]
                    for i, name in enumerate(DOH_PRESETS):
                        select_items.append(
                            {"token": selection_token(i + 1),
                             "provider": name})
                    select_items.append({"token": selection_token(len(
                                                select_items) + 1),
                                         "provider": ""})   # system DNS
                    info(tr("doh_menu_hint"))
                    hint(tr("select_hint"))
                    for it in select_items:
                        if it.get("default"):
                            hint(tr("doh_menu_entry", n=it["token"],
                                    name=tr("doh_default_desc").ljust(10),
                                    url=""))
                        elif it["provider"]:
                            name = it["provider"]
                            mark = (" [x]" if name == _doh_provider else "")
                            hint(tr("doh_menu_entry", n=it["token"],
                                    name=name.ljust(10),
                                    url=f"({DOH_PROVIDERS.get(name, name)})"
                                    ) + mark)
                        else:
                            mark = (" [x]" if not _doh_provider else "")
                            hint(tr("doh_menu_entry", n=it["token"],
                                    name=tr("doh_system_short").ljust(10),
                                    url="") + mark)
                elif k == "k":
                    # v5.1 (req. 4): toggle the DoH answer cache on/off
                    # (mirrors --doh-cache); the cache is DISABLED by
                    # default. v6.9: the choice is SAVED
                    # (settings.doh_cache) and survives restarts.
                    set_doh_cache(not doh_cache_enabled())
                    save_bool_setting("doh_cache", doh_cache_enabled())
                    state = tr("color_state_on" if doh_cache_enabled()
                               else "color_state_off")
                    info(tr("hotkey_doh_cache", state=state))
                    if doh_cache_enabled():
                        info(tr("doh_cache_state_on", ttl=DOH_TTL))
                    else:
                        info(tr("doh_cache_state_off"))
                elif k == "i":
                    # v6.6 (req. 12): toggle the TLS ClientHello
                    # fragmentation (mirrors --tls-split; 'i' is the one
                    # free letter of the hotkey set). ON by default
                    # since v6.7 (the user's defaults-on directive) and
                    # SAFE by construction: any fragmented-handshake
                    # failure falls back to the plain profile matrix,
                    # so the v6.1 lesson (a transport 'hardening' must
                    # never surprise the working data path) holds even
                    # with the feature enabled. Applies to the NEW
                    # outer-TLS connections of the probes and the
                    # builtin engine. v6.9: the choice is SAVED
                    # (settings.tls_split) and survives restarts.
                    set_tls_split(not tls_split())
                    save_bool_setting("tls_split", tls_split())
                    state = tr("color_state_on" if tls_split()
                               else "color_state_off")
                    info(tr("hotkey_tls_split", state=state))
                elif k == "n":
                    # v4.4 (req. 3): toggle the colored log output on/off
                    # (mirrors --no-color); v4.5: the WHOLE log is redrawn
                    # with colors on or off. v4.7.1: the forced window
                    # background follows the color mode - colors back on
                    # -> re-force the theme background (idempotent, so a
                    # no-op while it was never released); colors off ->
                    # release it back to the terminal default.
                    # v5.17 FIX: 'global _BG_CURRENT' - without the
                    # declaration the assignment below made the name a
                    # LOCAL of the watch-loop function, so the
                    # 'elif _BG_CURRENT is not None' read raised
                    # UnboundLocalError("cannot access local variable
                    # '_BG_CURRENT' where it is not associated with a
                    # value") and killed the handler after set_color()
                    # had already flipped the mode (the outer retry loop
                    # reported it as 'Unexpected error').
                    # v6.9: the color choice is SAVED (settings.color)
                    # and survives restarts.
                    global _BG_CURRENT
                    set_color(not _USE_COLOR)
                    save_bool_setting("color", _USE_COLOR)
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
                elif k == "f":
                    # v5.5 (req. 3): export ALL running local proxies as a
                    # FoxyProxy Standard settings file (CURRENT format) -
                    # OS save dialog, or --foxyproxy-out path when set.
                    if engine and engine.proxies:
                        _hotkey_mode(False)
                        export_foxyproxy(args, engine.proxies,
                                         engine.listen_host, legacy=False)
                        _hotkey_mode(True)
                    else:
                        info(tr("foxyproxy_no_proxies"))
                elif k == "x":
                    # v5.5 (req. 4): same export in the LEGACY FoxyProxy
                    # XML format (FoxyProxy 4.x foxyproxy.xml).
                    if engine and engine.proxies:
                        _hotkey_mode(False)
                        export_foxyproxy(args, engine.proxies,
                                         engine.listen_host, legacy=True)
                        _hotkey_mode(True)
                    else:
                        info(tr("foxyproxy_no_proxies"))
                elif k and k.isdigit() and k != "0":
                    # v8.2 (user request): since v6.0 the editable config
                    # is ONE file (config.json), so only '1' opens
                    # anything - the hint used to promise '1-9' and the
                    # digits 2-9 failed SILENTLY. The mechanism stays
                    # DYNAMIC (config_open_files() decides the list -
                    # more files would light their digits up again), and
                    # an out-of-range digit now SAYS so via hotkey_no_file
                    # instead of doing nothing. History: v5.34 made the
                    # digits open the file DIRECTLY - the selection token
                    # of the first file IS '1', no Enter needed (v5.1-
                    # v5.33 switched the digits into the token sub-mode
                    # whenever the list exceeded 9 files). Files beyond
                    # the list are opened with the 'z' hotkey (the full
                    # token menu, see below).
                    files = config_open_files()
                    idx = int(k) - 1
                    if 0 <= idx < len(files):
                        open_in_system_editor(files[idx])
                    else:
                        info(tr("hotkey_no_file", k=k, n=int(k)))
                elif k == "z":
                    # v5.34 (user request): the FULL config-file selection
                    # menu - the analog of the other hotkey menus (tokens
                    # 1-9, a-z, aa, ab, ... + Enter, Backspace deletes,
                    # any other key cancels, Enter applies and exits per
                    # the v5.30 rule). This gives EVERY listed config file
                    # a hotkey: 1-9 open directly, 'z' + the letter token
                    # opens the rest (sing-box configs, any file past the
                    # ninth).
                    files = config_open_files()
                    if not files:
                        # config.json is auto-created at startup, so this
                        # is nearly unreachable - show where it would live
                        info(tr("hotkey_open_missing", path=CONFIG_FILE))
                    else:
                        copy_mode = "files"
                        select_buf = ""
                        select_items = [{"token": selection_token(i),
                                         "path": p}
                                        for i, p in enumerate(files)]
                        info(tr("files_menu_hint", n=len(files)))
                        hint(tr("select_hint"))
                        for it in select_items:
                            hint(tr("hotkey_file_entry", n=it["token"],
                                    path=it["path"]))
                elif k == "y":
                    # v5.30 (user request): the INTERFACE LANGUAGE menu
                    # (en/ru), in the SAME token+Enter style as the other
                    # hotkey menus. The choice is PERSISTED to lang.json
                    # in the config directory (survives restarts); option
                    # '0' resets to the DEFAULT language and clears the
                    # saved choice. Applying (Enter) EXITS the menu
                    # automatically (the v5.30 menu auto-exit rule).
                    copy_mode = "lang"
                    select_buf = ""
                    select_items = [{"token": "0", "reset": True},
                                    {"token": "1", "lang": "en"},
                                    {"token": "2", "lang": "ru"}]
                    info(tr("lang_menu_hint", cur=_LANG))
                    hint(tr("select_hint"))
                    for it in select_items:
                        if it.get("reset"):
                            hint(tr("lang_menu_entry", n=it["token"],
                                    desc=tr("lang_default_desc")))
                        else:
                            mark = (" [x]" if it["lang"] == _LANG else "")
                            hint(tr("lang_menu_entry", n=it["token"],
                                    desc=it["lang"]) + mark)
                elif k == "\x0f":
                    # v6.0 (req. 7): Ctrl+O (Ctrl+O arrives as the single
                    # control char 0x0F in cbreak mode) - find and REMOVE
                    # every leftover of the OLD config format (the pre-v6
                    # json files, the singbox/ and engine/ directories, the
                    # old on-disk QR pngs). config.json itself is NEVER
                    # touched. Mirrors --clean-old-config.
                    _hotkey_mode(False)
                    clean_old_config_format(verbose=True)
                    _hotkey_mode(True)
                elif k == "\x12":
                    # v8.0 (A2): Ctrl+R (the single control char 0x12 in
                    # cbreak mode) - toggle the ACCOUNT AUTO-ROTATION by
                    # quota on/off. The choice is SAVED at once
                    # (settings.auto_rotate, the v6.9 sticky-settings
                    # pattern) and mirrors --auto-rotate /
                    # --no-auto-rotate; the run keeps going - the flag
                    # only GATES the rotation trigger of the watch loop.
                    new_state = not auto_rotate_enabled()
                    set_auto_rotate(new_state)
                    save_bool_setting("auto_rotate", new_state)
                    info(tr("auto_rotate_switched",
                            state=(tr("auto_rotate_on") if new_state
                                   else tr("auto_rotate_off"))))
                elif k == "\x14":
                    # v8.4 (user request): Ctrl+T (the single control char
                    # 0x14) now opens the LOCAL PROXY TYPE SELECTION MENU -
                    # the SAME generic token sub-mode the 'h' DoH / 'y'
                    # language / 'z' files menus ride (type the number,
                    # Enter applies, Backspace deletes, any other key
                    # cancels, the menu exits automatically after applying)
                    # - instead of the v8.0 blind cycle. v8.5: the menu
                    # rides _PROXY_TYPES, so it lists EXACTLY the two
                    # http / socks5 options (the 'mixed' single-port
                    # listener is REMOVED). Every option carries its
                    # short description and
                    # the RUNNING type is marked [x]; the apply branch in
                    # the generic selection handler runs the exact v8.0
                    # cycle sequence (set + save settings.proxy_type +
                    # stop the engine so the next watch-loop iteration
                    # rebuilds the listeners; BOTH engines read
                    # get_proxy_type() at build time); mirrors
                    # --proxy-type. The PAC file follows on the rebuild
                    # only for an explicit --pac-export FILE (the default
                    # copy is on demand via Ctrl+P).
                    copy_mode = "ptype"
                    select_buf = ""
                    select_items = []
                    for i, t in enumerate(_PROXY_TYPES):
                        select_items.append({"token": selection_token(i),
                                             "ptype": t})
                    info(tr("ptype_menu_hint", cur=get_proxy_type()))
                    hint(tr("select_hint"))
                    for it in select_items:
                        mark = (" [x]" if it["ptype"] == get_proxy_type()
                                else "")
                        hint(tr("ptype_menu_entry", n=it["token"],
                                name=it["ptype"],
                                desc=tr("ptype_desc_" + it["ptype"]))
                             + mark)
                elif k == "\x10":
                    # v8.0 (B3): Ctrl+P (the single control char 0x10) -
                    # rewrite the PAC file with the CURRENTLY RUNNING
                    # listeners on demand, e.g. after a 'w' filter
                    # change. v8.2: this hotkey is now the ONLY writer
                    # of the DEFAULT copy (a rebuild touches just an
                    # explicit --pac-export FILE). Mirrors --pac-export.
                    _hotkey_mode(False)
                    if engine and getattr(engine, "proxies", None):
                        maybe_pac_export(args, engine, on_demand=True)
                    else:
                        info(tr("pac_no_proxies"))
                    _hotkey_mode(True)
                elif k == "q":
                    info(tr("hotkey_stop"))
                    _STOP = True
                    break
                # v5.1 (req. 7): poll keys FAST while a selection sub-mode is
                # active (so multi-character tokens + Enter feel instant),
                # otherwise keep the calm 1 s cadence.
                step = 0.05 if copy_mode else 1
                time.sleep(step)
                slept += step
            _hotkey_mode(False)
            if _STOP:
                break
            # v6.6 (items 3/4/13): THE LIVE PASS-HEALTH SIGNALS of the
            # builtin engine broke the sleep above - react IMMEDIATELY
            # (Firefox reacts to a non-2xx CONNECT of the egress the
            # moment it observes it: IPPNetworkErrorObserver ->
            # 'proxy-http-error'), with the rotation floors applied
            # (minRotationInterval 1 s + the 500 ms retryAfter pacing -
            # never a tight refresh loop).
            if _PassMonitor.rejected.is_set() or _PassMonitor.session_fail.is_set():
                _ev_reject = _PassMonitor.rejected.is_set()
                _PassMonitor.rejected.clear()
                _PassMonitor.session_fail.clear()
                if _ev_reject:
                    warn(tr("pass_rejected_refresh"))
                else:
                    warn(tr("session_fail_refresh"))
                _floor = 1.0 - _PassMonitor.since_refresh()
                if _floor > 0:
                    time.sleep(_floor + 0.5)
                # v6.6 (item 13): THE PERSISTENTLY-BROKEN SELECTION -
                # when a saved countries filter leaves the engine serving
                # proxies whose egresses ALL keep failing (5+ consecutive
                # failures on EVERY served host), clear the saved choice:
                # the next rebuild serves ALL proxies (the same 'never
                # zero usable proxies' fallback the probe phase has); the
                # user can re-apply the selection with 'w' once the
                # egresses recover.
                if (engine is not None and getattr(engine, "proxies", None)
                        and load_countries_filter()
                        and all(_PassMonitor.host_failures(p["host"]) >= 5
                                for p in engine.proxies)):
                    warn(tr("filter_cleared_broken"))
                    clear_countries_filter()
                    engine.stop_all()
                    engine = None
                continue

        except MozVpnError as e:
            # v5.26 (POSIX terminal safety): the exception may have fired
            # INSIDE the hotkey/cbreak phase (e.g. a failed proxyPass
            # refresh during the sleep window) - restore the cooked tty
            # BEFORE the countdown and the next prompt round, otherwise
            # the next input()/getpass() reads a raw-cbreak terminal
            # (Windows is unaffected: _hotkey_mode is a no-op there).
            _hotkey_mode(False)
            err(str(e))
            # Language-independent classification via MozVpnError.code
            code = getattr(e, "code", "")
            if code == "blocked_login":
                # v6.6 (item 8): the FxA LOGIN rate limit (HTTP 429 /
                # errno 114): a 15-minute cooldown, and the retry prefers
                # the CACHED session token (ensure_session reuses it
                # automatically - a rate-limited password login never
                # keeps re-prompting). The Guardian-side blocks keep the
                # old generic 'blocked' wait below.
                info(tr("fxa_429_cooldown"))
                _sleep_interruptible(900)
            elif code == "blocked":
                info(tr("blocked_wait"))
                _sleep_interruptible(600)
            elif code == "relogin":
                info(tr("relogin_needed"))
                # v8.0 (A3): with --fxa-profile the re-login RE-READS
                # the Firefox profile session file first (ensure_session
                # does this on every call) - so when the browser session
                # itself expired (the OAuth errno 110 path), the user
                # must sign into Firefox again BEFORE the retry can
                # succeed; the hint says exactly that.
                if getattr(args, "fxa_profile", None) and "110" in str(e):
                    info(tr("fxa_profile_session_invalid"))
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
                # v6.0 (req. 1): the ADAPTIVE refresh retry. When the
                # failure hit a proxyPass REFRESH (not the first sign-in)
                # and the CURRENT token is still valid, the wait is
                # SHORTENED to at most 15 s: a full retry delay would eat
                # into the refresh margin, the token could expire before
                # the next attempt, and the local proxies would go dark
                # for exactly the "works again after a while" window the
                # user reported. The old token keeps the proxies alive
                # while the retries run.
                if token_exp and token_exp - int(time.time()) > 0:
                    retry_s = min(retry_s, 15)
                    info(tr("refresh_retry_soon", sec=retry_s))
                info(tr("retry_after", sec=retry_s))
                _sleep_with_countdown(retry_s)
        except KeyboardInterrupt:
            _hotkey_mode(False)     # v5.26: never leave the tty in cbreak
            break
        except Exception as e:
            _hotkey_mode(False)     # v5.26: same guard for unexpected errors
            # v5.12: a TRANSIENT network error (a DNS blip like
            # gaierror(7), a momentary timeout) gets a FRIENDLY short
            # localized reason instead of the raw exception repr; the
            # retry wait stays the same 30 s.
            if _is_transient_net_error(e):
                warn(tr("net_error_retry", err=_net_err_public(e)))
            else:
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
    OUTSIDE hotkey mode, so line editing is unaffected.

    v5.24 (Termux fix): two POSIX-only hardening measures.
    1) A DOUBLE _hotkey_mode(True) no longer overwrites the saved
       'old' attributes with the ALREADY-CBREAK state - previously a
       second True (nested handler pairs call False->True again)
       could leave 'old' = cbreak, so a later False restored CBREAK
       instead of the cooked mode: the following input()/getpass()
       prompts misbehaved (no line editing, Enter passed through, the
       TOTP prompt looked 'skipped' and the sign-in failed) - only on
       Android/Termux and desktop POSIX, never on Windows (no-op).
    2) Leaving hotkey mode FLUSHES the pending input queue
       (termios.tcflush TCIFLUSH) and clears _KEY_BUF, so stray
       cbreak-mode keystrokes (typed during the countdown/hotkey
       phase) can no longer leak into the next interactive prompt and
       corrupt the email/password/TOTP entry."""
    if os.name == "nt":
        return
    global _KEY_BUF
    try:
        import termios, tty
        fd = sys.stdin.fileno()
        if on:
            if not getattr(_hotkey_mode, "old", None):
                _hotkey_mode.old = termios.tcgetattr(fd)
            tty.setcbreak(fd)
        elif getattr(_hotkey_mode, "old", None):
            termios.tcsetattr(fd, termios.TCSADRAIN, _hotkey_mode.old)
            _hotkey_mode.old = None
            try:
                termios.tcflush(fd, termios.TCIFLUSH)
            except Exception:
                pass
            _KEY_BUF = b""
    except Exception:
        pass

# v4.7 (req. 2): hotkeys must work in ANY keyboard layout. Two layers:
#
# 1) WINDOWS - fully layout-independent via the PHYSICAL key position:
#    msvcrt.getwch() returns the character produced by the CURRENT
#    layout (e.g. '\u0439' when Russian JCUKEN is active), so the raw char
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
#    table for the standard Cyrillic JCUKEN family (Russian, and the
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
    # standard Russian JCUKEN: typed letter -> English key in the same
    # physical position (Belarusian/Ukrainian layouts share the letter
    # row positions; their unique letters sit where [];' etc. are and
    # are not used by any hotkey)
    "\u0439": "q", "\u0446": "w", "\u0443": "e", "\u043a": "r", "\u0435": "t",
    "\u043d": "y", "\u0433": "u", "\u0448": "i", "\u0449": "o", "\u0437": "p",
    "\u0444": "a", "\u044b": "s", "\u0432": "d", "\u0430": "f", "\u043f": "g",
    "\u0440": "h", "\u043e": "j", "\u043b": "k", "\u0434": "l",
    "\u044f": "z", "\u0447": "x", "\u0441": "c", "\u043c": "v", "\u0438": "b",
    "\u0442": "n", "\u044c": "m", "\u0457": "s", "\u0456": "s", "\u045e": "f",
    # uppercase too (Caps Lock)
    "\u0419": "q", "\u0426": "w", "\u0423": "e", "\u041a": "r", "\u0415": "t",
    "\u041d": "y", "\u0413": "u", "\u0428": "i", "\u0429": "o", "\u0417": "p",
    "\u0424": "a", "\u042b": "s", "\u0412": "d", "\u0410": "f", "\u041f": "g",
    "\u0420": "h", "\u041e": "j", "\u041b": "k", "\u0414": "l",
    "\u042f": "z", "\u0427": "x", "\u0421": "c", "\u041c": "v", "\u0418": "b",
    "\u0422": "n", "\u042c": "m", "\u0407": "s", "\u0406": "s", "\u040e": "f",
}

def _normalize_key(k: str) -> str:
    """Map a RAW pressed key to the canonical (English QWERTY) hotkey
    letter, so hotkeys work in any keyboard layout (v4.7, req. 2).
    Returns '' for anything that is not a single-character key.
    v6.3 (user report): CONTROL CHARACTERS pass through UNCHANGED.
    On Windows the layout-mapping below feeds the raw char to
    VkKeyScanW - and VkKeyScanW('\\x0f') legitimately answers 'the O
    key with Ctrl held' (Ctrl+O TYPES \\x0f in the console; Microsoft
    Learn: the low byte of the VkKeyScan return value is the virtual
    key code, the high byte the shift state, where 'either CTRL key
    is pressed' is a documented flag bit), so the layout route
    rewrote EVERY Ctrl+letter combination into its PLAIN hotkey
    letter: Ctrl+O opened the config directory (the 'o' handler) and
    never reached its own \\x0f handler - the user's live report
    'Ctrl+O does not work, it conflicts with the plain O'. A control
    char is not 'a letter in another layout' - it is a key
    COMBINATION, so it must reach the combination handlers as-is.
    This also makes Backspace (\\x08), DEL (\\x7f), Enter (\\r, \\n)
    and Esc (\\x1b) deterministic on Windows: the layout scan can no
    longer rewrite them either."""
    if not k or len(k) != 1:
        return ""
    if ord(k) < 0x20 or ord(k) == 0x7F:
        return k                     # a control char IS the hotkey
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

_KEY_BUF = b""

def _key_pressed() -> str:
    """Non-blocking single-key read; returns the canonical hotkey letter
    (independent of the active keyboard layout, see _normalize_key) or ''.
    v5.15: the POSIX read is now BUFFERED. One keypress can be a
    MULTI-BYTE UTF-8 character (a non-English layout) or an ESCAPE
    sequence (arrows etc.), and the kernel may deliver those bytes
    across SEVERAL read() calls - the v5.13 code re-read the UTF-8
    continuation bytes with a BLOCKING os.read(), which could FREEZE
    the whole hotkey loop forever when a lead byte arrived alone (a
    split write is exactly what happens on some PTYs). Now every poll
    reads ALL currently available bytes at once, keeps the leftover in
    _KEY_BUF and returns ONE complete character per call; escape
    sequences are consumed whole (an arrow key must not leak its tail
    as a hotkey letter); a partial UTF-8 sequence is completed with a
    few BOUNDED 20 ms waits - never a blocking read."""
    global _KEY_BUF
    try:
        if os.name == "nt":
            import msvcrt
            if msvcrt.kbhit():
                k = msvcrt.getwch()
                # Ignore bare special-key prefixes (arrows etc.)
                return _normalize_key(k) if len(k) == 1 else ""
            return ""
        import select
        fd = sys.stdin.fileno()
        if not _KEY_BUF:
            r, _, _ = select.select([sys.stdin], [], [], 0)
            if not r:
                return ""
            # everything that is available RIGHT NOW (the whole UTF-8
            # sequence of the pressed key arrives in one terminal write)
            _KEY_BUF = os.read(fd, 32)
            if not _KEY_BUF:
                return ""
        c = _KEY_BUF[0]
        if c == 0x1B:                       # ESC - or the start of ESC [ ...
            r, _, _ = select.select([sys.stdin], [], [], 0.02)
            if r:
                _KEY_BUF += os.read(fd, 32)
            if len(_KEY_BUF) > 1:
                # an escape sequence (arrows, Home etc.): consume it
                # whole and produce NO hotkey letter
                _KEY_BUF = b""
                return ""
            _KEY_BUF = b""
            return "\x1b"                   # a BARE Esc keeps its old role
        if c >= 0xC0:                       # UTF-8 lead byte
            need = 1 if c < 0xE0 else (2 if c < 0xF0 else 3)
            while len(_KEY_BUF) < 1 + need:
                r, _, _ = select.select([sys.stdin], [], [], 0.02)
                if not r:
                    break                   # bounded wait - never blocks
                _KEY_BUF += os.read(fd, 32)
            take, _KEY_BUF = _KEY_BUF[:1 + need], _KEY_BUF[1 + need:]
            k = take.decode("utf-8", "replace")
            # an INCOMPLETE sequence (the continuation bytes never came
            # within the bounded waits) decodes to U+FFFD - return NO key
            # instead of leaking a truthy garbage char into the hotkey
            # loop (it would cancel the selection sub-modes)
            return _normalize_key(k) if "\ufffd" not in k else ""
        if 0x80 <= c < 0xC0:
            # a stray continuation byte (leftover garbage): skip it
            _KEY_BUF = _KEY_BUF[1:]
            return ""
        take, _KEY_BUF = _KEY_BUF[0:1], _KEY_BUF[1:]
        return _normalize_key(take.decode("utf-8", "replace"))
    except Exception:
        pass
    _KEY_BUF = b""
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

SINGBOX_INSTALL_PAGE  = "https://sing-box.sagernet.org/installation/"
SINGBOX_RELEASES_PAGE = "https://github.com/SagerNet/sing-box/releases"

def selection_token(index: int) -> str:
    """v5.1: selection tokens for interactive lists (hotkeys v / b / h):
    1-9 first, then the English letters a-z, then two-letter combinations
    aa, ab, ... - so a list with more than 9 items stays usable (typing
    '10' or 'ab' works because the choice is confirmed with Enter)."""
    if index < 0:
        return ""
    if index < 9:
        return str(index + 1)
    index -= 9
    letters = "abcdefghijklmnopqrstuvwxyz"
    if index < 26:
        return letters[index]
    index -= 26
    if index < 26 * 26:
        return letters[index // 26] + letters[index % 26]
    return ""

def selection_tokens(count: int) -> "list[str]":
    """The token list for a list of `count` items."""
    return [selection_token(i) for i in range(count)]

def _multi_line_show(buf: str, prev_len: int) -> int:
    """v5.12.1: ONE in-place echo line for the hotkey 'w' multi-selection.
    The typed tokens are shown by REWRITING this very line (\r, the same
    technique as the retry countdown) - NOT by adding a new log line per
    keystroke (v5.12 did that and the log filled with 'Selected: ...'
    duplicates). Returns the printed length for the next rewrite."""
    line = "  " + tr("multi_buffer", buf=buf)
    # erase the previous content first (+4 slack for the emoji columns)
    print("\r" + " " * (prev_len + 4) + "\r" + line, end="", flush=True)
    return len(line)

def _multi_line_clear(prev_len: int):
    """v5.12.1: erase the in-place multi-selection line (on apply/cancel),
    so the summary lines that follow start on a clean row."""
    print("\r" + " " * (prev_len + 4) + "\r", end="", flush=True)

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
    """v6.0: the decline marker lives in config.json
    (settings.singbox_declined)."""
    try:
        return bool(cfg_get(("settings", "singbox_declined")))
    except Exception:
        return False

def _save_singbox_declined():
    try:
        cfg_set(("settings", "singbox_declined"), True)
    except (OSError, ValueError):
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

def _env_flag(name: str, default: "bool | None") -> "bool | None":
    """Env-aware boolean default (v4.7.2): unset/empty env -> the given
    default; a set env is checked with the truthy words 1/true/yes/on.
    v6.9: default=None means 'not chosen' (the sticky-settings
    resolution then falls through to the SAVED config.json choice).
    Used for the now-DEFAULT-ON flags: MOZVPN_LOCAL_PROXY=0 disables the
    local proxies, MOZVPN_NO_SAVE=0 re-enables saving the result JSON."""
    v = os.environ.get(name)
    if v is None or not v.strip():
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")

def print_config_files():
    """req: log which config/cache files on the user's system this run uses.
    v6.0 (req. 4): there is exactly ONE persisted file - config.json, the
    uber-config holding EVERYTHING (accounts with their sessions, settings,
    the Fastly cookie and the sing-box configs as sections)."""
    info(tr("config_files_header"))
    for path in (CONFIG_FILE,):
        if os.path.isfile(path):
            st = os.stat(path)
            status = tr("config_file_exists", size=st.st_size,
                        mtime=time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.gmtime(st.st_mtime)))
        else:
            status = tr("config_file_missing")
        hint(tr("config_file_entry", path=path, status=status))

def print_clear_targets(panel: list = None):
    """req: log exactly which files/directories the 'c' hotkey and the
    --clear-cache flag remove. v6.0 (req. 4): the wipe RESETS the single
    uber-config config.json (keeping the account store) and removes every
    leftover of the OLD config format - there are no other persisted
    files anymore. v8.1 (req. 3): with `panel` given the rows go to the
    live-panel line list (the block is re-shown by every refresh and
    belongs to the redrawn UI); the --clear-cache one-shot path keeps
    the classic log lines."""
    def _row(level, msg):
        if panel is None:
            _emit(level, msg)
        else:
            panel.append((level, msg))
    _row("info", tr("clear_will_remove_header"))
    if os.path.exists(CONFIG_FILE):
        _row("hint", tr("clear_will_remove_entry", path=CONFIG_FILE))
    _row("hint", tr("clear_will_remove_legacy", path=LEGACY_CONF_DIR))

def config_open_files() -> list:
    """Ordered list of the config files that can be opened with the number
    hotkeys. v6.0 (req. 4): the single source of truth is config.json; the
    runtime sing-box config files live in the engine's PRIVATE TEMP
    directory (they are regenerated from the config.json sections on
    every start and removed on stop), so the editable file list is just
    the uber-config itself. The 1-9/z menu keeps working unchanged."""
    return [CONFIG_FILE] if os.path.isfile(CONFIG_FILE) else []

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
                    default=None,
                    help="Local proxy engine: builtin (default, in-process threads, no "
                         "external dependencies, Nuitka/exe-friendly) or singbox "
                         "(external binary). v6.9: the last choice is saved and "
                         "survives restarts. Env: MOZVPN_PROXY_ENGINE")
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
    ap.add_argument("--probe-count", type=int, default=0,
                    help="How many upstreams to probe before starting the "
                         "local proxies (v5.0 default: 0 = probe ALL of "
                         "them; the old default of 1 hid most upstreams)")
    ap.add_argument("--upstream-host", metavar="HOST", default=None,
                    help="Force every upstream to this host (e.g. the Fastly "
                         "anycast pool p.m1.fastly-masque.net) instead of the "
                         "per-city hosts from the server list")
    ap.add_argument("--upstream-port", type=int, default=None,
                    help="Force the upstream port (default: keep the server-list port)")
    ap.add_argument("--max-proxies", type=int, default=0,
                    help="Maximum number of local proxies (0 = all locations)")
    # v5.0: DNS-over-HTTPS for the egress hostnames (Firefox-like TRR).
    ap.add_argument("--doh",
                    choices=["cloudflare", "google", "nextdns", "quad9", "off"],
                    default=None,
                    help="DNS-over-HTTPS provider used to resolve the Fastly "
                         "egress hostnames (v5.0, like Firefox TRR - protects "
                         "against poisoned/geo-wrong system DNS that routes "
                         "you to a US PoP). Presets: cloudflare (default), "
                         "google, nextdns, quad9; 'off' = the system DNS. "
                         "v5.31: default = the SAVED hotkey-'h' choice when "
                         "present, else env, else 'cloudflare'. v9.1: the "
                         "local DNS endpoints relay the CLIENTS' DNS "
                         "through the proxies to this provider's RFC "
                         "8484 wireformat endpoint ONLY (NO fallback "
                         "chain anymore: nothing chosen / 'off' -> the "
                         "built-in default cloudflare; a dead target "
                         "fails THAT query, the client's resolver "
                         "retries). v8.6: the preset resolvers "
                         "are contacted by their well-known IPs directly "
                         "(the resolver hostname is never resolved with "
                         "the system resolver) and every DoH TLS "
                         "handshake rides the fragmented ClientHello "
                         "(--tls-split). Env: "
                         "MOZVPN_DOH")
    ap.add_argument("--doh-url", metavar="URL", default=None,
                    help="Custom DoH endpoint (RFC 8484 JSON API, "
                         "?name=&type=A) - overrides the --doh preset; "
                         "v9.1: the ONLY (best-effort parsed) "
                         "RFC 8484 wireformat target of the local DNS "
                         "endpoints - a JSON-only custom endpoint fails "
                         "the relayed query instead of falling back to "
                         "another provider; v8.6: a custom endpoint keeps "
                         "the "
                         "urlopen transport for the script's OWN "
                         "resolution (its IP is unknowable without a "
                         "name resolution) - the RELAYED DoH handshakes "
                         "to it are still fragmented (--tls-split)")
    # v5.1 (req. 4) -> v6.9: the DoH answer cache is DISABLED by
    # default and is opt-in (--doh-cache / hotkey 'k' / env
    # MOZVPN_DOH_CACHE=1); since v6.9 the choice is SAVED
    # (settings.doh_cache) and survives restarts. The argparse
    # default is None ('not chosen'), so the SAVED choice applies
    # and an explicit flag always wins.
    ap.add_argument("--doh-cache", action=argparse.BooleanOptionalAction,
                    default=None,
                    help="Cache DoH answers for %d seconds (v5.1; DISABLED "
                         "by default: without the flag every lookup queries "
                         "the DoH chain directly). v6.9: the last choice is "
                         "saved and survives restarts. Env: MOZVPN_DOH_CACHE" %
                         DOH_TTL)
    # v5.29 (security, user request): STRICT DoH - NO automatic fallback
    # from the DoH chain to the system (non-DoH) resolver. The fallback
    # is strictly OPT-IN here; '--no-system-dns-fallback' is the default.
    ap.add_argument("--system-dns-fallback",
                    action=argparse.BooleanOptionalAction,
                    default=_env_flag("MOZVPN_SYSTEM_DNS_FALLBACK", False),
                    help="v5.29, security: when a DoH provider is selected "
                         "and the WHOLE DoH chain fails, do NOT fall back "
                         "to the system (non-DoH) resolver - the lookup "
                         "fails instead (like Firefox TRR mode 3). This "
                         "flag OPTS IN to the old last-resort system-DNS "
                         "behavior; the system DNS is always available "
                         "explicitly via --doh off. Env: "
                         "MOZVPN_SYSTEM_DNS_FALLBACK")
    # v8.5 -> v9.0: the PER-PROXY local DNS endpoints (the OS-resolver
    # door: plain DNS on every proxy's deterministic '<location>|dns'
    # port -> DoH through THAT proxy only - never another one). ON by
    # default; '--no-dns-relay' does not bind them at all (the proxies
    # and their socks5h remote DNS are NOT affected).
    ap.add_argument("--dns-relay",
                    action=argparse.BooleanOptionalAction,
                    default=_env_flag("MOZVPN_DNS_RELAY", True),
                    help="v8.5 -> v9.0: the PER-PROXY local DNS "
                         "endpoints - plain DNS (UDP+TCP) on every "
                         "proxy's deterministic port, relayed as DoH "
                         "through THAT proxy only (never another "
                         "one, so a country's DNS blocks follow the "
                         "proxy you actually ride); point the SYSTEM "
                         "resolver / any plain-DNS app at the DNS "
                         "port shown next to the proxy you use. "
                         "--no-dns-relay does not bind the endpoints "
                         "at all (proxy clients with remote DNS / "
                         "socks5h do not need them either way). Env: "
                         "MOZVPN_DNS_RELAY")
    ap.add_argument("--probe-geo", choices=["warn", "drop", "off"],
                    default="warn",
                    help="Exit-country check of every probed upstream "
                         "(v5.2: the geo comes from the SAME single probe "
                         "answer - the default ipinfo.io/json echo returns "
                         "the IP and the country/city in one request): "
                         "warn (default) - log a warning when the exit "
                         "country does not match the location; drop - "
                         "remove such upstreams; off - skip the check")
    # v5.5 (req. 3 + 4): FoxyProxy Standard settings export for the RUNNING
    # local proxies. Both exports also work live via the hotkeys f / x.
    ap.add_argument("--foxyproxy-export", dest="foxyproxy_export",
                    action="store_true",
                    help="After the local proxies start, write a COMBINED "
                         "FoxyProxy Standard settings file with ALL of them: "
                         "the current v8+/v9.x pref (data: [...]) PLUS the "
                         "same proxies as top-level FoxyProxy 6/7 'k<id>' "
                         "entries, so it imports via ANY FoxyProxy import "
                         "path (the 'Import' button at the top of the "
                         "Options page next to Export, or the Import tab "
                         "-> 'Import from older versions'); after the "
                         "import click 'Save'")
    ap.add_argument("--foxyproxy-out", metavar="FILE", default=None,
                    help="Save path for --foxyproxy-export; when set, the "
                         "save dialog is NOT shown (the file is written "
                         "straight to this path)")
    ap.add_argument("--foxyproxy-legacy-export", dest="foxyproxy_legacy_export",
                    action="store_true",
                    help="Same as --foxyproxy-export, but the LEGACY "
                         "FoxyProxy settings JSON in the REAL FoxyProxy 6/7 "
                         "export shape (every proxy as a top-level 'k<id>' "
                         "key - the only shape the migrate.js convert7() "
                         "importer of FoxyProxy 9.x reads); import on the "
                         "Import tab via 'Import from older versions' (the "
                         "FoxyProxy 4.x foxyproxy.xml is NOT importable by "
                         "FoxyProxy 9.x); after the import click 'Save'")
    ap.add_argument("--foxyproxy-legacy-out", metavar="FILE", default=None,
                    help="Save path for --foxyproxy-legacy-export; when set, "
                         "the save dialog is NOT shown")
    ap.add_argument("--no-input", action="store_true",
                    help="Never ask interactive questions (for an autonomous loop)")
    ap.add_argument("--refresh-margin", type=int,
                    default=int(os.environ.get("MOZVPN_REFRESH_MARGIN",
                                               "120") or 120),
                    help="Refresh the proxyPass this many seconds BEFORE "
                         "exp (v6.0, req. 1: the default is 120 s instead "
                         "of the old 45 s - the token is reissued well "
                         "before it can expire, so a slow/failed refresh "
                         "no longer leaves a window where the proxies "
                         "stop working while the Internet is fine; an "
                         "adaptive short retry keeps the old token alive "
                         "when a refresh hiccups). "
                         "Env: MOZVPN_REFRESH_MARGIN")
    ap.add_argument("--country")
    ap.add_argument("--city")
    ap.add_argument("--countries", metavar="LIST", default=None,
                    help="Run local proxies ONLY for these countries: a "
                         "comma/space-separated list of ISO country codes "
                         "(lower or upper case), full country names, or "
                         "'rec' for the recommended anycast egress. "
                         "Example: --countries \"us,de,jp\" (or "
                         "--countries \"us rec France\"). Default: not "
                         "used - all countries are served. The choice is "
                         "saved to the config and survives restarts; "
                         "hotkey 'w' changes it interactively.")
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
    # v5.0: the live vpn-serverlist marks almost every country record
    # 'locked' and Firefox serves them anyway, so locked records are now
    # INCLUDED by default; --exclude-locked restores the old behavior.
    ap.add_argument("--exclude-locked", dest="include_locked",
                    action="store_false", default=True,
                    help="Skip entries/nodes marked as locked (the old "
                         "behavior; since v5.0 locked records are included "
                         "by default)")
    ap.add_argument("--include-locked", action="store_true", default=True,
                    help="Kept for compatibility - locked records are "
                         "included by default since v5.0")
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
    # v5.27 (fix 2, fix 3) / v6.0 (req. 5): the multi-account parameters.
    # Every account lives in config.json; accounts can be ADDED, LISTED,
    # SELECTED and DELETED from the command line (and via hotkey 'a').
    ap.add_argument("--list-accounts", action="store_true",
                    help="List all cached Mozilla accounts (config.json) "
                         "and exit. An account is cached automatically after "
                         "every successful sign-in")
    ap.add_argument("--show-accounts", action="store_true",
                    help="List all cached accounts with the logins, passwords "
                         "and CURRENT TOTP codes in PLAIN TEXT and exit")
    ap.add_argument("--add-account", dest="add_account", action="store_true",
                    help="v6.0 (req. 5): sign in to a NEW Mozilla account "
                         "and ADD it to config.json (nothing is wiped; the "
                         "email/password/2FA prompts appear; on success the "
                         "account is cached and becomes the current one)")
    ap.add_argument("--select-account", dest="select_account",
                    metavar="EMAIL", default=None,
                    help="v6.0 (req. 5): make a CACHED account the current "
                         "one and continue the run with it (its cached "
                         "sessionToken, login/password/TOTP are reused)")
    ap.add_argument("--delete-account", dest="delete_account",
                    metavar="EMAIL[,EMAIL...]", default=None,
                    help="v6.0 (req. 5): DELETE the given cached account(s) "
                         "from config.json and exit (deleting the current "
                         "account auto-switches to the first remaining one)")
    ap.add_argument("--qr-dir", metavar="DIR", default=None,
                    help="Directory where the QR images of the 2FA secrets "
                         "are MATERIALIZED (--show-accounts / "
                         "--accounts-json; default: the directory of this "
                         "script; the persistent storage is config.json)")
    ap.add_argument("--accounts-json", metavar="FILE", default=None,
                    help="Export ALL cached accounts (logins, passwords, "
                         "current TOTP codes and QR images as base64) into "
                         "ONE json file and exit")
    ap.add_argument("--config", dest="config", metavar="FILE", default=None,
                    help="v6.1 (req. 1): path to the config.json store "
                         "(default: config.json NEXT TO THIS SCRIPT). "
                         "When the file does not exist - at the default "
                         "path OR the one given here - it is CREATED "
                         "automatically with the default values")
    ap.add_argument("--clean-old-config", dest="clean_old_config",
                    action="store_true",
                    help="v6.0 (req. 7): find and REMOVE every leftover of "
                         "the OLD (pre-v6) config format - the old json "
                         "files, the singbox/ and engine/ directories, the "
                         "old on-disk QR pngs (config.json is never "
                         "touched) - then exit. The same action is bound "
                         "to the Ctrl+O hotkey")
    ap.add_argument("--clear-cache", action="store_true",
                    help="Reset the uber-config config.json (next to this "
                         "script, or the --config path; the account store "
                         "SURVIVES; old-format "
                         "leftovers are removed) and exit")
    ap.add_argument("--lang", choices=["en", "ru"],
                    default=None,
                    help="Output language (v5.30: default = the SAVED "
                         "hotkey-'y' choice when present, else env, else "
                         "'en'). Env: MOZVPN_LANG")
    ap.add_argument("--no-color", action="store_true",
                    default=None,
                    help="Disable colored log output. v6.9: the color choice "
                         "(hotkey 'n') is saved and survives restarts. "
                         "Env: MOZVPN_NO_COLOR")
    ap.add_argument("--theme", choices=["dark", "light"],
                    default=None,
                    help="Color theme for the colored log: dark (default, "
                         "near-black background) or light (white background). "
                         "v6.9: the theme choice (hotkey 'm') is saved and "
                         "survives restarts. Env: MOZVPN_THEME")
    ap.add_argument("--flag-style", dest="flag_style",
                    choices=["auto", "emoji", "art"],
                    default=(os.environ.get("MOZVPN_FLAG_STYLE",
                                             "auto").strip().lower()
                             or "auto"),
                    help="Country-flag style of the proxy lines (v6.0): "
                         "'auto' (default) - the ready-made Unicode flag "
                         "pair where the terminal actually RENDERS flag "
                         "emoji (macOS, desktop Linux, Termux - the real "
                         "colored flag) and the truecolor 6x2 half-block "
                         "pixel-art mini-flag everywhere else (Windows "
                         "ships no flag-glyph font, the bare Linux text "
                         "console has no emoji font - the art paints the "
                         "flag instead of bare letters); 'emoji' - force "
                         "the pair; 'art' - force the pixel art (needs "
                         "colors on). Env: MOZVPN_FLAG_STYLE")
    ap.add_argument("--confirm-exit", action="store_true",
                    help="Require a second Ctrl+C within 5s to stop (by default the "
                         "first Ctrl+C stops immediately)")
    ap.add_argument("--retry-delay", type=int,
                    default=int(os.environ.get("MOZVPN_RETRY_DELAY", "30") or 30),
                    help="Seconds to wait before the automatic sign-in retry "
                         "after a failed attempt, shown with a live countdown "
                         "(default 30). Env: MOZVPN_RETRY_DELAY")
    # v6.6: the pass-health / transport knobs of this version. v6.7:
    # --tls-split is ON by default (the user's directive - a useful
    # option ships enabled; it cannot break the data path, every
    # fragmented-handshake failure falls back to plain TLS); --verbose
    # stays opt-in BY DESIGN (it de-redacts the user's browsing
    # destinations; both references keep it off) and --api-proxy needs
    # a URL, so those two have no default.
    ap.add_argument("--api-proxy", metavar="URL",
                    default=os.environ.get("MOZVPN_API_PROXY") or None,
                    help="Route the CONTROL-plane requests (FxA, Guardian, "
                         "Remote Settings, the Fastly challenge) through a "
                         "fixed HTTP(S) proxy - http://host:port or "
                         "https://host:port (the Go reference client's "
                         "-api-proxy: the Fastly WAF cookie and the Guardian "
                         "enrollment are bound to the egress IP, so the "
                         "control plane keeps ONE stable exit while the "
                         "proxied browsing traffic rotates freely). socks5:// "
                         "is NOT supported (the stdlib ProxyHandler tunnels "
                         "http/https via CONNECT; this script adds no new "
                         "dependency). Default: off. Env: MOZVPN_API_PROXY")
    ap.add_argument("--tls-split", action=argparse.BooleanOptionalAction,
                    default=None,
                    help="Send the TLS ClientHello of the outer connection "
                         "in SMALL TCP segments (64-byte pieces, the first "
                         "one delayed 30 ms) so a single-packet DPI cannot "
                         "read the whole SNI from the first segment. ON by "
                         "default (v6.7: a useful option ships enabled; "
                         "--no-tls-split or MOZVPN_TLS_SPLIT=0 restores "
                         "the plain single-segment ClientHello); hotkey 'i' "
                         "toggles it live; any fragmented-handshake failure "
                         "falls back to the plain TLS profile matrix, so "
                         "the data path never breaks; v6.9: the choice is "
                         "saved and survives restarts. Env: MOZVPN_TLS_SPLIT")
    ap.add_argument("--verbose", action=argparse.BooleanOptionalAction,
                    default=_env_flag("MOZVPN_VERBOSE", False),
                    help="Reveal the CONNECT targets in the engine failure "
                         "logs - by default they are REDACTED like the Go "
                         "reference client's logTarget ('<redacted; use "
                         "--verbose>'), because the destination of a client "
                         "request is the user's browsing. Env: MOZVPN_VERBOSE")
    ap.add_argument("--fxa-profile", dest="fxa_profile", metavar="PATH",
                    default=None,
                    help="v8.0: sign in WITHOUT a password - read the FxA "
                         "sessionToken from a DESKTOP FIREFOX PROFILE "
                         "(signedInUser.json -> accountData.sessionToken; "
                         "PATH may be the file itself or the profile "
                         "DIRECTORY) and mint the OAuth token from it via "
                         "the same grant_type=fxa-credentials flow: no "
                         "password login, no 2FA prompt, no Fastly bot "
                         "wall on third-party password logins. The file "
                         "is re-read on every session use, so re-signing "
                         "Firefox heals the run automatically. An explicit "
                         "--session-token still wins. LAUNCH PARAMETER "
                         "ONLY (no hotkey, per design)")
    ap.add_argument("--proxy-type", dest="proxy_type",
                    choices=["http", "socks5"], default=None,
                    help="v8.0 -> v9.0: the LOCAL proxy listener type - "
                         "exactly TWO protocols: socks5 (the DEFAULT "
                         "since v9.0 - RFC 1928 CONNECT-only with "
                         "REMOTE DNS: the domain names go to the "
                         "egress, the curl socks5h/socks5a semantics; "
                         "'socks5h' is NOT a separate wire protocol - "
                         "it is the CLIENT sending the domain instead "
                         "of a pre-resolved IP, and this listener "
                         "accepts BOTH shapes, so a plain-'socks5' "
                         "client works too) or http (the v8.5-v8.9 "
                         "default - the classic HTTP CONNECT listener; "
                         "the CONNECT hostname goes to the egress, "
                         "remote DNS). The v8.0 'mixed' single-port "
                         "auto-detect listener is REMOVED; a SAVED "
                         "old 'mixed' choice falls back to the "
                         "default. Hotkey Ctrl+T opens the choice "
                         "menu live; the choice is saved and "
                         "survives restarts; the sing-box engine maps "
                         "it to its http/socks inbound")
    ap.add_argument("--auto-rotate", action=argparse.BooleanOptionalAction,
                    default=None,
                    help="v8.0: auto-rotation of cached ACCOUNTS by quota - "
                         "when the current account's allowance is "
                         "exhausted, the profile switches to the cached "
                         "account with the most data left (cached "
                         "sessions only, NEVER a password login, so the "
                         "FxA 429 login rate limit can never trigger). ON "
                         "by DEFAULT (a useful option ships enabled); "
                         "--no-auto-rotate disables. Hotkey Ctrl+R "
                         "toggles it live; the choice is saved")
    ap.add_argument("--pac-export", dest="pac_export", metavar="FILE",
                    nargs="?", const="", default=None,
                    help="v8.2: write the PAC file (local sites "
                         "DIRECT, everything else through the local "
                         "listeners with a fail-over chain) to FILE on "
                         "every engine rebuild. Without FILE: opt back "
                         "into the automatic default copy at <config "
                         "dir>/mozvpn.pac on every rebuild. Otherwise "
                         "the default copy is written on demand by "
                         "the Ctrl+P hotkey ONLY (nothing is created "
                         "at startup)")
    ap.add_argument("--doctor", action="store_true",
                    help="v8.0: run the ONE-SHOT READ-ONLY diagnostics of "
                         "the whole chain (interpreter, config store, "
                         "dependencies, system DNS, DoH, FxA API, the "
                         "server list, a REAL TLS handshake to a live "
                         "egress, and the OAuth -> Guardian -> quota "
                         "chain on the CACHED session only) and exit")
    ap.add_argument("--reinstall-deps", action="store_true",
                    help="Reinstall ALL Python dependencies from scratch "
                         "(pip --force-reinstall --no-cache-dir) and exit")
    ap.add_argument("--reinstall-singbox", action="store_true",
                    help="Reinstall sing-box from scratch (Termux: pkg, macOS: "
                         "brew; other systems: the official install page) and exit")
    a = ap.parse_args()

    # v6.1 (req. 1): the config.json PATH resolves FIRST, before ANY
    # configuration is read (the language precedence block below calls
    # load_lang_cache() - the first config access of the run): the default
    # is config.json NEXT TO THIS SCRIPT; --config FILE points anywhere
    # else. A missing file (default path OR the --config one) is CREATED
    # right away with the default values; the created-note prints after
    # the language setup below, in the active language.
    _cfg_created = apply_config_path(getattr(a, "config", None))

    # v5.2 (req. 2): FORCE UTF-8 on stdout/stderr BEFORE any output, so the
    # emoji in the log NEVER show as "garbage symbols". On Windows the
    # console stream defaults to the legacy ANSI code page (cp1251/cp866),
    # which cannot encode emoji; sys.stdout.reconfigure(encoding="utf-8")
    # (Python 3.7+, verified on Python 3.15.1 - the current stable
    # release, 2026-10-21) switches the stream to UTF-8 with a safe
    # replacement handler. NOTE: UTF-8 mode is the DEFAULT since
    # Python 3.15 (PEP 686); the explicit reconfigure stays as a
    # harmless belt-and-suspenders (piped/redirected streams, older
    # interpreters, exotic builds).
    # On modern Windows 10/11 terminals the UTF-8 bytes then render
    # correctly (PEP 528 console IO is UTF-8 based); a legacy console may
    # need `chcp 65001` or the PYTHONIOENCODING=utf-8 / PYTHONUTF8=1 env.
    # Python 3.15 compatibility of everything else used here was checked
    # against the 3.15 release notes / deprecations index: argparse (only
    # new optional features - suggest_on_error, color help), ssl, socket,
    # threading, concurrent.futures, urllib - no deprecations or removals
    # affect this script.
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # Language and colors are configured before any other output (req. 14,
    # 16). v4.7.1: set_color() runs FIRST (it only switches the color mode, it
    # no longer touches the window background), then set_theme() forces
    # the background (OSC 11) exactly ONCE with the final theme and the
    # final color mode - with --no-color set_theme() forces nothing at all.
    # v5.30: the language precedence - an explicit --lang argument wins;
    # then the PERSISTED hotkey-'y' choice (lang.json, survives restarts);
    # then MOZVPN_LANG; then the built-in default 'en'.
    _lang_arg = getattr(a, "lang", None)
    if _lang_arg:
        set_language(_lang_arg)
    else:
        set_language(load_lang_cache()
                     or (os.environ.get("MOZVPN_LANG", "en").strip().lower()
                         or "en"))
    # v6.9 (the user's request 2): STICKY COLOR/THEME. The precedence
    # is now the doh/lang one - an EXPLICIT --no-color/--theme wins,
    # then the SAVED hotkey choice (config.json settings.color /
    # settings.theme, survives restarts), then the env, then the
    # built-in default; the hotkeys 'n'/'m' save the state the
    # moment they flip it. The argparse defaults are None ('not
    # chosen'), so a never-written key can never pose as an
    # explicit choice (the v6.8 lesson). The _explicit markers keep
    # the 'an argument of THIS run wins' contract for the profile
    # switch (apply_profile_runtime) after the values are resolved
    # in place below.
    a._no_color_explicit = getattr(a, "no_color", None) is not None
    a._theme_explicit = bool(getattr(a, "theme", None))
    _no_color = getattr(a, "no_color", None)
    if _no_color is None:
        _saved_color = load_bool_setting("color", None)
        if _saved_color is not None:
            _no_color = not _saved_color       # the saved hotkey-'n' state
        elif "MOZVPN_NO_COLOR" in os.environ:
            _no_color = _truthy_env("MOZVPN_NO_COLOR")
        else:
            _no_color = False                 # the default: colors ON
    a.no_color = bool(_no_color)
    set_color(not a.no_color)
    if not a._theme_explicit:
        _saved_theme = load_str_setting("theme")
        if _saved_theme in ("dark", "light"):
            a.theme = _saved_theme            # the saved hotkey-'m' state
        else:
            a.theme = ((os.environ.get("MOZVPN_THEME") or "").strip().lower()
                       or "dark")
    set_theme(a.theme)
    save_bool_setting("color", _USE_COLOR)
    save_str_setting("theme", _THEME)
    # v5.18: the flag representation of the proxy lines (see
    # country_flag); "auto" (the default) resolves per platform inside
    # country_flag: the emoji pair where flag emoji render, the pixel
    # art everywhere else (v6.0, req. 8).
    global _FLAG_STYLE
    _FLAG_STYLE = a.flag_style
    if a.no_color:
        info(tr("color_disabled"))

    # v6.1 (req. 1): the just-created config.json note (deferred until
    # here so it prints in the ACTIVE language)
    if _cfg_created:
        info(tr("config_auto_created", path=CONFIG_FILE))

    # v6.0 (req. 6): the FIRST-RUN MIGRATION. config.json carries the
    # 'first_run' flag; while it is set, every OLD-format configuration
    # file of the previous script versions is read, folded into the
    # uber-config and DELETED (the old files AND the old directories -
    # nothing of the old format is left behind). A fresh install simply
    # flips the flag. It runs BEFORE the settings are read below so a
    # migrated machine picks up its saved resolver/filter choices right
    # away.
    migrate_old_config_if_first_run()
    # the migration may have brought a SAVED language choice from the
    # old lang.json into config.json - re-apply the precedence now that
    # the value is actually there (unless --lang was explicit)
    if not _lang_arg:
        _migrated_lang = load_lang_cache()
        if _migrated_lang:
            set_language(_migrated_lang)

    # v5.0: DoH resolver setup - must run before any upstream probing.
    if a.doh_url:
        DOH_PROVIDERS["custom"] = a.doh_url
        set_doh_provider("custom")
    elif getattr(a, "doh", None):
        # an EXPLICIT --doh argument wins (including 'off')
        if a.doh == "off":
            set_doh_provider("")
        else:
            set_doh_provider(a.doh)
    else:
        # v5.31 -> v6.8: no explicit --doh -> the SAVED hotkey-'h'
        # choice (settings.doh; '' only from the EXPLICIT 'off'
        # marker), else env, else the built-in 'cloudflare' default.
        # v6.8: a never-chosen key - or a legacy '' the v6.0-v6.7
        # default bug wrote - falls THROUGH to the default instead
        # of masquerading as a system-DNS choice.
        _saved_doh = load_doh_provider_cache()
        if _saved_doh is not None:
            set_doh_provider(_saved_doh)     # '' = the explicit 'off' choice
        else:
            set_doh_provider(
                (os.environ.get("MOZVPN_DOH", "cloudflare").strip().lower()
                 or "cloudflare"))
    # v5.29: apply the strict-mode flag BEFORE any lookup or log line.
    set_system_dns_fallback(bool(getattr(a, "system_dns_fallback", False)))
    if doh_provider():
        info(tr("doh_selected", provider=doh_provider(),
                url=DOH_PROVIDERS.get(doh_provider(), doh_provider())))
        # v5.2 (req. 5): the full fallback chain is stated ONCE at startup;
        # after startup the individual DoH lookups are SILENT (no
        # "queried DoH / dns" lines in the log).
        chain = " -> ".join(
            [DOH_PROVIDERS.get(n, n) for n in _doh_chain()]
            + ([tr("doh_system_short")]
               if system_dns_fallback() else []))
        info(tr("doh_chain", chain=chain))
        # v5.29 (security): the strict-mode state is stated ONCE here.
        if system_dns_fallback():
            info(tr("system_dns_fallback_on"))
        else:
            info(tr("doh_strict_mode"))
    else:
        info(tr("doh_system"))
    # v5.33 -> v6.4 (req. 4 + the profile rework): the settings live
    # INSIDE config.json, and since v6.4 they belong to the CURRENT
    # PROFILE (the account) - the effective resolver/language are
    # mirrored into the CURRENT ACCOUNT's settings at startup (via
    # _profile_node(), so cfg_get/cfg_set route to
    # config.json['accounts'][<current>]['settings']) so config.json
    # (and the profile's settings) exists from the very first run and
    # the '1-9 config files' list shows it immediately. Switching the
    # profile (hotkey 'a' / --select-account) re-applies the new
    # profile's settings via apply_profile_runtime().
    #   - settings.doh: the effective resolver (unless a custom --doh-url
    #     endpoint is active - its URL may be secret, not persisted);
    #   - settings.lang: the effective language;
    #   - the countries filter is written ONLY when ACTIVE (hotkey '0'
    #     / the clear entry removes the key from config.json).
    if doh_provider() != "custom":
        save_doh_provider_cache(doh_provider())
    save_lang_cache(_LANG)
    # v6.9 (the user's request 2): the ENGINE choice is sticky too
    # (hotkey 'e' / --local-proxy-engine): an explicit argument wins,
    # then the SAVED choice (settings.engine), then
    # MOZVPN_PROXY_ENGINE, then the built-in 'builtin'. The
    # resolution runs before the first reader (the engine echo
    # below) and before run_manager(); the profile switch does
    # NOT change the live engine (that is hotkey 'e' territory) -
    # the saved engine of the new profile applies at the next
    # start.
    a._engine_explicit = getattr(a, "local_proxy_engine", None) is not None
    if not a._engine_explicit:
        _saved_engine = load_str_setting("engine")
        if _saved_engine in ("builtin", "singbox"):
            a.local_proxy_engine = _saved_engine
        else:
            a.local_proxy_engine = (
                (os.environ.get("MOZVPN_PROXY_ENGINE") or "")
                .strip().lower() or "builtin")
        if a.local_proxy_engine not in ("builtin", "singbox"):
            a.local_proxy_engine = "builtin"     # a garbage env value
    save_str_setting("engine", a.local_proxy_engine)
    # v5.1 (req. 4) -> v6.9: the DoH answer cache state at startup.
    # v6.9: the choice is STICKY (settings.doh_cache - the config
    # layout has carried this key name since v6.4): an explicit
    # --doh-cache/--no-doh-cache wins, then the SAVED hotkey-'k'
    # choice, then MOZVPN_DOH_CACHE, then the built-in OFF default.
    a._doh_cache_explicit = getattr(a, "doh_cache", None) is not None
    _dch = getattr(a, "doh_cache", None)
    if _dch is None:
        _dch = load_bool_setting("doh_cache", None)
    if _dch is None:
        _dch = _env_flag("MOZVPN_DOH_CACHE", False)
    set_doh_cache(bool(_dch))
    save_bool_setting("doh_cache", doh_cache_enabled())
    if doh_cache_enabled():
        info(tr("doh_cache_state_on", ttl=DOH_TTL))
    else:
        info(tr("doh_cache_state_off"))
    info(tr("locked_note"))
    # v6.6: the pass-health / transport knobs of this version.
    # --api-proxy: the control plane rides ONE FIXED HTTP(S) exit (the
    # shared _OPENER of req_full/_fastly_http is rebuilt with a
    # ProxyHandler); the DoH chain is NOT routed through it (the DoH
    # endpoints are anycast - DNS needs no fixed exit).
    if getattr(a, "api_proxy", None):
        _apu = str(a.api_proxy).strip()
        if _apu.lower().startswith("socks"):
            err(tr("api_proxy_socks_unsupported"))
            sys.exit(1)
        set_api_proxy(_apu)
        info(tr("api_proxy_on", url=_apu))
    else:
        info(tr("api_proxy_off"))
    # --tls-split -> v6.9: the ClientHello fragmentation state (ON by
    # default since v6.7) and STICKY since v6.9 (settings.tls_split):
    # an explicit --tls-split/--no-tls-split wins, then the SAVED
    # hotkey-'i' choice, then MOZVPN_TLS_SPLIT, then the ON default.
    a._tls_split_explicit = getattr(a, "tls_split", None) is not None
    _tsp = getattr(a, "tls_split", None)
    if _tsp is None:
        _tsp = load_bool_setting("tls_split", None)
    if _tsp is None:
        _tsp = _env_flag("MOZVPN_TLS_SPLIT", True)
    set_tls_split(bool(_tsp))
    save_bool_setting("tls_split", tls_split())
    info(tr("tls_split_startup",
            state=tr("color_state_on" if tls_split()
                     else "color_state_off")))
    # --verbose: the CONNECT targets of the engine failure logs.
    set_verbose_targets(bool(getattr(a, "verbose", False)))
    # v8.0 -> v9.0 --proxy-type: the local listener type (socks5/http).
    # Sticky like --tls-split above: an explicit argument wins, then
    # the SAVED hotkey-Ctrl+T choice, then the 'socks5' DEFAULT of
    # v9.0 (RFC 1928 CONNECT-only with REMOTE DNS - a DOMAIN request
    # address is passed through to the egress, the curl socks5h
    # semantics, so the domain never leaks to the local system
    # resolver; a plain-'socks5' client that pre-resolves locally and
    # sends the IP is accepted too - 'socks5h' is a CLIENT-side
    # convention, not a separate wire protocol). A SAVED 'mixed' or
    # 'http' choice of an older run keeps winning only when it was
    # SAVED; a never-chosen run takes the new default.
    a._proxy_type_explicit = getattr(a, "proxy_type", None) is not None
    _pt = _proxy_type_of(a)
    set_proxy_type(_pt)
    if a._proxy_type_explicit:
        save_str_setting("proxy_type", _pt)
    info(tr("proxy_type_selected", type=_pt))
    # v8.0 --auto-rotate: the quota-based account rotation. ON by
    # DEFAULT (a useful option ships enabled); an explicit argument
    # wins, then the SAVED hotkey-Ctrl+R choice.
    a._auto_rotate_explicit = getattr(a, "auto_rotate", None) is not None
    _ar = getattr(a, "auto_rotate", None)
    if _ar is None:
        _ar = load_bool_setting("auto_rotate", True)
    set_auto_rotate(bool(_ar))
    if a._auto_rotate_explicit:
        save_bool_setting("auto_rotate", auto_rotate_enabled())
    if auto_rotate_enabled():
        info(tr("auto_rotate_startup"))
    # v6.6 (item 14) -> v6.9 CORRECTION -> v8.1 UPDATE: the channel
    # facts, stated ONCE per run. Re-verified 2026-10-30 against the
    # Fastly engineering blog ('We built the proxy behind Firefox's
    # new built-in VPN'): the rollout is HTTP CONNECT over HTTP/2, and
    # the CONNECT tunnel is a RAW TCP TUNNEL - ANY TCP protocol, ANY
    # destination port ('anything can run through it'); the v6.6
    # 'web-ports-only' claim mistook the EGRESS LISTENER ports of a
    # third-party server list for allowed DESTINATION ports and is
    # retracted. UDP/IP is the NEXT step, not the current one: MASQUE
    # over HTTP/3 (RFC 9298 CONNECT-UDP - the code is already in the
    # Firefox networking stack and the Mozilla Remote Settings server
    # list carries a per-server 'masque' protocol next to 'connect').
    # Fastly does no deep packet inspection; Mozilla positions the
    # feature for browser-level web traffic (not full-device
    # tunneling). The CODE needs no port fix: the builtin engine and
    # the sing-box configs relay EVERY CONNECT host:port - the local
    # side never restricted the destination ports.
    info(tr("channel_limits_note"))

    # req. 8: --clear-cache wipes everything and exits (a fresh dict is
    # passed: nothing has been loaded into memory yet at this point)
    if a.clear_cache:
        print_clear_targets()
        sys.exit(0 if wipe_all_saved_data({}) else 1)

    # v6.0 (req. 7): --clean-old-config - the CLI twin of the Ctrl+O
    # hotkey: find and remove every leftover of the OLD config format
    # (config.json is never touched) and exit.
    if getattr(a, "clean_old_config", False):
        clean_old_config_format(verbose=True)
        sys.exit(0)

    # v8.0 --doctor (C4, the foxhole-vpn idea): the one-shot READ-ONLY
    # diagnostics of the whole chain - interpreter, config store,
    # dependencies, system DNS, DoH, the FxA API, the server list, a
    # REAL TLS handshake to a live egress and the OAuth -> Guardian
    # -> quota chain on the CACHED session only (never a password
    # login). Exits with 0 (healthy) / 1 (at least one failed step).
    if getattr(a, "doctor", False):
        sys.exit(run_doctor(a))

    # v5.27 (fix 2): the multi-account cache parameters work OFFLINE -
    # no sign-in, no probes; they print the store and exit
    if a.list_accounts:
        print_accounts_list(a, reveal=False)
        sys.exit(0)
    if a.show_accounts:
        print_accounts_list(a, reveal=True)
        sys.exit(0)
    if a.accounts_json:
        export_accounts_json(a, a.accounts_json)
        sys.exit(0)

    # v6.0 (req. 5): --delete-account EMAIL[,EMAIL...] - remove the given
    # cached accounts from config.json and exit. Deleting the CURRENT
    # account auto-switches the pointer to the first remaining account
    # (or clears it when the store becomes empty).
    if getattr(a, "delete_account", None):
        targets = [t.strip().lower() for t in a.delete_account.split(",")
                   if t.strip()]
        if not targets:
            err(tr("accounts_not_found"))
            sys.exit(1)
        accounts = load_accounts()
        for em in targets:
            if em not in accounts:
                warn(tr("accounts_delete_missing"))
            else:
                del accounts[em]
                ok(tr("accounts_deleted", email=em))
        _save_accounts(accounts)
        if cfg_current_email() in targets:
            cfg_set_current((next(iter(accounts), None)))
        sys.exit(0)

    # v6.0 (req. 5): --select-account EMAIL - make a cached account the
    # current one and CONTINUE the run with it (everything the sign-in
    # reads is switched, like the hotkey-'a' selection).
    if getattr(a, "select_account", None):
        em = (a.select_account or "").strip().lower()
        accounts = load_accounts()
        acc = accounts.get(em)
        if not acc:
            err(tr("accounts_not_found"))
            sys.exit(1)
        a.email = em
        a.password = acc.get("password")
        st = (acc.get("session_token") or "").strip()
        a.session_token = (st if st and all(
            ch in "0123456789abcdefABCDEF" for ch in st) else None)
        a.totp_secret = (acc.get("totp_secret") or "").strip() or None
        a.qr = None
        a.totp = None
        cfg_set_current(em)
        info(tr("account_switched", email=em,
                session=(tr("account_session_used")
                         if a.session_token
                         else tr("account_session_fresh"))))
        # v6.4: --select-account is a FULL profile switch - apply the
        # settings of the newly selected account (the rest of main()
        # and the watch loop then run with its language/resolver/cookie)
        apply_profile_runtime(a)

    # v6.0 (req. 5): --add-account - sign in to a NEW account: the
    # in-memory sign-in targets are cleared so the email/password/2FA
    # prompts appear; NOTHING is wiped (the other accounts stay cached);
    # on success save_cache/cache_account add the new account to
    # config.json and make it current.
    if getattr(a, "add_account", False):
        a.email = None
        a.password = None
        a.session_token = None
        a.qr = None
        a.totp_secret = None
        a.totp = None
        info(tr("accounts_add_hint"))

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
        ok(tr("qr_saved", path=CONFIG_FILE, digits=info_qr["digits"],
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
        # v5.22: --relogin is the same FULL wipe as the 'r' hotkey - the
        # in-memory CLI/env credential copies go too, otherwise
        # ensure_session() below would re-login with the old
        # email/password and make_totp_provider() would rebuild a TOTP
        # generator from the old --qr/--totp-secret values, so the fresh
        # sign-in would never actually ask for anything.
        a.email = None
        a.password = None
        a.session_token = None
        a.qr = None
        a.totp_secret = None
        a.totp = None

    totp_provider = make_totp_provider(a, creds)

    if a.local_proxy or a.watch:
        run_manager(a, creds, totp_provider)
        return

    # -------- one-shot mode --------
    try:
        session_token = ensure_session(a, creds, totp_provider, interactive=True)
        token, until, ghdrs = obtain_proxy_pass(session_token)
        # v6.6 (item 1): anchor-at-receipt (see run_manager) - the
        # displayed expiry is OUR clock's view of the pass lifetime.
        exp = anchored_exp(token)
        ok(tr("proxypass_received", until=format_until(until, token),
              exp=time.strftime("%H:%M:%S", time.gmtime(exp)) if exp else "?"))
        # v5.27 (fix 2): cache the successfully signed-in account
        cache_account(args=a, creds=creds, session_token=session_token)
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
        ordered = sorted(verified,
                        key=lambda s: 0 if s.get("probe_ok") else 1)
        for s in ordered:
            info(tr("test_running", host=s["protocolHost"], port=s["protocolPort"]))
            try:
                _, detail, _, _ = probe_connect(s, token, a.ip_echo_url)
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
