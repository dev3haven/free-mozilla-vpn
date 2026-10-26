# 🦊 Free Mozilla VPN

A single-file utility that signs in to your Mozilla Account (Mozilla VPN / Firefox IP Protection) and starts local **HTTP proxies** for every available region.

No Python, no dependencies — one binary per platform.

## 📋 Requirements

* 📧 Mozilla Account **email**
* 🔑 Mozilla Account **password**
* 🔐 **Two-step authentication** enabled on the account: a TOTP code (Google Authenticator etc.) or the 2FA **QR image** saved as a file

## 🚀 Install

One command per platform. Each command downloads the **latest release** into the `mozvpn` folder of your home directory, sets permissions and creates the launcher entries — nothing to edit manually.

### 🤖 Android — Termux (with Termux:Widget)

1. Install [Termux](https://f-droid.org/en/packages/com.termux) and [Termux:Widget](https://f-droid.org/en/packages/com.termux.widget) **from the same source** (F-Droid or GitHub Releases — do not mix sources; the Google Play build is deprecated), open Termux once.
2. Paste this single line into Termux:

```bash
mkdir -p ~/mozvpn ~/.shortcuts && curl -fsL -o ~/mozvpn/mozvpn https://github.com/dev3haven/free-mozilla-vpn/releases/latest/download/mozvpn-termux-armv8-bionic && chmod +x ~/mozvpn/mozvpn && printf '#!/data/data/com.termux/files/usr/bin/bash\ncd ~/mozvpn && exec ./mozvpn\n' > ~/.shortcuts/MozVPN.sh && chmod +x ~/.shortcuts/MozVPN.sh
```

3. Add the **Termux:Widget** widget to your Android home screen, tap it and select **MozVPN** — a Termux session opens with the utility running.
4. If **MozVPN** is not in the widget list: press the **refresh** button on the widget, or open the Termux:Widget app and press **REFRESH**. If `curl` is not installed in Termux, run `pkg install curl` first.

> Termux builds run on any 64-bit ARM (aarch64) Android device. Termux on x86_64 Android is not supported by this release.

### 🐧 Linux (x86_64 / ARM64 / x86 — detected automatically)

Paste this single line into a terminal:

```bash
D=$(xdg-user-dir DESKTOP 2>/dev/null||echo "$HOME/Desktop"); mkdir -p ~/mozvpn "$D" ~/.local/share/applications && curl -fsL -o ~/mozvpn/mozvpn "https://github.com/dev3haven/free-mozilla-vpn/releases/latest/download/mozvpn-linux-$(case $(uname -m) in x86_64) echo x86_64-glibc2.39;; aarch64) echo armv8-glibc2.39;; i686) echo x86-glibc2.41;; esac)" && chmod +x ~/mozvpn/mozvpn && printf "[Desktop Entry]\nType=Application\nName=MozVPN\nTerminal=true\nExec=$HOME/mozvpn/mozvpn\nIcon=network-vpn\n" | tee ~/.local/share/applications/mozvpn.desktop > "$D/mozvpn.desktop" && chmod +x "$D/mozvpn.desktop"
```

This creates `~/mozvpn/mozvpn`, a **MozVPN** entry in the applications menu (works on GNOME, KDE and Mint Cinnamon/MATE/XFCE — all of them read `~/.local/share/applications`) and a desktop shortcut.

* **KDE / Mint**: the desktop shortcut works out of the box.
* **GNOME**: desktop icons require the *Desktop Icons* extension; the applications-menu entry works everywhere.

System requirements: the x86_64 and ARM64 builds need **glibc ≥ 2.39** (Ubuntu 24.04+, Debian 13+, Fedora 40+, Mint 22+, Arch); the 32-bit x86 build needs **glibc ≥ 2.41**. Alpine (musl) is not supported.

### 🪟 Windows 10 / 11 — Command Prompt

Paste this single line into `cmd.exe`:

```bat
md "%USERPROFILE%\mozvpn" 2>NUL & curl -fsL -o "%USERPROFILE%\mozvpn\mozvpn.exe" https://github.com/dev3haven/free-mozilla-vpn/releases/latest/download/mozvpn-windows-x86_64-ucrt.exe
```

Windows 11 on ARM64:

```bat
md "%USERPROFILE%\mozvpn" 2>NUL & curl -fsL -o "%USERPROFILE%\mozvpn\mozvpn.exe" https://github.com/dev3haven/free-mozilla-vpn/releases/latest/download/mozvpn-windows-arm64-ucrt.exe
```

The binary is unsigned: on first launch SmartScreen may warn — choose **More info → Run anyway**. Some antiviruses flag compiled one-file binaries as a false positive.

## ▶️ Usage

Start the binary — from the widget / menu / desktop shortcut, or manually:

| Platform | Command |
| --- | --- |
| Linux | `~/mozvpn/mozvpn` |
| Termux | `~/mozvpn/mozvpn` |
| Windows | `"%USERPROFILE%\mozvpn\mozvpn.exe"` |

1. On the first run the utility asks for your **email, password and 2FA** (TOTP code or QR image), then saves the profile locally into `config.json` next to the binary — subsequent runs start immediately.
2. The console shows a hotkey interface and starts a local HTTP proxy for **every available region**.
3. Use any proxy from the console output (25510 is just an example port):

```bash
curl -s --proxy http://127.0.0.1:25510 --proxy-insecure https://hackmyip.com
```

4. All command-line options: `mozvpn --help`. Multiple accounts, country filtering, DoH, language and an alternative sing-box engine are available — see `--help` and the in-app hotkey list.

## 🔄 Update / 🗑️ Uninstall

* **Update**: re-run the install command for your platform — it always downloads the latest release.
* **Uninstall**:
  * Linux: `rm -rf "$HOME/mozvpn" "$HOME/.local/share/applications/mozvpn.desktop" "$HOME/Desktop/mozvpn.desktop"`
  * Termux: `rm -rf "$HOME/mozvpn" "$HOME/.shortcuts/MozVPN.sh"`
  * Windows: `rmdir /s /q "%USERPROFILE%\mozvpn"`

## 📦 Available binaries (latest release)

| File | Platform |
| --- | --- |
| `mozvpn-windows-x86_64-ucrt.exe` | Windows 10/11 x64 |
| `mozvpn-windows-arm64-ucrt.exe` | Windows 11 on ARM |
| `mozvpn-windows-x86-ucrt.exe` | 32-bit Windows |
| `mozvpn-linux-x86_64-glibc2.39` | Linux x86_64 (glibc ≥ 2.39) |
| `mozvpn-linux-armv8-glibc2.39` | Linux ARM64 / ARMv8 (glibc ≥ 2.39) |
| `mozvpn-linux-armv9-glibc2.39` | Linux ARMv9-tuned (glibc ≥ 2.39) |
| `mozvpn-linux-x86-glibc2.41` | Linux 32-bit x86 (glibc ≥ 2.41) |
| `mozvpn-termux-armv8-bionic` | Termux, any aarch64 Android |
| `mozvpn-termux-armv9-bionic` | Termux, ARMv9-tuned |

All files and their sha256 digests: [Releases](https://github.com/dev3haven/free-mozilla-vpn/releases/latest).

## ⚠️ Troubleshooting

* **Sign-in fails / no proxies**: log in to the account in Firefox and open Mozilla VPN (IP Protection) at least once, then retry.
* **Linux: `GLIBC_2.xx not found`**: your distribution is older than the build's glibc — see the requirements above.
* **Termux widget is empty**: press the widget's refresh button or **REFRESH** in the Termux:Widget app; make sure Termux and Termux:Widget are installed from the same source.

## 📝 License

Use at your own risk. This project is not affiliated with Mozilla.
