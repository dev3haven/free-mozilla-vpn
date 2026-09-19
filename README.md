# 🦊 Free Mozilla VPN

The script connects to **Mozilla VPN** and runs local **HTTP proxies** for each available region.

## 📋 Requirements

Before you start, make sure you have:

- 📧 **Email / login** for your Mozilla Account
- 🔑 **Password** for your Mozilla Account
- 🔐 **TOTP code** or **QR.png** from your Mozilla Account's two-step authentication settings

> ⚠️ **Important:** Launch Mozilla VPN **inside Firefox Browser** at least **once** to make everything work.

### If you don't have a VPN button in Firefox

1. Open `about:config` and set `browser.ipProtection.enabled` to `true`.
2. If the button still doesn't appear, go to **Settings → Privacy & Security** and enable **"Allow Firefox to improve features, performance, and stability between updates"**.

---

## 🚀 Quick Start (`start.bat` / `start.sh`)

The simplest way to run. Choose `mozvpn.py` over `mozvpn_no_externals.py` if you have some troubles with `proxy.py` or other dependencies:

1. Install [Python](https://www.python.org/).
2. Download the repository as a **ZIP** file and unpack it.
3. Install the Python dependencies for `start.bat` / `start.sh`
   ```sh
   pip install pyotp zxing-cpp Pillow proxy.py
   ```
   OR install [sing-box](https://github.com/sagernet/sing-box) for `start_mozvpn.bat` / `start_mozvpn.sh`
4. Launch:
   - **Windows:** double-click `start.bat` or `start_mozvpn.bat`
   - **Linux:** double-click `start.sh` or `start_mozvpn.sh`
5. Enter your Mozilla Account credentials: login, password, TOTP/QR.png.
   - **Note!** `mozvpn.py` does not support QR mode.
7. Your credentials will be saved locally — next time just run `start.bat` or `start.sh` again.
8. Test one of the local HTTP proxies
   ```sh
   # 25510 is a port from '127.0.0.1:25510  United States/United States  -> us.m1.fastly-masque.net:2499' output
   curl -s --proxy http://127.0.0.1:25510 --proxy-insecure https://hackmyip.com
   ```

---

## ⭐ Recommended: `mozvpn_no_externals.py`

The script starts local proxies for **all available proxy geo regions** on their own ports. All information is printed to the console.

> ⚠️ **Warning:** Using the `--relogin` parameter can temporarily block your account. In that case, you'll need to log in to your Mozilla Account using Firefox Browser with a code from your email.

### Installation

1. Install the dependencies:
   ```sh
   pip install pyotp zxing-cpp Pillow proxy.py
   ```
2. Go to your Mozilla Account → **Two-step authentication** and save the QR code as `qr.png`.

### Usage

**With QR code:**
```sh
py mozvpn_no_externals.py --email example@gmail.com --password 123456 --qr qr.png --local-proxy --no-save
```

**With TOTP from Google Authenticator:**
```sh
py mozvpn_no_externals.py --email example@gmail.com --password 123456 --totp 177067 --local-proxy --no-save
```

---

## 🐍 Alternative: `mozvpn.py`

The script also starts local proxies for all available geo regions on their own ports.

### Installation

1. Install [sing-box](https://github.com/sagernet/sing-box).
2. Install the Python dependencies:
   ```sh
   pip install pyotp zxing-cpp
   ```
3. Open Firefox, log in to your Firefox account, and launch Mozilla VPN **inside Firefox** at least once.

### Usage

Get your 2FA code from Google Authenticator and run:
```sh
py mozvpn.py --email example@gmail.com --password 123456 --totp 177067 --use-sing-box --no-save
```

The script will cache your Mozilla **session token** and automatically update the **Mozilla VPN proxy pass token**.

---

## 🔧 Manual Usage

### Option 1: Python Script

1. Open Firefox, log in to your Firefox account, and launch Mozilla VPN **inside Firefox**.
2. Run the script with your credentials:
   ```sh
   py get_http_proxy_token_and_config.py --email example@gmail.com --password 123456 --totp 177067
   ```
3. The result will be printed to the console and saved to a file next to the script.
4. Use [sing-box](https://github.com/sagernet/sing-box) or another local proxy, adding the `Proxy-Authorization: Bearer <jwt>` header to each HTTP request.

### Option 2: JavaScript in Browser Console

1. Open Firefox, log in to your Firefox account, and launch Mozilla VPN **inside Firefox**.
2. Press `Ctrl + Shift + Alt + I` to open the Firefox developer console.
3. Copy and run the contents of `firefox_console_get_http_proxy_token_and_config.js`.
4. Get the **JWT token**, host, port, and other parameters.
5. Use sing-box (or another proxy) with the `Proxy-Authorization: Bearer <jwt>` header.

### Test the proxy pass token

```
curl -s --proxy https://p.m1.fastly-masque.net:2499 --proxy-header "Proxy-Authorization: Bearer eyJhbGci...8Zo8g" --proxy-insecure https://hackmyip.com
```

---

## 🌐 Using with sing-box

1. Configure [sing-box](https://github.com/sagernet/sing-box) by adding `Proxy-Authorization` with the `Bearer` token:

   ```sh
   sing-box run -c sing-box-config.json
   ```

   ```json
   {
     "log": { "disabled": true },
     "inbounds": [
       {
         "type": "http",
         "tag": "http-in",
         "listen": "127.0.0.1",
         "listen_port": 12122
       }
     ],
     "outbounds": [
       {
         "type": "http",
         "tag": "mozilla-upstream",
         "server": "p.m1.fastly-masque.net",
         "server_port": 2499,
         "headers": {
           "Proxy-Authorization": "Bearer eyJhbGci...8Zo8g"
         },
         "tls": { "enabled": true }
       }
     ]
   }
   ```

2. ⏰ **The JWT token expires every 10–15 minutes** — you need to refresh it regularly.

---

## 📝 License

Use at your own risk. This project is not affiliated with Mozilla.
