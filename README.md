# Free Mozilla VPN

The script connect to Mozilla VPN and run local **http** proxies for each available region.  
To connect to the Mozilla VPN you need to have: email/login, password, TOTP/QR.png from your Mozilla Acount.  
You need to **launch Mozilla VPN from within Firefox Browser** at least **once** to let all of that to work.

## Interactive python script `mozvpn_no_externals.py` (RECOMMENDED)

The script will start up local proxies for **all available proxy geo regions** on their own ports. You can find all info in the script console output.  
**Be aware** that using `--relogin` parameter can temporary block your account. In the case you need to use a **code from your email** and log in to Mozilla Account **using Firefox Browser**.

1. Install python dependencies that the script ask you to install: `pip install pyotp zxing-cpp Pillow proxy.py`
2. Go to your Mozilla Account, go to **Two-step authentication** and save QR code as `qr.png`
3. Run `mozvpn_no_externals.py` with the command. `--qr qr.png` is **path** to a `png` image file.
    ```sh
    py mozvpn_no_externals.py --email example@gmail.com --password 123456 --qr qr.png --local-proxy --no-save
    ```
    OR you can use TOTP from **Google Authenticator**
    ```sh
    py mozvpn_no_externals.py --email example@gmail.com --password 123456 --totp 177067 --local-proxy --no-save
    ```


## Interactive python script `mozvpn.py`

The script will start up local proxies for **all available proxy geo regions** on their own ports. You can find all info in the script console output.

1. Install [sing-box](https://github.com/sagernet/sing-box)
2. Install python dependencies that the script ask you to install: `pip install pyotp zxing-cpp`
3. Open Firefox and Log in to your Firefox account in **Firefox Browser**. Start Mozilla VPN at least once **inside Firefox** using in-built function.
4. Run `mozvpn.py` with the command. Use **Google Authenticator** or another tool to get **2FA (TOTP)** code.
    ```sh
    py mozvpn.py --email example@gmail.com --password 123456 --totp 177067 --use-sing-box --no-save
    ```
5. The script will cache your Mozilla **session token** locally and will reuse the token. The script will update the **Mozilla VPN proxy pass token** automaticly.

## Use mozilla vpn proxy manually with python script

1. Open Firefox and Log in to your Firefox account in **Firefox Browser**. Start Mozilla VPN at least once **inside Firefox** using in-built function.
2. Run `get_http_proxy_token_and_config.py` with your own credentials. Use **Google Authenticator** or another tool to get **2FA (TOTP)** code.
    ```sh
    py get_http_proxy_token_and_config.py --email example@gmail.com --password 123456 --totp 177067
    ```
3. Result will be printed in console and saved in file near the python script.
4. Use [sing-box](https://github.com/sagernet/sing-box) or another local proxy to add `Proxy-Authorization` with the `Bearer` jwt token http header to each http request

## Use mozilla vpn proxy manually with browser console JavaScript

1. Open Firefox and Log in to your Firefox account in **Firefox Browser**. Start Mozilla VPN at least once **inside Firefox** using in-built function.
2. press `ctrl+shift+alt+i` to open Firefox browser developer console
3. copy and paste `firefox_console_get_http_proxy_token_and_config.js` and run
4. Get jwt token, host, port and other
5. Use [sing-box](https://github.com/sagernet/sing-box) or another local proxy to add `Proxy-Authorization` with the `Bearer` jwt token http header to each http request

## How to use Mozilla VPN proxy with sing-box utility
1. Configure [sing-box](https://github.com/sagernet/sing-box), add `Proxy-Authorization` with the `Bearer` as in the example
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
            "Proxy-Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpX...Gi7QsSPZsCqqLaXnNLl4A"
          },
          "tls": { "enabled": true }
        }
      ]
    }
    ```
2. The **jwt proxy token** will be outdated each few tens of minutes and you have to repeat it each 10-15 minutes
