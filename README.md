# free_mozilla_vpn

## Interactive python script `mozvpn.py`

The script will start up local proxies for **all available proxy geo regions** on their own ports. You can find all info in the script console output.

1. Install [sing-box](https://github.com/sagernet/sing-box)
2. Install python dependencies that the script ask you to install
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
