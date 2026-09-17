# free_mozilla_vpn

## Use mozilla vpn proxy manually

1. press ctrl+shift+alt+i to open Firefox browser developer console
2. copy and paste `firefox_console_get_http_proxy_token_and_config.js` and run
3. Get jwt token, host, port
4. Configure [sing-box](https://github.com/sagernet/sing-box) or another local proxy to add `Proxy-Authorization` http header to each http request
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
