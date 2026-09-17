(async function getVPNProxyCredentialsAllLocations() {
    console.log("%c🚀 Получение proxyPass и реквизитов прокси для ВСЕХ локаций...", "color: #ff9500; font-weight: bold;");

    const guardianPath = "moz-src:///toolkit/components/ipprotection/fxa/GuardianClient.sys.mjs";
    const servicePath = "moz-src:///toolkit/components/ipprotection/IPProtectionService.sys.mjs";
    const serverListPath = "moz-src:///toolkit/components/ipprotection/IPProtectionServerlist.sys.mjs";

    // По записи на каждый протокол сервера (connect: scheme/host/port, masque: templateString)
    function extractServerCreds(server) {
        const creds = [];
        const protocols = (server.protocols && server.protocols.length)
            ? server.protocols
            : [{ name: "connect", host: server.hostname, port: server.port, scheme: "https" }];
        for (const p of protocols) {
            creds.push({
                hostname: server.hostname,
                port: server.port,
                protocol: p.name,                        // "connect" | "masque"
                protocolHost: p.host || server.hostname,
                protocolPort: p.port || server.port,
                scheme: p.scheme || null,                // только у connect
                templateString: p.templateString || null, // только у masque
                quarantined: !!server.quarantined,
            });
        }
        return creds;
    }

    try {
        const { GuardianClient } = ChromeUtils.importESModule(guardianPath);
        const { IPProtectionService } = ChromeUtils.importESModule(servicePath);
        const ServerlistModule = ChromeUtils.importESModule(serverListPath);

        const serverlist = ServerlistModule.IPProtectionServerlist;
        if (!serverlist) throw new Error("IPProtectionServerlist не найден в модуле");
        console.log("%c✅ Модули загружены", "color: green;");

        const authProvider = IPProtectionService.authProvider;
        if (!authProvider) throw new Error("authProvider не найден. Выполнен ли вход в FxA?");

        console.log("%c⏳ Получаем OAuth-токен...", "color: #ff9500;");
        const tokenHandle = await authProvider.getToken();
        if (!tokenHandle || !tokenHandle.token) throw new Error("Не удалось получить OAuth-токен.");
        console.log(`%c✅ OAuth-токен получен (длина: ${tokenHandle.token.length})`, "color: green;");

        const client = new GuardianClient();
        console.log("%c⏳ Запрашиваем proxyPass...", "color: #ff9500;");
        const result = await client.fetchProxyPass(tokenHandle);
        if (result.error || !result.pass || !result.pass.token) {
            console.error("%c❌ proxyPass не получен:", "color: red; font-weight: bold;",
                          result.error, "status:", result.status, result);
            return;
        }

        const PROXY_PASS_TOKEN = result.pass.token;
        console.log("%c✅ proxyPass получен!", "color: green; font-weight: bold;");
        console.log("Действителен до:", result.pass.until?.toString?.() ?? "неизвестно");

        console.log("%c⏳ Загружаем список серверов...", "color: #ff9500;");
        await serverlist.maybeFetchList();
        if (!serverlist.hasList) throw new Error("Список серверов пуст. Подождите синхронизации Remote Settings.");

        // ===== ВСЕ страны: [{code, available, locked}] =====
        const countries = serverlist.countries;
        console.log(`%c✅ Найдено стран: ${countries.length}`, "color: green;");

        const output = {
            fetchedAt: new Date().toISOString(),
            proxyPass: { token: PROXY_PASS_TOKEN,
                         validUntil: result.pass.until?.toString?.() ?? null },
            recommended: null,
            locations: [],
        };

        // anycast-локация для сравнения
        const recLoc = serverlist.getRecommendedLocation();
        if (recLoc && recLoc.city) {
            const recServer = serverlist.selectServer(recLoc.city);
            output.recommended = {
                countryCode: recLoc.country.code, countryName: recLoc.country.name,
                cityName: recLoc.city.name, cityCode: recLoc.city.code,
                servers: recServer ? extractServerCreds(recServer) : [],
            };
        }

        let totalServers = 0;
        for (const { code, available, locked } of countries) {
            if (!available) continue;
            const loc = serverlist.getLocation(code);
            if (!loc) continue;
            const country = loc.country;

            const countryEntry = { countryCode: country.code, countryName: country.name,
                                   locked: !!country.locked, cities: [] };
            for (const city of country.cities) {
                const usable = city.servers.filter(s => !s.quarantined);
                if (!usable.length) continue;
                countryEntry.cities.push({
                    cityName: city.name, cityCode: city.code,
                    serverCount: usable.length,
                    servers: usable.flatMap(extractServerCreds),
                });
                totalServers += usable.length;
            }
            if (countryEntry.cities.length) output.locations.push(countryEntry);
        }

        console.log(`%c✅ ЛОКАЦИЙ: ${output.locations.length}, СЕРВЕРОВ: ${totalServers}`,
                    "color: #0a84ff; font-weight: bold; font-size: 15px;");
        for (const c of output.locations) {
            for (const city of c.cities) {
                for (const s of city.servers) {
                    console.log(`${c.countryCode.padEnd(3)} ${c.countryName.padEnd(15)} ` +
                        `${city.cityName.padEnd(15)} ${s.protocol.padEnd(8)} ` +
                        `${(s.scheme ?? "-").padEnd(6)} ${s.protocolHost}:${s.protocolPort}` +
                        (c.locked ? "  [locked]" : ""));
                }
            }
        }
        console.log("%c📋 Bearer-токен (JWT):", "color: #0a84ff; font-weight: bold;");
        console.log(PROXY_PASS_TOKEN);
        console.log(JSON.stringify(output, null, 2));
        try { copy(output); console.log("%c📋 JSON скопирован в буфер обмена", "color: green;"); } catch (_) {}
        return output;
    } catch (e) {
        console.error("%c❌ ОШИБКА:", "color: red; font-weight: bold;", e);
        console.error("Стек:", e.stack);
    }
})();
