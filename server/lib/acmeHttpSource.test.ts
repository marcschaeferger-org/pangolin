import fs from "fs";
import http from "http";
import https from "https";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";
import { AddressInfo } from "net";
import { createHttpCertSource, HttpCertSourceLogger } from "./acmeHttpSource";
import { assertEquals } from "@test/assert";

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

interface Captured {
    lines: { level: string; msg: string }[];
    log: HttpCertSourceLogger;
    count(level: string): number;
}

function captureLog(): Captured {
    const lines: { level: string; msg: string }[] = [];
    return {
        lines,
        log: {
            debug: (msg) => lines.push({ level: "debug", msg }),
            info: (msg) => lines.push({ level: "info", msg }),
            warn: (msg) => lines.push({ level: "warn", msg })
        },
        count: (level) => lines.filter((l) => l.level === level).length
    };
}

async function listen(server: http.Server): Promise<number> {
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    return (server.address() as AddressInfo).port;
}

const CERTS = [
    {
        wildcard: true,
        altName: "*.example.com",
        certName: "*.example.com",
        commonName: "*.example.com",
        certFile: "CERT",
        keyFile: "KEY",
        futureField: { anything: 1 }
    }
];

const TOKEN = "test-token-not-a-secret";

// Mock controller: 200 with valid bearer, 401 otherwise, 503 on /down.
function controllerHandler(
    seen: { auth?: string; accept?: string }[]
): Handler {
    return (req, res) => {
        seen.push({
            auth: req.headers.authorization,
            accept: req.headers.accept
        });
        if (req.url === "/down") {
            res.writeHead(503).end("not ready");
            return;
        }
        if (req.url === "/slow") {
            setTimeout(() => res.writeHead(200).end("[]"), 2000);
            return;
        }
        if (req.url === "/v9") {
            res.writeHead(200, {
                "content-type": "application/json",
                "x-pangolin-cert-api": "9"
            }).end(JSON.stringify(CERTS));
            return;
        }
        if (req.headers.authorization !== `Bearer ${TOKEN}`) {
            res.writeHead(401).end("unauthorized");
            return;
        }
        res.writeHead(200, {
            "content-type": "application/json",
            "x-pangolin-cert-api": "1"
        }).end(JSON.stringify(CERTS));
    };
}

function tmpDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), "acme-http-src-"));
}

async function testHttp() {
    console.log("Running acmeHttpSource HTTP tests...");
    const seen: { auth?: string; accept?: string }[] = [];
    const server = http.createServer(controllerHandler(seen));
    const port = await listen(server);
    const base = `http://127.0.0.1:${port}`;
    const dir = tmpDir();

    try {
        // 200 with token file, Accept header, API header logged once
        {
            const tokenFile = path.join(dir, "token");
            fs.writeFileSync(tokenFile, `${TOKEN}\n`);
            const c = captureLog();
            const src = createHttpCertSource(
                { endpoint: `${base}/certs`, bearerTokenFile: tokenFile },
                c.log
            );
            const certs = await src.fetch();
            assertEquals(certs?.length, 1, "200: expected one cert");
            assertEquals(certs?.[0].certName, "*.example.com", "200: certName");
            assertEquals(
                seen.at(-1)?.auth,
                `Bearer ${TOKEN}`,
                "200: bearer header (trimmed file)"
            );
            assertEquals(
                seen.at(-1)?.accept,
                "application/json",
                "Accept header"
            );
            await src.fetch();
            const apiInfos = c.lines.filter((l) =>
                l.msg.includes("cert API version 1")
            ).length;
            assertEquals(apiInfos, 1, "API version logged exactly once");
            assertEquals(
                c.lines.filter((l) => l.msg.includes("plain HTTP")).length,
                1,
                "plain-HTTP token warning once"
            );
        }

        // 401 without token -> null, warn
        {
            const c = captureLog();
            const src = createHttpCertSource(
                { endpoint: `${base}/certs` },
                c.log
            );
            const certs = await src.fetch();
            assertEquals(certs, null, "401: null result");
            assertEquals(seen.at(-1)?.auth, undefined, "401: no auth header");
            assertEquals(c.count("warn"), 1, "401: one warn");
            assertEquals(
                c.lines[0].msg.includes("status 401"),
                true,
                "401: status in message"
            );
        }

        // env-style static token
        {
            const c = captureLog();
            const src = createHttpCertSource(
                { endpoint: `${base}/certs`, bearerToken: TOKEN },
                c.log
            );
            assertEquals((await src.fetch())?.length, 1, "static token: 200");
        }

        // token file takes precedence over static token
        {
            const tokenFile = path.join(dir, "token-prec");
            fs.writeFileSync(tokenFile, TOKEN);
            const src = createHttpCertSource(
                {
                    endpoint: `${base}/certs`,
                    bearerTokenFile: tokenFile,
                    bearerToken: "wrong"
                },
                captureLog().log
            );
            assertEquals((await src.fetch())?.length, 1, "file wins over env");
        }

        // token rotation without restart
        {
            const tokenFile = path.join(dir, "token-rot");
            fs.writeFileSync(tokenFile, "old-token");
            const src = createHttpCertSource(
                { endpoint: `${base}/certs`, bearerTokenFile: tokenFile },
                captureLog().log
            );
            assertEquals(await src.fetch(), null, "rotation: old token -> 401");
            fs.writeFileSync(tokenFile, TOKEN);
            const future = new Date(Date.now() + 5000);
            fs.utimesSync(tokenFile, future, future);
            assertEquals((await src.fetch())?.length, 1, "rotation: new token");
        }

        // missing token file -> null, warn, no request
        {
            const c = captureLog();
            const before = seen.length;
            const src = createHttpCertSource(
                {
                    endpoint: `${base}/certs`,
                    bearerTokenFile: path.join(dir, "missing")
                },
                c.log
            );
            assertEquals(await src.fetch(), null, "missing token file: null");
            assertEquals(seen.length, before, "missing token file: no request");
            assertEquals(c.count("warn"), 1, "missing token file: warn");
        }

        // 503 -> null; throttled warn; recovery logged
        {
            const c = captureLog();
            let t = 0;
            const src = createHttpCertSource(
                { endpoint: `${base}/down`, bearerToken: TOKEN },
                c.log,
                () => t
            );
            assertEquals(await src.fetch(), null, "503: null");
            t = 10_000;
            await src.fetch();
            t = 30_000;
            await src.fetch();
            const w503 = () =>
                c.lines.filter(
                    (l) => l.level === "warn" && l.msg.includes("status 503")
                );
            assertEquals(w503().length, 1, "503: throttled to one warn");
            t = 61_000;
            await src.fetch();
            assertEquals(w503().length, 2, "503: warn again after 60s");
            assertEquals(
                w503()[1].msg.includes("2 similar message(s) suppressed"),
                true,
                "503: suppressed count reported"
            );
        }

        // recovery
        {
            const tokenFile = path.join(dir, "token-rec");
            fs.writeFileSync(tokenFile, "bad");
            const c = captureLog();
            const src = createHttpCertSource(
                { endpoint: `${base}/certs`, bearerTokenFile: tokenFile },
                c.log
            );
            await src.fetch();
            fs.writeFileSync(tokenFile, TOKEN + " ");
            const future = new Date(Date.now() + 10_000);
            fs.utimesSync(tokenFile, future, future);
            await src.fetch();
            assertEquals(
                c.lines.some((l) => l.msg.includes("recovered")),
                true,
                "recovery logged"
            );
        }

        // unknown API version -> warn once, still parsed
        {
            const c = captureLog();
            const src = createHttpCertSource({ endpoint: `${base}/v9` }, c.log);
            assertEquals((await src.fetch())?.length, 1, "v9 parsed as v1");
            assertEquals(c.count("warn"), 1, "v9: one warn");
        }

        // timeout
        {
            const c = captureLog();
            const src = createHttpCertSource(
                { endpoint: `${base}/slow`, timeoutMs: 200 },
                c.log
            );
            const start = Date.now();
            assertEquals(await src.fetch(), null, "timeout: null");
            assertEquals(
                Date.now() - start < 1500,
                true,
                "timeout: aborted early"
            );
            assertEquals(c.count("warn"), 1, "timeout: warn");
        }

        // unreachable
        {
            const c = captureLog();
            const src = createHttpCertSource(
                { endpoint: "http://127.0.0.1:1/certs" },
                c.log
            );
            assertEquals(await src.fetch(), null, "unreachable: null");
            assertEquals(c.count("warn"), 1, "unreachable: warn");
        }

        // credentials in URL rejected, token never leaks into logs
        {
            const c = captureLog();
            const src = createHttpCertSource(
                { endpoint: `http://u:p@127.0.0.1:${port}/certs` },
                c.log
            );
            assertEquals(await src.fetch(), null, "userinfo URL: null");
            assertEquals(
                c.lines.some((l) => l.msg.includes(TOKEN)),
                false,
                "token not logged"
            );
        }
    } finally {
        server.close();
        fs.rmSync(dir, { recursive: true, force: true });
    }
    console.log("All acmeHttpSource HTTP tests passed!");
}

function makeCert(
    dir: string,
    name: string
): { cert: string; key: string } | null {
    const key = path.join(dir, `${name}.key`);
    const cert = path.join(dir, `${name}.crt`);
    const r = spawnSync("openssl", [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=127.0.0.1",
        "-addext",
        "subjectAltName=IP:127.0.0.1",
        "-keyout",
        key,
        "-out",
        cert
    ]);
    if (r.status !== 0) return null;
    return { cert, key };
}

async function testHttpsCa() {
    console.log("Running acmeHttpSource HTTPS/CA tests...");
    const dir = tmpDir();
    try {
        const server1 = makeCert(dir, "server");
        const other = makeCert(dir, "other");
        if (!server1 || !other) {
            console.log("SKIPPED HTTPS/CA tests: openssl not available");
            return;
        }
        const seen: { auth?: string; accept?: string }[] = [];
        const server = https.createServer(
            {
                cert: fs.readFileSync(server1.cert),
                key: fs.readFileSync(server1.key)
            },
            controllerHandler(seen)
        );
        const port = await listen(server);
        const endpoint = `https://127.0.0.1:${port}/certs`;
        try {
            // without CA file: self-signed cert rejected
            {
                const c = captureLog();
                const src = createHttpCertSource(
                    { endpoint, bearerToken: TOKEN },
                    c.log
                );
                assertEquals(await src.fetch(), null, "no CA: TLS rejected");
                assertEquals(c.count("warn"), 1, "no CA: warn");
            }
            // with matching CA file
            {
                const c = captureLog();
                const src = createHttpCertSource(
                    { endpoint, bearerToken: TOKEN, caFile: server1.cert },
                    c.log
                );
                assertEquals((await src.fetch())?.length, 1, "CA: 200");
                assertEquals(
                    c.lines.some((l) => l.msg.includes("plain HTTP")),
                    false,
                    "CA: no plain-HTTP warning"
                );
            }
            // with wrong CA file
            {
                const src = createHttpCertSource(
                    { endpoint, bearerToken: TOKEN, caFile: other.cert },
                    captureLog().log
                );
                assertEquals(await src.fetch(), null, "wrong CA: rejected");
            }
            // missing CA file
            {
                const c = captureLog();
                const src = createHttpCertSource(
                    { endpoint, caFile: path.join(dir, "nope.crt") },
                    c.log
                );
                assertEquals(await src.fetch(), null, "missing CA: null");
                assertEquals(c.count("warn"), 1, "missing CA: warn");
            }
        } finally {
            server.close();
        }
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
    console.log("All acmeHttpSource HTTPS/CA tests passed!");
}

(async () => {
    try {
        await testHttp();
        await testHttpsCa();
        process.exit(0);
    } catch (err) {
        console.error("Test failed:", err);
        process.exit(1);
    }
})();
