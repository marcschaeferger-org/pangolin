import {
    PlatformConfigInput,
    resolvePlatform,
    runPlatformDiagnostics
} from "./platform";
import { configSchema } from "./readConfigFile";
import { assertEquals, assertEqualsObj } from "@test/assert";

function testResolve() {
    console.log("Running resolvePlatform tests...");
    assertEqualsObj(
        resolvePlatform({}),
        { type: undefined, certSource: "acme_json", certSourceDerived: true },
        "defaults: acme_json derived (sync flag defaults to true)"
    );
    assertEquals(
        resolvePlatform({ acme: { acme_http_endpoint: "http://x" } })
            .certSource,
        "http",
        "endpoint -> http"
    );
    assertEquals(
        resolvePlatform({ flags: { enable_acme_cert_sync: false } }).certSource,
        "none",
        "sync disabled -> none"
    );
    assertEquals(
        resolvePlatform({
            flags: { enable_acme_cert_sync: false },
            acme: { acme_http_endpoint: "http://x" }
        }).certSource,
        "none",
        "endpoint but sync disabled -> none"
    );
    assertEqualsObj(
        resolvePlatform({
            platform: { type: "kubernetes", cert_source: "external" }
        }),
        {
            type: "kubernetes",
            certSource: "external",
            certSourceDerived: false
        },
        "explicit cert_source wins"
    );
    console.log("All resolvePlatform tests passed!");
}

async function diag(
    cfg: PlatformConfigInput,
    opts: { ssl?: boolean; exists?: boolean } = {}
) {
    const lines: { level: string; msg: string }[] = [];
    let sslQueried = false;
    await runPlatformDiagnostics(cfg, {
        hasSslSiteResources: async () => {
            sslQueried = true;
            return opts.ssl ?? true;
        },
        pathExists: () => opts.exists ?? false,
        log: {
            debug: (msg) => lines.push({ level: "debug", msg }),
            info: (msg) => lines.push({ level: "info", msg }),
            warn: (msg) => lines.push({ level: "warn", msg })
        }
    });
    return {
        warns: lines.filter((l) => l.level === "warn"),
        infos: lines.filter((l) => l.level === "info"),
        sslQueried
    };
}

async function testDiagnostics() {
    console.log("Running runPlatformDiagnostics tests...");

    // platform unset: no info/warn, no DB query (default behavior)
    {
        const r = await diag({ flags: { enable_acme_cert_sync: false } });
        assertEquals(r.warns.length + r.infos.length, 0, "unset: silent");
        assertEquals(r.sslQueried, false, "unset: no DB query");
    }

    const k8sNone: PlatformConfigInput = {
        platform: { type: "kubernetes" },
        flags: { enable_acme_cert_sync: false }
    };

    // kubernetes, no source, SSL site resources -> warn
    {
        const r = await diag(k8sNone);
        assertEquals(r.infos.length, 1, "k8s: startup info");
        assertEquals(r.warns.length, 1, "k8s none + ssl: warn");
    }
    // openshift, acme.json missing -> warn
    {
        const r = await diag(
            { platform: { type: "openshift" } },
            { exists: false }
        );
        assertEquals(r.warns.length, 1, "openshift missing acme.json: warn");
    }
    // kubernetes, no SSL site resources -> no warn
    {
        const r = await diag(k8sNone, { ssl: false });
        assertEquals(r.warns.length, 0, "k8s none, no ssl: no warn");
    }
    // kubernetes + http endpoint -> no warn, no DB query
    {
        const r = await diag({
            platform: { type: "kubernetes" },
            acme: { acme_http_endpoint: "https://ctrl/api/v1/certificates" }
        });
        assertEquals(r.warns.length, 0, "k8s http: no warn");
        assertEquals(r.sslQueried, false, "k8s http: no DB query");
        assertEquals(
            r.infos[0].msg.includes("cert source http (derived)"),
            true,
            "k8s http: derived source logged"
        );
    }
    // kubernetes + acme.json present -> no warn
    {
        const r = await diag(
            { platform: { type: "kubernetes" } },
            { exists: true }
        );
        assertEquals(r.warns.length, 0, "k8s acme.json present: no warn");
    }
    // kubernetes + external -> no warn
    {
        const r = await diag({
            platform: { type: "kubernetes", cert_source: "external" },
            flags: { enable_acme_cert_sync: false }
        });
        assertEquals(r.warns.length, 0, "k8s external: no warn");
    }
    // docker, no source -> no warn
    {
        const r = await diag({
            platform: { type: "docker" },
            flags: { enable_acme_cert_sync: false }
        });
        assertEquals(r.warns.length, 0, "docker: no warn");
    }
    // explicit http without endpoint -> consistency warn
    {
        const r = await diag(
            { platform: { type: "docker", cert_source: "http" } },
            { exists: true }
        );
        assertEquals(
            r.warns.length,
            1,
            "cert_source=http without endpoint: warn"
        );
    }
    // DB error is swallowed
    {
        let threw = false;
        try {
            await runPlatformDiagnostics(k8sNone, {
                hasSslSiteResources: async () => {
                    throw new Error("db down");
                },
                pathExists: () => false,
                log: { debug() {}, info() {}, warn() {} }
            });
        } catch {
            threw = true;
        }
        assertEquals(threw, false, "DB error swallowed");
    }
    console.log("All runPlatformDiagnostics tests passed!");
}

function withEnv(env: Record<string, string>, fn: () => void) {
    const old: Record<string, string | undefined> = {};
    for (const k of Object.keys(env)) {
        old[k] = process.env[k];
        process.env[k] = env[k];
    }
    try {
        fn();
    } finally {
        for (const k of Object.keys(env)) {
            if (old[k] === undefined) delete process.env[k];
            else process.env[k] = old[k];
        }
    }
}

function testSchema() {
    console.log("Running config schema tests...");
    const platform = configSchema.shape.platform;
    const acme = configSchema.shape.acme;

    assertEqualsObj<unknown>(
        platform.parse(undefined),
        {},
        "platform default: empty"
    );
    assertEquals(
        platform.parse({ type: "kubernetes" }).type,
        "kubernetes",
        "platform yaml"
    );
    assertEquals(
        platform.safeParse({ type: "nomad" }).success,
        false,
        "invalid platform type rejected"
    );
    withEnv(
        { PANGOLIN_PLATFORM: "openshift", PANGOLIN_CERT_SOURCE: "http" },
        () => {
            const p = platform.parse(undefined);
            assertEquals(p.type, "openshift", "PANGOLIN_PLATFORM env");
            assertEquals(p.cert_source, "http", "PANGOLIN_CERT_SOURCE env");
        }
    );

    const a = acme.parse(undefined);
    assertEquals(
        a.acme_json_path,
        "config/letsencrypt/acme.json",
        "acme default path"
    );
    assertEquals(a.sync_interval_ms, 5000, "acme default interval");
    assertEquals(a.acme_http_endpoint, undefined, "acme default endpoint");
    withEnv(
        {
            ACME_HTTP_ENDPOINT: "https://ctrl/api/v1/certificates",
            ACME_HTTP_BEARER_TOKEN: "t"
        },
        () => {
            const e = acme.parse(undefined);
            assertEquals(
                e.acme_http_endpoint,
                "https://ctrl/api/v1/certificates",
                "ACME_HTTP_ENDPOINT env"
            );
            assertEquals(
                e.acme_http_bearer_token,
                "t",
                "ACME_HTTP_BEARER_TOKEN env"
            );
        }
    );
    const f = acme.parse({
        acme_http_bearer_token_file: "/run/secrets/token",
        acme_http_ca_file: "/run/secrets/ca.crt"
    });
    assertEquals(
        f.acme_http_bearer_token_file,
        "/run/secrets/token",
        "token file"
    );
    assertEquals(f.acme_http_ca_file, "/run/secrets/ca.crt", "ca file");
    console.log("All config schema tests passed!");
}

(async () => {
    try {
        testResolve();
        await testDiagnostics();
        testSchema();
        process.exit(0);
    } catch (err) {
        console.error("Test failed:", err);
        process.exit(1);
    }
})();
