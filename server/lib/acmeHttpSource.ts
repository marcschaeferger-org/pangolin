import fs from "fs";
import http from "http";
import https from "https";

// HTTP pull source for certificates (`acme.acme_http_endpoint`).
//
// Kept free of config/db/logger imports so it can be unit tested in
// isolation; acmeCertSync.ts wires it to the real config and logger.

export interface HttpCert {
    wildcard: boolean;
    altName: string;
    certName: string;
    commonName: string;
    certFile: string;
    keyFile: string;
}

export interface HttpCertSourceOptions {
    endpoint: string;
    // Path to a file containing the bearer token. Re-read whenever its
    // mtime changes, so a rotated Kubernetes Secret volume is picked up
    // without a restart. Takes precedence over `bearerToken`.
    bearerTokenFile?: string;
    // Static bearer token (e.g. from ACME_HTTP_BEARER_TOKEN).
    bearerToken?: string;
    // PEM bundle used as the only trusted CA(s) for the endpoint.
    caFile?: string;
    timeoutMs?: number;
    // Minimum interval between two warn-level failure logs.
    warnIntervalMs?: number;
    maxResponseBytes?: number;
}

export interface HttpCertSourceLogger {
    debug(msg: string): void;
    info(msg: string): void;
    warn(msg: string): void;
}

export const CERT_API_HEADER = "x-pangolin-cert-api";
export const SUPPORTED_CERT_API_VERSION = "1";

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_WARN_INTERVAL_MS = 60_000;
const DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024 * 1024;

interface CachedFile {
    path: string;
    mtimeMs: number;
    size: number;
    value: string;
}

// Reads a file and caches it by (path, mtime, size).
function readCached(
    filePath: string,
    cache: CachedFile | null,
    trim: boolean
): CachedFile {
    const stat = fs.statSync(filePath);
    if (
        cache &&
        cache.path === filePath &&
        cache.mtimeMs === stat.mtimeMs &&
        cache.size === stat.size
    ) {
        return cache;
    }
    const raw = fs.readFileSync(filePath, "utf8");
    return {
        path: filePath,
        mtimeMs: stat.mtimeMs,
        size: stat.size,
        value: trim ? raw.trim() : raw
    };
}

interface RawResponse {
    status: number;
    headers: http.IncomingHttpHeaders;
    body: string;
}

function request(
    url: URL,
    headers: Record<string, string>,
    ca: string | undefined,
    timeoutMs: number,
    maxBytes: number
): Promise<RawResponse> {
    return new Promise((resolve, reject) => {
        const isHttps = url.protocol === "https:";
        const lib = isHttps ? https : http;
        const options: https.RequestOptions = {
            method: "GET",
            headers,
            signal: AbortSignal.timeout(timeoutMs)
        };
        if (isHttps && ca) {
            options.ca = ca;
        }

        const req = lib.request(url, options, (res) => {
            const chunks: Buffer[] = [];
            let received = 0;
            res.on("data", (chunk: Buffer) => {
                received += chunk.length;
                if (received > maxBytes) {
                    req.destroy(
                        new Error(`response exceeds ${maxBytes} bytes`)
                    );
                    return;
                }
                chunks.push(chunk);
            });
            res.on("end", () =>
                resolve({
                    status: res.statusCode ?? 0,
                    headers: res.headers,
                    body: Buffer.concat(chunks).toString("utf8")
                })
            );
            res.on("error", reject);
        });
        req.on("error", reject);
        req.end();
    });
}

export interface HttpCertSource {
    // Returns the certificates, or null if nothing should be changed
    // (endpoint unreachable, non-200, bad payload). A null result must
    // never cause existing certificates to be removed.
    fetch(): Promise<HttpCert[] | null>;
}

export function createHttpCertSource(
    opts: HttpCertSourceOptions,
    log: HttpCertSourceLogger,
    now: () => number = Date.now
): HttpCertSource {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const warnIntervalMs = opts.warnIntervalMs ?? DEFAULT_WARN_INTERVAL_MS;
    const maxBytes = opts.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;

    let tokenCache: CachedFile | null = null;
    let caCache: CachedFile | null = null;
    let lastWarnAt: number | null = null;
    let suppressed = 0;
    let failing = false;
    let apiVersionLogged = false;
    let plaintextTokenWarned = false;

    const fail = (msg: string): null => {
        failing = true;
        const t = now();
        if (lastWarnAt === null || t - lastWarnAt >= warnIntervalMs) {
            const extra =
                suppressed > 0
                    ? ` (${suppressed} similar message(s) suppressed)`
                    : "";
            log.warn(`acmeCertSync: ${msg}${extra}`);
            lastWarnAt = t;
            suppressed = 0;
        } else {
            suppressed++;
            log.debug(`acmeCertSync: ${msg}`);
        }
        return null;
    };

    const resolveToken = (): string | undefined => {
        if (opts.bearerTokenFile) {
            tokenCache = readCached(opts.bearerTokenFile, tokenCache, true);
            return tokenCache.value || undefined;
        }
        return opts.bearerToken || undefined;
    };

    const resolveCa = (): string | undefined => {
        if (!opts.caFile) return undefined;
        caCache = readCached(opts.caFile, caCache, false);
        return caCache.value;
    };

    return {
        async fetch() {
            let url: URL;
            try {
                url = new URL(opts.endpoint);
            } catch {
                return fail(`invalid HTTP endpoint URL "${opts.endpoint}"`);
            }
            if (url.username || url.password) {
                return fail(
                    "credentials in acme_http_endpoint are not supported, use acme_http_bearer_token_file"
                );
            }

            const headers: Record<string, string> = {
                Accept: "application/json"
            };
            let ca: string | undefined;
            try {
                const token = resolveToken();
                if (token) {
                    headers.Authorization = `Bearer ${token}`;
                    if (url.protocol === "http:" && !plaintextTokenWarned) {
                        plaintextTokenWarned = true;
                        log.warn(
                            `acmeCertSync: sending bearer token over plain HTTP to ${url.host}`
                        );
                    }
                }
                ca = resolveCa();
            } catch (err) {
                return fail(`could not read token/CA file: ${err}`);
            }

            let res: RawResponse;
            try {
                res = await request(url, headers, ca, timeoutMs, maxBytes);
            } catch (err) {
                return fail(
                    `could not reach HTTP endpoint ${url.origin}${url.pathname}: ${err}`
                );
            }

            if (res.status !== 200) {
                const hint =
                    res.status === 401 || res.status === 403
                        ? " (check acme_http_bearer_token_file)"
                        : "";
                return fail(
                    `HTTP endpoint returned status ${res.status}${hint}`
                );
            }

            const rawVersion = res.headers[CERT_API_HEADER];
            const apiVersion = Array.isArray(rawVersion)
                ? rawVersion[0]
                : rawVersion;
            if (apiVersion !== undefined && !apiVersionLogged) {
                apiVersionLogged = true;
                if (apiVersion.trim() === SUPPORTED_CERT_API_VERSION) {
                    log.info(
                        `acmeCertSync: HTTP endpoint reports cert API version ${apiVersion}`
                    );
                } else {
                    log.warn(
                        `acmeCertSync: HTTP endpoint reports unknown cert API version "${apiVersion}", parsing as v${SUPPORTED_CERT_API_VERSION}`
                    );
                }
            }

            let body: unknown;
            try {
                body = JSON.parse(res.body);
            } catch (err) {
                return fail(`could not parse JSON from HTTP endpoint: ${err}`);
            }
            if (!Array.isArray(body)) {
                return fail("HTTP endpoint did not return a JSON array");
            }

            if (failing) {
                failing = false;
                lastWarnAt = null;
                suppressed = 0;
                log.info("acmeCertSync: HTTP endpoint recovered");
            }

            // Unknown fields are ignored (forward compatible).
            return body as HttpCert[];
        }
    };
}
