// `platform` config block: deployment platform and certificate source.
//
// In this release the block only drives defaults reporting and startup
// diagnostics; it does not change runtime behavior. Callers must not use it
// in the saas build.

export const PLATFORM_TYPES = ["docker", "kubernetes", "openshift"] as const;
export type PlatformType = (typeof PLATFORM_TYPES)[number];

export const CERT_SOURCES = ["acme_json", "http", "files", "external"] as const;
export type CertSource = (typeof CERT_SOURCES)[number];

export interface PlatformConfigInput {
    platform?: { type?: PlatformType; cert_source?: CertSource };
    flags?: { enable_acme_cert_sync?: boolean };
    acme?: { acme_http_endpoint?: string; acme_json_path?: string };
}

export interface ResolvedPlatform {
    type: PlatformType | undefined;
    certSource: CertSource | "none";
    certSourceDerived: boolean;
}

// Explicit cert_source wins; otherwise derive it the way the sync already
// behaves: HTTP endpoint > acme.json file sync > none.
export function resolvePlatform(cfg: PlatformConfigInput): ResolvedPlatform {
    const type = cfg.platform?.type;
    const explicit = cfg.platform?.cert_source;
    if (explicit) {
        return { type, certSource: explicit, certSourceDerived: false };
    }
    const syncEnabled = cfg.flags?.enable_acme_cert_sync ?? true;
    let certSource: CertSource | "none" = "none";
    if (syncEnabled && cfg.acme?.acme_http_endpoint) {
        certSource = "http";
    } else if (syncEnabled) {
        certSource = "acme_json";
    }
    return { type, certSource, certSourceDerived: true };
}

export interface PlatformDiagnosticsDeps {
    hasSslSiteResources: () => Promise<boolean>;
    pathExists: (p: string) => boolean;
    log: {
        debug(m: string): void;
        info(m: string): void;
        warn(m: string): void;
    };
}

const CONTAINER_PLATFORMS: ReadonlySet<PlatformType> = new Set([
    "kubernetes",
    "openshift"
]);

export async function runPlatformDiagnostics(
    cfg: PlatformConfigInput,
    deps: PlatformDiagnosticsDeps
): Promise<void> {
    const p = resolvePlatform(cfg);
    const { log } = deps;
    const sourceLabel = `${p.certSource}${p.certSourceDerived ? " (derived)" : ""}`;

    if (!p.type) {
        log.debug(
            `platform: not set, using default behavior; cert source ${sourceLabel}`
        );
        return;
    }
    log.info(`platform: type=${p.type}, cert source ${sourceLabel}`);

    const syncEnabled = cfg.flags?.enable_acme_cert_sync ?? true;
    const endpoint = cfg.acme?.acme_http_endpoint;
    const jsonPath = cfg.acme?.acme_json_path ?? "config/letsencrypt/acme.json";

    // Consistency between an explicit cert_source and what will actually run.
    if (!p.certSourceDerived) {
        if (p.certSource === "http" && (!endpoint || !syncEnabled)) {
            log.warn(
                "platform: cert_source=http but acme.acme_http_endpoint is unset or flags.enable_acme_cert_sync is false"
            );
        } else if (p.certSource === "acme_json" && endpoint) {
            log.warn(
                "platform: cert_source=acme_json but acme.acme_http_endpoint is set; the HTTP endpoint takes precedence"
            );
        } else if (p.certSource === "files") {
            log.warn(
                "platform: cert_source=files is not implemented yet; no certificates will be synced"
            );
        }
    }

    if (!CONTAINER_PLATFORMS.has(p.type) || p.certSource === "external") {
        return;
    }

    let usable = false;
    if (syncEnabled && endpoint) {
        usable = true;
    } else if (syncEnabled && deps.pathExists(jsonPath)) {
        usable = true;
    }
    if (usable) return;

    let hasSsl = false;
    try {
        hasSsl = await deps.hasSslSiteResources();
    } catch (err) {
        log.debug(`platform: could not check for SSL site resources: ${err}`);
        return;
    }
    if (!hasSsl) return;

    log.warn(
        `platform: type=${p.type} but no certificate source is available (no acme.acme_http_endpoint, no acme.json at "${jsonPath}"${syncEnabled ? "" : ", flags.enable_acme_cert_sync=false"}); SSL site resources will stay "pending". Set acme.acme_http_endpoint or platform.cert_source=external.`
    );
}
