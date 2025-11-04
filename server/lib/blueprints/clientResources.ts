import {
    SiteResource,
    siteResources,
    Transaction,
} from "@server/db";
import { sites } from "@server/db";
import { eq, and } from "drizzle-orm";
import {
    Config,
} from "./types";
import logger from "@server/logger";

export type ClientResourcesResults = {
    resource: SiteResource;
}[];

export async function updateClientResources(
    orgId: string,
    config: Config,
    trx: Transaction,
    siteId?: number
): Promise<ClientResourcesResults> {
    const results: ClientResourcesResults = [];

    for (const [resourceNiceId, resourceData] of Object.entries(
        config["client-resources"]
    )) {
        const [existingResource] = await trx
            .select()
            .from(siteResources)
            .where(
                and(
                    eq(siteResources.orgId, orgId),
                    eq(siteResources.niceId, resourceNiceId)
                )
            )
            .limit(1);

        const resourceSiteId = resourceData.site;
        let site;

        if (resourceSiteId) {
            // Look up site by niceId
            [site] = await trx
                .select({ siteId: sites.siteId })
                .from(sites)
                .where(
                    and(
                        eq(sites.niceId, resourceSiteId),
                        eq(sites.orgId, orgId)
                    )
                )
                .limit(1);
        } else if (siteId) {
            // Use the provided siteId directly, but verify it belongs to the org
            [site] = await trx
                .select({ siteId: sites.siteId })
                .from(sites)
                .where(and(eq(sites.siteId, siteId), eq(sites.orgId, orgId)))
                .limit(1);
        } else {
            throw new Error(`Target site is required`);
        }

        if (!site) {
            throw new Error(
                `Site not found: ${resourceSiteId} in org ${orgId}`
            );
        }

        // Check for duplicate resource names across different sites
        if (existingResource && siteId && existingResource.siteId !== siteId) {
            // Get site information for better error messaging
            const [currentSite] = await trx
                .select({ niceId: sites.niceId, name: sites.name })
                .from(sites)
                .where(eq(sites.siteId, siteId))
                .limit(1);

            const [existingSite] = await trx
                .select({ niceId: sites.niceId, name: sites.name })
                .from(sites)
                .where(eq(sites.siteId, existingResource.siteId))
                .limit(1);

            const existingSiteName =
                existingSite?.name || existingSite?.niceId || "unknown";
            const currentSiteName =
                currentSite?.name || currentSite?.niceId || "unknown";

            logger.error(
                `Duplicate client resource name detected: Resource '${resourceNiceId}' (nice ID) already exists on site [${existingSiteName}], but is being configured again on site [${currentSiteName}]. Each client resource name must be unique across all sites. Please rename the resource to avoid conflicts (e.g., '${resourceNiceId}-${currentSite?.niceId || "site"}').`
            );

            throw new Error(
                `Duplicate client resource name '${resourceNiceId}': This resource name is already in use on site [${existingSiteName}]. Please use a unique name for this resource on site [${currentSiteName}] to avoid conflicts. Suggestion: rename to '${resourceNiceId}-${currentSite?.niceId || "site"}'.`
            );
        }

        if (existingResource) {
            // Update existing resource
            const [updatedResource] = await trx
                .update(siteResources)
                .set({
                    name: resourceData.name || resourceNiceId,
                    siteId: site.siteId,
                    proxyPort: resourceData["proxy-port"]!,
                    destinationIp: resourceData.hostname,
                    destinationPort: resourceData["internal-port"],
                    protocol: resourceData.protocol
                })
                .where(
                    eq(
                        siteResources.siteResourceId,
                        existingResource.siteResourceId
                    )
                )
                .returning();

                results.push({ resource: updatedResource });
        } else {
            // Create new resource
            const [newResource] = await trx
                .insert(siteResources)
                .values({
                    orgId: orgId,
                    siteId: site.siteId,
                    niceId: resourceNiceId,
                    name: resourceData.name || resourceNiceId,
                    proxyPort: resourceData["proxy-port"]!,
                    destinationIp: resourceData.hostname,
                    destinationPort: resourceData["internal-port"],
                    protocol: resourceData.protocol
                })
                .returning();

            logger.info(
                `Created new client resource ${newResource.name} (${newResource.siteResourceId}) for org ${orgId}`
            );

            results.push({ resource: newResource });
        }
    }

    return results;
}
