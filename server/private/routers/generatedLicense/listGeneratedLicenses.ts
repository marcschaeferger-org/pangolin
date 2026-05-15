/*
 * This file is part of a proprietary work.
 *
 * Copyright (c) 2025-2026 Fossorial, Inc.
 * All rights reserved.
 *
 * This file is licensed under the Fossorial Commercial License.
 * You may not use this file except in compliance with the License.
 * Unauthorized use, copying, modification, or distribution is strictly prohibited.
 *
 * This file is not licensed under the AGPLv3.
 */

import { Request, Response, NextFunction } from "express";
import HttpCode from "@server/types/HttpCode";
import createHttpError from "http-errors";
import logger from "@server/logger";
import { response as sendResponse } from "@server/lib/response";
import privateConfig from "#private/lib/config";
import {
    GeneratedLicenseKey,
    ListGeneratedLicenseKeysResponse
} from "@server/routers/generatedLicense/types";

function isValidOrgId(orgId: string): boolean {
    return /^[A-Za-z0-9_-]{1,128}$/.test(orgId);
}

async function fetchLicenseKeys(orgId: string): Promise<any> {
    try {
        const baseUrl = privateConfig.getRawPrivateConfig().server.fossorial_api;
        const url = new URL(
            `/api/v1/license-internal/enterprise/${encodeURIComponent(orgId)}/list`,
            baseUrl
        );

        const response = await fetch(url.toString(), {
            method: "GET",
            headers: {
                "api-key":
                    privateConfig.getRawPrivateConfig().server
                        .fossorial_api_key!,
                "Content-Type": "application/json"
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error fetching license keys:", error);
        throw error;
    }
}

export async function listSaasLicenseKeys(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<any> {
    try {
        const { orgId } = req.params;

        if (!orgId) {
            return next(
                createHttpError(
                    HttpCode.BAD_REQUEST,
                    "Organization ID is required"
                )
            );
        }

        if (!isValidOrgId(orgId)) {
            return next(
                createHttpError(
                    HttpCode.BAD_REQUEST,
                    "Organization ID format is invalid"
                )
            );
        }

        const apiResponse = await fetchLicenseKeys(orgId);
        const keys: GeneratedLicenseKey[] = apiResponse.data.licenseKeys || [];

        return sendResponse<ListGeneratedLicenseKeysResponse>(res, {
            data: keys,
            success: true,
            error: false,
            message: "Successfully retrieved license keys",
            status: HttpCode.OK
        });
    } catch (error) {
        logger.error(error);
        return next(
            createHttpError(
                HttpCode.INTERNAL_SERVER_ERROR,
                "An error occurred while fetching license keys"
            )
        );
    }
}
