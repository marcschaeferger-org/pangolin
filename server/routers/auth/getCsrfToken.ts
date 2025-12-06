import { NextFunction, Request, Response } from "express";
import { SESSION_COOKIE_NAME } from "@server/auth/sessions/app";
import { generateCsrfToken } from "@server/auth/sessions/csrf";
import HttpCode from "@server/types/HttpCode";
import response from "@server/lib/response";

export type CsrfTokenResponse = {
    csrfToken: string;
};

/**
 * Get the CSRF token for the current session.
 * This endpoint is used by clients to retrieve a valid CSRF token
 * that must be included in state-changing requests.
 */
export async function getCsrfToken(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<any> {
    const sessionToken = req.cookies?.[SESSION_COOKIE_NAME];

    if (!sessionToken) {
        return res.status(HttpCode.UNAUTHORIZED).json({
            error: "No active session"
        });
    }

    const csrfToken = generateCsrfToken(sessionToken);

    return response<CsrfTokenResponse>(res, HttpCode.OK, {
        csrfToken
    });
}
