import { NextFunction, Request, Response } from "express";
import { SESSION_COOKIE_NAME } from "@server/auth/sessions/app";

// Enforce CSRF only when a cookie-based session is present. This avoids breaking
// token-based or machine-to-machine POSTs that do not use browser cookies.
export function csrfProtectionMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
) {
    // Allow safe/idempotent methods without checks
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") {
        return next();
    }

    const hasSessionCookie = Boolean((req as any).cookies?.[SESSION_COOKIE_NAME]);

    if (!hasSessionCookie) {
        // No session cookie -> CSRF does not apply
        return next();
    }

    const csrfToken = req.headers["x-csrf-token"];
    if (!csrfToken || csrfToken !== "x-csrf-protection") {
        return res.status(403).json({ error: "CSRF token missing or invalid" });
    }

    return next();
}
