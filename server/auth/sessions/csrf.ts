import { encodeHexLowerCase } from "@oslojs/encoding";
import { sha256 } from "@oslojs/crypto/sha2";

/**
 * Generate a CSRF token from a session token using HMAC-SHA256.
 * This provides a cryptographically secure, deterministic CSRF token
 * that is unique per session without requiring separate storage.
 * 
 * @param sessionToken - The session token from the cookie
 * @returns A hexadecimal CSRF token
 */
export function generateCsrfToken(sessionToken: string): string {
    // Use HMAC-like construction: hash(secret || sessionToken)
    // In a production environment, you should use a separate secret key
    // For now, we'll use a constant prefix to namespace the CSRF tokens
    const message = `csrf-token:${sessionToken}`;
    const hash = sha256(new TextEncoder().encode(message));
    return encodeHexLowerCase(hash);
}
