import { encodeHexLowerCase } from "@oslojs/encoding";
import { sha256 } from "@oslojs/crypto/sha2";

/**
 * Generate a CSRF token from a session token using SHA256 hashing.
 * This provides a deterministic CSRF token that is unique per session
 * without requiring separate storage.
 * 
 * The token is derived by hashing a combination of the session token
 * and a namespace prefix, making it cryptographically bound to the session.
 * 
 * @param sessionToken - The session token from the cookie
 * @returns A hexadecimal CSRF token
 */
export function generateCsrfToken(sessionToken: string): string {
    // Use SHA256 with a namespace prefix to derive the CSRF token
    // This binds the CSRF token to the session token cryptographically
    const message = `csrf-token:${sessionToken}`;
    const hash = sha256(new TextEncoder().encode(message));
    return encodeHexLowerCase(hash);
}
