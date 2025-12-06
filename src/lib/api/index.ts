import { Env } from "@app/lib/types/env";
import axios, { AxiosInstance, InternalAxiosRequestConfig } from "axios";

let apiInstance: AxiosInstance | null = null;
let csrfToken: string | null = null;

/**
 * Fetch the CSRF token from the server.
 * This function is called once per session to retrieve the CSRF token.
 */
async function fetchCsrfToken(baseURL: string): Promise<string | null> {
    try {
        const response = await axios.get(`${baseURL}/auth/csrf-token`, {
            withCredentials: true
        });
        return response.data.csrfToken;
    } catch (error) {
        // If we can't get a CSRF token (e.g., not logged in), return null
        // The middleware will handle requests without tokens appropriately
        return null;
    }
}

export function createApiClient({ env }: { env: Env }): AxiosInstance {
    if (apiInstance) {
        return apiInstance;
    }

    const w = typeof globalThis !== 'undefined' && 'window' in globalThis ? (globalThis as typeof globalThis & { window: Window }).window : undefined;
    if (typeof w === 'undefined') {
        return;
    }

    let baseURL;
    const suffix = "api/v1";

    if (w.location.port === env.server.nextPort) {
        // this means the user is addressing the server directly
        baseURL = `${w.location.protocol}//${w.location.hostname}:${env.server.externalPort}/${suffix}`;
        axios.defaults.withCredentials = true;
    } else {
        // user is accessing through a proxy
        baseURL = `${env.app.dashboardUrl}/${suffix}`;
    }

    if (!baseURL) {
        throw new Error("Failed to create api client, invalid environment");
    }

    apiInstance = axios.create({
        baseURL,
        timeout: 10000,
        headers: {
            "Content-Type": "application/json"
        },
        withCredentials: true
    });

    // Add request interceptor to include CSRF token in state-changing requests
    apiInstance.interceptors.request.use(
        async (config: InternalAxiosRequestConfig) => {
            // Only add CSRF token for state-changing methods
            const method = config.method?.toLowerCase();
            if (method && !['get', 'head', 'options'].includes(method)) {
                // Fetch CSRF token if we don't have one yet
                if (!csrfToken) {
                    csrfToken = await fetchCsrfToken(baseURL);
                }
                
                // Add CSRF token to headers if we have one
                if (csrfToken) {
                    config.headers['X-CSRF-Token'] = csrfToken;
                }
            }
            return config;
        },
        (error) => {
            return Promise.reject(error);
        }
    );

    // Add response interceptor to refresh CSRF token on 403 errors
    apiInstance.interceptors.response.use(
        (response) => response,
        async (error) => {
            if (error.response?.status === 403 && error.config && !error.config._retry) {
                // Mark request as retried to avoid infinite loops
                error.config._retry = true;
                
                // Refresh CSRF token
                csrfToken = await fetchCsrfToken(baseURL);
                
                // Retry the request with new token
                if (csrfToken) {
                    error.config.headers['X-CSRF-Token'] = csrfToken;
                    return apiInstance!.request(error.config);
                }
            }
            return Promise.reject(error);
        }
    );

    return apiInstance;
}

// we can pull from env var here becuase it is only used in the server
export const internal = axios.create({
    baseURL: `http://localhost:${process.env.SERVER_EXTERNAL_PORT}/api/v1`,
    timeout: 10000,
    headers: {
        "Content-Type": "application/json"
    }
});

export const priv = axios.create({
    baseURL: `http://localhost:${process.env.SERVER_INTERNAL_PORT}/api/v1`,
    timeout: 10000,
    headers: {
        "Content-Type": "application/json"
    }
});

export * from "./formatAxiosError";

