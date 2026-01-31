/*
CORS Anywhere as a Cloudflare Worker!
(c) 2019 by Zibri (www.zibri.org)
email: zibri AT zibri DOT org
https://github.com/Zibri/cloudflare-cors-anywhere

This Cloudflare Worker script acts as a CORS proxy that allows
cross-origin resource sharing for specified origins and URLs.
It handles OPTIONS preflight requests and modifies response headers accordingly to enable CORS.
The script also includes functionality to parse custom headers and provide detailed information
about the CORS proxy service when accessed without specific parameters.
The script is configurable with whitelist patterns for both origins and target URLs.
The main goal is to facilitate cross-origin requests while enforcing specific security and rate-limiting policies.
*/

// Configuration: Hardcoded Whitelist
// whitelist = [ "^http.?://www.zibri.org$", "zibri.org$", "test\\..*" ];  // regexp for whitelisted urls
const defaultWhitelistUrls = [ ".*" ];           // regexp for whitelisted urls
const defaultWhitelistOrigins = [ ".*" ];   // regexp for whitelisted origins

// Function to check if a given URI or origin is listed in the whitelist or blacklist
function isListedInWhitelist(uri, listing) {
    let isListed = false;
    if (typeof uri === "string") {
        listing.forEach((pattern) => {
            if (uri.match(pattern) !== null) {
                isListed = true;
            }
        });
    } else {
        // When URI is null (e.g., when Origin header is missing), decide based on the implementation
        isListed = true; // true accepts null origins, false would reject them
    }
    return isListed;
}

export default {
    async fetch(request, env, ctx) {
        const isPreflightRequest = (request.method === "OPTIONS");
        
        const originUrl = new URL(request.url);

        // Fetch configuration from KV if available
        // Expected KV binding name: KV
        // Keys: 'whitelistUrls', 'whitelistOrigins' (values should be JSON arrays of strings)
        let kvWhitelistUrls = [];
        let kvWhitelistOrigins = [];
        
        if (env.KV) {
            try {
                const wlu = await env.KV.get("whitelistUrls", { type: "json" });
                if (Array.isArray(wlu)) kvWhitelistUrls = wlu;
                
                const wlo = await env.KV.get("whitelistOrigins", { type: "json" });
                if (Array.isArray(wlo)) kvWhitelistOrigins = wlo;
            } catch (e) {
                console.warn("Failed to fetch from KV:", e);
            }
        }

        const whitelistUrls = [...defaultWhitelistUrls, ...kvWhitelistUrls];
        const whitelistOrigins = [...defaultWhitelistOrigins, ...kvWhitelistOrigins];

        // Function to modify headers to enable CORS
        function setupCORSHeaders(headers) {
            headers.set("Access-Control-Allow-Origin", request.headers.get("Origin"));
            if (isPreflightRequest) {
                headers.set("Access-Control-Allow-Methods", request.headers.get("access-control-request-method"));
                const requestedHeaders = request.headers.get("access-control-request-headers");

                if (requestedHeaders) {
                    headers.set("Access-Control-Allow-Headers", requestedHeaders);
                }

                headers.delete("X-Content-Type-Options"); // Remove X-Content-Type-Options header
            }
            return headers;
        }

        const targetUrl = decodeURIComponent(decodeURIComponent(originUrl.search.substr(1)));

        const originHeader = request.headers.get("Origin");
        const connectingIp = request.headers.get("CF-Connecting-IP");

        // Check if both the target URL and the Origin are in their respective whitelists
        if ((isListedInWhitelist(targetUrl, whitelistUrls)) && (isListedInWhitelist(originHeader, whitelistOrigins))) {
            let customHeaders = request.headers.get("x-cors-headers");

            if (customHeaders !== null) {
                try {
                    customHeaders = JSON.parse(customHeaders);
                } catch (e) {}
            }

            if (originUrl.search.startsWith("?")) {
                const filteredHeaders = {};
                for (const [key, value] of request.headers.entries()) {
                    if (
                        (key.match("^origin") === null) &&
                        (key.match("eferer") === null) &&
                        (key.match("^cf-") === null) &&
                        (key.match("^x-forw") === null) &&
                        (key.match("^x-cors-headers") === null)
                    ) {
                        filteredHeaders[key] = value;
                    }
                }

                if (customHeaders !== null) {
                    Object.entries(customHeaders).forEach((entry) => (filteredHeaders[entry[0]] = entry[1]));
                }

                const newRequest = new Request(request, {
                    redirect: "follow",
                    headers: filteredHeaders
                });

                const response = await fetch(targetUrl, newRequest);
                let responseHeaders = new Headers(response.headers);
                const exposedHeaders = [];
                const allResponseHeaders = {};
                for (const [key, value] of response.headers.entries()) {
                    exposedHeaders.push(key);
                    allResponseHeaders[key] = value;
                }
                exposedHeaders.push("cors-received-headers");
                responseHeaders = setupCORSHeaders(responseHeaders);

                responseHeaders.set("Access-Control-Expose-Headers", exposedHeaders.join(","));
                responseHeaders.set("cors-received-headers", JSON.stringify(allResponseHeaders));

                const responseBody = isPreflightRequest ? null : await response.arrayBuffer();

                const responseInit = {
                    headers: responseHeaders,
                    status: isPreflightRequest ? 200 : response.status,
                    statusText: isPreflightRequest ? "OK" : response.statusText
                };
                return new Response(responseBody, responseInit);

            } else {
                let responseHeaders = new Headers();
                responseHeaders = setupCORSHeaders(responseHeaders);

                let country = false;
                let colo = false;
                // request.cf is available in Cloudflare Workers
                if (typeof request.cf !== "undefined") {
                    country = request.cf.country || false;
                    colo = request.cf.colo || false;
                }

                return new Response(
                    "CLOUDFLARE-CORS-ANYWHERE\n\n" +
                    "Source:\nhttps://github.com/Zibri/cloudflare-cors-anywhere\n\n" +
                    "Usage:\n" +
                    originUrl.origin + "/?uri\n\n" +
                    "Donate:\nhttps://paypal.me/Zibri/5\n\n" +
                    "Limits: 100,000 requests/day\n" +
                    "          1,000 requests/10 minutes\n\n" +
                    (originHeader !== null ? "Origin: " + originHeader + "\n" : "") +
                    "IP: " + connectingIp + "\n" +
                    (country ? "Country: " + country + "\n" : "") +
                    (colo ? "Datacenter: " + colo + "\n" : "") +
                    "\n" +
                    (customHeaders !== null ? "\nx-cors-headers: " + JSON.stringify(customHeaders) : ""),
                    {
                        status: 200,
                        headers: responseHeaders
                    }
                );
            }
        } else {
            return new Response(
                "Create your own CORS proxy</br>\n" +
                "<a href='https://github.com/Zibri/cloudflare-cors-anywhere'>https://github.com/Zibri/cloudflare-cors-anywhere</a></br>\n" +
                "\nDonate</br>\n" +
                "<a href='https://paypal.me/Zibri/5'>https://paypal.me/Zibri/5</a>\n",
                {
                    status: 403,
                    statusText: 'Forbidden',
                    headers: {
                        "Content-Type": "text/html"
                    }
                }
            );
        }
    }
};
