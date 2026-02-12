import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
dotenv.config();

// ---- Config ----
const {
    SPOTIFY_CLIENT_ID,
    SPOTIFY_CLIENT_SECRET,
    REDIRECT_URI,
    NODE_ENV,
} = process.env;

const isProd = NODE_ENV === "production";
const hasClientSecret = Boolean(SPOTIFY_CLIENT_SECRET);

// Spotify requires scopes to be space-separated.
// You can override via env if you add more endpoints later.
const REQUIRED_SCOPES = ["user-top-read"]; // needed for /v1/me/top/tracks
const SPOTIFY_SCOPES = (process.env.SPOTIFY_SCOPES || REQUIRED_SCOPES.join(" ")).trim();

// PKCE is only needed when you *don't* have a client secret (public client).
// If you do have a secret (server-side app), Spotify's standard Authorization Code Flow is simpler.
const USE_PKCE = !hasClientSecret;

// ---- App ----
const app = express();
app.set("trust proxy", 1); // important on Render / reverse proxies
app.use(cookieParser());
app.use(express.static("public"));

app.use(
    helmet({
        // keep defaults; avoids breaking OAuth redirects
        crossOriginResourcePolicy: { policy: "cross-origin" },
    })
);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
});

// ---- Cookies ----
const cookieBaseOpts = {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd,
    path: "/",
};

const authTempCookieOpts = {
    ...cookieBaseOpts,
    maxAge: 10 * 60 * 1000,
};

const accessCookieOpts = {
    ...cookieBaseOpts,
    maxAge: 60 * 60 * 1000,
};

const refreshCookieOpts = {
    ...cookieBaseOpts,
    maxAge: 30 * 24 * 60 * 60 * 1000,
};

function clearAuthCookies(res) {
    // Clearing cookies can be finicky if you ever changed Secure / SameSite.
    // So we clear using both secure=true and secure=false variants.
    const variants = [
        { ...cookieBaseOpts, secure: true },
        { ...cookieBaseOpts, secure: false },
    ];

    for (const opts of variants) {
        res.clearCookie("spotify_access_token", opts);
        res.clearCookie("spotify_refresh_token", opts);
        res.clearCookie("spotify_auth_state", opts);
        res.clearCookie("spotify_code_verifier", opts);
        res.clearCookie("spotify_scope", opts);
    }
}

// ---- Helpers ----
const STATE_BYTE_LENGTH = 16;
const VERIFY_BYTE_LENGTH = 32;

function base64url(buffer) {
    return buffer
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

function requiredEnvOk() {
    return Boolean(SPOTIFY_CLIENT_ID && REDIRECT_URI);
}

function authHeaderBasic(clientId, clientSecret) {
    const token = Buffer.from(`${clientId}:${clientSecret}`, "utf8").toString("base64");
    return `Basic ${token}`;
}

// ---- LOGIN ----
app.get("/login", authLimiter, (req, res) => {
    if (!requiredEnvOk()) {
        return res
            .status(500)
            .send("Server misconfigured: set SPOTIFY_CLIENT_ID and REDIRECT_URI.");
    }

    // Always blow away any old cookies first so you can't get stuck using an old token.
    clearAuthCookies(res);

    const state = crypto.randomBytes(STATE_BYTE_LENGTH).toString("hex");
    res.cookie("spotify_auth_state", state, authTempCookieOpts);

    const params = new URLSearchParams({
        response_type: "code",
        client_id: SPOTIFY_CLIENT_ID,
        scope: SPOTIFY_SCOPES,
        redirect_uri: REDIRECT_URI,
        state,
        // Forces Spotify to show the consent dialog (helps when scopes changed).
        // This is the #1 reason people keep getting "missing scope" even after re-login.
        show_dialog: "true",
    });

    if (USE_PKCE) {
        const codeVerifier = base64url(crypto.randomBytes(VERIFY_BYTE_LENGTH));
        const codeChallenge = base64url(
            crypto.createHash("sha256").update(codeVerifier).digest()
        );
        res.cookie("spotify_code_verifier", codeVerifier, authTempCookieOpts);
        params.set("code_challenge_method", "S256");
        params.set("code_challenge", codeChallenge);
    }

    res.redirect("https://accounts.spotify.com/authorize?" + params.toString());
});

// ---- CALLBACK ----
app.get("/callback", authLimiter, async (req, res) => {
    const code = typeof req.query.code === "string" ? req.query.code : null;
    const state = typeof req.query.state === "string" ? req.query.state : null;

    const storedState = req.cookies["spotify_auth_state"];
    const codeVerifier = req.cookies["spotify_code_verifier"];

    if (!code || !state || state !== storedState) {
        clearAuthCookies(res);
        return res.status(400).send("Invalid auth session. Hit /login again.");
    }

    try {
        let tokenRes;

        if (USE_PKCE) {
            if (!codeVerifier) {
                clearAuthCookies(res);
                return res.status(400).send("Missing PKCE verifier. Hit /login again.");
            }

            tokenRes = await axios.post(
                "https://accounts.spotify.com/api/token",
                new URLSearchParams({
                    grant_type: "authorization_code",
                    code,
                    redirect_uri: REDIRECT_URI,
                    client_id: SPOTIFY_CLIENT_ID,
                    code_verifier: codeVerifier,
                }),
                { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
            );
        } else {
            tokenRes = await axios.post(
                "https://accounts.spotify.com/api/token",
                new URLSearchParams({
                    grant_type: "authorization_code",
                    code,
                    redirect_uri: REDIRECT_URI,
                }),
                {
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        Authorization: authHeaderBasic(
                            SPOTIFY_CLIENT_ID,
                            SPOTIFY_CLIENT_SECRET
                        ),
                    },
                }
            );
        }

        const { access_token, refresh_token, scope } = tokenRes.data;

        res.cookie("spotify_access_token", access_token, accessCookieOpts);
        if (refresh_token) res.cookie("spotify_refresh_token", refresh_token, refreshCookieOpts);
        if (scope) res.cookie("spotify_scope", scope, refreshCookieOpts);

        // Clear one-time cookies
        res.clearCookie("spotify_auth_state", cookieBaseOpts);
        res.clearCookie("spotify_code_verifier", cookieBaseOpts);

        // Helpful server log: verify the scope Spotify actually granted.
        console.log("Spotify token granted scopes:", scope || "(none in response)");

        res.redirect("/");
    } catch (err) {
        console.error("Token exchange failed:", err?.response?.data || err.message);
        clearAuthCookies(res);
        res.status(500).send("Token exchange failed. Check server logs.");
    }
});

async function refreshAccessToken(req, res) {
    const refreshToken = req.cookies.spotify_refresh_token;
    if (!refreshToken) return null;

    try {
        let tokenRes;

        if (USE_PKCE) {
            tokenRes = await axios.post(
                "https://accounts.spotify.com/api/token",
                new URLSearchParams({
                    grant_type: "refresh_token",
                    refresh_token: refreshToken,
                    client_id: SPOTIFY_CLIENT_ID,
                }),
                { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
            );
        } else {
            tokenRes = await axios.post(
                "https://accounts.spotify.com/api/token",
                new URLSearchParams({
                    grant_type: "refresh_token",
                    refresh_token: refreshToken,
                }),
                {
                    headers: {
                        "Content-Type": "application/x-www-form-urlencoded",
                        Authorization: authHeaderBasic(
                            SPOTIFY_CLIENT_ID,
                            SPOTIFY_CLIENT_SECRET
                        ),
                    },
                }
            );
        }

        const { access_token } = tokenRes.data;
        res.cookie("spotify_access_token", access_token, accessCookieOpts);
        return access_token;
    } catch (err) {
        console.error("Refresh failed:", err?.response?.data || err.message);
        return null;
    }
}

function clampInt(v, min, max, fallback) {
    const n = parseInt(String(v), 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.max(min, Math.min(max, n));
}

// ---- API: Top Tracks (supports popularity filter + paging) ----
app.get("/api/top-tracks", async (req, res) => {
    const allowedRanges = new Set(["short_term", "medium_term", "long_term"]);
    const rangeParam = typeof req.query.time_range === "string" ? req.query.time_range : "";
    const time_range = allowedRanges.has(rangeParam) ? rangeParam : "short_term";

    const limit = clampInt(req.query.limit, 1, 50, 20);
    const maxPopularity = clampInt(req.query.max_popularity, 0, 100, 100);

    let accessToken = req.cookies["spotify_access_token"];
    if (!accessToken) return res.status(401).json({ error: "Not logged in" });

    const callSpotify = async (token, params) => {
        return axios.get("https://api.spotify.com/v1/me/top/tracks", {
            headers: { Authorization: `Bearer ${token}` },
            params,
        });
    };

    const run = async (token) => {
        // If maxPopularity is 100, no filtering needed.
        if (maxPopularity >= 100) {
            const apiRes = await callSpotify(token, { time_range, limit });
            return { ...apiRes.data, scanned: apiRes.data?.items?.length ?? 0 };
        }

        // Otherwise: page through results and filter.
        const pageSize = 50;
        const maxScanned = 500; // safety cap

        let offset = 0;
        let scanned = 0;
        const kept = [];
        let total = null;

        while (kept.length < limit && scanned < maxScanned) {
            const apiRes = await callSpotify(token, {
                time_range,
                limit: pageSize,
                offset,
            });

            const items = apiRes.data?.items || [];
            total = typeof apiRes.data?.total === "number" ? apiRes.data.total : total;

            scanned += items.length;

            for (const t of items) {
                if (typeof t?.popularity === "number" && t.popularity <= maxPopularity) {
                    kept.push(t);
                    if (kept.length >= limit) break;
                }
            }

            if (items.length < pageSize) break; // no more pages
            offset += pageSize;
            if (typeof total === "number" && offset >= total) break;
        }

        return {
            items: kept,
            scanned,
            total,
            time_range,
            max_popularity: maxPopularity,
        };
    };

    try {
        const payload = await run(accessToken);
        return res.json(payload);
    } catch (err) {
        const status = err?.response?.status;

        // Token expired or revoked
        if (status === 401) {
            const newToken = await refreshAccessToken(req, res);
            if (!newToken) {
                clearAuthCookies(res);
                return res.status(401).json({
                    error: "Session expired. Click Log in and try again.",
                });
            }

            try {
                const payload = await run(newToken);
                return res.json(payload);
            } catch (err2) {
                console.error(err2?.response?.data || err2.message);
                return res.status(500).json({ error: "Spotify API call failed after refresh" });
            }
        }

        // Insufficient scope (this is your current error)
        if (status === 403) {
            const spotifyMsg = err?.response?.data?.error?.message;
            const grantedScope = req.cookies["spotify_scope"];
            const hint =
                "Spotify rejected this request (403). Your token is missing user-top-read. " +
                "Go to /logout then /login again (consent screen will re-appear). " +
                "If it still fails, confirm you’re logging in with the same Spotify account and the same app client_id.";

            return res.status(403).json({
                error: hint,
                spotify_message: spotifyMsg,
                expected_scopes: REQUIRED_SCOPES,
                requested_scopes: SPOTIFY_SCOPES,
                token_scopes_seen: grantedScope || null,
            });
        }

        // Rate limit
        if (status === 429) {
            const retryAfter = err?.response?.headers?.["retry-after"];
            return res.status(429).json({
                error: "Spotify rate limited this server. Try again in a moment.",
                retry_after_seconds: retryAfter ? Number(retryAfter) : null,
            });
        }

        console.error(err?.response?.data || err.message);
        return res.status(500).json({ error: "Spotify API call failed" });
    }
});

// ---- LOGOUT ----
app.get("/logout", (req, res) => {
    clearAuthCookies(res);
    res.redirect("/");
});

// ---- Optional debug route (safe to keep; it exposes NO tokens) ----
app.get("/api/session", (req, res) => {
    const hasAccessToken = Boolean(req.cookies["spotify_access_token"]);
    res.json({
        logged_in: hasAccessToken,
        token_scopes_seen: req.cookies["spotify_scope"] || null,
        using_pkce: USE_PKCE,
        requested_scopes: SPOTIFY_SCOPES,
    });
});

// ---- Start ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`OAuth mode: ${USE_PKCE ? "PKCE (public)" : "Auth Code (confidential)"}`);
    if (!requiredEnvOk()) {
        console.warn(
            "⚠️ Missing SPOTIFY_CLIENT_ID or REDIRECT_URI. /login will fail until you set them."
        );
    }
});