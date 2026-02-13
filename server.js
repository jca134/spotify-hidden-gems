// server.js
import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

dotenv.config();

// ---- Track Spotify rate-limit cooldown so we can report "time remaining" ----
const spotifyCooldownUntilByToken = new Map(); // accessToken -> epochMs

// ---- Small in-memory cache so changing the popularity slider doesn't hammer Spotify ----
const TOP_TRACKS_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const topTracksCache = new Map(); // cacheKey -> { ts: number, tracks: Array }

// ---- Helpers ----
function clampInt(n, lo, hi, fallback) {
    const x = Number(n);
    if (!Number.isFinite(x)) return fallback;
    return Math.min(hi, Math.max(lo, Math.trunc(x)));
}

function getCacheKey(req, time_range) {
    const refresh = req.cookies["spotify_refresh_token"];
    const access = req.cookies["spotify_access_token"];
    return `${refresh || access || "anon"}:${time_range}`;
}

function parseRetryAfterSeconds(err) {
    const raw = err?.response?.headers?.["retry-after"];
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? n : null;
}

function msToSecondsCeil(ms) {
    return Math.max(0, Math.ceil(ms / 1000));
}

function formatCountdown(totalSeconds) {
    const s = Math.max(0, Math.floor(totalSeconds));
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;

    if (h > 0) return `${h}h ${m}m ${sec}s`;
    return `${m}m ${sec}s`;
}

// IMPORTANT: This is the improved 403 message generator.
// Your /api/session shows the scope is fine, so 403 is usually dev-mode allowlist / quota mode / user access.
function friendly403(spotifyMsg, req) {
    const msg = spotifyMsg || "Forbidden";
    const looksLikeDevUserIssue =
        /user not (registered|approved)|developer dashboard|allowlist|access denied|insufficient client scope|forbidden/i.test(
            msg
        );

    const suffix = req?.cookies?.spotify_scope ? ` (token scopes seen: "${req.cookies.spotify_scope}")` : "";

    if (looksLikeDevUserIssue) {
        return (
            `Spotify returned 403: "${msg}". Your scopes look OK${suffix}. ` +
            `This is commonly caused by Spotify app quota/dev mode restrictions: ` +
            `Developer Dashboard → your app → Users and Access (User Management) → add your Spotify account email. ` +
            `Then remove the app under Spotify Account → Authorized apps, and /login again.`
        );
    }

    return (
        `Spotify returned 403: "${msg}". Your scopes look OK${suffix}. ` +
        `Try removing the app under Spotify Account → Authorized apps, then /login again. ` +
        `Also verify you're logging into the same Spotify account and using the same app client_id.`
    );
}

// ---- Config ----
const { SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, REDIRECT_URI, NODE_ENV } = process.env;

const isProd = NODE_ENV === "production";
const hasClientSecret = Boolean(SPOTIFY_CLIENT_SECRET);

// We always require user-top-read for /v1/me/top/tracks
const REQUIRED_SCOPES = ["user-top-read"];

// Merge required scopes with optional env scopes so env can't accidentally remove required scope.
const envScopesRaw = (process.env.SPOTIFY_SCOPES || "").trim();
const envScopes = envScopesRaw.length ? envScopesRaw.split(/[\s,]+/).filter(Boolean) : [];
const scopeSet = new Set([...envScopes, ...REQUIRED_SCOPES]);
const SPOTIFY_SCOPES = Array.from(scopeSet).join(" ");

// PKCE only needed when you *don't* have a client secret.
const USE_PKCE = !hasClientSecret;

// ---- App ----
const app = express();
app.set("trust proxy", 1);
app.use(cookieParser());
app.use(express.static("public"));

app.use(
    helmet({
        crossOriginResourcePolicy: { policy: "cross-origin" },
    })
);

// Rate limit auth endpoints to reduce abuse
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
});

// Limit API calls to avoid hammering Spotify
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
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
    // Clear both secure and non-secure variants to prevent “sticky” cookies after changing NODE_ENV
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

const STATE_BYTE_LENGTH = 16;
const VERIFY_BYTE_LENGTH = 32;

function base64url(buffer) {
    return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
        return res.status(500).send("Server misconfigured: set SPOTIFY_CLIENT_ID and REDIRECT_URI.");
    }

    // blow away old cookies so you don’t get stuck with stale tokens
    clearAuthCookies(res);

    const state = crypto.randomBytes(STATE_BYTE_LENGTH).toString("hex");
    res.cookie("spotify_auth_state", state, authTempCookieOpts);

    const params = new URLSearchParams({
        response_type: "code",
        client_id: SPOTIFY_CLIENT_ID,
        scope: SPOTIFY_SCOPES,
        redirect_uri: REDIRECT_URI,
        state,
        show_dialog: "true", // force consent screen (helps when scopes changed)
    });

    if (USE_PKCE) {
        const codeVerifier = base64url(crypto.randomBytes(VERIFY_BYTE_LENGTH));
        const codeChallenge = base64url(crypto.createHash("sha256").update(codeVerifier).digest());
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
                        Authorization: authHeaderBasic(SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET),
                    },
                }
            );
        }

        const { access_token, refresh_token, scope } = tokenRes.data;

        res.cookie("spotify_access_token", access_token, accessCookieOpts);
        if (refresh_token) res.cookie("spotify_refresh_token", refresh_token, refreshCookieOpts);
        if (scope) res.cookie("spotify_scope", scope, refreshCookieOpts);

        // clear one-time cookies
        res.clearCookie("spotify_auth_state", cookieBaseOpts);
        res.clearCookie("spotify_code_verifier", cookieBaseOpts);

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
                        Authorization: authHeaderBasic(SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET),
                    },
                }
            );
        }

        const { access_token, scope } = tokenRes.data;

        res.cookie("spotify_access_token", access_token, accessCookieOpts);
        if (scope) res.cookie("spotify_scope", scope, refreshCookieOpts);

        return access_token;
    } catch (err) {
        console.error("Refresh failed:", err?.response?.data || err.message);
        return null;
    }
}

// ---- Spotify API helpers ----
async function fetchUserTopTracks(token, { time_range, maxTracks }) {
    const pageSize = 50;
    let offset = 0;
    const out = [];

    while (out.length < maxTracks) {
        const limit = Math.min(pageSize, maxTracks - out.length);

        const apiRes = await axios.get("https://api.spotify.com/v1/me/top/tracks", {
            headers: { Authorization: `Bearer ${token}` },
            params: { time_range, limit, offset },
        });

        const items = apiRes.data?.items || [];
        out.push(...items);

        if (items.length < limit) break;
        offset += limit;

        const total = typeof apiRes.data?.total === "number" ? apiRes.data.total : null;
        if (typeof total === "number" && offset >= total) break;
    }

    return out;
}

async function fetchTracksByIds(token, ids) {
    const byId = new Map();

    for (let i = 0; i < ids.length; i += 50) {
        const chunk = ids.slice(i, i + 50);

        const apiRes = await axios.get("https://api.spotify.com/v1/tracks", {
            headers: { Authorization: `Bearer ${token}` },
            params: { ids: chunk.join(",") },
        });

        const tracks = apiRes.data?.tracks || [];
        for (const t of tracks) {
            if (t?.id) byId.set(t.id, t);
        }
    }

    return byId;
}

// ---- API: Top Tracks ----
app.get("/api/top-tracks", apiLimiter, async (req, res) => {
    const allowedRanges = new Set(["short_term", "medium_term", "long_term"]);
    const rangeParam = typeof req.query.time_range === "string" ? req.query.time_range : "";
    const time_range = allowedRanges.has(rangeParam) ? rangeParam : "short_term";

    const maxPopularity = clampInt(req.query.max_popularity, 0, 100, 100);
    const limit = 20;
    const maxScanned = 100;

    let accessToken = req.cookies["spotify_access_token"];
    if (!accessToken) return res.status(401).json({ error: "Not logged in" });

    const cacheKey = getCacheKey(req, time_range);
    const cached = topTracksCache.get(cacheKey);
    const cacheFresh = cached && Date.now() - cached.ts < TOP_TRACKS_CACHE_TTL_MS;

    const run = async (token) => {
        let tracksFull;
        let cache_used = false;

        if (cacheFresh) {
            tracksFull = cached.tracks;
            cache_used = true;
        } else {
            const cooldownUntil = spotifyCooldownUntilByToken.get(token);
            if (cooldownUntil && Date.now() < cooldownUntil) {
                const remainingSeconds = msToSecondsCeil(cooldownUntil - Date.now());
                const e = new Error("cooldown");
                e._cooldownSeconds = remainingSeconds;
                e._cooldownUntil = cooldownUntil;
                throw e;
            }

            const topItems = await fetchUserTopTracks(token, { time_range, maxTracks: maxScanned });
            const ids = topItems.map((t) => t?.id).filter(Boolean);

            const byId = await fetchTracksByIds(token, ids);

            tracksFull = topItems
                .map((t) => (t?.id ? byId.get(t.id) : null) || t)
                .filter(Boolean);

            topTracksCache.set(cacheKey, { ts: Date.now(), tracks: tracksFull });
        }

        const missingPopularity = tracksFull.filter((t) => typeof t?.popularity !== "number").length;

        const filtered = tracksFull.filter(
            (t) => typeof t?.popularity === "number" && t.popularity <= maxPopularity
        );

        const items = maxPopularity >= 100 ? tracksFull.slice(0, limit) : filtered.slice(0, limit);

        return {
            items,
            scanned: tracksFull.length,
            time_range,
            max_popularity: maxPopularity,
            missing_popularity: missingPopularity,
            cache_used,
        };
    };

    try {
        const payload = await run(accessToken);
        return res.json(payload);
    } catch (err) {
        // Manual cooldown
        if (err?._cooldownSeconds != null) {
            return res.status(429).json({
                error: `Rate limited. Try again in ${formatCountdown(err._cooldownSeconds)}.`,
                retry_after_seconds: err._cooldownSeconds,
                wait_until: new Date(err._cooldownUntil).toISOString(),
            });
        }

        const status = err?.response?.status;

        // Expired token -> refresh
        if (status === 401) {
            const newToken = await refreshAccessToken(req, res);
            if (!newToken) {
                clearAuthCookies(res);
                return res.status(401).json({ error: "Session expired. Click Log in and try again." });
            }

            try {
                const payload = await run(newToken);
                return res.json(payload);
            } catch (err2) {
                const status2 = err2?.response?.status;

                if (status2 === 429) {
                    const retryAfterSeconds = parseRetryAfterSeconds(err2);
                    if (retryAfterSeconds) {
                        const until = Date.now() + retryAfterSeconds * 1000;
                        spotifyCooldownUntilByToken.set(newToken, until);
                        return res.status(429).json({
                            error: `Rate limited. Try again in ${formatCountdown(retryAfterSeconds)}.`,
                            retry_after_seconds: retryAfterSeconds,
                            wait_until: new Date(until).toISOString(),
                        });
                    }
                    return res.status(429).json({
                        error: "Rate limited. Please wait a bit and try again.",
                        retry_after_seconds: null,
                        wait_until: null,
                    });
                }

                if (status2 === 403) {
                    const spotifyMsg = err2?.response?.data?.error?.message;
                    return res.status(403).json({
                        error: friendly403(spotifyMsg, req),
                        spotify_message: spotifyMsg || null,
                        expected_scopes: REQUIRED_SCOPES,
                        requested_scopes: SPOTIFY_SCOPES,
                        token_scopes_seen: req.cookies["spotify_scope"] || null,
                    });
                }

                console.error(err2?.response?.data || err2.message);
                return res.status(500).json({ error: "Spotify API call failed after refresh" });
            }
        }

        // 403: show real Spotify message + dev-mode allowlist hint if applicable
        if (status === 403) {
            const spotifyMsg = err?.response?.data?.error?.message;
            return res.status(403).json({
                error: friendly403(spotifyMsg, req),
                spotify_message: spotifyMsg || null,
                expected_scopes: REQUIRED_SCOPES,
                requested_scopes: SPOTIFY_SCOPES,
                token_scopes_seen: req.cookies["spotify_scope"] || null,
            });
        }

        // 429: countdown + store cooldown
        if (status === 429) {
            const retryAfterSeconds = parseRetryAfterSeconds(err);
            if (retryAfterSeconds) {
                const until = Date.now() + retryAfterSeconds * 1000;
                spotifyCooldownUntilByToken.set(accessToken, until);
                return res.status(429).json({
                    error: `Rate limited. Try again in ${formatCountdown(retryAfterSeconds)}.`,
                    retry_after_seconds: retryAfterSeconds,
                    wait_until: new Date(until).toISOString(),
                });
            }
            return res.status(429).json({
                error: "Rate limited. Please wait a bit and try again.",
                retry_after_seconds: null,
                wait_until: null,
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

// ---- Debug route (no tokens exposed) ----
app.get("/api/session", (req, res) => {
    const hasAccessToken = Boolean(req.cookies["spotify_access_token"]);
    res.json({
        logged_in: hasAccessToken,
        token_scopes_seen: req.cookies["spotify_scope"] || null,
        using_pkce: USE_PKCE,
        requested_scopes: SPOTIFY_SCOPES,
        client_id_suffix: SPOTIFY_CLIENT_ID ? SPOTIFY_CLIENT_ID.slice(-6) : null,
        redirect_uri: REDIRECT_URI || null,
    });
});

// ---- Start ----
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`OAuth mode: ${USE_PKCE ? "PKCE (public)" : "Auth Code (confidential)"}`);
    console.log(`Requested scopes: ${SPOTIFY_SCOPES}`);
    if (!requiredEnvOk()) {
        console.warn("⚠️ Missing SPOTIFY_CLIENT_ID or REDIRECT_URI. /login will fail until you set them.");
    }
});
