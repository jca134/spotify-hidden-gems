import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const STATE_BYTE_LENGTH = 16;
const VERIFY_BYTE_LENGTH = 32;

dotenv.config();

const {
    SPOTIFY_CLIENT_ID,
    SPOTIFY_CLIENT_SECRET,
    REDIRECT_URI,
    NODE_ENV,
} = process.env;

if (!SPOTIFY_CLIENT_ID) {
    throw new Error("Missing env var: SPOTIFY_CLIENT_ID");
}
if (!SPOTIFY_CLIENT_SECRET) {
    throw new Error("Missing env var: SPOTIFY_CLIENT_SECRET");
}
if (!REDIRECT_URI) {
    throw new Error("Missing env var: REDIRECT_URI (must exactly match Spotify dashboard Redirect URI)");
}

const app = express();
app.use(cookieParser());
app.use(express.static("public"));

// Render / proxies
app.set("trust proxy", 1);

app.use(
    helmet({
        crossOriginResourcePolicy: { policy: "cross-origin" },
    })
);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    standardHeaders: true,
    legacyHeaders: false,
});

// Detect HTTPS properly behind proxy (Render)
const isSecureRequest = (req) => {
    // req.secure works with trust proxy + https upstream
    if (req.secure) return true;
    const xfProto = req.get("x-forwarded-proto");
    return xfProto === "https";
};

const cookieBaseOpts = (req) => ({
    httpOnly: true,
    sameSite: "lax",
    secure: isSecureRequest(req), // ✅ important on Render
});

const authTempCookieOpts = (req) => ({
    ...cookieBaseOpts(req),
    maxAge: 10 * 60 * 1000,
});

const accessCookieOpts = (req) => ({
    ...cookieBaseOpts(req),
    maxAge: 60 * 60 * 1000,
});

const refreshCookieOpts = (req) => ({
    ...cookieBaseOpts(req),
    maxAge: 30 * 24 * 60 * 60 * 1000,
});

function base64url(buffer) {
    return buffer
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// Helpful debug endpoint (remove later if you want)
app.get("/api/debug-auth", (req, res) => {
    res.json({
        redirect_uri: REDIRECT_URI,
        has_access_cookie: Boolean(req.cookies["spotify_access_token"]),
        has_refresh_cookie: Boolean(req.cookies["spotify_refresh_token"]),
        has_state_cookie: Boolean(req.cookies["spotify_auth_state"]),
        has_verifier_cookie: Boolean(req.cookies["spotify_code_verifier"]),
        node_env: NODE_ENV,
        x_forwarded_proto: req.get("x-forwarded-proto") || null,
        req_secure: req.secure,
    });
});

// --- LOGIN: Authorization Code Flow + PKCE ---
app.get("/login", authLimiter, async (req, res) => {
    const state = crypto.randomBytes(STATE_BYTE_LENGTH).toString("hex");
    const codeVerifier = base64url(crypto.randomBytes(VERIFY_BYTE_LENGTH));
    const codeChallenge = base64url(
        crypto.createHash("sha256").update(codeVerifier).digest()
    );

    // ✅ cookie opts depend on request HTTPS
    res.cookie("spotify_auth_state", state, authTempCookieOpts(req));
    res.cookie("spotify_code_verifier", codeVerifier, authTempCookieOpts(req));

    const scope = "user-top-read";

    const params = new URLSearchParams({
        response_type: "code",
        client_id: SPOTIFY_CLIENT_ID,
        scope,
        redirect_uri: REDIRECT_URI,
        state,

        // ✅ forces Spotify to re-prompt and actually grant new scopes
        show_dialog: "true",

        code_challenge_method: "S256",
        code_challenge: codeChallenge,
    });

    res.redirect("https://accounts.spotify.com/authorize?" + params.toString());
});

// --- CALLBACK: exchange code for access token ---
app.get("/callback", authLimiter, async (req, res) => {
    const code = typeof req.query.code === "string" ? req.query.code : null;
    const state = typeof req.query.state === "string" ? req.query.state : null;

    const storedState = req.cookies["spotify_auth_state"];
    const codeVerifier = req.cookies["spotify_code_verifier"];

    if (!code || !state || state !== storedState || !codeVerifier) {
        res.clearCookie("spotify_auth_state", cookieBaseOpts(req));
        res.clearCookie("spotify_code_verifier", cookieBaseOpts(req));
        return res.status(400).send("Invalid auth session. Try again.");
    }

    try {
        const tokenRes = await axios.post(
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

        const { access_token, refresh_token } = tokenRes.data;

        res.cookie("spotify_access_token", access_token, accessCookieOpts(req));

        if (refresh_token) {
            res.cookie("spotify_refresh_token", refresh_token, refreshCookieOpts(req));
        }

        res.clearCookie("spotify_auth_state", cookieBaseOpts(req));
        res.clearCookie("spotify_code_verifier", cookieBaseOpts(req));

        res.redirect("/");
    } catch (err) {
        console.error("Token exchange failed:", err?.response?.data || err.message);
        res.clearCookie("spotify_auth_state", cookieBaseOpts(req));
        res.clearCookie("spotify_code_verifier", cookieBaseOpts(req));
        res.status(500).send("Token exchange failed.");
    }
});

async function refreshAccessToken(req, res) {
    const refreshToken = req.cookies.spotify_refresh_token;
    if (!refreshToken) return null;

    try {
        const tokenRes = await axios.post(
            "https://accounts.spotify.com/api/token",
            new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: refreshToken,
                client_id: SPOTIFY_CLIENT_ID,
                client_secret: SPOTIFY_CLIENT_SECRET,
            }),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        const { access_token } = tokenRes.data;
        res.cookie("spotify_access_token", access_token, accessCookieOpts(req));
        return access_token;
    } catch (err) {
        console.error("Refresh failed:", err?.response?.data || err.message);
        return null;
    }
}

// --- API: Top Tracks (scan up to 1000, return top 20 under popularity threshold) ---
app.get("/api/top-tracks", async (req, res) => {
    const allowedRanges = new Set(["short_term", "medium_term", "long_term"]);
    const rangeParam = typeof req.query.time_range === "string" ? req.query.time_range : "";
    const time_range = allowedRanges.has(rangeParam) ? rangeParam : "short_term";

    const rawMaxPopularity =
        typeof req.query.max_popularity === "string"
            ? parseInt(req.query.max_popularity, 10)
            : 100;

    const max_popularity = Number.isFinite(rawMaxPopularity)
        ? Math.min(Math.max(rawMaxPopularity, 0), 100)
        : 100;

    const MAX_SCAN = 1000; // ✅ your requirement
    const PAGE_SIZE = 50;
    const MAX_RETURN = 20;

    let accessToken = req.cookies["spotify_access_token"];
    if (!accessToken) return res.status(401).json({ error: "Not logged in" });

    const spotifyGet = async (url, params) => {
        const doReq = (token) =>
            axios.get(url, {
                headers: { Authorization: `Bearer ${token}` },
                params,
            });

        try {
            return await doReq(accessToken);
        } catch (err) {
            if (err.response?.status === 401) {
                const newToken = await refreshAccessToken(req, res);
                if (!newToken) throw err;
                accessToken = newToken;
                return await doReq(newToken);
            }
            throw err;
        }
    };

    const ensurePopularity = async (tracks) => {
        const missing = tracks.filter((t) => typeof t?.popularity !== "number" && t?.id);
        if (missing.length === 0) return tracks;

        const byId = new Map();
        for (let i = 0; i < missing.length; i += 50) {
            const chunk = missing.slice(i, i + 50);
            const ids = chunk.map((t) => t.id).join(",");
            const r = await spotifyGet("https://api.spotify.com/v1/tracks", { ids });
            for (const tr of r.data?.tracks || []) {
                if (tr?.id) byId.set(tr.id, tr);
            }
        }

        return tracks.map((t) => {
            if (typeof t?.popularity === "number") return t;
            const full = t?.id ? byId.get(t.id) : null;
            return full ? { ...t, popularity: full.popularity } : t;
        });
    };

    try {
        let offset = 0;
        let scanned = 0;
        const matches = [];

        while (scanned < MAX_SCAN && matches.length < MAX_RETURN) {
            const pageLimit = Math.min(PAGE_SIZE, MAX_SCAN - scanned);
            const pageRes = await spotifyGet("https://api.spotify.com/v1/me/top/tracks", {
                time_range,
                limit: pageLimit,
                offset,
            });

            let items = Array.isArray(pageRes.data?.items) ? pageRes.data.items : [];
            scanned += items.length;
            offset += items.length;

            items = await ensurePopularity(items);

            for (const t of items) {
                const pop = typeof t?.popularity === "number" ? t.popularity : null;
                if (pop !== null && pop <= max_popularity) {
                    matches.push(t);
                    if (matches.length >= MAX_RETURN) break;
                }
            }

            if (items.length < pageLimit) break;
        }

        return res.json({
            items: matches,
            scanned,
            max_popularity,
            time_range,
        });
    } catch (err) {
        const status = err?.response?.status;

        console.error("Spotify API error:", {
            status,
            data: err?.response?.data,
            message: err?.message,
        });

        if (status) {
            const spotifyMsg =
                err?.response?.data?.error?.message ||
                err?.response?.data?.message ||
                "Spotify API error";

            if (status === 403) {
                return res.status(403).json({
                    error:
                        "Spotify rejected this request (403). Your token is missing user-top-read. Hit /logout then /login again (or revoke the app in Spotify settings) and retry.",
                    spotify: spotifyMsg,
                });
            }

            if (status === 429) {
                return res.status(429).json({
                    error: "Rate limited by Spotify (429). Try again in a few seconds.",
                    spotify: spotifyMsg,
                });
            }

            return res.status(status).json({
                error: spotifyMsg,
                spotify: err?.response?.data,
            });
        }

        return res.status(500).json({
            error: "Server error contacting Spotify",
            details: err?.message,
        });
    }
});

// --- LOGOUT ---
app.get("/logout", (req, res) => {
    res.clearCookie("spotify_access_token", cookieBaseOpts(req));
    res.clearCookie("spotify_refresh_token", cookieBaseOpts(req));
    res.clearCookie("spotify_auth_state", cookieBaseOpts(req));
    res.clearCookie("spotify_code_verifier", cookieBaseOpts(req));
    res.redirect("/");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
