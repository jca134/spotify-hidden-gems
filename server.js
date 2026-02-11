import express from "express"; // web server routes
import axios from "axios"; // Spotify HTTP requests
import dotenv from "dotenv"; // loads .env to process.env
import cookieParser from "cookie-parser"; // lets you read cookies
import crypto from "crypto"; // Secure random and SHA256
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const STATE_BYTE_LENGTH = 16;
const VERIFY_BYTE_LENGTH = 32;

dotenv.config();

const app = express();
app.use(cookieParser());
app.use(express.static("public"));

// ---- Minimal safe defaults ----
app.set("trust proxy", 1); // important if behind a proxy (Render/Heroku/Nginx) for secure cookies + req.secure

app.use(
    helmet({
        // keep defaults; avoids breaking OAuth redirects
        crossOriginResourcePolicy: { policy: "cross-origin" }
    })
);

// Rate limit auth endpoints to reduce abuse
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60, // 60 requests / 15 min per IP
    standardHeaders: true,
    legacyHeaders: false
});

const isProd = process.env.NODE_ENV === "production";

// Centralized cookie options
const cookieBaseOpts = {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd // only send over HTTPS in production
};

// Short-lived cookies for PKCE/state
const authTempCookieOpts = {
    ...cookieBaseOpts,
    maxAge: 10 * 60 * 1000 // 10 minutes
};

// Access/refresh token cookie lifetimes
const accessCookieOpts = {
    ...cookieBaseOpts,
    maxAge: 60 * 60 * 1000 // 1 hour
};

const refreshCookieOpts = {
    ...cookieBaseOpts,
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
};

// URL Format: https://accounts.spotify.com/authorize? + code_challenge=Ab-c_def...
function base64url(buffer) {
    return buffer
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// --- LOGIN: Authorization Code Flow + PKCE ---
app.get("/login", authLimiter, async (req, res) => {
    const state = crypto.randomBytes(STATE_BYTE_LENGTH).toString("hex");
    const codeVerifier = base64url(crypto.randomBytes(VERIFY_BYTE_LENGTH));
    const codeChallenge = base64url(
        crypto.createHash("sha256").update(codeVerifier).digest()
    );

    // Store state + verifier in short-lived, httpOnly cookies
    res.cookie("spotify_auth_state", state, authTempCookieOpts);
    res.cookie("spotify_code_verifier", codeVerifier, authTempCookieOpts);

    const scope = "user-top-read";
    const params = new URLSearchParams({
        response_type: "code",
        client_id: process.env.SPOTIFY_CLIENT_ID,
        scope,
        redirect_uri: process.env.REDIRECT_URI,
        state,
        code_challenge_method: "S256",
        code_challenge: codeChallenge
    });

    res.redirect("https://accounts.spotify.com/authorize?" + params.toString());
});

// --- CALLBACK: exchange code for access token ---
app.get("/callback", authLimiter, async (req, res) => {
    const { code, state } = req.query;
    const storedState = req.cookies["spotify_auth_state"];
    const codeVerifier = req.cookies["spotify_code_verifier"];

    if (!code || !state || state !== storedState || !codeVerifier) {
        // Clear temp cookies to avoid weird retry/replay states
        res.clearCookie("spotify_auth_state", cookieBaseOpts);
        res.clearCookie("spotify_code_verifier", cookieBaseOpts);
        return res.status(400).send("Invalid auth session. Try again.");
    }

    try {
        const tokenRes = await axios.post(
            "https://accounts.spotify.com/api/token",
            new URLSearchParams({
                grant_type: "authorization_code",
                code,
                redirect_uri: process.env.REDIRECT_URI,
                client_id: process.env.SPOTIFY_CLIENT_ID,
                code_verifier: codeVerifier
            }),
            {
                headers: { "Content-Type": "application/x-www-form-urlencoded" }
            }
        );

        const { access_token, refresh_token } = tokenRes.data;

        // Store tokens in httpOnly cookies with reasonable expiration
        res.cookie("spotify_access_token", access_token, accessCookieOpts);

        if (refresh_token) {
            res.cookie("spotify_refresh_token", refresh_token, refreshCookieOpts);
        }

        // Clear state/verifier after successful use
        res.clearCookie("spotify_auth_state", cookieBaseOpts);
        res.clearCookie("spotify_code_verifier", cookieBaseOpts);

        res.redirect("/");
    } catch (err) {
        console.error(err?.response?.data || err.message);
        // Clear temp cookies on failure too
        res.clearCookie("spotify_auth_state", cookieBaseOpts);
        res.clearCookie("spotify_code_verifier", cookieBaseOpts);
        res.status(500).send("Token exchange failed.");
    }
});

// Helper: refresh token when needed
async function refreshAccessToken(req, res) {
    const refreshToken = req.cookies.spotify_refresh_token;
    if (!refreshToken) return null;

    const { SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET } = process.env;

    const tokenRes = await axios.post(
        "https://accounts.spotify.com/api/token",
        new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: SPOTIFY_CLIENT_ID,
            client_secret: SPOTIFY_CLIENT_SECRET
        }),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    const { access_token } = tokenRes.data;
    res.cookie("spotify_access_token", access_token, accessCookieOpts);
    return access_token;
}

// --- API: Top Tracks (filtered by popularity) ---
app.get("/api/top-tracks", async (req, res) => {
    const allowedRanges = new Set(["short_term", "medium_term", "long_term"]);
    const time_range = allowedRanges.has(req.query.time_range)
        ? req.query.time_range
        : "short_term";

    // user-set popularity threshold (0-100)
    const maxPopularityRaw = req.query.max_popularity;
    const max_popularity =
        maxPopularityRaw === undefined
            ? 100
            : Math.max(0, Math.min(100, parseInt(String(maxPopularityRaw), 10)));

    if (Number.isNaN(max_popularity)) {
        return res.status(400).json({ error: "max_popularity must be an integer 0-100" });
    }

    // requirements
    const TARGET_COUNT = 20;
    const PAGE_SIZE = 50; // Spotify max
    const MAX_SCAN = 1000; // at most 1000 songs searched
    const MAX_PAGES = Math.ceil(MAX_SCAN / PAGE_SIZE); // 20 pages

    let accessToken = req.cookies["spotify_access_token"];
    if (!accessToken) return res.status(401).json({ error: "Not logged in" });

    const filtered = [];
    let scanned = 0;

    // helper to fetch one page (and refresh once if needed)
    async function fetchTopTracksPage(offset) {
        try {
            return await axios.get("https://api.spotify.com/v1/me/top/tracks", {
                headers: { Authorization: `Bearer ${accessToken}` },
                params: { time_range, limit: PAGE_SIZE, offset }
            });
        } catch (err) {
            if (err.response?.status === 401) {
                const newToken = await refreshAccessToken(req, res);
                if (!newToken) return null;
                accessToken = newToken;

                // retry once with refreshed token
                return await axios.get("https://api.spotify.com/v1/me/top/tracks", {
                    headers: { Authorization: `Bearer ${accessToken}` },
                    params: { time_range, limit: PAGE_SIZE, offset }
                });
            }
            throw err;
        }
    }

    try {
        for (let page = 0; page < MAX_PAGES && filtered.length < TARGET_COUNT; page++) {
            const offset = page * PAGE_SIZE;
            const apiRes = await fetchTopTracksPage(offset);

            if (!apiRes) {
                return res.status(401).json({ error: "Session expired. Please log in again." });
            }

            const items = apiRes.data?.items || [];
            if (items.length === 0) break;

            scanned += items.length;

            for (const track of items) {
                if (filtered.length >= TARGET_COUNT) break;

                // track.popularity is 0-100
                if (typeof track?.popularity === "number" && track.popularity <= max_popularity) {
                    filtered.push(track);
                }
            }

            // stop early if Spotify has no more beyond this
            if (items.length < PAGE_SIZE) break;
        }

        return res.json({
            time_range,
            max_popularity,
            requested: TARGET_COUNT,
            returned: filtered.length,
            scanned, // how many tracks we looked at (<= 1000)
            items: filtered
        });
    } catch (err) {
        console.error(err?.response?.data || err.message);
        return res.status(500).json({ error: "Spotify API call failed" });
    }
});

// --- LOGOUT ---
app.get("/logout", (req, res) => {
    res.clearCookie("spotify_access_token", cookieBaseOpts);
    res.clearCookie("spotify_refresh_token", cookieBaseOpts);
    res.clearCookie("spotify_auth_state", cookieBaseOpts);
    res.clearCookie("spotify_code_verifier", cookieBaseOpts);
    res.redirect("/");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));