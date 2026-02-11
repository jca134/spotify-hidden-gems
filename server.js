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

const app = express();
app.use(cookieParser());
app.use(express.static("public"));

// ---- Minimal safe defaults ----
app.set("trust proxy", 1);

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

const isProd = process.env.NODE_ENV === "production";

const cookieBaseOpts = {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd,
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
                code_verifier: codeVerifier,
            }),
            {
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
            }
        );

        const { access_token, refresh_token } = tokenRes.data;

        res.cookie("spotify_access_token", access_token, accessCookieOpts);

        if (refresh_token) {
            res.cookie("spotify_refresh_token", refresh_token, refreshCookieOpts);
        }

        res.clearCookie("spotify_auth_state", cookieBaseOpts);
        res.clearCookie("spotify_code_verifier", cookieBaseOpts);

        res.redirect("/");
    } catch (err) {
        console.error(err?.response?.data || err.message);
        res.clearCookie("spotify_auth_state", cookieBaseOpts);
        res.clearCookie("spotify_code_verifier", cookieBaseOpts);
        res.status(500).send("Token exchange failed.");
    }
});

async function refreshAccessToken(req, res) {
    const refreshToken = req.cookies.spotify_refresh_token;
    if (!refreshToken) return null;

    const { SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET } = process.env;

    try {
        const tokenRes = await axios.post(
            "https://accounts.spotify.com/api/token",
            new URLSearchParams({
                grant_type: "refresh_token",
                refresh_token: refreshToken,
                client_id: SPOTIFY_CLIENT_ID,
                // If you are using a confidential client (server-side), keep this:
                client_secret: SPOTIFY_CLIENT_SECRET,
            }),
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );

        const { access_token } = tokenRes.data;
        res.cookie("spotify_access_token", access_token, accessCookieOpts);
        return access_token;
    } catch (err) {
        console.error("Refresh failed:", err?.response?.data || err.message);
        return null;
    }
}

// --- API: Top Tracks ---
app.get("/api/top-tracks", async (req, res) => {
    const allowedRanges = new Set(["short_term", "medium_term", "long_term"]);
    const rangeParam = typeof req.query.time_range === "string" ? req.query.time_range : "";
    const time_range = allowedRanges.has(rangeParam) ? rangeParam : "short_term";

    const rawLimit = typeof req.query.limit === "string" ? parseInt(req.query.limit, 10) : 20;
    const limit = Number.isFinite(rawLimit) ? Math.min(Math.max(rawLimit, 1), 50) : 20;

    let accessToken = req.cookies["spotify_access_token"];
    if (!accessToken) return res.status(401).json({ error: "Not logged in" });

    const callSpotify = async (token) => {
        return axios.get("https://api.spotify.com/v1/me/top/tracks", {
            headers: { Authorization: `Bearer ${token}` },
            params: { time_range, limit },
        });
    };

    try {
        const apiRes = await callSpotify(accessToken);
        return res.json(apiRes.data);
    } catch (err) {
        if (err.response?.status === 401) {
            const newToken = await refreshAccessToken(req, res);
            if (!newToken) {
                return res
                    .status(401)
                    .json({ error: "Session expired. Please log in again." });
            }

            const apiRes2 = await callSpotify(newToken);
            return res.json(apiRes2.data);
        }

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
app.listen(PORT, () => console.log(`Server running on port ${PORT}`)); // ✅ fixed