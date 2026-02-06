import express from "express"; // web server routes
import axios from "axios"; // Spotify HTTP requests
import dotenv from "dotenv"; // loads .env to process.env
import cookieParser from "cookie-parser"; // lets you read cookies
import crypto from "crypto"; // Secure random and SHA256
import path from "path";
import { fileURLToPath } from "url";

const STATE_BYTE_LENGTH = 16;
const VERIFY_BYTE_LENGTH = 32;
// Read in secret data from .env
dotenv.config();

// App creation
const app = express();

app.use(cookieParser()); // Allows you to request cookie info
app.use(express.static("public")); // Simplifies: GET /index.html -> /public/index.html

// Saving file name and directory of server.js
// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

const { SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, REDIRECT_URI } = process.env; // Load from process.env

// URL Format: https://accounts.spotify.com/authorize? + code_challenge=Ab-c_def...
// Mute complete code_challenge to access
function base64url(buffer) {
    return buffer
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// --- Login Authentification + Handshake---
app.get("/login", async (req, res) => {
    // PKCE
    const state = crypto.randomBytes(STATE_BYTE_LENGTH).toString("hex");
    const codeVerifier = base64url(crypto.randomBytes(VERIFY_BYTE_LENGTH));
    const codeChallenge = base64url(
        crypto.createHash("sha256").update(codeVerifier).digest()
    );

    // Stores to browser cookie and only the server (via HTTP requests)
    // can access info, not JavaScript

    const cookieOpts = {
        httpOnly: true,
        sameSite: "lax",
        secure: false // set true when using https in production
    };

    res.cookie("spotify_auth_state", state, cookieOpts);
    res.cookie("spotify_code_verifier", codeVerifier, { httpOnly: true });

    // Create req params
    const scope = "user-top-read"; // Request from Spotify
    const params = new URLSearchParams({
        response_type: "code", // Tells Spotify to return an authorization *code*
        client_id: SPOTIFY_CLIENT_ID,
        scope,
        redirect_uri: REDIRECT_URI, // Where Spotify sends the user after login
        state,
        code_challenge_method: "S256",
        code_challenge: codeChallenge
    });

    res.redirect("https://accounts.spotify.com/authorize?" + params.toString());
});

// --- CALLBACK: exchange code for access token ---
app.get("/callback", async (req, res) => {
    // Gets authentification code
    // Code makes it so data can't be accessed by others
    // State ensures callback query is the same one sent out
    const { code, state } = req.query;
    const storedState = req.cookies.spotify_auth_state;
    const codeVerifier = req.cookies.spotify_code_verifier;

    if (!state || state !== storedState) {
        return res.status(400).send("State mismatch. Try again.");
    }

    // PKCE established. Request for authorization_code
    try {
        const tokenRes = await axios.post(
            "https://accounts.spotify.com/api/token",
            new URLSearchParams({
                grant_type: "authorization_code",
                code,
                redirect_uri: REDIRECT_URI,
                client_id: SPOTIFY_CLIENT_ID,
                code_verifier: codeVerifier
            }),
            {
                headers: { "Content-Type": "application/x-www-form-urlencoded" }
            }
        );

        const { access_token, refresh_token } = tokenRes.data;

        // Store tokens in cookies
        res.cookie("spotify_access_token", access_token, { httpOnly: true });
        if (refresh_token) {
            res.cookie("spotify_refresh_token", refresh_token, { httpOnly: true });
        }

        res.redirect("/");
    } catch (err) {
        console.error(err?.response?.data || err.message);
        res.status(500).send("Token exchange failed.");
    }
});

// Helper: refresh token when needed
async function refreshAccessToken(req, res) {
    const refreshToken = req.cookies.spotify_refresh_token;
    if (!refreshToken) return null;

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
    res.cookie("spotify_access_token", access_token, { httpOnly: true });
    return access_token;
}

// --- API: Top Tracks ---
app.get("/api/top-tracks", async (req, res) => {
    const time_range = req.query.time_range || "short_term"; // short_term, medium_term, long_term
    const limit = Math.min(parseInt(req.query.limit || "20", 10), 50);

    let accessToken = req.cookies.spotify_access_token;
    if (!accessToken) return res.status(401).json({ error: "Not logged in" });

    try {
        const apiRes = await axios.get("https://api.spotify.com/v1/me/top/tracks", {
            headers: { Authorization: `Bearer ${accessToken}` },
            params: { time_range, limit }
        });
        res.json(apiRes.data);
    } catch (err) {
        if (err.response?.status === 401) {
            const newToken = await refreshAccessToken(req, res);

            if (!newToken) {
                return res.status(401).json({ error: "Session expired. Please log in again." });
            }

            const apiRes2 = await axios.get(
                "https://api.spotify.com/v1/me/top/tracks",
                {
                    headers: { Authorization: `Bearer ${newToken}` },
                    params: { time_range, limit }
                }
            );

            return res.json(apiRes2.data);
        }

        console.error(err?.response?.data || err.message);
        res.status(500).json({ error: "Spotify API call failed" });
    }
});

// --- LOGOUT ---
app.get("/logout", (req, res) => {
    res.clearCookie("spotify_access_token");
    res.clearCookie("spotify_refresh_token");
    res.clearCookie("spotify_auth_state");
    res.clearCookie("spotify_code_verifier");
    res.redirect("/");
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));