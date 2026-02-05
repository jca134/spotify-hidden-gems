import express from "express"; // web server routes
import axios from "axios"; // Spotify HTTP requests
import dotenv from "dotenv"; // loads .env to process.env
import cookieParser from "cookie-parser"; // lets you read cookies
import crypto from "crypto"; // Secure random and SHA256
import path from "path";
import { fileURLToPath } from "url";
import res from "express/lib/response";

const STATE_BYTE_LENGTH = 16;
const VERIFY_BYTE_LENGTH = 32;
// Read in secret data from .env
dotenv.config();

// App creation
const app = express();

app.use(cookieParser()); // Allows you to request cookie info
app.use(express.static("public")); // Simplifies: GET /index.html -> /public/index.html

// Saving file name and directory of server.js
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const { SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, REDIRECT_URI } = process.env; // Load from process.env

// URL Format: https://accounts.spotify.com/authorize? + code_challenge=Ab-c_def...
// Mute complete code_challenge to access
function base64url (buffer){
    return buffer
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// --- LOGIN AUTHENTIFICATION + CRYPTOGRAPHY HANDSHAKE---
app.get("/login", async (req, res) => {
    const state = crypto.randomBytes(STATE_BYTE_LENGTH).toString("hex");
    const codeVerifier = base64url(crypto.randomBytes(VERIFY_BYTE_LENGTH));
    const codeChallenge = base64url(
        crypto.createHash("sha256").update(codeVerifier).digest()
    );

    // Stores to browser cookie and only the server (via HTTP requests)
    // can access info, not JavaScript
    res.cookie("spotify_auth_state", state, {httpOnly: true});
    res.cookie("spotify_code_verifier", codeVerifier, {httpOnly: true});

});