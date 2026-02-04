import express from "express"; // web server routes
import axios from "axios"; // Spotify HTTP requests
import dotenv from "dotenv"; // loads .env to process.env
import cookieParser from "cookie-parser"; // lets you read cookies
import crypto from "crypto"; // Secure random and SHA256
import path from "path";
import { fileURLToPath } from "url";

dotenv.config(); // Read in secret data from .env

const app = express(); // App creation

app.use(cookieParser()); // Allows you to request cookie info
app.use(express.static("public")); // Simplifies: GET /index.html -> public/index.html

const __filename = fileURLToPath(import.meta.url); // /Users/jaden/project/server.js
const __dirname = path.dirname(__filename); // /Users/jaden/project

const { SPOTIFY_CLIENT_ID, SPOTIFY_CLIENT_SECRET, REDIRECT_URI } = process.env; // Load from process.env

// Used to add SecureRandom secret to URL to prove you're the original user
// https://accounts.spotify.com/authorize? + code_challenge=Ab-c_def...
// Mute complete code_challenge to access
function base64url (buffer){
    return buffer
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

// --- LOGIN AUTHENTIFICATION + HANDSHAKE---


