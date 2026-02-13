# Spotify Top Tracks (Hidden Gems)

This is a tiny Express app that lets a user log in with Spotify and view their top tracks.

## Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Deploy (Render)

Set environment variables:

- `SPOTIFY_CLIENT_ID`
- `SPOTIFY_CLIENT_SECRET`
- `REDIRECT_URI` 
- `NODE_ENV=production`

Start command: `npm start`

## Debugging

- `GET /api/session` returns whether you appear logged in and what scopes Spotify said it granted (no tokens are exposed).
