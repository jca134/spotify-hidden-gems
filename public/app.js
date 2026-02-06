// app.js

const tracksEl = document.getElementById("tracks");
const statusEl = document.getElementById("status");
const timeRangeEl = document.getElementById("timeRange");
const loadBtn = document.getElementById("loadBtn");

// Small helper to avoid XSS if track names contain weird characters
function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (ch) => {
        const map = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        };
        return map[ch] || ch;
    });
}

function setStatus(msg) {
    statusEl.textContent = msg || "";
}

function setLoading(isLoading) {
    loadBtn.disabled = isLoading;
    loadBtn.textContent = isLoading ? "Loading..." : "Load tracks";
}

function trackCard(track, i) {
    const img =
        track?.album?.images?.[1]?.url ||
        track?.album?.images?.[0]?.url ||
        "";

    const title = escapeHtml(track?.name ?? "Unknown track");
    const artists = escapeHtml(
        (track?.artists ?? []).map((a) => a.name).join(", ") || "Unknown artist"
    );

    const url = track?.external_urls?.spotify || "#";

    // This markup matches your CSS:
    // .card is a row, image 56x56, text grouped, etc.
    return `
    <div class="card" role="article">
      ${img ? `<img src="${img}" alt="Album art for ${title}" loading="lazy" />` : ""}

      <div class="card-body" style="display:flex; flex-direction:column; gap:4px; min-width:0;">
        <div class="rank">#${i + 1}</div>
        <div class="card-title" title="${title}" style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
          ${title}
        </div>
        <div class="card-subtitle" title="${artists}" style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
          ${artists}
        </div>
        <a class="link" target="_blank" rel="noopener noreferrer" href="${url}">
          Open in Spotify
        </a>
      </div>
    </div>
  `;
}

async function loadTopTracks() {
    try {
        setLoading(true);
        setStatus("Loading your top tracks…");
        tracksEl.innerHTML = "";

        const timeRange = timeRangeEl.value;

        const res = await fetch(
            `/api/top-tracks?time_range=${encodeURIComponent(timeRange)}&limit=20`,
            { headers: { Accept: "application/json" } }
        );

        // Try to parse JSON if possible
        const contentType = res.headers.get("content-type") || "";
        const data = contentType.includes("application/json") ? await res.json() : null;

        if (!res.ok) {
            // Common Spotify app case: user not logged in / token missing
            if (res.status === 401) {
                setStatus("You’re not logged in. Click “Log in” at the top, then try again.");
                return;
            }

            const msg =
                (data && (data.error || data.message)) ||
                `Request failed (${res.status})`;
            setStatus(msg);
            return;
        }

        const items = data?.items || [];

        if (items.length === 0) {
            setStatus(`No tracks found for ${timeRange}.`);
            return;
        }

        setStatus(`Showing top ${items.length} tracks (${timeRange.replace("_", " ")}).`);

        // Build HTML with correct index
        tracksEl.innerHTML = items.map((t, i) => trackCard(t, i)).join("");
    } catch (err) {
        console.error(err);
        setStatus("Network error. Is your server running and /api/top-tracks reachable?");
    } finally {
        setLoading(false);
    }
}

// Button click
loadBtn.addEventListener("click", loadTopTracks);

// Optional: press Enter while focused in the select to load
timeRangeEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadTopTracks();
});
