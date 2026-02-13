// ======================= public/app.js (FULL COPY/PASTE) =======================
const tracksEl = document.getElementById("tracks");
const statusEl = document.getElementById("status");
const timeRangeEl = document.getElementById("timeRange");
const loadBtn = document.getElementById("loadBtn");

const popularitySliderEl = document.getElementById("popularitySlider");
const popularityInputEl = document.getElementById("popularityInput");
const popularityHintEl = document.getElementById("popularityHint");

// Small helper to avoid XSS if track names contain weird characters
function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (ch) => {
        const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
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

// Keep slider + number input synced (no clamping in JS)
function setPopularityUI(val) {
    const v = String(val ?? "");
    popularitySliderEl.value = v;
    popularityInputEl.value = v;
    popularityHintEl.innerHTML = `Showing tracks with popularity ≤ <strong>${escapeHtml(v)}</strong>`;
}

// init: default to 100 if empty
setPopularityUI(popularitySliderEl.value || popularityInputEl.value || 100);

popularitySliderEl.addEventListener("input", () => {
    setPopularityUI(popularitySliderEl.value);
});

popularityInputEl.addEventListener("input", () => {
    setPopularityUI(popularityInputEl.value);
});

function trackCard(track, i) {
    const img = track?.album?.images?.[1]?.url || track?.album?.images?.[0]?.url || "";

    const title = escapeHtml(track?.name ?? "Unknown track");
    const artists = escapeHtml((track?.artists ?? []).map((a) => a.name).join(", ") || "Unknown artist");

    // robust: handle number or numeric string
    const popularityNum = Number(track?.popularity);
    const popularity = Number.isFinite(popularityNum) ? popularityNum : "N/A";

    const url = track?.external_urls?.spotify || "#";

    return `
    <div class="card" role="article">
      ${img ? `<img src="${img}" alt="Album art for ${title}" loading="lazy" />` : ""}

      <div class="card-body">
        <div class="rank">#${i + 1}</div>

        <div class="card-title" title="${title}">
          ${title}
        </div>

        <div class="card-subtitle" title="${artists}">
          ${artists}
        </div>

        <div class="popularity">Popularity: ${popularity}</div>

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

        // No clampInt: rely on HTML min/max, but still convert to a number
        const maxPopularity = Number(popularityInputEl.value);

        const res = await fetch(
            `/api/top-tracks?time_range=${encodeURIComponent(timeRange)}&max_popularity=${encodeURIComponent(
                maxPopularity
            )}`,
            { headers: { Accept: "application/json" } }
        );

        const contentType = res.headers.get("content-type") || "";
        const data = contentType.includes("application/json") ? await res.json() : null;

        if (!res.ok) {
            if (res.status === 401) {
                setStatus("You’re not logged in. Click “Log in” at the top, then try again.");
                return;
            }
            const msg = (data && (data.error || data.message)) || `Request failed (${res.status})`;
            setStatus(msg);
            return;
        }

        const items = data?.items || [];
        const scanned = data?.scanned;

        if (items.length === 0) {
            setStatus(`No tracks found under popularity ≤ ${maxPopularity}. (Scanned ${scanned ?? "?"} tracks)`);
            return;
        }

        const shownRange = timeRange.replace("_", " ");
        setStatus(
            `Showing ${items.length} tracks (${shownRange}) with popularity ≤ ${maxPopularity}.` +
            (typeof scanned === "number" ? ` Scanned ${scanned} tracks.` : "")
        );

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

// Enter key on select triggers load
timeRangeEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadTopTracks();
});
