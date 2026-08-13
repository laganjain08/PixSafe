
// ============================================================
//  PixSafe — scan.js  (Improved)
// ============================================================

let history = JSON.parse(localStorage.getItem('pixsafe_history')) || [];
let stats = JSON.parse(localStorage.getItem('pixsafe_stats')) || { total: 0, safe: 0, harmful: 0 };

// Stores base64 + mime of current image so we can send it to backend
let currentImageData = null;

const SCAN_STAGES = [
    "Initializing Neural Engines...",
    "Extracting Metadata Headers...",
    "Running Heuristic Analysis...",
    "Querying AI Vision Model...",
    "Finalizing Threat Assessment..."
];

window.onload = () => {
    updateStatsUI();
    renderHistory();
};

// ============================================================
//  TAB SWITCHING
// ============================================================
function switchTab(type) {
    document.querySelectorAll('.scan-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.scan-pane').forEach(p => p.classList.remove('active'));

    if (type === 'url') {
        document.getElementById('tab-url').classList.add('active');
        document.getElementById('pane-url').classList.add('active');
    } else {
        document.getElementById('tab-img').classList.add('active');
        document.getElementById('pane-image').classList.add('active');
    }
}

// ============================================================
//  FILE HANDLING — now reads base64 for AI analysis
// ============================================================
function handleDrag(e) {
    e.preventDefault();
    document.getElementById('dropZone').classList.add('dragover');
}

function handleDragLeave(e) {
    e.preventDefault();
    document.getElementById('dropZone').classList.remove('dragover');
}

function handleDrop(e) {
    e.preventDefault();
    document.getElementById('dropZone').classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    handleFile(file);
}

function handleFile(file) {
    if (!file || !file.type.startsWith('image/')) return;

    // Size guard — 10MB max (Claude Vision limit)
    if (file.size > 10 * 1024 * 1024) {
        showFileError('File too large (max 10MB for AI analysis).');
        return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
        const dataURL = e.target.result;

        // Save for backend — split off the "data:image/png;base64," prefix
        const [meta, base64] = dataURL.split(',');
        const mimeType = meta.match(/:(.*?);/)[1];

        currentImageData = { base64, mimeType, fileName: file.name, fileSize: file.size };

        // Show preview
        const preview = document.getElementById('previewImg');
        preview.src = dataURL;
        preview.style.display = 'block';

        document.querySelector('.drop-icon').style.display = 'none';
        document.querySelector('.drop-text').style.display = 'none';

        // Show file info badge
        const sizeKB = (file.size / 1024).toFixed(1);
        showFileBadge(file.name, sizeKB);

        document.getElementById('imgScanBtn').disabled = false;
    };
    reader.readAsDataURL(file);
}

function showFileBadge(name, sizeKB) {
    let badge = document.getElementById('fileBadge');
    if (!badge) {
        badge = document.createElement('div');
        badge.id = 'fileBadge';
        badge.style.cssText = `
            margin-top: 8px;
            padding: 6px 12px;
            background: rgba(16,185,129,0.1);
            border: 1px solid rgba(16,185,129,0.3);
            border-radius: 6px;
            font-size: 0.78rem;
            color: #10b981;
            text-align: center;
        `;
        document.getElementById('dropZone').after(badge);
    }
    badge.textContent = `📎 ${name} · ${sizeKB} KB · Ready for AI scan`;
}

function showFileError(msg) {
    let errEl = document.getElementById('fileError');
    if (!errEl) {
        errEl = document.createElement('div');
        errEl.id = 'fileError';
        errEl.style.cssText = `
            margin-top: 8px; padding: 8px 12px;
            background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3);
            border-radius: 6px; font-size: 0.8rem; color: #ef4444; text-align: center;
        `;
        document.getElementById('dropZone').after(errEl);
    }
    errEl.textContent = '⚠️ ' + msg;
}

// ============================================================
//  SCAN STAGE ANIMATION
// ============================================================
async function runAnalysisAnimation(isImageScan = false) {
    const loaderText = document.querySelector('.loader span');
    const stages = isImageScan ? SCAN_STAGES : SCAN_STAGES.slice(0, -2).concat(["Finalizing Threat Assessment..."]);

    for (const stage of stages) {
        if (loaderText) loaderText.innerText = stage;
        await new Promise(r => setTimeout(r, isImageScan ? 700 : 500));
    }
}

// ============================================================
//  URL SCANNER
// ============================================================
async function scanURL() {
    const urlInput = document.getElementById('urlInput').value.trim();
    if (!urlInput) return alert('Please enter a URL');

    try {
        let normalizedUrl = urlInput.trim();
        if (/^www\./i.test(normalizedUrl)) {
            normalizedUrl = 'https://' + normalizedUrl;
        }

        const parsed = new URL(normalizedUrl);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return alert('Only http:// and https:// URLs are supported.');
        }

        // Use normalizedUrl going forward instead of urlInput
    } catch (e) {
        return alert('That is not a valid URL. Example: https://example.com or www.example.com');
    }


    toggleLoading(true);
    runAnalysisAnimation(false); // Don't await — run in parallel

    try {
        const response = await fetch('https://pixsafe.onrender.com/api/scan-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });

        if (!response.ok) throw new Error(`Server error: ${response.status}`);

        const data = await response.json();

        const result = {
            target: data.url,
            type: 'URL',
            verdict: data.verdict,
            score: data.score,
            reasons: data.reasons || [],
            date: new Date(data.timestamp || Date.now()).toLocaleString()
        };

        displayResult(result);
        saveScan(result);

    } catch (error) {
        handleSystemError(error);
    } finally {
        toggleLoading(false);
    }
}

// ============================================================
//  IMAGE SCANNER — now sends real base64 to backend for AI
// ============================================================
async function scanImage() {
    if (!currentImageData) return alert('Please upload an image first!');

    toggleLoading(true, true);
    runAnalysisAnimation(true); // Don't await — runs in parallel with fetch

    try {
        const response = await fetch('https://pixsafe.onrender.com/api/scan-image', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                fileName: currentImageData.fileName,
                fileSize: currentImageData.fileSize,
                base64Image: currentImageData.base64,       // ← NEW: actual image data
                mimeType: currentImageData.mimeType      // ← NEW: e.g. "image/png"
            })
        });

        if (!response.ok) throw new Error(`Server error: ${response.status}`);

        const data = await response.json();

        const result = {
            target: currentImageData.fileName,
            type: 'IMAGE',
            verdict: data.verdict,
            score: data.score,
            reasons: data.reasons || [],
            date: new Date(data.timestamp || Date.now()).toLocaleString()
        };

        displayResult(result);
        saveScan(result);

    } catch (error) {
        handleSystemError(error);
    } finally {
        toggleLoading(false);
    }
}

// ============================================================
//  UI HELPERS
// ============================================================

function toggleLoading(isLoading, isAI = false) {
    document.getElementById('loader').classList.toggle('hidden', !isLoading);

    if (isLoading) {
        document.getElementById('resultCard').style.display = 'none';
        document.getElementById('detailsGrid').innerHTML = '';

        // Show AI badge if using Claude Vision
        if (isAI) {
            const loaderText = document.querySelector('.loader span');
            const aiBadge = document.createElement('div');
            aiBadge.id = 'aiBadge';
            aiBadge.style.cssText = `
                font-size: 0.7rem; color: #818cf8;
                margin-top: 4px; letter-spacing: 1px;
            `;
            aiBadge.textContent = '⚡ SCAN VISION ACTIVE';
            if (!document.getElementById('aiBadge')) {
                loaderText?.parentNode.appendChild(aiBadge);
            }
        }
    } else {
        document.getElementById('aiBadge')?.remove();
    }
}

function displayResult(res) {
    const card = document.getElementById('resultCard');
    const label = document.getElementById('verdictLabel');
    const icon = document.getElementById('verdictIcon');
    const bar = document.getElementById('scoreBar');
    const detailsGrid = document.getElementById('detailsGrid');

    card.style.display = 'block';
    card.className = `result-card ${res.verdict.toLowerCase()}`;

    label.innerText = res.verdict;
    label.className = `verdict-label ${res.verdict.toLowerCase()}`;
    icon.innerText = res.verdict === 'SAFE' ? '✅' : '🚫';
    const badge = document.getElementById('verdictBadge');
    badge.innerText = res.verdict === 'SAFE' ? 'Safe' : 'Danger';
    badge.className = `verdict-badge ${res.verdict.toLowerCase()}`;

    bar.style.width = res.score + '%';
    bar.style.backgroundColor = res.verdict === 'SAFE' ? '#10b981' : '#ef4444';
    bar.style.transition = 'width 0.8s ease';

    // Analysis summary text
    document.getElementById('analysisText').innerText = res.verdict === 'SAFE'
        ? `AI Insight: Scanned ${res.type.toLowerCase()} passed all ${res.reasons.length} checks. No threats found.`
        : `Security Alert: ${res.score}% threat confidence. ${res.type} flagged by AI analysis.`;

    // Severity colour coding for log chips
    const severityColours = {
        '[CRITICAL]': '#ef4444',
        '[HIGH]': '#f97316',
        '[MEDIUM]': '#eab308',
        '[LOW]': '#6b7280',
        '[AI]': '#818cf8',
        '[INFO]': '#60a5fa',
        '[SAFE]': '#10b981',
    };

    if (res.reasons?.length > 0) {
        detailsGrid.innerHTML = res.reasons.map(reason => {
            const tag = Object.keys(severityColours).find(k => reason.startsWith(k)) || '';
            const color = severityColours[tag] || '#888';
            const text = tag ? reason.slice(tag.length).trim() : reason;

            return `
                <div class="detail-chip" style="border-left: 3px solid ${color}; padding-left: 10px;">
                    ${tag ? `<span style="color:${color}; font-weight:600; margin-right:6px; font-size:0.72rem;">${tag}</span>` : ''}
                    <span>${text}</span>
                </div>
            `;
        }).join('');
    }
}

// ============================================================
//  PERSISTENCE
// ============================================================

function saveScan(res) {
    history.unshift(res);
    if (history.length > 10) history.pop();

    stats.total++;
    if (res.verdict === 'SAFE') stats.safe++; else stats.harmful++;

    localStorage.setItem('pixsafe_history', JSON.stringify(history));
    localStorage.setItem('pixsafe_stats', JSON.stringify(stats));

    updateStatsUI();
    renderHistory();
}

function updateStatsUI() {
    document.getElementById('statTotal').innerText = stats.total;
    document.getElementById('statSafe').innerText = stats.safe;
    document.getElementById('statDanger').innerText = stats.harmful;
}

function renderHistory() {
    const list = document.getElementById('historyList');

    if (history.length === 0) {
        list.innerHTML = '<div class="history-empty">Neural database empty. Start a scan above.</div>';
        return;
    }

    list.innerHTML = history.map(item => {
        const name = item.target.length > 35
            ? item.target.substring(0, 32) + '...'
            : item.target;

        const scoreBar = item.score !== undefined
            ? `<div style="
                height:3px; width:100%; background:#1f2937; border-radius:2px; margin-top:4px;
               ">
                <div style="
                    height:3px;
                    width:${item.score}%;
                    background: ${item.verdict === 'SAFE' ? '#10b981' : '#ef4444'};
                    border-radius:2px;
                "></div>
               </div>`
            : '';

        return `
            <div class="history-item">
                <div style="flex:1; min-width:0;">
                    <strong>${item.type}:</strong>
                    <span title="${item.target}">${name}</span>
                    <div style="font-size:0.75rem; color:#888; margin-top:2px;">${item.date}</div>
                    ${scoreBar}
                </div>
                <span class="history-badge ${item.verdict.toLowerCase()}" style="flex-shrink:0;">
                    ${item.verdict}
                </span>
            </div>
        `;
    }).join('');
}

function handleSystemError(error) {
    console.error('Connection Error:', error);

    // Show inline error instead of alert
    const card = document.getElementById('resultCard');
    card.style.display = 'block';
    card.className = 'result-card danger';
    document.getElementById('verdictLabel').innerText = 'ERROR';
    document.getElementById('verdictIcon').innerText = '⚠️';
    document.getElementById('scoreBar').style.width = '0%';
    document.getElementById('analysisText').innerText =
        'Could not connect to backend. Make sure "node server.js" is running on port 3000. ' +
        'If using Claude Vision, ensure ANTHROPIC_API_KEY is set.';
    document.getElementById('detailsGrid').innerHTML = `
        <div class="detail-chip" style="border-left: 3px solid #ef4444; padding-left:10px;">
            <span style="color:#ef4444; font-weight:600; font-size:0.72rem;">[ERROR]</span>
            <span>${error.message}</span>
        </div>
    `;
}

function clearHistory() {
    if (confirm('Permanently wipe all security logs?')) {
        history = [];
        stats = { total: 0, safe: 0, harmful: 0 };
        localStorage.clear();
        updateStatsUI();
        renderHistory();
    }
}
