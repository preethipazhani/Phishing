const API_URL = "http://127.0.0.1:5000";

let stats = { scans: 0, threats: 0, safe: 0 };

// Auto-run fake logs to simulate a busy SOC Dashboard
const fakeLogs = [
    "External ping dropped from 104.28.x.x",
    "Incoming packet heuristic: Normal",
    "Analyzing DNS records for anomalies...",
    "User authentication attempt logged",
    "Safe request processed via proxy interface",
    "Updating threat definitions db_v2.1",
    "Port scan detected and blocked [IP Masked]"
];

function triggerFakeLog() {
    const randomLog = fakeLogs[Math.floor(Math.random() * fakeLogs.length)];
    addFeedLog(randomLog, 'info');
    setTimeout(triggerFakeLog, Math.random() * 8000 + 4000);
}

// Start fake activity
triggerFakeLog();

function addFeedLog(msg, type) {
    const feed = document.getElementById('feed-logs');
    const timeFrame = new Date().toTimeString().split(' ')[0];
    
    const div = document.createElement('div');
    div.className = `feed-log log-${type}`;
    div.innerHTML = `<span class="log-time">[${timeFrame}]</span> ${msg}`;
    
    feed.prepend(div);
    if(feed.children.length > 50) feed.lastChild.remove();
}

function switchTab(tabId) {
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    event.currentTarget.classList.add('active');
    
    document.querySelectorAll('.tab-pane').forEach(t => t.classList.add('hidden'));
    document.getElementById(tabId).classList.remove('hidden');
    
    document.getElementById('result-card').classList.add('hidden');
    addFeedLog(`Switched view to ${tabId.replace('tab-', '').toUpperCase()}`, 'info');
}

function setGlobalAlert(isDanger) {
    const txt = document.getElementById('global-text');
    const box = document.getElementById('global-status');
    const gaugeFill = document.getElementById('risk-gauge');
    const gaugeTxt = document.getElementById('risk-text');
    
    if(isDanger) {
        box.classList.add('status-danger');
        txt.innerText = "ALERT : CRITICAL THREAT DETECTED";
        gaugeFill.className = "gauge-fill high";
        gaugeTxt.innerText = "HIGH";
        gaugeTxt.className = "gauge-text high";
        
        // Flash entire screen
        const flash = document.getElementById('alert-flash');
        flash.classList.remove('hidden');
        setTimeout(() => flash.classList.add('hidden'), 500);
        
    } else {
        box.classList.remove('status-danger');
        txt.innerText = "SYSTEM LIVE : MONITORING INTEL";
        gaugeFill.className = "gauge-fill"; // default low
        gaugeTxt.innerText = "LOW";
        gaugeTxt.className = "gauge-text";
    }
}

async function runScan(type) {
    const inputEl = document.getElementById(`input-${type}`);
    const payload = inputEl.value.trim();
    
    if(!payload) {
        addFeedLog("Scan aborted - Empty payload", "warn");
        return;
    }

    // Hide result box, show generic overlay
    document.getElementById('result-card').classList.add('hidden');
    document.getElementById('scan-overlay').classList.remove('hidden');
    addFeedLog(`Intercepted ${type.toUpperCase()} payload. Initiating ML heuristics...`, "warn");

    const endpoint = type === 'url' ? '/check-url' : '/check-text';
    const bodyData = type === 'url' ? { url: payload } : { text: payload };

    try {
        // Artificial delay for UI effect
        await new Promise(r => setTimeout(r, 1500));
        addFeedLog(`Connecting to Scikit-Learn Engine...`, "info");
        await new Promise(r => setTimeout(r, 1000));

        const response = await fetch(`${API_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(bodyData)
        });

        const data = await response.json();
        
        document.getElementById('scan-overlay').classList.add('hidden');

        if (response.ok) {
            renderResult(data, payload);
        } else {
            addFeedLog(`API Error: ${data.error}`, "crit");
        }
    } catch (err) {
        document.getElementById('scan-overlay').classList.add('hidden');
        addFeedLog("Engine connection failed.", "crit");
    }
}

function renderResult(data, payload) {
    const card = document.getElementById('result-card');
    const statusTxt = document.getElementById('result-status');
    const circTxt = document.getElementById('conf-text');
    const circStroke = document.getElementById('conf-circle');
    const bar = document.getElementById('result-bar');
    const expl = document.getElementById('result-expl');
    
    card.classList.remove('hidden');
    stats.scans++;
    document.getElementById('wdgt-scans').innerText = stats.scans;

    const confNum = parseFloat(data.confidence);
    const dashArrayStr = `${confNum}, 100`;

    // Type out explanation
    expl.innerHTML = '';
    let i = 0;
    function typeWriter() {
        if(i < data.explanation.length) {
            expl.innerHTML += data.explanation.charAt(i);
            i++;
            setTimeout(typeWriter, 20);
        }
    }
    typeWriter();

    if(data.is_phishing) {
        stats.threats++;
        document.getElementById('wdgt-threats').innerText = stats.threats;
        
        card.style.borderColor = "var(--neon-red)";
        card.style.boxShadow = "0 0 20px rgba(255,0,60,0.3)";
        
        statusTxt.innerText = "PHISHING";
        statusTxt.className = "status-danger";
        
        circStroke.className.baseVal = "circle danger-stroke";
        bar.className = "progress-fill danger-glow";
        
        addFeedLog(`THREAT BLOCKED: ${payload.substring(0,25)}...`, "crit");
        setGlobalAlert(true);
        
    } else {
        stats.safe++;
        document.getElementById('wdgt-safe').innerText = stats.safe;
        
        card.style.borderColor = "var(--neon-green)";
        card.style.boxShadow = "0 0 20px rgba(0,255,68,0.3)";
        
        statusTxt.innerText = "SAFE";
        statusTxt.className = "status-safe";
        
        circStroke.className.baseVal = "circle safe-stroke";
        bar.className = "progress-fill safe-glow";
        
        addFeedLog(`Payload cleared via heuristic scan.`, "safe");
        setGlobalAlert(false);
    }

    // Trigger animations
    setTimeout(() => {
        circTxt.textContent = `${confNum}%`;
        circStroke.setAttribute("stroke-dasharray", dashArrayStr);
        bar.style.width = `${confNum}%`;
    }, 100);
}

function updateFileName() {
    const input = document.getElementById('input-eml');
    const display = document.getElementById('file-name-display');
    if (input.files && input.files.length > 0) {
        display.innerText = "SELECTED: " + input.files[0].name;
    } else {
        display.innerText = "Upload a .eml file exported from your email client";
    }
}

async function runEmailScan() {
    const fileInput = document.getElementById('input-eml');
    if (!fileInput.files || fileInput.files.length === 0) {
        addFeedLog("Scan aborted - No .eml file loaded", "warn");
        return;
    }

    const file = fileInput.files[0];
    
    document.getElementById('result-card').classList.add('hidden');
    
    const overlay = document.getElementById('scan-overlay');
    const overlayBlinkText = overlay.querySelector('.blink-text');
    const overlaySubText = overlay.querySelector('p');
    const origBlinkText = overlayBlinkText.innerText;
    const origSubText = overlaySubText.innerText;
    
    overlayBlinkText.innerText = "PARSING HEADERS...";
    overlaySubText.innerText = "Extracting forensic artifacts from .eml format";
    overlay.classList.remove('hidden');
    addFeedLog(`Intercepted EML payload. Extracting headers...`, "warn");

    const formData = new FormData();
    formData.append('file', file);

    try {
        await new Promise(r => setTimeout(r, 1500));
        addFeedLog(`Cross-referencing signatures...`, "info");
        await new Promise(r => setTimeout(r, 1000));

        const response = await fetch(`${API_URL}/analyze-email`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();
        
        overlay.classList.add('hidden');
        overlayBlinkText.innerText = origBlinkText;
        overlaySubText.innerText = origSubText;

        if (response.ok) {
            renderEmailResult(data, file.name);
        } else {
            addFeedLog(`API Error: ${data.error}`, "crit");
        }
    } catch (err) {
        overlay.classList.add('hidden');
        overlayBlinkText.innerText = origBlinkText;
        overlaySubText.innerText = origSubText;
        addFeedLog("Engine connection failed.", "crit");
    }
}

function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe.toString().replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

function renderEmailResult(data, filename) {
    const card = document.getElementById('result-card');
    const statusTxt = document.getElementById('result-status');
    const circTxt = document.getElementById('conf-text');
    const circStroke = document.getElementById('conf-circle');
    const bar = document.getElementById('result-bar');
    const expl = document.getElementById('result-expl');
    
    card.classList.remove('hidden');
    stats.scans++;
    document.getElementById('wdgt-scans').innerText = stats.scans;

    const confNum = parseFloat(data.confidence);
    const dashArrayStr = `${confNum}, 100`;
    
    let isDanger = data.result === "SUSPICIOUS" || data.result === "MALICIOUS";
    let isWarning = data.result === "LOW RISK";
    
    // Auth string builder
    let authBadges = "";
    if (data.security_checks) {
        const spfCol = data.security_checks.spf === 'pass' ? 'var(--neon-green)' : 'var(--neon-red)';
        const dkimCol = data.security_checks.dkim === 'present' ? 'var(--neon-green)' : 'var(--neon-red)';
        const dmarcCol = data.security_checks.dmarc === 'aligned' ? 'var(--neon-green)' : 'var(--neon-red)';
        authBadges = `
            <div style="margin-top: 10px; margin-bottom: 5px;">
                <span style="border: 1px solid ${spfCol}; color: ${spfCol}; padding: 2px 6px; font-size: 0.7rem; border-radius: 3px;">SPF: ${data.security_checks.spf.toUpperCase()}</span>
                <span style="border: 1px solid ${dkimCol}; color: ${dkimCol}; padding: 2px 6px; font-size: 0.7rem; border-radius: 3px; margin-left: 5px;">DKIM: ${data.security_checks.dkim.toUpperCase()}</span>
                <span style="border: 1px solid ${dmarcCol}; color: ${dmarcCol}; padding: 2px 6px; font-size: 0.7rem; border-radius: 3px; margin-left: 5px;">DMARC: ${data.security_checks.dmarc.toUpperCase()}</span>
            </div>
        `;
    }
    
    let domainSim = "";
    if (data.domain_analysis && data.domain_analysis.similar_to_brand) {
        domainSim = `<div style="color: var(--neon-red); font-size: 0.75rem; margin-top: 5px;">⚠️ TYPOSQUATTING ALERT: Domain resembles known brand "${data.domain_analysis.similar_to_brand}" (Distance: ${data.domain_analysis.distance})</div>`;
    }

    let headerHtml = `
        <div style="margin-bottom: 10px; font-weight: bold; color: var(--neon-cyan); letter-spacing: 1px;">
            RISK LEVEL: <span style="color: ${isDanger ? 'var(--neon-red)' : (isWarning ? 'var(--neon-yellow)' : 'var(--neon-green)')}">${data.risk_level}</span>
        </div>
        ${authBadges}
        <div class="header-grid">
            <div class="h-label">FROM:</div><div class="h-val ${data.flags.some(r => r.includes('From')) ? 'suspicious-highlight' : ''}">${escapeHtml(data.headers.from)}</div>
            <div class="h-label">TO:</div><div class="h-val">${escapeHtml(data.headers.to)}</div>
            <div class="h-label">SUBJECT:</div><div class="h-val ${data.flags.some(r => r.includes('Subject') || r.includes('keywords')) ? 'suspicious-highlight' : ''}">${escapeHtml(data.headers.subject)}</div>
            <div class="h-label">RETURN-PATH:</div><div class="h-val ${data.flags.some(r => r.includes('Return-Path')) ? 'suspicious-highlight' : ''}">${escapeHtml(data.headers.return_path)}</div>
        </div>
        ${domainSim}
        <div style="font-weight: bold; color: var(--neon-cyan); margin-top: 15px; margin-bottom: 5px;">FLAGS DETECTED:</div>
        <ul style="padding-left: 20px; font-size: 0.85rem; color: var(--text-main);">
            ${data.flags.map(f => `<li style="margin-bottom: 5px; ${f.includes('found.') ? 'color: var(--neon-green);' : 'color: var(--neon-red);'}">${escapeHtml(f)}</li>`).join('')}
        </ul>
    `;
    expl.innerHTML = headerHtml;

    if(isDanger) {
        stats.threats++;
        document.getElementById('wdgt-threats').innerText = stats.threats;
        
        card.style.borderColor = "var(--neon-red)";
        card.style.boxShadow = "0 0 20px rgba(255,0,60,0.3)";
        
        statusTxt.innerText = data.result.toUpperCase();
        statusTxt.className = "status-danger";
        statusTxt.style.color = "var(--neon-red)";
        statusTxt.style.textShadow = "0 0 20px var(--neon-red)";
        
        circStroke.className.baseVal = "circle danger-stroke";
        bar.className = "progress-fill danger-glow";
        
        addFeedLog(`THREAT CAUGHT: ${filename}`, "crit");
        setGlobalAlert(true);
        
    } else if(isWarning) {
        stats.scans++; // Tracked as normal scan
        card.style.borderColor = "var(--neon-yellow)";
        card.style.boxShadow = "0 0 20px rgba(255,234,0,0.3)";
        
        statusTxt.innerText = "LOW RISK";
        statusTxt.className = "";
        statusTxt.style.color = "var(--neon-yellow)";
        statusTxt.style.textShadow = "0 0 20px var(--neon-yellow)";
        
        circStroke.className.baseVal = "circle warn-stroke"; // fallback to original class or new
        bar.className = "progress-fill warn-glow"; // Needs CSS definitions later
        
        addFeedLog(`Heuristic Warning on ${filename}`, "warn");
        setGlobalAlert(false);
    } else {
        stats.safe++;
        document.getElementById('wdgt-safe').innerText = stats.safe;
        
        card.style.borderColor = "var(--neon-green)";
        card.style.boxShadow = "0 0 20px rgba(0,255,68,0.3)";
        
        statusTxt.innerText = "SAFE";
        statusTxt.className = "status-safe";
        statusTxt.style.color = "var(--neon-green)";
        statusTxt.style.textShadow = "0 0 20px var(--neon-green)";
        
        circStroke.className.baseVal = "circle safe-stroke";
        bar.className = "progress-fill safe-glow";
        
        addFeedLog(`Email analysis clean.`, "safe");
        setGlobalAlert(false);
    }

    setTimeout(() => {
        circTxt.textContent = `${confNum}%`;
        circStroke.setAttribute("stroke-dasharray", dashArrayStr);
        bar.style.width = `${confNum}%`;
    }, 100);
}

// Adding Drag and Drop support
document.addEventListener('DOMContentLoaded', () => {
    const uploadArea = document.querySelector('.upload-area');
    const inputEml = document.getElementById('input-eml');
    if(uploadArea && inputEml) {
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--neon-cyan)';
            uploadArea.style.boxShadow = '0 0 20px rgba(0,255,204,0.5)';
        });
        uploadArea.addEventListener('dragleave', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--neon-cyan)';
            uploadArea.style.boxShadow = 'none';
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.style.borderColor = 'var(--neon-cyan)';
            uploadArea.style.boxShadow = 'none';
            if (e.dataTransfer.files.length > 0) {
                inputEml.files = e.dataTransfer.files;
                updateFileName();
            }
        });
    }
});
