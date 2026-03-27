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
