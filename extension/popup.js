document.addEventListener('DOMContentLoaded', () => {
    const urlBox = document.getElementById('current-url');
    const scanBtn = document.getElementById('scan-btn');
    const resultDiv = document.getElementById('result');
    const resStatus = document.getElementById('res-status');
    const resConf = document.getElementById('res-conf');
    const resExp = document.getElementById('res-exp');

    let currentTabUrl = '';

    // Get the current active tab's URL
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        currentTabUrl = tabs[0].url;
        // Truncate URL for display
        urlBox.textContent = currentTabUrl.length > 50 ? currentTabUrl.substring(0, 50) + "..." : currentTabUrl;
    });

    scanBtn.addEventListener('click', async () => {
        if (!currentTabUrl || currentTabUrl.startsWith('chrome://')) {
            alert("Cannot scan internal browser pages.");
            return;
        }

        scanBtn.textContent = "Scanning...";
        scanBtn.disabled = true;

        try {
            // Note: Make sure the local Flask server is running on port 5000
            const response = await fetch("http://127.0.0.1:5000/check-url", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: currentTabUrl })
            });

            const data = await response.json();
            
            resultDiv.style.display = "block";
            resultDiv.className = data.is_phishing ? 'danger' : 'safe';
            
            resStatus.textContent = data.result;
            resStatus.style.color = data.is_phishing ? "#ff3366" : "#00ff88";
            resConf.textContent = `Confidence: ${data.confidence}`;
            resExp.textContent = data.explanation;

        } catch (error) {
            resultDiv.style.display = "block";
            resStatus.textContent = "Error: Backend Not Reachable";
            resExp.textContent = "Please ensure the local Flask server is running on port 5000.";
        } finally {
            scanBtn.textContent = "Scan Current Page";
            scanBtn.disabled = false;
        }
    });
});
