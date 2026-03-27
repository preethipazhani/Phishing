// Background service worker for PhishGuard Local
// Can be expanded later for real-time background URL checking

chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishGuard Local Extension Installed.");
});
