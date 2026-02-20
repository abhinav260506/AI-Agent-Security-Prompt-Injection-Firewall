console.log("Surgical-Guard Background Service Worker Loaded");

import { AnalysisEngine } from '../core/AnalysisEngine.js';

// Listen for messages from Content Script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    // HANDLER: Text Analysis
    if (request.type === 'ANALYZE_TEXT') {
        const textAsString = request.payload.text;
        const originUrl = sender.tab ? sender.tab.url : 'unknown';

        console.log(`Background: Analysis requested for ${originUrl} (${textAsString.length} chars)`);

        (async () => {
            try {
                // Perform Analysis (Now Async)
                const findings = await AnalysisEngine.analyze(textAsString);

                // Log if threats found
                if (findings.length > 0) {
                    console.warn(`Background: Detected ${findings.length} threats in content from ${originUrl}`);
                } else {
                    console.log("Background: Clean content.");
                }

                // Return results
                sendResponse({
                    status: 'SUCCESS',
                    findings: findings
                });

            } catch (error) {
                console.error("Background: Analysis failed", error);
                sendResponse({
                    status: 'ERROR',
                    message: error.message
                });
            }
        })();

        return true; // Keep channel open for async response
    }

    // HANDLER: Threat Logging
    if (request.type === 'THREATS_DETECTED') {
        const { count, matches, context } = request.payload;

        console.log(`Background: Logging ${count} threats from "${context.title}"`);

        // Update Badge
        chrome.action.setBadgeText({ text: '!' });
        chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });

        // Save to Activity Log
        chrome.storage.local.get(['activityLog'], (result) => {
            const logs = result.activityLog || [];

            const newEntry = {
                id: Date.now().toString(), // Simple ID
                timestamp: context.timestamp,
                title: context.title,
                url: context.url,
                threatCount: count,
                threatType: matches[0].type, // Log the primary threat type
                details: matches.map(m => m.subtype || m.type).join(', ')
            };

            // Prepend new log (Newest first)
            const updatedLogs = [newEntry, ...logs].slice(0, 100); // Keep last 100

            chrome.storage.local.set({ activityLog: updatedLogs }, () => {
                console.log("Background: Threat logged successfully.");
            });
        });

        return false; // Sync response is fine
    }
});
