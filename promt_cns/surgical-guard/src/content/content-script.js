import { Scanner } from '../core/Scanner';

console.log("Surgical-Guard: Firewall Active");

const scanner = new Scanner();

// Flag to prevent MutationObserver loop
let isSanitizing = false;

// --- UI SHIELD LOGIC ---
function createShield() {
    if (document.getElementById('surgical-guard-shield')) return;

    const shield = document.createElement('div');
    shield.id = 'surgical-guard-shield';
    shield.style.position = 'fixed';
    shield.style.top = '0';
    shield.style.left = '0';
    shield.style.width = '100vw';
    shield.style.height = '100vh';
    shield.style.backgroundColor = 'rgba(255, 255, 255, 0.98)';
    shield.style.zIndex = '2147483647'; // Max Z-Index
    shield.style.display = 'flex';
    shield.style.flexDirection = 'column';
    shield.style.alignItems = 'center';
    shield.style.justifyContent = 'center';
    shield.style.fontFamily = 'system-ui, -apple-system, sans-serif';
    shield.style.transition = 'opacity 0.3s ease';

    const logo = document.createElement('div');
    logo.innerText = '🛡️';
    logo.style.fontSize = '48px';
    logo.style.marginBottom = '20px';
    logo.style.animation = 'pulse 1.5s infinite';

    const text = document.createElement('div');
    text.innerText = 'Surgical-Guard Analyzing...';
    text.style.fontSize = '24px';
    text.style.fontWeight = '600';
    text.style.color = '#333';

    const subtext = document.createElement('div');
    subtext.innerText = 'Verifying content safety with AI';
    subtext.style.fontSize = '14px';
    subtext.style.color = '#666';
    subtext.style.marginTop = '8px';

    // Add CSS animation
    const style = document.createElement('style');
    style.innerHTML = `
        @keyframes pulse {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.1); opacity: 0.8; }
            100% { transform: scale(1); opacity: 1; }
        }
    `;
    document.head.appendChild(style);

    shield.appendChild(logo);
    shield.appendChild(text);
    shield.appendChild(subtext);
    document.body.appendChild(shield);

    // Hide scrollbars on body
    document.body.style.overflow = 'hidden';
}

function removeShield() {
    const shield = document.getElementById('surgical-guard-shield');
    if (shield) {
        shield.style.opacity = '0';
        setTimeout(() => {
            if (shield.parentNode) shield.parentNode.removeChild(shield);
            document.body.style.overflow = ''; // Restore scroll
        }, 300);
    }
}


async function runGuard(isSilent = false, specificNodes = null) {
    console.log(`Surgical-Guard: Scanning page... (Silent: ${isSilent})`);

    // 1. ACTIVATE SHIELD (Only if NOT silent)
    if (!isSilent) {
        createShield();
    }

    // Prevent observer from triggering while we scan/sanitize
    isSanitizing = true;

    // Scope detection:
    let targetNodes = [];

    if (specificNodes && specificNodes.length > 0) {
        // Targeted Scan (from MutationObserver)
        targetNodes = specificNodes;
    } else {
        // Full Page / Heuristic Scan (Manual or Initial Load)
        if (window.location.hostname.includes('mail.google.com')) {
            const emailBodies = document.querySelectorAll('.a3s, .gmail_quote, .im, h2.hP, span.gD, span.y2, span.bog');
            if (emailBodies.length > 0) {
                targetNodes = Array.from(emailBodies);
            }
        } else {
            targetNodes = [document.body];
        }
    }

    // Aggregate results from all targets
    const results = {
        matches: [],
        sanitizedCount: 0
    };

    try {
        // Process nodes
        for (const node of targetNodes) {
            // No DOM Evacuation needed. Scan the live node directly.
            // This prevents layout thrashing and broken event listeners.
            const nodeResults = await scanner.scanPage(node);
            results.matches.push(...nodeResults.matches);
            results.sanitizedCount += nodeResults.sanitizedCount;
        }

        if (results.matches.length > 0) {
            console.group("🚨 Surgical-Guard: Threats Detected! 🚨");
            console.warn(`Found ${results.matches.length} threats.`);

            // EXTRACT METADATA FOR LOGGING
            let pageTitle = document.title;
            // Gmail specific subject extraction
            if (window.location.hostname.includes('mail.google.com')) {
                const subjectElement = document.querySelector('h2.hP');
                if (subjectElement) {
                    pageTitle = subjectElement.innerText;
                }
            }

            const timestamp = new Date().toISOString();

            chrome.runtime.sendMessage({
                type: 'THREATS_DETECTED',
                payload: {
                    count: results.matches.length,
                    matches: results.matches,
                    context: {
                        title: pageTitle,
                        url: window.location.href,
                        timestamp: timestamp
                    }
                }
            });
            console.groupEnd();
        } else {
            console.log("Surgical-Guard: No threats detected.");
            chrome.runtime.sendMessage({
                type: 'SAFE',
                payload: { count: 0 }
            });
        }

    } catch (e) {
        console.error("Surgical-Guard: Scan error", e);
    } finally {
        // 2. DEACTIVATE SHIELD (Checking internal check inside removeShield is safe)
        if (!isSilent) {
            removeShield();
        }

        // Release lock
        setTimeout(() => {
            isSanitizing = false;
        }, 1000);
    }

    return results; // Return for popup handling
}

// Legacy applyTextSanitization function removed as it is now handled by Scanner + TextLocator.

// State to track if scanning has been activated for this page
let isScanningActive = false;

// Listen for manual trigger from Popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "MANUAL_SCAN") {
        console.log("Surgical-Guard: Manual scan requested.");
        isScanningActive = true; // ACTIVATE scanning for this session

        setTimeout(async () => {
            await runGuard(false); // Manual scan = Show Shield
            sendResponse({ status: 'COMPLETE' });
        }, 10);

        return true;
    }
});

// --- CLIPBOARD OUTPUT CONTROLLER ---
// Enforces that only visible text is copied, stripping hidden HTML vectors.
document.addEventListener('copy', (e) => {
    // Only intervene if we are actively protecting the page
    if (isScanningActive) {
        try {
            const selection = document.getSelection();
            if (!selection.rangeCount) return;

            e.preventDefault();
            const text = selection.toString();

            // We can add further sanitation here if needed, 
            // but text/plain is already a strong filter against HTML injection.
            e.clipboardData.setData('text/plain', text);

            console.log("Surgical-Guard Output Controller: Intercepted copy. Enforced safe text/plain.");
        } catch (err) {
            console.error("Surgical-Guard: Clipboard interception failed", err);
        }
    }
});

// Dynamic Content Observer (for Gmail/SPAs)
let timeoutId = null;
let pendingMutations = new Set(); // Store Nodes that changed

const observer = new MutationObserver((mutations) => {
    try {
        if (!isScanningActive || isSanitizing) return;

        let shouldDebounce = false;

        mutations.forEach(m => {
            if (!m.target) return;
            const target = m.target.nodeType === 1 ? m.target : m.target.parentElement;
            if (target && target.closest) {
                // If the mutation is within our targets, add the top-most target container to avoid duplicate nested scans
                const emailContainer = target.closest('.a3s, .gmail_quote, .im, .hP, .gD, .y2, .bog');
                if (emailContainer) {
                    pendingMutations.add(emailContainer);
                    shouldDebounce = true;
                } else if (!window.location.hostname.includes('mail.google.com')) {
                    pendingMutations.add(target);
                    shouldDebounce = true;
                }
            }
        });

        if (shouldDebounce) {
            if (timeoutId) clearTimeout(timeoutId);
            timeoutId = setTimeout(async () => {
                if (document.hidden || pendingMutations.size === 0) return;

                // Get nodes and clear the queue
                const nodesToScan = Array.from(pendingMutations);
                pendingMutations.clear();

                try {
                    await runGuard(true, nodesToScan);
                } catch (e) {
                    console.error("Surgical-Guard: Scan failed safely", e);
                }
            }, 500);
        }

    } catch (err) {
        console.error("Surgical-Guard: Critical Observer Error", err);
    }
});

try {
    // Observe ROOT because body might not exist at document_start
    const targetRoot = document.body || document.documentElement;
    observer.observe(targetRoot, {
        childList: true,
        subtree: true
    });
} catch (e) {
    console.warn("Surgical-Guard: Could not start observer", e);
}

// AUTO-RUN ON LOAD
setTimeout(() => {
    // Only auto-run if we haven't already (or if user wants aggressive mode)
    // For safety, we default to running.
    console.log("Surgical-Guard: Auto-starting protection...");
    isScanningActive = true;
    // Initial load = Show Shield (false)
    runGuard(false).catch(e => console.error("Surgical-Guard: Auto-run error", e));
}, 500); // Fast start (500ms)
