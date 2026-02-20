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


async function runGuard(isSilent = false) {
    console.log(`Surgical-Guard: Scanning page... (Silent: ${isSilent})`);

    // 1. ACTIVATE SHIELD (Only if NOT silent)
    if (!isSilent) {
        createShield();
    }

    // Prevent observer from triggering while we scan/sanitize
    isSanitizing = true;

    // Scope detection:
    let targetNodes = [];

    // Gmail detection (heuristic)
    if (window.location.hostname.includes('mail.google.com')) {
        // Target: 
        // 1. Read Mode (.a3s)
        // 2. Write Mode Quoted Text (.gmail_quote, .im)
        // 3. Headers: Subject (h2.hP) & Sender (span.gD)
        // 4. Inbox: Snippet (span.y2) & Subject (span.bog)
        const emailBodies = document.querySelectorAll('.a3s, .gmail_quote, .im, h2.hP, span.gD, span.y2, span.bog');
        if (emailBodies.length > 0) {
            targetNodes = Array.from(emailBodies);
        }
    } else {
        targetNodes = [document.body];
    }

    // Aggregate results from all targets
    const results = {
        matches: [],
        sanitizedCount: 0
    };

    try {
        // Process nodes
        for (const node of targetNodes) {
            // EVACUATION: Physically remove content so AI cannot see it.
            // We use a DocumentFragment to move nodes out of the live DOM.
            const originalFragment = document.createDocumentFragment();

            // Move children (Preserving event listeners/state)
            // If node is body, be careful not to remove our own Shield!
            const children = Array.from(node.childNodes);
            for (const child of children) {
                // Skip the Shield if it's in the body
                if (child.id === 'surgical-guard-shield') continue;
                originalFragment.appendChild(child);
            }

            // Show Placeholder in the live DOM (so user knows what's happening)
            const placeholder = document.createElement('div');
            placeholder.className = 'surgical-guard-placeholder';
            placeholder.innerText = '🛡️ Surgical-Guard: Analyzing content...';
            placeholder.style.cssText = 'padding: 20px; color: #666; font-family: sans-serif; background: #f9f9f9; border: 1px dashed #ccc; margin: 10px; border-radius: 8px; text-align: center;';
            node.appendChild(placeholder);

            // Create a detached wrapper for scanning (Scanner needs an Element, not Fragment)
            const detachedWrapper = document.createElement('div');
            detachedWrapper.appendChild(originalFragment);

            // SCAN the Detached Wrapper
            // The Scanner and Sanitizer will modify 'detachedWrapper' in-place.
            const nodeResults = await scanner.scanPage(detachedWrapper);
            results.matches.push(...nodeResults.matches);
            results.sanitizedCount += nodeResults.sanitizedCount;

            // RESTORE
            // 1. Remove Placeholder
            if (placeholder.parentNode === node) {
                node.removeChild(placeholder);
            }

            // 2. Put back the (now sanitized) content
            while (detachedWrapper.firstChild) {
                node.appendChild(detachedWrapper.firstChild);
            }
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
const observer = new MutationObserver((mutations) => {
    try {
        if (!isScanningActive) return;
        if (isSanitizing) return;

        if (timeoutId) clearTimeout(timeoutId);

        // SMART DEBOUNCE LOGIC
        // If we detect changes in Gmail email body (.a3s) or high-priority areas, we scan faster.
        let debounceTime = 500; // Default lowered from 3000ms

        // Check if mutation affects email body or quoted text or headers or inbox
        const isTargetDetection = mutations.some(m => {
            // Handle Text Nodes (nodeType 3) by checking parent
            if (!m.target) return false;
            const target = m.target.nodeType === 1 ? m.target : m.target.parentElement;
            return target && target.closest && (
                target.closest('.a3s') ||
                target.closest('.gmail_quote') ||
                target.closest('.im') ||
                target.closest('.hP') ||
                target.closest('.gD') ||
                target.closest('.y2') ||
                target.closest('.bog')
            );
        });

        if (isTargetDetection) {
            console.log("Surgical-Guard: Immediate scan triggered for Content/Quote.");
            if (timeoutId) clearTimeout(timeoutId);
            // Run immediately (microtask)
            timeoutId = setTimeout(async () => {
                try {
                    if (document.hidden) return;
                    await runGuard(true);
                } catch (e) {
                    console.error("Surgical-Guard: Scan failed safely", e);
                }
            }, 0); // 0ms delay
            return;
        }

        // Debounce scan (standard persistence)
        timeoutId = setTimeout(async () => {
            try {
                if (document.hidden) return;
                // Silent Scan for background updates
                await runGuard(true);
            } catch (e) {
                console.error("Surgical-Guard: Scan failed safely", e);
            }
        }, debounceTime);
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
