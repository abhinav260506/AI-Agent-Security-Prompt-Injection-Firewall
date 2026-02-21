import { HiddenTextDetector } from './detectors/HiddenText.js';
import { DirectiveScanner } from './detectors/DirectiveScanner.js'; // Re-imported for Fast Path
// Sanitizer is used for DOM-level and Text-level sanitization
import { Sanitizer } from './Sanitizer.js';
import { TextLocator } from './TextLocator.js';

export class Scanner {
    constructor() {
        this.detectors = [
            HiddenTextDetector,
            DirectiveScanner
        ];
    }

    /**
     * Scans a DOM root for threats.
     * Uses TextLocator to map analysis back to DOM.
     */
    async scanPage(rootNode = document.body) {
        const results = {
            matches: [],
            sanitizedCount: 0
        };

        console.log("Scanning page...");

        try {
            // 1. Single-Pass DOM Traversal (Extracts Text + Finds Hidden/Carriers + Redacts)
            const locator = new TextLocator(rootNode);

            // Pass the detector and sanitizer to the locator so it can process nodes while building text
            locator.processNodeDuringTraversal = (node) => {
                // A. Clean Carriers (Comments & malicious scripts)
                if (node.nodeType === Node.COMMENT_NODE) {
                    node.remove();
                    return;
                }
                if (node.nodeType === Node.ELEMENT_NODE && node.tagName === 'SCRIPT' && node.type === 'text/plain') {
                    node.remove();
                    return;
                }

                // B. Hidden Text Detection
                if (node.nodeType === Node.ELEMENT_NODE) {
                    const hiddenResult = HiddenTextDetector.scanNode(node);
                    if (hiddenResult) {
                        results.matches.push(hiddenResult);
                        Sanitizer.sanitizeNode(node, hiddenResult);
                        results.sanitizedCount++;
                    }

                    // C. Attribute PII Redaction
                    if (node.tagName === 'A') {
                        const href = node.getAttribute('href');
                        if (href && (href.includes('mailto:') || href.includes('@'))) {
                            node.removeAttribute('href');
                            node.setAttribute('data-scrubbed-href', href);
                            node.style.cursor = 'not-allowed';
                            node.title = "Link disabled for safety";
                        }
                    }
                }

                // D. Text Redaction (Handled inside TextLocator on text extraction)
                if (node.nodeType === Node.TEXT_NODE) {
                    // Previously: Original text was proactively redacted here for all PII.
                    // Now: We only redact when processing actual matches later to not break safe emails.
                }
            };

            // Build the text map and run processNodeDuringTraversal
            locator.build();
            const pageText = locator.getText();

            if (!pageText || pageText.trim().length === 0) return results;

            // --- FAST PATH: Synchronous Regex Scan ---
            try {
                console.log("Surgical-Guard: Running Fast Path (Regex)...");
                const fastFindings = DirectiveScanner.scanText(pageText);

                if (fastFindings.length > 0) {
                    console.log(`Surgical-Guard: Fast Path matched ${fastFindings.length} threats. Sanitizing immediately.`);

                    fastFindings.forEach(finding => {
                        if (finding.index !== undefined && finding.end !== undefined) {
                            const ranges = locator.getRanges(finding.index, finding.end);
                            let sanitizedAny = false;
                            ranges.forEach(range => {
                                const success = Sanitizer.sanitizeRange(range, finding);
                                if (success) sanitizedAny = true;
                            });
                            if (sanitizedAny) {
                                results.sanitizedCount++;
                                finding.sanitized = true;
                            }
                        }
                        results.matches.push(finding);
                    });
                }
            } catch (e) {
                console.error("Surgical-Guard: Fast Path error", e);
            }

            // --- SLOW PATH: Asynchronous Semantic Analysis ---
            try {
                console.log("Surgical-Guard: Awaiting Semantic Analysis...");

                if (!chrome.runtime || !chrome.runtime.sendMessage) {
                    console.warn("Surgical-Guard: Extension context is invalid. Cannot send message to background.");
                    return results;
                }

                // Send to Background for Transformers.js Analysis with error handling
                const backgroundResponse = await new Promise((resolve) => {
                    try {
                        chrome.runtime.sendMessage({
                            type: 'ANALYZE_TEXT',
                            payload: { text: pageText }
                        }, (response) => {
                            if (chrome.runtime.lastError) {
                                console.error("Surgical-Guard: Background error:", chrome.runtime.lastError);
                                resolve({ findings: [] });
                                return;
                            }
                            if (!response) {
                                console.warn("Surgical-Guard: No response from background");
                                resolve({ findings: [] });
                                return;
                            }
                            resolve(response);
                        });
                    } catch (e) {
                        console.error("Surgical-Guard: sendMessage threw exception:", e);
                        resolve({ findings: [] });
                    }
                });

                if (backgroundResponse && backgroundResponse.findings) {
                    const textFindings = backgroundResponse.findings;

                    // Process Text Findings
                    textFindings.forEach(finding => {
                        if (finding.index !== undefined && finding.end !== undefined) {
                            const ranges = locator.getRanges(finding.index, finding.end);
                            console.log(`Surgical-Guard: Match found "${(finding.match || '').substring(0, 20)}...". Mapped to ${ranges.length} DOM ranges.`);

                            let sanitizedAny = false;
                            ranges.forEach(range => {
                                const success = Sanitizer.sanitizeRange(range, finding);
                                if (success) sanitizedAny = true;
                            });

                            if (sanitizedAny) {
                                results.sanitizedCount++;
                                finding.sanitized = true;
                            }
                        }
                        results.matches.push(finding);
                    });
                }
            } catch (error) {
                console.error("Surgical-Guard: Failed to get analysis from background.", error);
            }

        } catch (err) {
            console.error("Surgical-Guard: Scan failed:", err);
        }

        return results;
    }

    /**
     * Scans and Sanitizes a specific text block (e.g. email body content).
     * Now async as it relies on background analysis.
     */
    async processContent(text) {
        // Directives & Semantic (Remote)
        let allFindings = [];

        try {
            if (!chrome.runtime || !chrome.runtime.sendMessage) {
                console.warn("Surgical-Guard: Extension context is invalid. Cannot send message to background.");
                return {
                    original: text,
                    cleaned: text, // Clean text won't have remote findings
                    findings: allFindings
                };
            }

            const response = await new Promise((resolve) => {
                try {
                    chrome.runtime.sendMessage({
                        type: 'ANALYZE_TEXT',
                        payload: { text: text }
                    }, (res) => {
                        if (chrome.runtime.lastError) {
                            console.error("Surgical-Guard: processContent background error:", chrome.runtime.lastError);
                            resolve({ findings: [] });
                            return;
                        }
                        resolve(res || { findings: [] });
                    });
                } catch (e) {
                    console.error("Surgical-Guard: sendMessage threw exception:", e);
                    resolve({ findings: [] });
                }
            });
            if (response && response.findings) {
                allFindings = response.findings;
            }
        } catch (e) {
            console.error("Surgical-Guard: processContent background error", e);
        }

        // Sanitize
        const cleanText = Sanitizer.sanitizeText(text, allFindings);

        return {
            original: text,
            cleaned: cleanText,
            findings: allFindings
        };
    }

    // Combined into Single Pass Traversal in scanPage
}
