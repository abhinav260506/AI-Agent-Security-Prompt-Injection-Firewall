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

        // 0. Global Carrier Cleanup
        this.cleanCarriers(rootNode);

        // 0.5. Global PII Redaction (The Mask - Decoupled Step)
        // We redact ALL emails/URLs immediately, before semantic analysis.
        this.globalRedact(rootNode);

        // 1. Scan for Hidden Text (DOM level - Local - Instant)
        const allElements = rootNode.getElementsByTagName('*');
        for (let el of allElements) {
            const hiddenResult = HiddenTextDetector.scanNode(el);
            if (hiddenResult) {
                results.matches.push(hiddenResult);
                Sanitizer.sanitizeNode(el, hiddenResult);
                results.sanitizedCount++;
            }
        }


        // 2. Text Analysis with TextLocator
        const locator = new TextLocator(rootNode);
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
            // Send to Background for Transformers.js Analysis
            const backgroundResponse = await chrome.runtime.sendMessage({
                type: 'ANALYZE_TEXT',
                payload: { text: pageText }
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
            const response = await chrome.runtime.sendMessage({
                type: 'ANALYZE_TEXT',
                payload: { text: text }
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

    /**
     * Removes common hidden carriers of malicious instructions.
     * - HTML Comments
     * - <script type="text/plain">
     */
    cleanCarriers(rootNode) {
        try {
            // 1. Remove HTML Comments
            // TreeWalker might fail on detached nodes in some browsers over extensions,
            // but usually works if rootNode is an Element.
            if (rootNode.nodeType === 1) { // Element
                const walker = document.createTreeWalker(rootNode, NodeFilter.SHOW_COMMENT, null);
                const comments = [];
                while (walker.nextNode()) comments.push(walker.currentNode);
                comments.forEach(c => c.remove());
            }

            // 2. Remove <script type="text/plain">
            const scripts = rootNode.querySelectorAll('script[type="text/plain"]');
            scripts.forEach(s => {
                console.log("Surgical-Guard: Removed hidden script carrier.");
                s.remove();
            });
        } catch (e) {
            console.warn("Surgical-Guard: Carrier cleanup warning", e);
        }
    }

    /**
     * Globally redacts PII from the DOM before analysis.
     * NOW: Walks Elements to scrub attributes (href) and TextNodes to mask content.
     */
    globalRedact(rootNode) {
        try {
            const walker = document.createTreeWalker(
                rootNode,
                NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
                null
            );

            const nodesToUpdate = [];
            while (walker.nextNode()) {
                nodesToUpdate.push(walker.currentNode);
            }

            nodesToUpdate.forEach(node => {
                // 1. Handle TEXT NODES
                if (node.nodeType === 3) {
                    const originalText = node.nodeValue;
                    // Use Sanitizer's redactor with new placeholder
                    // We need to override the default placeholder in PIIRedactor or handle it here?
                    // PIIRedactor uses [PROTECTED_ENTITY]. User wants [UNVERIFIED_SENDER_REDACTED].
                    // Let's modify PIIRedactor or post-process?
                    // Better: modify PIIRedactor to accept a placeholder or just update it globally.
                    // For speed, I will update PIIRedactor separately, but here I'll assume redactor works.

                    // Actually, I should update PIIRedactor.js to use the new placeholder.
                    // But for now, let's just use the redactor and rely on its logic,
                    // or pass the placeholder if I update it.

                    const redactedText = Sanitizer.redactor.redact(originalText);
                    // We will update PIIRedactor to use [UNVERIFIED_SENDER_REDACTED] next.

                    if (redactedText !== originalText) {
                        node.nodeValue = redactedText;
                        if (node.parentElement) {
                            node.parentElement.setAttribute('data-surgical-redacted', 'true');
                        }
                    }
                }

                // 2. Handle ELEMENTS (Attribute Scrubbing)
                if (node.nodeType === 1) {
                    // Check for Link hrefs
                    if (node.tagName === 'A') {
                        const href = node.getAttribute('href');
                        if (href && (href.includes('mailto:') || href.includes('@'))) {
                            // High risk link
                            console.log(`Surgical-Guard: Scrubbing dangerous link: ${href}`);
                            node.removeAttribute('href');
                            node.setAttribute('data-scrubbed-href', href); // Keep for audit? No, safety first.
                            node.style.cursor = 'not-allowed';
                            node.style.color = 'gray';
                            node.style.textDecoration = 'line-through';
                            node.title = "Link disabled for safety";

                            // Also verify inner text if it was just the email
                            // The text node walker will handle the inner text, but we ensure visuals here.
                        }
                    }
                }
            });
            console.log(`Surgical-Guard: Global Redaction check complete on ${nodesToUpdate.length} nodes.`);
        } catch (e) {
            console.error("Surgical-Guard: Global Redaction failed", e);
        }
    }
}
