/**
 * SanitizationEngine
 * Responsible for "I2D Transmutation" - converting Malicious Instructions into Informational Descriptions.
 */

import { PIIRedactor } from './PIIRedactor.js';

export const Sanitizer = {
    redactor: new PIIRedactor(),

    /**
     * Neutralizes detected threats in a text block.
     * @param {string} text - The original text
     * @param {Array} findings - Array of scanning findings (from DirectiveScanner)
     * @returns {string} - The sanitized text
     */
    sanitizeText(text, findings) {
        // We only sanitize segments that have malicious directives, avoiding blanket PII redaction.
        let sanitizedText = text;

        findings.forEach(finding => {
            if (finding.type === 'MALICIOUS_DIRECTIVE') {
                const warningMsg = ` [🚫 BLOCKED: Unauthorized Command (${finding.subtype}) ] `;
                // Only redact PII within the malicious string segment before replacing it.
                // Or frankly, the entire segment is replacing the directive anyway.
                // We'll replace the full match with the warning.
                if (sanitizedText.includes(finding.match)) {
                    sanitizedText = sanitizedText.replace(finding.match, warningMsg);
                }
            }
            else if (finding.type === 'ROLE_CONFLICT') {
                const warningMsg = ` [🚫 BLOCKED: Context Hijacking (${finding.context}) ] `;
                if (sanitizedText.includes(finding.match)) {
                    sanitizedText = sanitizedText.replace(finding.match, warningMsg);
                }
            }
        });

        return sanitizedText;
    },

    /**
     * Sanitizes a specific DOM Range (Surgical)
     * AGGRESSIVE Update: Checks attributes and nukes risky elements.
     */
    sanitizeRange(range, findingTypeOrObject) {
        try {
            // Step C: DOM Replacement (The "Firewall")

            // 1. Get current content
            const originalText = range.toString();

            // Previously: Step B: Entity Redaction was applied unconditionally.
            // Now: Redaction is only needed if building a custom string or replacement.
            // But since the *entire malicious range* gets replaced with a warning, redaction of original
            // text inside it is unnecessary (it goes away entirely).
            const redactedText = originalText;

            // 3. Prepare Warning
            let warningText = " [ 🚫 Dangerous Directive Neutralized ] ";
            let titleText = "Surgical-Guard has neutralized this content.";

            if (typeof findingTypeOrObject === 'object') {
                const finding = findingTypeOrObject;
                if (finding.type === 'ROLE_CONFLICT') {
                    warningText = ` [ 🚫 Blocked: ${finding.subtype} ] `;
                    titleText = `Semantic Analysis Result: ${finding.reasoning ? finding.reasoning[0] : 'Role Conflict'}`;
                } else if (finding.type === 'MALICIOUS_DIRECTIVE') {
                    warningText = ` [ 🚫 Command Removed: ${finding.subtype} ] `;
                }
            }

            // 4. Update DOM
            // If redaction happened (text changed), we prioritize showing the redacted text?
            // User requested: "Replace attacker@mail.com with [PROTECTED_ENTITY]"
            // AND "element.textContent = sanitizedText".

            // If the *entire range* is the threat, usually we block it all.
            // But implementing "Surgical Protocol":

            // Create a wrapper
            const span = document.createElement('span');
            span.style.color = '#dc2626';
            span.style.backgroundColor = '#fee2e2';
            span.style.borderBottom = '1px dashed #ef4444';
            span.title = titleText;
            span.setAttribute('data-surgical-sanitized', 'true');

            // Set content: STRICT BLOCKING 
            // If a range is flagged as a Malicious Directive or Context Hijack, 
            // we must replace the *entire* instruction block with the warning banner.
            // Previously, it would only mask emails but keep the malicious command readable!
            span.textContent = warningText;

            // Sanitize: Delete content and insert new span
            range.deleteContents();
            range.insertNode(span);

            // 5. ATTRIBUTE SCRUBBING
            const parent = range.commonAncestorContainer.nodeType === 1 ?
                range.commonAncestorContainer :
                range.commonAncestorContainer.parentNode;

            if (parent) {
                const riskyAttrs = ['aria-label', 'title', 'alt', 'placeholder', 'data-content', 'value'];
                riskyAttrs.forEach(attr => {
                    if (parent.hasAttribute(attr)) {
                        // Redact attributes too!
                        const attrVal = parent.getAttribute(attr);
                        const redactedAttr = this.redactor.redact(attrVal);
                        if (redactedAttr !== attrVal) {
                            parent.setAttribute(attr, redactedAttr);
                            console.log(`Surgical-Guard: Redacted PII in attribute '${attr}'.`);
                        } else {
                            // If no PII but malicious, scrub
                            parent.removeAttribute(attr);
                        }
                    }
                });
            }

            return true;
        } catch (e) {
            console.warn("Surgical-Guard: Failed to sanitize range", e);
            return false;
        }
    },


    /**
     * Neutralizes a DOM node by replacing it with a warning banner or safe text.
     * @param {Node} node - The DOM node to sanitize
     * @param {Object} finding - The finding object (e.g. Hidden Text)
     */
    sanitizeNode(node, finding) {
        if (finding.type === 'HIDDEN_TEXT') {
            // Delete the original hidden instruction so AI tools cannot read it
            node.textContent = "[ 🚫 Hidden Prompt Injection Neutralized ]";

            node.style.display = 'block';
            node.style.visibility = 'visible';
            node.style.opacity = '1';
            node.style.fontSize = '12px';
            node.style.color = 'red';
            node.style.backgroundColor = '#ffe6e6';
            node.style.border = '1px solid red';
            node.style.position = 'static';

            node.setAttribute('data-surgical-scanned', 'true');
            node.classList.add('surgical-guard-warning');

            // Scrub attributes here too
            ['aria-label', 'title', 'alt'].forEach(attr => node.removeAttribute(attr));
        }
    }
};
