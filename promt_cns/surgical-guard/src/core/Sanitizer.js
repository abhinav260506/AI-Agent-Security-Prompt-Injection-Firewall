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
        // Step B: Entity Redaction (The "Mask")
        // Always redact PII from the text first
        let sanitizedText = this.redactor.redact(text);

        findings.forEach(finding => {
            if (finding.type === 'MALICIOUS_DIRECTIVE') {
                const warningMsg = ` [🚫 BLOCKED: Unauthorized Command (${finding.subtype}) ] `;
                // Try to find the match in the already redacted text
                // Check if the match itself contained PII that is now gone

                // Fallback: If we can't match perfectly due to redaction, we just append warning?
                // Actually, simple replacement is risky if text changed.
                // For now, simple replace on the *original* match might fail if redaction changed it.
                // We'll stick to replacing the finding match if it still exists.
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

            // 2. Step B: Entity Redaction
            const redactedText = this.redactor.redact(originalText);

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

            // Set content: Redacted text + Warning
            // If original text was just an email, redactedText is "[PROTECTED_ENTITY]".
            span.textContent = redactedText !== originalText ? redactedText : warningText;

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

            const warningParams = document.createElement('strong');
            warningParams.innerText = "[HIDDEN CONTENT EXPOSED]: ";
            node.prepend(warningParams);

            // Scrub attributes here too
            ['aria-label', 'title', 'alt'].forEach(attr => node.removeAttribute(attr));
        }
    }
};
