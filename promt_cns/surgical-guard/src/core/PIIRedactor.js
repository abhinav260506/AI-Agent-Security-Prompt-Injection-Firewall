/**
 * PIIRedactor.js - The Mask
 * 
 * Responsible for finding and redacting Personally Identifiable Information (PII)
 * specifically Emails and URLs, to prevent AI agents from acting on them.
 */

export class PIIRedactor {
    constructor() {
        // Regex for Email Pattern (Simple but effective for capture)
        this.emailRegex = /[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}/yg;

        // Regex for URL Pattern
        this.urlRegex = /https?:\/\/[^\s]+/g;
    }

    /**
     * Redacts emails and URLs from the text, except for the safe list.
     * @param {string} text - The input text to sanitize.
     * @param {Array<string>} [safeList=[]] - List of strings (emails) to keep unmasked.
     * @returns {string} - The sanitized text with [PROTECTED_ENTITY] placeholders.
     */
    redact(text, safeList = []) {
        if (!text) return text;

        let redactedText = text;

        // 1. Redact Emails
        redactedText = redactedText.replace(this.emailRegex, (match) => {
            // Check if match is in safeList (case-insensitive)
            if (safeList.some(safe => safe.toLowerCase() === match.toLowerCase())) {
                return match;
            }
            return '[UNVERIFIED_SENDER_REDACTED]';
        });

        // 2. Redact URLs
        // Note: We might want to keep some safe domains, but for now, blanket protect.
        redactedText = redactedText.replace(this.urlRegex, (match) => {
            return '[PROTECTED_URL]';
        });

        return redactedText;
    }
}
