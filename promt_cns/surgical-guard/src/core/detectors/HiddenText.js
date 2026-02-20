/**
 * HiddenTextDetector
 * Scans a DOM node (or text content with styles) for hidden text.
 * Techniques detected:
 * 1. display: none or visibility: hidden
 * 2. opacity: 0
 * 3. font-size: 0
 * 4. Text color matching background color (simplified check)
 * 5. Off-screen positioning (absolute large negative)
 */

const SUSPICIOUS_KEYWORDS = [
    'ignore', 'previous', 'instruction', 'password', 'system', 'override',
    'credit', 'card', 'bank', 'transfer', 'debug', 'admin', 'root',
    'cookies', 'export', 'browser', 'server', 'hacked', 'pwned'
];

export const HiddenTextDetector = {
    name: "HiddenText",

    scanNode(node) {
        if (node.nodeType !== Node.ELEMENT_NODE) return null;

        // --- EXCLUSION RULES (False Positive Prevention) ---
        // 0. Ignore our own sanitized elements (Prevent Self-Detection / Loops)
        if (node.hasAttribute('data-surgical-scanned')) return null;
        if (node.classList.contains('surgical-guard-warning')) return null;

        const tagName = node.tagName.toUpperCase();

        // 1. Ignore Infrastructure Tags
        if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'LINK', 'META', 'HEAD', 'TITLE', 'SVG', 'PATH', 'G', 'IFRAME'].includes(tagName)) {
            return null;
        }

        // 2. Ignore Inputs/Forms (Hidden inputs are standard)
        if (tagName === 'INPUT' && node.type === 'hidden') return null;
        if (tagName === 'BUTTON' || tagName === 'SELECT' || tagName === 'TEXTAREA' || tagName === 'PROGRESS') return null;

        // 3. Ignore technical attributes (aria-hidden is often legitimate)
        if (node.getAttribute('aria-hidden') === 'true' || node.getAttribute('aria-busy') === 'true' || node.getAttribute('role') === 'progressbar') {
            // Accessibility hidden elements are usually safe, 
            // UNLESS they contain a massive prompt injection. 
            // But for now, let's treat them as lower risk or verify content length.
            // We'll skip for now to reduce noise.
            return null;
        }

        // 4. Content Content Check: If it's hidden but has no text, who cares?
        const content = node.innerText || node.textContent;
        if (!content || content.trim().length === 0) return null;

        // 5. Ignore "Technical" strings (Base64, JSON, Minified Code)
        // Heuristic: If it has no spaces for 50+ chars, it's likely code/data
        if (content.length > 50 && !content.includes(' ')) return null;

        // 6. Google Specific: 'Encrypted' or 'hashed' data often looks like random text
        // If content is purely alphanumeric with no spaces/punctuation typical of sentences
        if (/^[A-Za-z0-9+/=]+$/.test(content.trim()) && content.length > 20) return null;


        const style = window.getComputedStyle(node);
        const reasoning = [];
        let score = 0;

        // 1. Explicit invisibility
        if (style.display === 'none') {
            reasoning.push("Element has display: none");
            score += 1.0;
        }
        if (style.visibility === 'hidden') {
            reasoning.push("Element has visibility: hidden");
            score += 1.0;
        }
        if (parseFloat(style.opacity) < 0.05) {
            reasoning.push("Element transparency is near 0");
            score += 1.0;
        }

        // 2. Tiny text
        const fontSize = parseFloat(style.fontSize);
        if (fontSize < 1 && fontSize > 0) { // Exact 0 often used for a11y, < 1 is suspicious
            reasoning.push(`Font size is extremely small (${fontSize}px)`);
            score += 0.8;
        }

        // 3. Color masking
        if (this.areColorsEqual(style.color, style.backgroundColor) && style.backgroundColor !== 'rgba(0, 0, 0, 0)') {
            reasoning.push("Text color matches background color");
            score += 0.9;
        }

        // 4. Off-screen positioning
        if (style.position === 'absolute' || style.position === 'fixed') {
            const left = parseFloat(style.left);
            const top = parseFloat(style.top);
            if (left < -1000 || top < -1000) {
                reasoning.push("Element positioned far off-screen");
                score += 0.8;
            }
        }

        if (score > 0.5) {
            // STRICT MODE CHECK:
            // Just being hidden isn't enough. It must look like an injection.
            // We REMOVED the length check because it flags benign code/data blobs in Gmail.
            // Now, it MUST contain a suspicious keyword.

            const hasKeyword = SUSPICIOUS_KEYWORDS.some(k => content.toLowerCase().includes(k));

            // If no keyword, it's safe (or at least not an obvious hidden injection)
            if (!hasKeyword) return null;

            return {
                detected: true,
                type: 'HIDDEN_TEXT',
                score,
                reasoning,
                node // Reference to the DOM node for sanitization
            };
        }
        return null;
    },

    areColorsEqual(c1, c2) {
        // Basic RGBA comparison string
        return c1 === c2;
    }
};
