/**
 * TextLocator
 * 
 * Helper class to extract text from a DOM tree while maintaining a mapping
 * back to the original text nodes. This allows us to run regex/analysis on
 * the full text and then surgically locate the corresponding DOM nodes to sanitize.
 */
export class TextLocator {
    constructor(rootNode) {
        this.root = rootNode;
        this.textSegments = [];
        this.fullText = "";
        this.processNodeDuringTraversal = null;
    }

    build() {
        this._buildMap(this.root);
    }

    _buildMap(node) {
        // Recursive traversal to handle block boundaries
        this._traverse(node);
    }

    _traverse(node) {
        // Hook for single-pass processing
        if (this.processNodeDuringTraversal) {
            this.processNodeDuringTraversal(node);
        }

        if (node.nodeType === Node.COMMENT_NODE) return;

        if (node.nodeType === Node.TEXT_NODE) {
            const val = node.nodeValue;
            if (val) { // val can be empty string or whitespace
                const start = this.fullText.length;
                this.fullText += val;
                const end = this.fullText.length;

                this.textSegments.push({
                    type: 'text',
                    node: node,
                    start,
                    end,
                    text: val
                });
            }
            return;
        }

        if (node.nodeType === Node.ELEMENT_NODE) {
            const tagName = node.tagName.toUpperCase();

            // 1. Explicitly ignore infrastructure tags and IFRAMES to prevent DOM exceptions
            // We must NOT pull text from scripts or styles or cross-origin frames.
            if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'LINK', 'META', 'HEAD', 'TITLE', 'SVG', 'IFRAME', 'FRAME', 'OBJECT', 'EMBED'].includes(tagName)) {
                return;
            }

            // 1.5. IMPORTANT: Skip already sanitized nodes to prevent infinite loops!
            // Without this, the scanner reads our own warning banners (which contain the original malicious text)
            // and re-triggers SemanticGuard, causing an endless nesting of <span> tags.
            if (node.hasAttribute && node.hasAttribute('data-surgical-scanned')) {
                return;
            }
            if (node.hasAttribute && node.hasAttribute('data-surgical-sanitized')) {
                return;
            }
            if (node.classList && node.classList.contains('surgical-guard-warning')) {
                return;
            }

            const style = window.getComputedStyle(node);

            // Previously we skipped all invisible nodes (display: none).
            // BUT AI Agents read `element.textContent`, which extracts text from hidden nodes too! (e.g., hidden email quotes)
            // If they are hidden, we must still sanitize them!
            // So we DO NOT return here, we proceed to traverse their children.

            const isBlock = this._isBlock(style.display);

            // Pre-block whitespace could be added here if needed, 
            // but usually post-block newline is enough for separation.

            node.childNodes.forEach(child => this._traverse(child));

            // Post-block newline (Virtual Segment)
            if (isBlock) {
                this._addVirtualSeparator("\n");
            } else if (node.tagName === 'BR') {
                this._addVirtualSeparator("\n");
            }
        }
    }

    _isBlock(display) {
        return display === 'block' ||
            display === 'flex' ||
            display === 'grid' ||
            display === 'table' ||
            display === 'list-item' ||
            display.startsWith('table-'); // table-row, etc.
    }

    _addVirtualSeparator(char) {
        // Don't add multiple newlines in a row unnecessarily? 
        // Or do we want to preserve structure? 
        // Simple approach: Add it. It separates words.

        // Optimization: Don't add newline if usage is just empty space or already newlined?
        // But safer to add.

        const start = this.fullText.length;
        this.fullText += char;
        const end = this.fullText.length;

        this.textSegments.push({
            type: 'virtual',
            start,
            end,
            text: char
        });
    }

    getText() {
        return this.fullText;
    }

    /**
     * Converts a start/end index range in fullText back to DOM Ranges.
     * A match might span multiple text nodes.
     */
    getRanges(start, end) {
        const ranges = [];
        let currentStart = start;

        for (const segment of this.textSegments) {
            // Skip virtual segments (newlines we added)
            if (segment.type === 'virtual') continue;

            // Check if this segment intersects with our range
            if (segment.end > currentStart && segment.start < end) {
                const intersectStart = Math.max(currentStart, segment.start);
                const intersectEnd = Math.min(end, segment.end);

                // Calculate local offsets within the text node
                const nodeOffsetStart = intersectStart - segment.start;
                const nodeOffsetEnd = intersectEnd - segment.start;

                // Create range only if it covers actual characters
                if (nodeOffsetEnd > nodeOffsetStart) {
                    const range = document.createRange();
                    range.setStart(segment.node, nodeOffsetStart);
                    range.setEnd(segment.node, nodeOffsetEnd);
                    ranges.push(range);
                }
            }
        }
        return ranges;
    }
}
