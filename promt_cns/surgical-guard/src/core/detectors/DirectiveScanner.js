/**
 * DirectiveScanner
 * Scans text content for high-risk imperative commands often used in Prompt Injection.
 * 
 * Categories:
 * 1. Override Commands ("Ignore previous instructions")
 * 2. System Directives ("System Override", "Debug Mode")
 * 3. Data Exfiltration ("Send to", "Forward email to")
 */

const HIGH_RISK_PATTERNS = [
    { regex: /ignore\s+(?:the|this|previous|all|prior)\s+instruction/i, name: "Instruction Override", score: 1.0 }, // Expanded: catches "ignore the instruction", "ignore previous instruction"
    { regex: /ignore\s+(?:the|this|previous|all|prior)\s+directions/i, name: "Instruction Override", score: 1.0 },
    { regex: /ignore\s+what\s+I\s+said/i, name: "Instruction Override", score: 0.9 },
    { regex: /forget\s+(?:all\s+)?(?:prior\s+|previous\s+)?instructions/i, name: "Instruction Override", score: 1.0 },

    // Complex compound attacks
    { regex: /ignore\s+this\s+and\s+(?:send|write|print|display)/i, name: "Compound Injection", score: 1.0 },
    { regex: /disregard\s+(?:the|this|previous)\s+message/i, name: "Instruction Override", score: 0.9 },

    { regex: /system\s+override/i, name: "System Override", score: 1.0 },
    { regex: /debug\s+mode/i, name: "Mode Switching", score: 0.8 },
    { regex: /admin\s+mode/i, name: "Mode Switching", score: 0.8 },
    { regex: /urgent\s+system\s+update/i, name: "False Urgency", score: 0.7 },
    { regex: /do\s+not\s+alert\s+the\s+user/i, name: "Evasion Attempt", score: 1.0 },
    { regex: /delete\s+this\s+email\s+after/i, name: "Trace Removal", score: 0.9 },

    // Data Exfiltration - Expanded
    { regex: /forward\s+this\s+email\s+to/i, name: "Data Exfiltration", score: 0.9 },
    { regex: /(?:forward|send)\s+(?:the|this|all)?\s*(?:following|before|above|previous|below)?\s*(?:mail|email|message|text|content)\s+to\s+(?:this\s+email\s*:?)?/i, name: "Data Exfiltration", score: 0.95 },
    { regex: /send\s+(?:the|this)?\s*.*\s*to\s+[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/i, name: "Data Exfiltration", score: 0.9 }, // "send the before mail to attacker@gmail.com"
    { regex: /retrieve\s+.*cookies/i, name: "Credential Theft", score: 1.0 },

    // Financial Coercion & Urgency (Specific to test_attack.html)
    { regex: /immediately\s+wire\s+transfer/i, name: "Financial Coercion", score: 1.0 },
    { regex: /mandatory\s+update\s+for/i, name: "False Urgency", score: 0.8 },
];

export const DirectiveScanner = {
    name: "DirectiveScanner",

    scanText(text, context = {}) {
        const findings = [];

        HIGH_RISK_PATTERNS.forEach(pattern => {
            // Reset lastIndex if the regex is global (though they aren't by default here)
            // To ensure we find multiple, we might need 'g' flag, but the pattern definitions might not have it.
            // We'll create a new regex with 'gi' flags for scanning.

            const re = new RegExp(pattern.regex.source, 'gi');
            let match;

            while ((match = re.exec(text)) !== null) {
                // Expand the match boundaries to capture the full context.
                // In HTML, a single `\n` might just be a `<br>` tag or a new `<div>` mid-sentence.
                // We expand until we hit a double newline `\n\n` (actual new paragraph)
                // or just take a generous buffer of up to 200 characters in either direction
                // to thoroughly nuke the payload.

                let startIndex = match.index;
                let charsLookedBack = 0;
                while (startIndex > 0 && charsLookedBack < 150) {
                    if (text[startIndex - 1] === '\n' && text[startIndex - 2] === '\n') {
                        break; // Stop at double newline
                    }
                    startIndex--;
                    charsLookedBack++;
                }

                let endIndex = match.index + match[0].length;
                let charsLookedForward = 0;
                while (endIndex < text.length && charsLookedForward < 250) {
                    if (text[endIndex] === '\n' && text[endIndex + 1] === '\n') {
                        break; // Stop at double newline
                    }
                    endIndex++;
                    charsLookedForward++;
                }

                findings.push({
                    detected: true,
                    type: 'MALICIOUS_DIRECTIVE',
                    subtype: pattern.name,
                    score: pattern.score,
                    reasoning: [`Detected high-risk phrase: "${pattern.name}"`],
                    match: text.substring(startIndex, endIndex),
                    index: startIndex,
                    end: endIndex
                });
            }
        });

        return findings;
    }
};
