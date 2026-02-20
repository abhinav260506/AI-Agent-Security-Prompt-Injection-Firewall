import { DirectiveScanner } from './detectors/DirectiveScanner.js';
import { SemanticGuard } from './detectors/SemanticGuard.js';

/**
 * AnalysisEngine
 * 
 * Orchestrates the semantic and directive analysis of text.
 * Designed to run in the Background Service Worker to offload processing from the Content Script.
 */
export const AnalysisEngine = {

    /**
     * Analyzes text for threats using multiple detectors.
     * @param {string} text - The raw text content to analyze.
     * @returns {Array} - Combined list of findings/threats.
     */
    async analyze(text) {
        if (!text || typeof text !== 'string') {
            console.warn("AnalysisEngine: Invalid text provided for analysis.");
            return [];
        }

        const findings = [];

        try {
            // 1. Directive Scanner (Regex based)
            // Fast, high-confidence pattern matching for commands.
            const directiveResults = DirectiveScanner.scanText(text);
            findings.push(...directiveResults);

            // 2. Semantic Guard (Transformer Model)
            // Slower, deeper analysis for meaning.
            // AWAITING ASYNC ANALYSIS
            const semanticResults = await SemanticGuard.analyze(text);
            findings.push(...semanticResults);

        } catch (error) {
            console.error("AnalysisEngine: Error during analysis breakdown.", error);
        }

        return findings;
    }
};
