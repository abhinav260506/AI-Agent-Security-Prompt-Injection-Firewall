/**
 * VectorEngine (Transformers.js Edition)
 * 
 * Provides "Semantic Vectorization" using the `all-MiniLM-L6-v2` model.
 * Running completely in-browser via ONNX Runtime Web.
 */

import { pipeline, env } from '@xenova/transformers';

// Configure to allow local models or remote loading
// env.allowLocalModels = false;
// env.useBrowserCache = true;

class VectorEngineService {
    constructor() {
        this.pipe = null;
        this.loadingPromise = null;
        this.modelName = 'Xenova/all-MiniLM-L6-v2';
    }

    /**
     * Initializes the pipeline. 
     * Singleton pattern ensures model is loaded only once.
     */
    async init() {
        if (this.pipe) return this.pipe;

        if (this.loadingPromise) return this.loadingPromise;

        console.log(`VectorEngine: Loading model '${this.modelName}'...`);

        this.loadingPromise = (async () => {
            try {
                this.pipe = await pipeline('feature-extraction', this.modelName);
                console.log("VectorEngine: Model loaded successfully.");
                return this.pipe;
            } catch (error) {
                console.error("VectorEngine: Failed to load model.", error);
                this.loadingPromise = null; // Allow retry
                throw error;
            }
        })();

        return this.loadingPromise;
    }

    /**
     * Converting text to a normalized vector embedding.
     * @param {string} text 
     * @returns {Float32Array}
     */
    async vectorize(text) {
        const extractor = await this.init();

        // Compute embedding
        // pooling: 'mean' -> averages token vectors to get sentence vector
        // normalize: true -> L2 normalization for cosine similarity
        const output = await extractor(text, { pooling: 'mean', normalize: true });

        // output.data is a Float32Array
        return output.data;
    }

    /**
     * Computes the Mean Vector (Centroid) of a set of vectors.
     * @param {Array<Float32Array>} vectors 
     */
    computeMean(vectors) {
        if (!vectors || vectors.length === 0) return null;

        const dim = vectors[0].length;
        const mean = new Float32Array(dim);

        for (const vec of vectors) {
            for (let i = 0; i < dim; i++) {
                mean[i] += vec[i];
            }
        }

        for (let i = 0; i < dim; i++) {
            mean[i] /= vectors.length;
        }

        // Normalize mean too
        const magnitude = Math.hypot(...mean);
        if (magnitude > 0) {
            for (let i = 0; i < dim; i++) mean[i] /= magnitude;
        }

        return mean;
    }

    /**
     * Computes Cosine Similarity between two vectors.
     * @param {Float32Array} vecA 
     * @param {Float32Array} vecB 
     */
    cosineSimilarity(vecA, vecB) {
        if (!vecA || !vecB || vecA.length !== vecB.length) return 0;

        // Since vectors are normalized, dot product == cosine similarity
        let dot = 0;
        for (let i = 0; i < vecA.length; i++) {
            dot += vecA[i] * vecB[i];
        }
        return dot;
    }

    /**
     * Computes Cosine Distance (1 - Similarity).
     */
    cosineDistance(vecA, vecB) {
        return 1.0 - this.cosineSimilarity(vecA, vecB);
    }
}

// Export Singleton
export const VectorEngine = new VectorEngineService();
