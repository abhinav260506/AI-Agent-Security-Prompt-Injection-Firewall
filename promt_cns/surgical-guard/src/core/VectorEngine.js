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

        // LRU Cache for Vector Embeddings
        this.cache = new Map();
        this.MAX_CACHE_SIZE = 500;
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
                // Request WebGPU if available, fallback to WASM
                const options = {
                    device: 'webgpu',
                    dtype: 'fp32' // Or fp16 if preferred
                };

                this.pipe = await pipeline('feature-extraction', this.modelName, options);
                console.log("VectorEngine: Model loaded successfully (WebGPU enabled).");
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
        if (!text) return null;

        // 1. Check Cache
        if (this.cache.has(text)) {
            // Move to end (marks as most recently used)
            const cachedVector = this.cache.get(text);
            this.cache.delete(text);
            this.cache.set(text, cachedVector);
            return cachedVector;
        }

        const extractor = await this.init();

        // 2. Compute embedding
        // pooling: 'mean' -> averages token vectors to get sentence vector
        // normalize: true -> L2 normalization for cosine similarity
        const output = await extractor(text, { pooling: 'mean', normalize: true });
        const vectorData = output.data;

        // 3. Update Cache
        this.cache.set(text, vectorData);
        if (this.cache.size > this.MAX_CACHE_SIZE) {
            // Delete oldest (first item in Map iteration order)
            const firstKey = this.cache.keys().next().value;
            this.cache.delete(firstKey);
        }

        return vectorData;
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
