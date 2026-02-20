# Surgical-Guard

**Surgical-Guard** is a browser extension designed to act as an "AI Safety Firewall". It protects AI agents (and users) from **Indirect Prompt Injections** by analyzing content on web pages before it is processed by AI tools.

## Features

-   **Deep Content Scanning**: Analyzes text on the page for malicious directives and semantic anomalies.
-   **Surgical Sanitization**: Removes only the malicious parts of the text, preserving the rest of the content.
-   **Structure-Aware**: Understands DOM structure to ensure sanitization doesn't break page layout.
-   **Privacy-Focused**: Analysis runs locally or within the browser's background service worker, keeping data secure.
-   **Scope Detection**: Intelligently identifies email bodies in Gmail to avoid over-scanning.

## Architecture

-   **Manifest V3**: Built on the latest Chrome Extension standard.
-   **React + Vite**: UI built with React for a responsive popup.
-   **Background Worker**: Offloads heavy semantic analysis to the background thread.
-   **Content Script**: Handles DOM manipulation and "surgical" text replacement.
-   **Vector Engine**: Custom lightweight JS-based semantic vector engine for anomalous topic detection.

## Development

### Prerequisites

-   Node.js (v16 or higher)
-   npm

### Setup

1.  Clone the repository.
2.  Install dependencies:
    ```bash
    npm install
    ```

### Build

To create a production build:

```bash
npm run build
```

The output will be in the `dist` directory.

### Install in Chrome

1.  Open Chrome and navigate to `chrome://extensions/`.
2.  Enable **Developer mode** in the top right corner.
3.  Click **Load unpacked**.
4.  Select the `dist` directory created by the build step.

## Usage

1.  Navigate to a page (e.g., Gmail).
2.  The extension will automatically scan specific content (like email bodies).
3.  Click the extension icon to see a report of threats found and sanitized.
4.  You can manually trigger a scan from the popup if needed.
