import React, { useState, useEffect } from 'react';

export default function Popup() {
    const [status, setStatus] = useState('IDLE'); // IDLE, SCANNING, SAFE, THREATS
    const [results, setResults] = useState(null);
    const [logs, setLogs] = useState([]);

    // Load logs on mount
    useEffect(() => {
        chrome.storage.local.get(['activityLog'], (result) => {
            if (result.activityLog) {
                setLogs(result.activityLog);
            }
        });

        // Clear badge on open
        chrome.action.setBadgeText({ text: '' });
    }, []);

    const handleScan = async () => {
        setStatus('SCANNING');
        setResults(null);

        // Get active tab
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        if (!tab) {
            setStatus('ERROR');
            setResults({ error: "No active tab found" });
            return;
        }

        // Send message to content script
        try {
            chrome.tabs.sendMessage(tab.id, { type: 'MANUAL_SCAN' }, (response) => {
                if (chrome.runtime.lastError) {
                    setStatus('ERROR');
                    setResults({ error: "Could not connect to page. Try reloading the page." });
                    return;
                }

                if (response && response.status === 'COMPLETE') {
                    // Manual scan finished, wait a bit for logs to update if threats were found? 
                    // Or just let the user see the local result.
                    // For now, simple completion.
                    setStatus('IDLE'); // Reset to allowed re-scan
                }
            });
        } catch (e) {
            setStatus('ERROR');
            setResults({ error: e.message });
        }
    };

    const handleClearLogs = () => {
        chrome.storage.local.set({ activityLog: [] }, () => {
            setLogs([]);
        });
    };

    // Format Date: "Feb 18, 10:30 PM"
    const formatDate = (isoString) => {
        try {
            const date = new Date(isoString);
            return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ', ' +
                date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
        } catch (e) { return isoString; }
    };

    return (
        <div className="p-4 w-96 bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 h-[600px] flex flex-col">
            <header className="flex items-center justify-between mb-6">
                <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-purple-600">
                    Surgical-Guard
                </h1>
                <div className={`px-2 py-1 rounded text-xs font-bold ${status === 'SAFE' ? 'bg-green-100 text-green-800' :
                    status === 'THREATS' ? 'bg-red-100 text-red-800' :
                        'bg-gray-200 text-gray-800'
                    }`}>
                    {status}
                </div>
            </header>

            <div className="main-action flex justify-center mb-6">
                <button
                    onClick={handleScan}
                    disabled={status === 'SCANNING'}
                    className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded-lg shadow-lg transition-all transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed w-full"
                >
                    {status === 'SCANNING' ? 'Scanning...' : 'Scan Current Page'}
                </button>
            </div>

            {/* ERROR / STATUS AREA */}
            <div className="status-area mb-6">
                {status === 'ERROR' && results && (
                    <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-lg text-center">
                        <p className="text-yellow-700 text-sm">{results.error}</p>
                    </div>
                )}
            </div>

            {/* ACTIVITY LOG SECTION */}
            <div className="flex-1 overflow-hidden flex flex-col">
                <div className="flex justify-between items-center mb-3 border-b pb-1">
                    <h2 className="text-sm font-bold text-gray-500 uppercase tracking-wide">
                        Threat Activity Log
                    </h2>
                    {logs.length > 0 && (
                        <button
                            onClick={handleClearLogs}
                            className="text-[10px] text-red-500 hover:text-red-700 underline cursor-pointer"
                        >
                            Clear History
                        </button>
                    )}
                </div>

                <div className="activity-list overflow-y-auto custom-scrollbar flex-1 space-y-3 pr-1">
                    {logs.length === 0 ? (
                        <p className="text-center text-gray-400 text-xs py-4">No threats recorded yet.</p>
                    ) : (
                        logs.map(log => (
                            <div key={log.id} className="bg-white p-3 rounded-md border-l-4 border-l-red-500 shadow-sm border border-gray-100">
                                <div className="flex justify-between items-start mb-1">
                                    <h3 className="font-bold text-sm text-gray-800 truncate w-48" title={log.title}>
                                        {log.title || 'Unknown Page'}
                                    </h3>
                                    <span className="text-[10px] text-gray-400 whitespace-nowrap">
                                        {formatDate(log.timestamp)}
                                    </span>
                                </div>
                                <div className="flex justify-between items-center">
                                    <span className="text-xs font-semibold text-red-600 bg-red-50 px-2 py-0.5 rounded">
                                        {log.threatCount} Threat{log.threatCount > 1 ? 's' : ''}
                                    </span>
                                    <span className="text-[10px] text-gray-500 italic truncate max-w-[120px]">
                                        {log.details}
                                    </span>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            </div>

            <footer className="mt-4 text-center text-xs text-gray-400 border-t pt-4">
                AI Safety Firewall Active • Clipboard Protected 📋
            </footer>
        </div>
    );
}
