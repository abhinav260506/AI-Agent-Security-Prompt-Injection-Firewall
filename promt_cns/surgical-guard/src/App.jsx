import { useState, useEffect } from 'react';
import './App.css';

function App() {
    const [status, setStatus] = useState('secure'); // secure, warning, danger
    const [threats, setThreats] = useState([]);
    const [scanning, setScanning] = useState(false);
    const [activeTabId, setActiveTabId] = useState(null);

    useEffect(() => {
        // 1. Get the current active tab ID
        if (typeof chrome !== 'undefined' && chrome.tabs) {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0]?.id) {
                    setActiveTabId(tabs[0].id);
                }
            });
        }

        // 2. Listen for messages, but filter by tab ID
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
            const listener = (message, sender, sendResponse) => {
                // Ignore messages from other tabs (or background tasks not related to this tab)
                if (activeTabId && sender.tab && sender.tab.id !== activeTabId) {
                    return;
                }

                if (message.type === 'THREATS_DETECTED') {
                    setStatus('danger');
                    setThreats(message.payload.matches);
                    setScanning(false);
                } else if (message.type === 'SAFE') {
                    setStatus('secure');
                    setThreats([]);
                    setScanning(false);
                }
            };

            chrome.runtime.onMessage.addListener(listener);
            return () => chrome.runtime.onMessage.removeListener(listener);
        }
    }, [activeTabId]); // Re-bind listener when activeTabId is set

    const handleScan = () => {
        setScanning(true);
        setThreats([]);
        setStatus('secure'); // reset

        if (activeTabId) {
            chrome.tabs.sendMessage(activeTabId, { type: "MANUAL_SCAN" });
        } else {
            // Fallback if ID not set yet (rare)
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0]?.id) {
                    chrome.tabs.sendMessage(tabs[0].id, { type: "MANUAL_SCAN" });
                }
            });
        }

        // Fallback timeout
        setTimeout(() => setScanning(false), 2000);
    };

    return (
        <div className="w-80 min-h-[450px] bg-slate-900 text-white p-5 font-sans flex flex-col">
            <header className="flex items-center justify-between mb-6 border-b border-slate-700 pb-4">
                <h1 className="text-xl font-bold bg-gradient-to-r from-blue-400 to-cyan-300 bg-clip-text text-transparent">
                    Surgical-Guard
                </h1>
                <div className={`w-3 h-3 rounded-full ${status === 'secure' ? 'bg-green-500 shadow-[0_0_10px_#22c55e]' : 'bg-red-500 shadow-[0_0_10px_#ef4444]'}`}></div>
            </header>

            <div className="status-card mb-6 text-center flex-grow">
                {status === 'secure' ? (
                    <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700 backdrop-blur-sm transition-all duration-300">
                        <div className="text-5xl mb-2">{scanning ? '🔍' : '🛡️'}</div>
                        <h2 className="text-lg font-semibold text-green-400">{scanning ? 'Analyzing...' : 'System Secure'}</h2>
                        <p className="text-sm text-slate-400 mt-1">
                            {scanning ? 'Scanning semantic context...' : 'No active threats detected.'}
                        </p>
                    </div>
                ) : (
                    <div className="p-4 bg-red-900/20 rounded-xl border border-red-500/50 backdrop-blur-sm transition-all duration-300 animate-pulse">
                        <div className="text-5xl mb-2">⚠️</div>
                        <h2 className="text-lg font-semibold text-red-400">Threat Detected</h2>
                        <p className="text-sm text-red-200 mt-1">{threats.length} potential injection attempts blocked.</p>
                    </div>
                )}
            </div>

            <button
                onClick={handleScan}
                disabled={scanning}
                className="w-full py-3 mb-6 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 rounded-lg font-bold shadow-lg transition-all"
            >
                {scanning ? 'Surgically Scanning...' : 'Scan Page'}
            </button>

            <div className="log-section max-h-40 overflow-y-auto">
                <h3 className="text-xs font-uppercase tracking-wider text-slate-500 mb-3 sticky top-0 bg-slate-900 pb-2">ACTIVITY LOG</h3>
                <div className="space-y-2">
                    {!scanning && threats.length === 0 && (
                        <div className="text-sm text-slate-600 italic text-center py-2">Ready to scan.</div>
                    )}
                    {threats.map((t, i) => (
                        <div key={i} className="text-xs bg-slate-800 p-2 rounded border-l-2 border-red-500 text-left mb-2">
                            <span className="font-bold text-red-300 block">{t.type}</span>
                            <span className="text-slate-400 block mb-1" title={t.subtype}>{t.subtype}</span>
                            {t.match && (
                                <div className="bg-black/30 p-1 rounded text-slate-500 font-mono break-all leading-tight">
                                    "{t.match.substring(0, 60)}{t.match.length > 60 ? '...' : ''}"
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}

export default App;
