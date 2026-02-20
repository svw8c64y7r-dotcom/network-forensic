import React, { useState } from 'react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { Upload, FileText, Activity, Shield, AlertTriangle, Download, BarChart3, Binary, Search, Network } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
});

const COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#6366f1'];

function App() {
    const [file, setFile] = useState(null);
    const [analyzing, setAnalyzing] = useState(false);
    const [report, setReport] = useState(null);

    const handleUpload = async (e) => {
        const uploadedFile = e.target.files[0];
        if (!uploadedFile) return;

        setFile(uploadedFile);
        setAnalyzing(true);
        setReport(null);

        const formData = new FormData();
        formData.append('file', uploadedFile);

        try {
            const response = await api.post('/analyze', formData);
            setReport(response.data);
        } catch (error) {
            console.error('Analysis failed:', error);
            alert('Analysis failed. Make sure the backend is running and you have set VITE_API_URL if in production.');
        } finally {
            setAnalyzing(false);
        }
    };

    const handleDownload = async () => {
        try {
            const response = await api.post('/generate_report', report, {
                responseType: 'blob',
            });
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `Forensic_Report_${report.filename}.pdf`);
            document.body.appendChild(link);
            link.click();
        } catch (error) {
            console.error('Download failed:', error);
        }
    };

    return (
        <div className="min-h-screen bg-[#0a0a0c] text-white p-8 font-sans selection:bg-blue-500/30">
            <div className="fixed inset-0 bg-[radial-gradient(circle_at_50%_0%,_#1d1d2b_0%,_transparent_50%)] pointer-events-none" />

            <header className="mb-16 text-center relative pt-8">
                <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="inline-block p-3 rounded-2xl bg-blue-500/10 border border-blue-500/20 mb-6 shadow-[0_0_50px_-12px_rgba(59,130,246,0.3)]"
                >
                    <Shield className="w-10 h-10 text-blue-400" />
                </motion.div>
                <motion.h1
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-7xl font-black bg-gradient-to-r from-blue-400 via-indigo-500 to-purple-600 bg-clip-text text-transparent mb-4 tracking-tighter"
                >
                    AetherTrace
                </motion.h1>
                <p className="text-gray-400 text-xl font-medium opacity-60 tracking-wide">Advanced PCAP Forensics Intelligence Platform</p>
            </header>

            <main className="max-w-7xl mx-auto relative">
                <div className="glass p-12 mb-12 text-center group transition-all duration-500 hover:border-blue-500/30">
                    <input
                        type="file"
                        id="pcap-upload"
                        className="hidden"
                        accept=".pcap,.pcapng"
                        onChange={handleUpload}
                        disabled={analyzing}
                    />
                    <label htmlFor="pcap-upload" className="cursor-pointer block">
                        <motion.div
                            whileHover={{ scale: 1.02 }}
                            whileTap={{ scale: 0.98 }}
                            className="flex flex-col items-center gap-6"
                        >
                            <div className="p-8 rounded-full bg-white/5 border border-white/10 group-hover:bg-blue-500/10 group-hover:border-blue-500/20 transition-all duration-500 shadow-inner">
                                {analyzing ? (
                                    <Activity className="w-16 h-16 text-blue-400 animate-pulse" />
                                ) : (
                                    <Upload className="w-16 h-16 text-gray-400 group-hover:text-blue-400 transition-colors" />
                                )}
                            </div>
                            <div>
                                <h3 className="text-3xl font-bold mb-2 tracking-tight">Upload PCAP for Analysis</h3>
                                <p className="text-gray-500 font-medium">Drag and drop your network trace files here</p>
                            </div>
                        </motion.div>
                    </label>
                    {analyzing && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className="mt-8 flex items-center justify-center gap-3 text-blue-400 font-bold tracking-widest uppercase text-sm"
                        >
                            <div className="w-2 h-2 rounded-full bg-blue-400 animate-ping" />
                            Deciphering Traffic Patterns...
                        </motion.div>
                    )}
                </div>

                <AnimatePresence>
                    {report && (
                        <motion.div
                            initial={{ opacity: 0, y: 40 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="grid grid-cols-1 xl:grid-cols-3 gap-8"
                        >
                            <div className="glass p-8 col-span-1 xl:col-span-2 space-y-8">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-4">
                                        <FileText className="text-blue-400 w-8 h-8" />
                                        <h2 className="text-3xl font-bold tracking-tight">{report.filename}</h2>
                                    </div>
                                    <button
                                        onClick={handleDownload}
                                        className="flex items-center gap-3 bg-blue-600 hover:bg-blue-500 px-6 py-3 rounded-xl font-bold transition-all shadow-lg shadow-blue-900/20 active:scale-95"
                                    >
                                        <Download className="w-5 h-5" /> Generate PDF Report
                                    </button>
                                </div>

                                <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
                                    <div className="bg-white/5 p-6 rounded-2xl border border-white/5">
                                        <p className="text-gray-500 text-sm font-bold uppercase mb-2">Total Packets</p>
                                        <p className="text-3xl font-black">{report.protocols_chart.reduce((acc, curr) => acc + curr.packets, 0).toLocaleString()}</p>
                                    </div>
                                    <div className="bg-white/5 p-6 rounded-2xl border border-white/5">
                                        <p className="text-gray-500 text-sm font-bold uppercase mb-2">Risk Score</p>
                                        <p className={`text-3xl font-black ${report.risk.level === 'High' ? 'text-red-400' : report.risk.level === 'Medium' ? 'text-yellow-400' : 'text-green-400'}`}>
                                            {report.risk.score}/100
                                        </p>
                                    </div>
                                    <div className="bg-white/5 p-6 rounded-2xl border border-white/5">
                                        <p className="text-gray-500 text-sm font-bold uppercase mb-2">Protocol Count</p>
                                        <p className="text-3xl font-black">{report.protocols_chart.length}</p>
                                    </div>
                                    <div className="bg-white/5 p-6 rounded-2xl border border-white/5">
                                        <p className="text-gray-500 text-sm font-bold uppercase mb-2">Status</p>
                                        <p className="text-3xl font-black text-blue-400">Verified</p>
                                    </div>
                                </div>

                                <div>
                                    <h3 className="text-2xl font-bold mb-6 flex items-center gap-3">
                                        <BarChart3 className="text-blue-400" /> Protocol Distribution
                                    </h3>
                                    <div className="h-80 w-full bg-black/20 rounded-3xl p-6 border border-white/5">
                                        <ResponsiveContainer width="100%" height="100%">
                                            <BarChart data={report.protocols_chart}>
                                                <XAxis
                                                    dataKey="protocol"
                                                    stroke="#4b5563"
                                                    fontSize={12}
                                                    tickLine={false}
                                                    axisLine={false}
                                                />
                                                <YAxis
                                                    stroke="#4b5563"
                                                    fontSize={12}
                                                    tickLine={false}
                                                    axisLine={false}
                                                    tickFormatter={(value) => `${value}`}
                                                />
                                                <Tooltip
                                                    contentStyle={{ backgroundColor: '#1a1a1f', border: '1px solid #333', borderRadius: '12px' }}
                                                    cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                                                />
                                                <Bar dataKey="packets" radius={[6, 6, 0, 0]}>
                                                    {report.protocols_chart.map((entry, index) => (
                                                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                                    ))}
                                                </Bar>
                                            </BarChart>
                                        </ResponsiveContainer>
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-8">
                                <div className={`glass p-8 border-l-4 transition-all duration-500 shadow-xl ${report.risk.level === 'High' ? 'border-l-red-500 shadow-red-900/10' :
                                        report.risk.level === 'Medium' ? 'border-l-yellow-500 shadow-yellow-900/10' :
                                            'border-l-green-500 shadow-green-900/10'
                                    }`}>
                                    <div className="flex items-center gap-4 mb-6">
                                        <AlertTriangle className={report.risk.level === 'High' ? 'text-red-400' : report.risk.level === 'Medium' ? 'text-yellow-400' : 'text-green-400'} />
                                        <h3 className="text-2xl font-bold">Threat Assessment</h3>
                                    </div>
                                    <div className="space-y-6">
                                        <div>
                                            <div className="flex justify-between items-end mb-2">
                                                <span className="text-gray-400 text-sm font-bold uppercase">Security Risk</span>
                                                <span className={`text-2xl font-black ${report.risk.level === 'High' ? 'text-red-400' : report.risk.level === 'Medium' ? 'text-yellow-400' : 'text-green-400'}`}>
                                                    {report.risk.level.toUpperCase()}
                                                </span>
                                            </div>
                                            <div className="h-4 bg-white/5 rounded-full overflow-hidden border border-white/5">
                                                <motion.div
                                                    initial={{ width: 0 }}
                                                    animate={{ width: `${report.risk.score}%` }}
                                                    className={`h-full ${report.risk.level === 'High' ? 'bg-red-500' : report.risk.level === 'Medium' ? 'bg-yellow-500' : 'bg-green-500'} shadow-[0_0_20px_rgba(0,0,0,0.5)]`}
                                                />
                                            </div>
                                        </div>
                                        <div className="space-y-3">
                                            <p className="text-gray-400 text-sm font-bold uppercase tracking-widest">Findings:</p>
                                            {report.risk.reasons.map((reason, i) => (
                                                <div key={i} className="flex gap-4 p-4 rounded-xl bg-white/5 border border-white/5 hover:bg-white/10 transition-colors">
                                                    <Binary className="w-5 h-5 text-blue-400 shrink-0" />
                                                    <p className="text-sm text-gray-300 font-medium leading-relaxed">{reason}</p>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                </div>

                                <div className="glass p-8">
                                    <div className="flex items-center gap-4 mb-6">
                                        <Activity className="text-blue-400" />
                                        <h3 className="text-2xl font-bold">Top Talkers</h3>
                                    </div>
                                    <div className="space-y-1">
                                        {report.top_talkers.map((host, idx) => (
                                            <div key={idx} className="flex items-center justify-between p-4 rounded-xl hover:bg-white/5 transition-all group">
                                                <div className="space-y-1">
                                                    <div className="text-sm font-mono font-bold text-gray-200">{host.src}</div>
                                                    <div className="text-[10px] text-gray-500 font-bold uppercase tracking-tighter flex items-center gap-1">
                                                        <Network className="w-3 h-3" /> {host.dst}
                                                    </div>
                                                </div>
                                                <div className="text-right">
                                                    <div className="text-blue-400 font-black text-sm">{(host.total_bytes / 1024).toFixed(1)} KB</div>
                                                    <div className="text-[10px] text-gray-500 font-bold">{host.total_packets} PKTS</div>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </div>

                            <div className="glass p-8 col-span-full">
                                <div className="flex items-center gap-4 mb-6">
                                    <BarChart3 className="text-green-400" />
                                    <h3 className="text-2xl font-bold uppercase tracking-tight">Full Protocol Hierarchy</h3>
                                </div>
                                <pre className="bg-[#000]/40 p-10 rounded-3xl overflow-x-auto text-xs text-blue-100/60 font-mono leading-relaxed border border-white/5 backdrop-blur-3xl scrollbar-thin scrollbar-thumb-white/10">
                                    {report.protocol_hierarchy}
                                </pre>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </main>
        </div>
    );
}

export default App;
