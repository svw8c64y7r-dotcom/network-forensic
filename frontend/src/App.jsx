import React, { useState } from 'react';
import { Upload, FileText, Activity, ShieldAlert, BarChart3, Download } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const api = axios.create({
    baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
});

function App() {
    const [file, setFile] = useState(null);
    const [analyzing, setAnalyzing] = useState(false);
    const [report, setReport] = useState(null);

    const COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#f43f5e', '#f97316', '#eab308', '#22c55e', '#06b6d4'];

    const handleUpload = async (e) => {
        const selectedFile = e.target.files[0];
        if (!selectedFile) return;

        setFile(selectedFile);
        setAnalyzing(true);

        const formData = new FormData();
        formData.append('file', selectedFile);

        try {
            const response = await api.post('/analyze', formData);
            setReport(response.data);
        } catch (error) {
            console.error('Analysis failed', error);
            alert('Analysis failed. Make sure the backend is running.');
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
            link.setAttribute('download', `Forensics_Report_${report.filename}.pdf`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        } catch (error) {
            console.error('Report generation failed', error);
            alert('Failed to generate report.');
        }
    };

    return (
        <div className="max-w-7xl mx-auto p-8 pt-16">
            <header className="mb-12 text-center">
                <motion.h1
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-5xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent mb-4"
                >
                    PCAP Forensics Core
                </motion.h1>
                <p className="text-gray-400 text-lg">Automated Network Traffic Analysis & Forensic Reporting</p>
            </header>

            {!report ? (
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    className="glass p-12 text-center max-w-2xl mx-auto border-dashed border-2 border-white/20"
                >
                    <Upload className="w-16 h-16 mx-auto mb-6 text-blue-400 opacity-50" />
                    <h2 className="text-2xl font-semibold mb-2">Upload PCAP for Analysis</h2>
                    <p className="text-gray-400 mb-8">Drag and drop your network trace files here</p>

                    <label className="bg-blue-600 hover:bg-blue-500 px-8 py-3 rounded-full font-medium cursor-pointer transition-colors inline-block">
                        {analyzing ? 'Analyzing...' : 'Select File'}
                        <input type="file" className="hidden" onChange={handleUpload} disabled={analyzing} />
                    </label>
                </motion.div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    {/* Risk Level Card */}
                    <div className="glass p-6 col-span-1 border-t-4 border-t-red-500">
                        <div className="flex items-center gap-4 mb-4">
                            <ShieldAlert className={report.risk.score > 50 ? "text-red-500" : "text-yellow-500"} />
                            <h3 className="text-xl font-bold">Threat Assessment</h3>
                        </div>
                        <div className="text-4xl font-bold mb-2">{report.risk.score}%</div>
                        <p className="text-gray-400 mb-4">Risk Level: <span className={report.risk.level === 'High' ? "text-red-400 font-bold" : "text-yellow-400"}>{report.risk.level}</span></p>
                        <div className="space-y-2">
                            {report.risk.reasons.map((reason, idx) => (
                                <div key={idx} className="text-xs bg-white/5 p-2 rounded border border-white/10 opacity-80">
                                    ⚠️ {reason}
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="glass p-6 col-span-1">
                        <div className="flex items-center gap-4 mb-4">
                            <FileText className="text-blue-400" />
                            <h3 className="text-xl font-bold">File Integrity</h3>
                        </div>
                        <p className="text-gray-400 text-sm mb-2">Filename:</p>
                        <p className="text-white font-mono text-xs truncate mb-4">{report.filename}</p>
                        <button
                            onClick={handleDownload}
                            className="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl transition-all font-semibold flex items-center justify-center gap-2 shadow-lg shadow-blue-900/20"
                        >
                            <Download size={18} /> Export PDF Report
                        </button>
                    </div>

                    <div className="glass p-6 col-span-1">
                        <div className="flex items-center gap-4 mb-4">
                            <Activity className="text-purple-400" />
                            <h3 className="text-xl font-bold">Protocol Breakdown</h3>
                        </div>
                        <div className="h-40 w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={report.protocols_chart}>
                                    <XAxis dataKey="protocol" hide />
                                    <Tooltip
                                        contentStyle={{ backgroundColor: '#18181b', border: '1px solid #333', borderRadius: '8px' }}
                                        itemStyle={{ color: '#fff' }}
                                    />
                                    <Bar dataKey="frames">
                                        {report.protocols_chart.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </div>

                    <div className="glass p-8 col-span-full xl:col-span-2">
                        <div className="flex items-center gap-4 mb-6">
                            <BarChart3 className="text-green-400" />
                            <h3 className="text-2xl font-bold">Protocol Hierarchy Details</h3>
                        </div>
                        <pre className="bg-black/40 p-6 rounded-xl overflow-x-auto text-xs text-gray-300 font-mono border border-white/5 max-h-96">
                            {report.protocol_hierarchy}
                        </pre>
                    </div>

                    <div className="glass p-8 col-span-full xl:col-span-1">
                        <div className="flex items-center gap-4 mb-6">
                            <Activity className="text-blue-400" />
                            <h3 className="text-2xl font-bold">Top Talkers</h3>
                        </div>
                        <div className="overflow-x-auto">
                            <table className="w-full text-left text-sm">
                                <thead>
                                    <tr className="border-b border-white/10 text-gray-400">
                                        <th className="pb-3 font-medium">Source / Destination</th>
                                        <th className="pb-3 font-medium text-right">Bytes</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-white/5">
                                    {report.top_talkers.map((host, idx) => (
                                        <tr key={idx} className="group">
                                            <td className="py-3">
                                                <div className="text-white font-mono text-xs">{host.src}</div>
                                                <div className="text-gray-500 text-[10px]">↔ {host.dst}</div>
                                            </td>
                                            <td className="py-3 text-right">
                                                <div className="text-blue-400 font-bold">{(host.total_bytes / 1024).toFixed(1)} KB</div>
                                                <div className="text-gray-500 text-[10px]">{host.total_packets} pkts</div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default App;
