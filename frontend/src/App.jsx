import React, { useState, useEffect, useRef } from 'react';
import { Activity, ShieldAlert, Network, RefreshCw, FileText, Upload, Trash2, ShieldCheck, CheckCircle2, AlertTriangle, AlertCircle, Search } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, PieChart, Pie } from 'recharts';
import NetworkGraph from './NetworkGraph';



const CHART_COLORS = ['#185FA5','#534AB7','#3B6D11','#854F0B','#0F6E56','#A32D2D','#3C3489','#5F5E5A'];
const PROTO_COLORS = { 'TCP': '#8B5CF6', 'UDP': '#3B82F6', 'ICMP': '#EC4899', 'Other': '#64748B' };

function fmtBytes(n) {
  if (!n) return '0 B';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + ' MB';
  if (n >= 1000) return (n / 1000).toFixed(1) + ' KB';
  return n + ' B';
}

function App() {
  const [data, setData] = useState(null);
  const [isOffline, setIsOffline] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [activeGraph, setActiveGraph] = useState('asset-pubip');
  
  // Search & Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('');
  
  // Capture Controls
  const [captureStatus, setCaptureStatus] = useState({ active: false, packets_captured: 0 });
  const [uploading, setUploading] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);
  
  // Timer progress (simulating 4-hour window countdown)
  const [progressWidth, setProgressWidth] = useState(0);
  const fileInputRef = useRef(null);

  const fetchData = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/report');
      if (!response.ok) throw new Error('API Error');
      const json = await response.json();
      
      setData(json);
      setIsOffline(false);
    } catch {
      console.warn('Backend API offline.');
      setData(null);
      setIsOffline(true);
    }
  };

  const fetchCaptureStatus = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/capture/status');
      if (response.ok) {
        const status = await response.json();
        setCaptureStatus(status);
      }
    } catch {
      // Keep local defaults
    }
  };

  const handleStartCapture = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/capture/start', { method: 'POST' });
      if (res.ok) {
        setActionMessage({ type: 'success', text: 'Live packet capture and flow aggregation initiated.' });
        fetchCaptureStatus();
      }
    } catch {
      setActionMessage({ type: 'error', text: 'Backend connection offline. Cannot start live capture.' });
    }
  };

  const handleStopCapture = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/capture/stop', { method: 'POST' });
      if (res.ok) {
        const body = await res.json();
        setActionMessage({ type: 'success', text: `Capture stopped. Saved ${body.captured || 0} flow records to DuckDB.` });
        fetchCaptureStatus();
        fetchData();
      }
    } catch {
      setActionMessage({ type: 'error', text: 'Backend connection offline. Cannot stop capture.' });
    }
  };

  const handleClearDatabase = async () => {
    if (!window.confirm("Clear all captured traffic and reset the database?")) return;
    try {
      const res = await fetch('http://localhost:8000/api/clear', { method: 'POST' });
      if (res.ok) {
        // Immediately wipe React state so UI goes blank right away
        setData(null);
        setCaptureStatus({ active: false, packets_captured: 0 });
        setActionMessage({ type: 'success', text: 'Database cleared and any active capture stopped.' });
        // Then fetch the fresh (empty) state from backend to confirm
        await fetchData();
        await fetchCaptureStatus();
      }
    } catch {
      setActionMessage({ type: 'error', text: 'Failed to reset database.' });
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    
    setUploading(true);
    setActionMessage({ type: 'info', text: `Parsing PCAP data: ${file.name}...` });
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
      const res = await fetch('http://localhost:8000/api/upload-pcap', {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        const body = await res.json();
        setActionMessage({ type: 'success', text: body.message });
        fetchData();
      } else {
        const body = await res.json();
        setActionMessage({ type: 'error', text: body.detail || 'Failed to parse PCAP file.' });
      }
    } catch {
      setActionMessage({ type: 'error', text: 'Connection failed during upload.' });
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleForceRefresh = async () => {
    try {
      await fetch('http://localhost:8000/api/refresh');
      await fetchData();
      setActionMessage({ type: 'success', text: 'Re-evaluating compliance datasets...' });
    } catch {
      await fetchData();
    }
  };

  // Real 4-hour window progress calculation
  // The window anchors to 4-hour UTC boundaries (00:00, 04:00, 08:00, 12:00, 16:00, 20:00)
  const WINDOW_SECONDS = 4 * 60 * 60; // 14400 seconds

  const computeWindowProgress = () => {
    const now = Math.floor(Date.now() / 1000); // current epoch seconds
    const elapsed = now % WINDOW_SECONDS; // seconds elapsed in current 4h window
    return (elapsed / WINDOW_SECONDS) * 100;
  };

  const computeTimeRemaining = () => {
    const now = Math.floor(Date.now() / 1000);
    const elapsed = now % WINDOW_SECONDS;
    const remaining = WINDOW_SECONDS - elapsed;
    const h = Math.floor(remaining / 3600);
    const m = Math.floor((remaining % 3600) / 60);
    return `${h}h ${m}m remaining`;
  };

  useEffect(() => {
    fetchData();
    fetchCaptureStatus();
    setProgressWidth(computeWindowProgress());
    
    // Poll backend every 15 seconds for data refresh
    const dataInterval = setInterval(() => {
      fetchData();
      fetchCaptureStatus();
    }, 15000);

    // Update the progress bar every 30 seconds (smooth enough for a 4h bar)
    const progressInterval = setInterval(() => {
      const progress = computeWindowProgress();
      setProgressWidth(progress);
      // When a new 4-hour window starts (progress resets near 0), force a data refresh
      if (progress < 0.1) {
        fetchData();
      }
    }, 30000);

    return () => {
      clearInterval(dataInterval);
      clearInterval(progressInterval);
    };
  }, []);

  // Compute stats metrics dynamically
  const assetsList = data?.unique_assets || [];
  const publicIPsList = data?.public_ips || [];
  const gatewaysList = data?.gateways || [];
  const natBypassList = data?.natBypass || [];
  const protocolsList = data?.protoPort || [];
  const absentIPsList = data?.absentIPs || [];

  const totalBytes = assetsList.reduce((acc, curr) => acc + (curr.bytes || 0), 0) + 
                     publicIPsList.reduce((acc, curr) => acc + (curr.bytesIn || 0), 0);
  const totalFlows = protocolsList.reduce((acc, curr) => acc + (curr.flows || 0), 0);
  const uniqueProtocols = [...new Set(protocolsList.map(p => p.proto))].length;

  // Recharts Top Talkers data formatting
  const sortedTalkers = [...assetsList]
    .sort((a, b) => (b.bytes || 0) - (a.bytes || 0))
    .slice(0, 8)
    .map(a => ({ ip: a.ip, bytes: a.bytes, host: a.host }));

  // Recharts Protocol Distribution data formatting
  const protocolDataMap = {};
  protocolsList.forEach(p => {
    protocolDataMap[p.proto] = (protocolDataMap[p.proto] || 0) + p.flows;
  });
  const protocolChartData = Object.entries(protocolDataMap).map(([name, value]) => ({ name, value }));

  // Recharts Ports Frequency horizontal bar data formatting
  const portChartData = [...protocolsList]
    .sort((a, b) => b.flows - a.flows)
    .slice(0, 8)
    .map(p => ({
      name: p.port === 0 ? 'ICMP' : `${p.port}/${p.proto}`,
      flows: p.flows
    }));

  // Dynamic Compliance calculations
  const calculateAssetCompliance = (asset) => {
    const isBypass = natBypassList.includes(asset.ip);
    const assetProtos = protocolsList.filter(p => p.ips.includes(asset.ip));
    const activePortsCount = assetProtos.length;

    let score = 100;
    if (isBypass) score -= 30; // Direct route bypass
    
    // Check if asset runs High Risk ports
    const runsHighRisk = assetProtos.some(p => p.risk === 'High');
    if (runsHighRisk) score -= 20;

    // Check if asset runs excessive active port count
    if (activePortsCount > 5) score -= 10;
    if (activePortsCount === 0) score = 50; // Inactive status

    return Math.max(40, score);
  };

  const assetComplianceDetails = assetsList.map(a => ({
    ...a,
    score: calculateAssetCompliance(a),
    viaGateway: !natBypassList.includes(a.ip),
    protosUsed: [...new Set(protocolsList.filter(p => p.ips.includes(a.ip)).map(p => p.proto))]
  }));

  const compliantCount = assetComplianceDetails.filter(a => a.score >= 80).length;
  const partialCount = assetComplianceDetails.filter(a => a.score > 50 && a.score < 80).length;
  const nonCompliantCount = assetComplianceDetails.filter(a => a.score <= 50).length;
  const overallScore = assetComplianceDetails.length > 0
    ? Math.round(assetComplianceDetails.reduce((acc, curr) => acc + curr.score, 0) / assetComplianceDetails.length)
    : null;

  const handleExportCSV = () => {
    const headers = ['IP Address', 'Hostname', 'Type', 'Compliance %', 'Via Gateway', 'Protocols Used', 'Traffic (Bytes)'];
    const rows = assetComplianceDetails.map(a => [
      a.ip,
      a.host,
      a.type,
      `${a.score}%`,
      a.viaGateway ? 'Yes' : 'NAT Bypass',
      a.protosUsed.join('|'),
      a.bytes
    ]);

    const csvContent = [headers, ...rows].map(e => e.join(",")).join("\n");
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `netflow_compliance_report_${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="min-h-screen bg-[#080B10] text-[#E2E8F0] px-4 py-6 md:p-8 flex flex-col font-sans select-none">
      
      {/* Dynamic Offline / Connection Status Banner */}
      {isOffline && (
        <div className="mb-4 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-xs md:text-sm text-amber-400 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 animate-pulse" />
          <span><strong>Backend Offline:</strong> Python backend (http://localhost:8000) is currently unreachable. Start backend with `python main.py` to upload PCAPs or start live capture.</span>
        </div>
      )}

      {/* Global Actions Notification Toast */}
      {actionMessage && (
        <div className={`mb-4 border rounded-lg p-3 text-xs md:text-sm flex items-center justify-between gap-2 transition-all ${
          actionMessage.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
          actionMessage.type === 'error' ? 'bg-rose-500/10 border-rose-500/30 text-rose-400' :
          'bg-[#121722] border-slate-700 text-slate-300'
        }`}>
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4" />
            <span>{actionMessage.text}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="hover:text-white font-mono text-xs">✕</button>
        </div>
      )}

      {/* Dashboard Top Telemetry & Control Panel */}
      <header className="mb-6 flex flex-col lg:flex-row justify-between lg:items-center gap-4 border-b border-[#1e293b] pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-[#00F2FE] animate-pulse"></span>
            <h1 className="text-xl md:text-2xl font-bold tracking-tight text-white font-sans">NetFlow Analytics Dashboard</h1>
          </div>
          <p className="text-xs text-[#94A3B8] font-mono mt-1">HTC Internship — Network Intelligence Platform</p>
        </div>

        {/* Real-time Tool bar */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* File Upload Input */}
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileUpload} 
            accept=".pcap,.pcapng" 
            className="hidden" 
          />
          <button 
            disabled={uploading}
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-2 bg-[#121722] hover:bg-[#1c2436] text-xs font-mono text-slate-200 border border-slate-700 px-3.5 py-2 rounded-md cursor-pointer transition-colors disabled:opacity-50"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>{uploading ? 'Parsing...' : 'Upload PCAP'}</span>
          </button>

          {/* Live Sniffer Toggle */}
          <button
            onClick={captureStatus.active ? handleStopCapture : handleStartCapture}
            className={`flex items-center gap-2 text-xs font-mono border px-3.5 py-2 rounded-md cursor-pointer transition-all ${
              captureStatus.active 
              ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 hover:bg-rose-500/30' 
              : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${captureStatus.active ? 'bg-rose-500 animate-ping' : 'bg-emerald-400'}`}></span>
            <span>{captureStatus.active ? `Capturing (${captureStatus.packets_captured})` : 'Start Live Capture'}</span>
          </button>

          {/* Clear DB */}
          <button
            onClick={handleClearDatabase}
            className="flex items-center gap-2 bg-[#121722] hover:bg-rose-950/20 hover:text-rose-400 hover:border-rose-500/30 text-xs font-mono text-slate-400 border border-slate-700 px-3.5 py-2 rounded-md cursor-pointer transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </header>

      {/* Progress timeline bar — synced to real 4-hour UTC boundaries */}
      <div className="bg-[#111622] border border-[#1e293b] rounded-lg p-3.5 flex flex-col md:flex-row md:items-center gap-4 mb-6">
        <div className="flex items-center gap-2 justify-between md:justify-start">
          <span className="text-[11px] font-mono text-[#94A3B8] uppercase tracking-wider">4h window progress</span>
          <span className="bg-[#185FA5]/20 text-[#00F2FE] border border-[#185FA5]/30 text-[10px] font-mono font-medium px-2 py-0.5 rounded">
            ⏱ Window: 4h
          </span>
        </div>
        <div className="flex-grow h-2 bg-[#080B10] rounded-full overflow-hidden border border-[#1e293b]">
          <div className="h-full bg-gradient-to-r from-[#185FA5] to-[#00F2FE] rounded-full transition-all duration-[30s]" style={{ width: `${progressWidth}%` }}></div>
        </div>
        <div className="flex items-center justify-between md:justify-end gap-4">
          <span className="text-xs font-mono text-[#94A3B8] min-w-[140px] text-right">
            {Math.round(progressWidth)}% — {computeTimeRemaining()}
          </span>
          <button 
            onClick={handleForceRefresh} 
            className="flex items-center gap-1.5 bg-[#1a2336] hover:bg-[#25324d] text-white text-xs font-mono border border-[#2a3c5a] px-3.5 py-1.5 rounded transition-colors"
          >
            <RefreshCw className="w-3 h-3 animate-spin-slow" /> Re-Evaluate
          </button>
        </div>
      </div>

      {/* Dynamic Data Warning / Action Required Banner */}
      {assetsList.length === 0 && (
        <div className="mb-6 bg-gradient-to-r from-blue-900/10 to-indigo-900/10 border border-blue-500/20 rounded-lg p-5 text-center shadow-lg">
          <div className="flex flex-col items-center gap-3">
            <div className="h-9 w-9 rounded-full bg-blue-500/10 flex items-center justify-center border border-blue-500/20">
              <Activity className="w-4 h-4 text-[#00F2FE] animate-pulse" />
            </div>
            <h2 className="text-sm font-bold text-white font-mono">No NetFlow Traffic Data Available</h2>
            <p className="text-xs text-[#94A3B8] font-mono max-w-lg mx-auto leading-relaxed">
              The database is currently empty. To analyze network assets, gateways, protocols, NAT bypasses, and compliance metrics, please upload a NetFlow PCAP file or start a live capture simulation.
            </p>
            <div className="flex gap-3 mt-1.5">
              <button 
                onClick={() => fileInputRef.current?.click()}
                className="bg-[#00F2FE]/10 hover:bg-[#00F2FE]/20 text-[#00F2FE] border border-[#00F2FE]/30 text-xs font-mono px-4 py-2 rounded transition-all cursor-pointer"
              >
                Upload PCAP
              </button>
              <button 
                onClick={captureStatus.active ? handleStopCapture : handleStartCapture}
                className="bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-mono px-4 py-2 rounded transition-all cursor-pointer"
              >
                {captureStatus.active ? 'Stop Capture' : 'Start Live Capture'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Segment Navigation Tabs */}
      <div className="flex border-b border-[#1e293b] mb-6 overflow-x-auto gap-1">
        {[
          { id: 'overview', label: 'Overview', icon: <Activity className="w-3.5 h-3.5" /> },
          { id: 'assets', label: 'Assets & IPs', icon: <ShieldAlert className="w-3.5 h-3.5" /> },
          { id: 'protocols', label: 'Protocols & Ports', icon: <Network className="w-3.5 h-3.5" /> },
          { id: 'graphs', label: 'Relationship Graphs', icon: <Network className="w-3.5 h-3.5" /> },
          { id: 'compliance', label: 'Compliance Report', icon: <FileText className="w-3.5 h-3.5" /> },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 py-2.5 px-4 text-xs font-mono border-b-2 font-medium cursor-pointer transition-all ${
              activeTab === tab.id 
              ? 'border-[#00F2FE] text-white bg-[#111622]/30' 
              : 'border-transparent text-[#94A3B8] hover:text-white hover:bg-[#111622]/10'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* TAB CONTENT AREAS */}
      {activeTab === 'overview' && (
        <div className="flex flex-col gap-6 animate-fade-in">
          
          {/* Main metrics grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3.5">
            {[
              { label: 'Internal Assets', val: assetsList.length, color: 'text-[#3B82F6]' },
              { label: 'Public IPs', val: publicIPsList.length, color: 'text-[#8B5CF6]' },
              { label: 'Gateways', val: gatewaysList.length, color: 'text-[#E5A93C]' },
              { label: 'NAT Bypass IPs', val: natBypassList.length, color: natBypassList.length > 0 ? 'text-[#FF3366]' : 'text-emerald-400' },
              { label: 'Protocols', val: uniqueProtocols, color: 'text-[#3B82F6]' },
              { label: 'Unique Ports', val: protocolsList.length, color: 'text-[#8B5CF6]' },
              { label: 'Total Flows', val: totalFlows.toLocaleString(), color: 'text-[#3B6D11]' },
              { label: 'Total Bytes', val: fmtBytes(totalBytes), color: 'text-slate-100' },
            ].map((metric, i) => (
              <div key={i} className="bg-[#111622] border border-[#1e293b] rounded-lg p-3 flex flex-col justify-between">
                <span className="text-[10px] text-[#94A3B8] font-mono uppercase tracking-wider block mb-1">{metric.label}</span>
                <span className={`text-lg md:text-xl font-bold font-mono tracking-tight ${metric.color}`}>{metric.val}</span>
              </div>
            ))}
          </div>

          {/* Gateway & NAT analyses columns */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Gateway analysis card */}
            <div className="bg-[#111622] border border-[#1e293b] rounded-lg p-5">
              <h3 className="text-sm font-semibold tracking-tight text-white mb-4 uppercase tracking-wider font-mono">Gateway Analysis</h3>
              <div className="space-y-3.5">
                {gatewaysList.length === 0 ? (
                  <div className="text-slate-500 font-mono text-xs py-2 text-center">
                    No active gateways identified in traffic yet.
                  </div>
                ) : (
                  gatewaysList.map((gw, idx) => (
                    <div key={idx} className="flex items-center justify-between border-b border-[#1e293b] pb-2">
                      <div className="flex items-center gap-3">
                        <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
                        <span className="text-xs font-mono font-medium text-white">{gw.ip}</span>
                        <span className="text-xs text-[#94A3B8] font-mono">({gw.host})</span>
                      </div>
                      <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-mono px-2 py-0.5 rounded">Active Gateway</span>
                    </div>
                  ))
                )}
              </div>
              <p className="text-[11px] text-[#94A3B8] font-mono mt-4">Configured NAT gateway identified from traffic routing mapping, flow symmetries, and internal outbound connections.</p>
            </div>

            {/* NAT bypass card */}
            <div className="bg-[#111622] border border-[#1e293b] rounded-lg p-5">
              <h3 className="text-sm font-semibold tracking-tight text-white mb-4 uppercase tracking-wider font-mono">NAT Bypass Alerts</h3>
              <div className="space-y-3">
                {assetsList.length === 0 ? (
                  <div className="text-slate-500 font-mono text-xs py-2 text-center">
                    Awaiting traffic data.
                  </div>
                ) : natBypassList.length === 0 ? (
                  <div className="text-emerald-400 font-mono text-xs flex items-center gap-2 py-2">
                    <CheckCircle2 className="w-4 h-4" /> No gateway bypass flows detected.
                  </div>
                ) : (
                  natBypassList.map((ip, idx) => (
                    <div key={idx} className="flex items-center justify-between border-b border-[#1e293b] pb-2">
                      <div className="flex items-center gap-3">
                        <span className="h-2 w-2 rounded-full bg-[#FF3366] animate-pulse"></span>
                        <span className="text-xs font-mono font-medium text-white">{ip}</span>
                        <span className="text-xs text-[#94A3B8] font-mono">({getHostname(ip)})</span>
                      </div>
                      <span className="bg-rose-500/10 text-[#FF3366] border border-rose-500/30 text-[10px] font-mono px-2 py-0.5 rounded uppercase tracking-wider">NAT Bypass</span>
                    </div>
                  ))
                )}
              </div>
              <p className="text-[11px] text-[#94A3B8] font-mono mt-4">Outbound packets observed bypassing the primary gateway. Indicates potential direct internet routing or split-tunnel configuration anomalies.</p>
            </div>
          </div>

          {/* Top Talkers Bytes chart */}
          <div className="bg-[#111622] border border-[#1e293b] rounded-lg p-5">
            <h3 className="text-sm font-semibold tracking-tight text-white mb-4 uppercase tracking-wider font-mono">Top talkers (bytes)</h3>
            {sortedTalkers.length === 0 ? (
              <div className="h-[240px] w-full flex flex-col justify-center items-center border border-dashed border-slate-800 rounded bg-[#0a0d14]">
                <span className="text-slate-600 font-mono text-xs">No talker traffic data available</span>
              </div>
            ) : (
              <>
                <div className="h-[240px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={sortedTalkers}>
                      <XAxis dataKey="ip" stroke="#64748B" fontSize={10} fontClassName="font-mono" />
                      <YAxis stroke="#64748B" fontSize={10} fontClassName="font-mono" tickFormatter={fmtBytes} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#111622', borderColor: '#1e293b' }} 
                        labelClassName="text-slate-400 font-mono text-xs" 
                        formatter={(val) => [fmtBytes(val), 'Traffic']}
                      />
                      <Bar dataKey="bytes" fill="#185FA5">
                        {sortedTalkers.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1.5 font-mono text-[10px] text-[#94A3B8] mt-4 border-t border-[#1e293b] pt-3">
                  {sortedTalkers.map((t, idx) => (
                    <div key={idx} className="flex items-center gap-1">
                      <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: CHART_COLORS[idx % CHART_COLORS.length] }}></span>
                      <span>{t.ip} ({t.host})</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {activeTab === 'assets' && (
        <div className="flex flex-col gap-6 animate-fade-in">
          {/* Filters Bar */}
          <div className="flex flex-col md:flex-row gap-3">
            <div className="relative flex-grow">
              <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
              <input 
                type="text" 
                placeholder="Search IP or hostname..." 
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full bg-[#111622] border border-[#1e293b] rounded-md py-2 pl-9 pr-4 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-[#00F2FE]"
              />
            </div>
            <select
              value={filterType}
              onChange={e => setFilterType(e.target.value)}
              className="bg-[#111622] border border-[#1e293b] rounded-md py-2 px-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-[#00F2FE]"
            >
              <option value="">All Types</option>
              <option value="Internal">Internal</option>
              <option value="Gateway">Gateway</option>
            </select>
          </div>

          {/* Internal Assets Table */}
          <div className="bg-[#111622] border border-[#1e293b] rounded-lg overflow-hidden">
            <div className="p-4 border-b border-[#1e293b] flex items-center justify-between">
              <h3 className="text-xs font-semibold text-white tracking-wider uppercase font-mono">Discovered Assets & Gateways</h3>
              <span className="bg-[#1e293b] text-slate-300 px-2 py-0.5 rounded text-[10px] font-mono">
                {assetsList.length + gatewaysList.length} Found
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="bg-[#0c101a] border-b border-[#1e293b] text-[#94A3B8] font-medium uppercase text-[10px] tracking-wider">
                    <th className="p-3">IP Address</th>
                    <th className="p-3">Hostname</th>
                    <th className="p-3">Type</th>
                    <th className="p-3">Active Protocols</th>
                    <th className="p-3 text-right">Traffic</th>
                    <th className="p-3 text-right">Flows</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e293b]/40">
                  {gatewaysList.length === 0 && assetsList.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="p-8 text-center text-slate-500 font-mono">
                        No assets or gateways discovered yet.
                      </td>
                    </tr>
                  ) : (
                    <>
                      {/* Map Gateways first */}
                      {gatewaysList
                        .filter(g => g.ip.includes(searchQuery) || g.host.toLowerCase().includes(searchQuery.toLowerCase()))
                        .filter(() => !filterType || filterType === 'Gateway')
                        .map((gw, idx) => (
                          <tr key={`gw-${idx}`} className="hover:bg-[#1c2436]/20 transition-colors">
                            <td className="p-3 text-white font-bold">{gw.ip}</td>
                            <td className="p-3 text-slate-400">{gw.host}</td>
                            <td className="p-3">
                              <span className="bg-[#EAF3DE]/10 text-emerald-400 border border-emerald-500/20 text-[9px] font-semibold px-2 py-0.5 rounded uppercase">Gateway</span>
                            </td>
                            <td className="p-3 text-[#94A3B8]">SNMP | UDP</td>
                            <td className="p-3 text-right text-[#94A3B8]">0 B</td>
                            <td className="p-3 text-right text-[#94A3B8]">0</td>
                          </tr>
                        ))
                      }
                      {/* Map Assets */}
                      {assetsList
                        .filter(a => a.ip.includes(searchQuery) || a.host.toLowerCase().includes(searchQuery.toLowerCase()))
                        .filter(() => !filterType || filterType === 'Internal')
                        .map((asset, idx) => {
                          const protosUsed = [...new Set(protocolsList.filter(p => p.ips.includes(asset.ip)).map(p => p.proto))];
                          return (
                            <tr key={`asset-${idx}`} className="hover:bg-[#1c2436]/20 transition-colors">
                              <td className="p-3 text-white font-semibold">{asset.ip}</td>
                              <td className="p-3 text-slate-400">{asset.host}</td>
                              <td className="p-3">
                                <span className="bg-[#E6F1FB]/10 text-[#00F2FE] border border-[#185FA5]/30 text-[9px] font-semibold px-2 py-0.5 rounded uppercase">Internal</span>
                              </td>
                              <td className="p-3">
                                <div className="flex gap-1 flex-wrap">
                                  {protosUsed.map((pr, pidx) => (
                                    <span key={pidx} className="bg-[#1e293b] text-slate-300 text-[9px] px-1.5 py-0.2 rounded">{pr}</span>
                                  ))}
                                </div>
                              </td>
                              <td className="p-3 text-right text-slate-200">{fmtBytes(asset.bytes)}</td>
                              <td className="p-3 text-right text-slate-300">{asset.flows}</td>
                            </tr>
                          );
                        })
                      }
                    </>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Public IPs Geolocation & Risk Analysis */}
          <div className="bg-[#111622] border border-[#1e293b] rounded-lg overflow-hidden">
            <div className="p-4 border-b border-[#1e293b]">
              <h3 className="text-xs font-semibold text-white tracking-wider uppercase font-mono">Public IPs Communicating with Network</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="bg-[#0c101a] border-b border-[#1e293b] text-[#94A3B8] font-medium uppercase text-[10px] tracking-wider">
                    <th className="p-3">Public IP</th>
                    <th className="p-3">Geolocation</th>
                    <th className="p-3">Target Assets</th>
                    <th className="p-3">Protocols</th>
                    <th className="p-3 text-right">Traffic (Bytes In)</th>
                    <th className="p-3 text-right">Threat Score</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e293b]/40">
                  {publicIPsList.length === 0 ? (
                    <tr>
                      <td colSpan="6" className="p-8 text-center text-slate-500 font-mono">
                        No public IPs communicating with the network yet.
                      </td>
                    </tr>
                  ) : (
                    publicIPsList.map((peer, idx) => {
                      const badgeColor = peer.threat > 50 ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                                         peer.threat > 20 ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                                         'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
                      return (
                        <tr key={idx} className="hover:bg-[#1c2436]/20 transition-colors">
                          <td className="p-3 text-white font-semibold">{peer.ip}</td>
                          <td className="p-3 text-slate-400">{peer.geo}</td>
                          <td className="p-3 text-slate-300 text-[11px]">{peer.talks.join(', ')}</td>
                          <td className="p-3">
                            <div className="flex gap-1 flex-wrap">
                              {peer.proto.map((pr, pidx) => (
                                <span key={pidx} className="bg-[#185FA5]/10 text-[#00F2FE] text-[9px] px-1.5 py-0.2 rounded border border-[#185FA5]/30">{pr}</span>
                              ))}
                            </div>
                          </td>
                          <td className="p-3 text-right text-slate-200">{fmtBytes(peer.bytesIn)}</td>
                          <td className="p-3 text-right">
                            <span className={`text-[9px] font-bold px-2 py-0.5 rounded font-mono ${badgeColor}`}>{peer.threat}/100</span>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'protocols' && (
        <div className="flex flex-col gap-6 animate-fade-in">
          
          {/* Recharts Pie and Ports usage charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Protocol distribution pie chart */}
            <div className="bg-[#111622] border border-[#1e293b] rounded-lg p-5">
              <h3 className="text-sm font-semibold tracking-tight text-white mb-4 uppercase tracking-wider font-mono">Protocol Distribution</h3>
              {protocolChartData.length === 0 ? (
                <div className="h-[200px] w-full flex items-center justify-center border border-dashed border-slate-800 rounded bg-[#0a0d14]">
                  <span className="text-slate-600 font-mono text-xs">No protocol data available</span>
                </div>
              ) : (
                <>
                  <div className="h-[200px] w-full flex items-center justify-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={protocolChartData}
                          cx="50%"
                          cy="50%"
                          innerRadius={50}
                          outerRadius={75}
                          paddingAngle={4}
                          dataKey="value"
                        >
                          {protocolChartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={PROTO_COLORS[entry.name] || PROTO_COLORS['Other']} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#111622', borderColor: '#1e293b', labelClassName: 'font-mono' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="flex flex-wrap gap-x-4 gap-y-1.5 justify-center font-mono text-[10px] text-[#94A3B8] mt-2">
                    {protocolChartData.map((p, idx) => (
                      <div key={idx} className="flex items-center gap-1.5">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: PROTO_COLORS[p.name] || PROTO_COLORS['Other'] }}></span>
                        <span>{p.name}: {p.value.toLocaleString()} flows</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>

            {/* Port frequency horizontal bar chart */}
            <div className="bg-[#111622] border border-[#1e293b] rounded-lg p-5">
              <h3 className="text-sm font-semibold tracking-tight text-white mb-4 uppercase tracking-wider font-mono">Port Usage Frequency</h3>
              {portChartData.length === 0 ? (
                <div className="h-[200px] w-full flex items-center justify-center border border-dashed border-slate-800 rounded bg-[#0a0d14]">
                  <span className="text-slate-600 font-mono text-xs">No port data available</span>
                </div>
              ) : (
                <div className="h-[200px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={portChartData} layout="vertical">
                      <XAxis type="number" stroke="#64748B" fontSize={10} fontClassName="font-mono" />
                      <YAxis dataKey="name" type="category" stroke="#64748B" fontSize={10} fontClassName="font-mono" width={60} />
                      <Tooltip contentStyle={{ backgroundColor: '#111622', borderColor: '#1e293b' }} />
                      <Bar dataKey="flows" fill="#185FA5" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </div>

          {/* Protocols and Ports details grid */}
          <div className="bg-[#111622] border border-[#1e293b] rounded-lg overflow-hidden">
            <div className="p-4 border-b border-[#1e293b]">
              <h3 className="text-xs font-semibold text-white tracking-wider uppercase font-mono">Protocol & Port Service Audit</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="bg-[#0c101a] border-b border-[#1e293b] text-[#94A3B8] font-medium uppercase text-[10px] tracking-wider">
                    <th className="p-3">Protocol</th>
                    <th className="p-3">Port</th>
                    <th className="p-3">Service Name</th>
                    <th className="p-3 text-right">Flows Count</th>
                    <th className="p-3 text-right">Bytes Count</th>
                    <th className="p-3 text-right">Endpoint Bindings</th>
                    <th className="p-3 text-right">Risk Assessment</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e293b]/40">
                  {protocolsList.length === 0 ? (
                    <tr>
                      <td colSpan="7" className="p-8 text-center text-slate-500 font-mono">
                        No active protocols or ports audited yet.
                      </td>
                    </tr>
                  ) : (
                    protocolsList.map((service, idx) => {
                      const riskBadge = service.risk === 'High' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
                                        service.risk === 'Medium' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                                        'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
                      return (
                        <tr key={idx} className="hover:bg-[#1c2436]/20 transition-colors">
                          <td className="p-3">
                            <span className="bg-[#1e293b] text-slate-300 text-[10px] font-bold px-2 py-0.5 rounded">{service.proto}</span>
                          </td>
                          <td className="p-3 text-white">{service.port || '—'}</td>
                          <td className="p-3 text-slate-400">{service.service}</td>
                          <td className="p-3 text-right text-slate-300">{service.flows.toLocaleString()}</td>
                          <td className="p-3 text-right text-slate-200">{fmtBytes(service.bytes)}</td>
                          <td className="p-3 text-right text-slate-400">{service.ips.length} assets</td>
                          <td className="p-3 text-right">
                            <span className={`text-[9px] font-bold px-2 py-0.5 rounded ${riskBadge}`}>{service.risk}</span>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'graphs' && (
        <div className="flex flex-col gap-4 animate-fade-in">
          {/* Sub Navigation controls */}
          <div className="flex gap-2">
            {[
              { id: 'asset-pubip', label: 'Asset ↔ Public IPs' },
              { id: 'asset-proto', label: 'Asset ↔ Protocols' },
              { id: 'gateway-flow', label: 'Gateway Flow Topology' },
            ].map(nav => (
              <button
                key={nav.id}
                onClick={() => setActiveGraph(nav.id)}
                className={`py-1.5 px-3.5 text-xs font-mono border rounded transition-all cursor-pointer ${
                  activeGraph === nav.id 
                  ? 'bg-[#185FA5]/20 text-[#00F2FE] border-[#185FA5]/40 font-medium' 
                  : 'bg-[#111622] text-[#94A3B8] border-slate-800 hover:text-white'
                }`}
              >
                {nav.label}
              </button>
            ))}
          </div>

          {/* SVG Graph Component container */}
          <div className="h-[480px]">
            <NetworkGraph type={activeGraph} data={data} />
          </div>
        </div>
      )}

      {activeTab === 'compliance' && (
        <div className="flex flex-col gap-6 animate-fade-in">
          
          {/* Header Row */}
          <div className="flex flex-col md:flex-row justify-between md:items-center gap-3">
            <div>
              <h3 className="text-sm font-semibold tracking-tight text-white uppercase tracking-wider font-mono">NetFlow Compliance Report</h3>
              <p className="text-[10px] text-[#94A3B8] font-mono mt-0.5">Calculated over sliding 4-hour capture integrity audits</p>
            </div>
            <button 
              onClick={handleExportCSV}
              className="flex items-center gap-2 bg-[#121722] hover:bg-[#1a2336] text-xs font-mono text-slate-200 border border-slate-700 px-4 py-2 rounded transition-colors self-start md:self-auto cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5 rotate-180" /> Export CSV
            </button>
          </div>

          {/* Compliance Metrics Grid */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
            {[
              { label: 'Compliant Assets', val: compliantCount, icon: <ShieldCheck className="w-5 h-5 text-emerald-400" /> },
              { label: 'Partial Compliance', val: partialCount, icon: <AlertTriangle className="w-5 h-5 text-amber-400" /> },
              { label: 'Non-Compliant', val: nonCompliantCount, icon: <AlertCircle className="w-5 h-5 text-rose-400" /> },
              { label: 'Absent Assets', val: absentIPsList.length, icon: <AlertCircle className="w-5 h-5 text-rose-500" /> },
              { label: 'Overall Score', val: overallScore !== null ? `${overallScore}%` : '—', icon: <Activity className="w-5 h-5 text-[#00F2FE]" />, textClass: 'text-[#00F2FE]' },
            ].map((metric, i) => (
              <div key={i} className="bg-[#111622] border border-[#1e293b] rounded-lg p-4 flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-[#94A3B8] font-mono uppercase tracking-wider block mb-1">{metric.label}</span>
                  <span className={`text-xl font-bold font-mono tracking-tight ${metric.textClass || 'text-white'}`}>{metric.val}</span>
                </div>
                {metric.icon}
              </div>
            ))}
          </div>

          {/* Compliance Status Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3.5">
            {assetComplianceDetails.length === 0 ? (
              <div className="col-span-full bg-[#111622] border border-dashed border-slate-800 rounded-lg p-8 text-center text-slate-500 font-mono text-xs">
                No internal assets evaluated. Run a traffic capture to audit compliance.
              </div>
            ) : (
              assetComplianceDetails.map((asset, idx) => {
                const borderClass = asset.score >= 80 ? 'border-emerald-500/20' : 
                                    asset.score > 50 ? 'border-amber-500/20' : 
                                    'border-rose-500/20 warning-pulse';
                const textClass = asset.score >= 80 ? 'text-emerald-400' : 
                                  asset.score > 50 ? 'text-amber-400' : 
                                  'text-rose-400';
                const progressBg = asset.score >= 80 ? 'bg-emerald-400' : 
                                   asset.score > 50 ? 'bg-amber-400' : 
                                   'bg-rose-400';
                
                return (
                  <div key={idx} className={`bg-[#111622] border rounded-lg p-4 flex flex-col justify-between ${borderClass}`}>
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-white font-mono font-bold text-sm">{asset.ip}</span>
                        <span className={`text-xs font-mono font-bold ${textClass}`}>{asset.score}%</span>
                      </div>
                      <span className="text-[10px] text-[#94A3B8] font-mono block mb-3">{asset.host}</span>
                      
                      <div className="space-y-1.5 font-mono text-[10px]">
                        <div className="flex justify-between text-[#94A3B8] border-b border-[#1e293b]/40 pb-1">
                          <span>Protocols</span>
                          <span className="text-slate-300 font-semibold">{asset.protosUsed.join(', ') || 'None'}</span>
                        </div>
                        <div className="flex justify-between text-[#94A3B8] border-b border-[#1e293b]/40 pb-1">
                          <span>Via Gateway</span>
                          <span className="flex items-center gap-1">
                            <span className={`h-1.5 w-1.5 rounded-full ${asset.viaGateway ? 'bg-emerald-400' : 'bg-amber-400'}`}></span>
                            <span className={asset.viaGateway ? 'text-emerald-400 font-semibold' : 'text-amber-400 font-semibold'}>
                              {asset.viaGateway ? 'Yes' : 'Bypass'}
                            </span>
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="mt-4">
                      <div className="h-1 bg-[#080B10] rounded-full overflow-hidden">
                        <div className={`h-full ${progressBg} rounded-full`} style={{ width: `${asset.score}%` }}></div>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Absent Assets panel */}
          <div className="bg-[#111622] border border-[#1e293b] rounded-lg overflow-hidden">
            <div className="p-4 border-b border-[#1e293b]">
              <h3 className="text-xs font-semibold text-white tracking-wider uppercase font-mono">Expected assets absent in current 4h traffic</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="bg-[#0c101a] border-b border-[#1e293b] text-[#94A3B8] font-medium uppercase text-[10px] tracking-wider">
                    <th className="p-3">IP Address</th>
                    <th className="p-3">Hostname</th>
                    <th className="p-3">Last Seen</th>
                    <th className="p-3">Expected Protocol Profile</th>
                    <th className="p-3 text-right">Compliance Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e293b]/40">
                  {absentIPsList.length === 0 ? (
                    <tr>
                      <td colSpan="5" className="p-8 text-center text-slate-500 font-mono">
                        {assetsList.length === 0 ? "Awaiting traffic capture to identify absent assets." : "No expected assets are absent (all are active)."}
                      </td>
                    </tr>
                  ) : (
                    absentIPsList.map((absent, idx) => (
                      <tr key={idx} className="hover:bg-[#1c2436]/20 transition-colors">
                        <td className="p-3 text-slate-400 font-bold">{absent.ip}</td>
                        <td className="p-3 text-slate-500">{getHostname(absent.ip)}</td>
                        <td className="p-3 text-slate-400">{absent.lastSeen}</td>
                        <td className="p-3 text-slate-400">{absent.expectedProtos}</td>
                        <td className="p-3 text-right">
                          <span className="bg-rose-500/10 text-rose-500 border border-rose-500/20 text-[9px] font-bold px-2 py-0.5 rounded uppercase">Absent</span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Global hostname resolver helper (matches backend configuration)
function getHostname(ip) {
  const HOSTNAME_MAP = {
    '10.0.0.10': 'web-server-01',
    '10.0.0.11': 'web-server-02',
    '10.0.0.20': 'db-server-01',
    '10.0.0.21': 'db-server-02',
    '10.0.0.30': 'app-server-01',
    '10.0.0.40': 'mail-server',
    '10.0.0.50': 'file-server',
    '10.0.1.100': 'workstation-A',
    '10.0.1.101': 'workstation-B',
    '10.0.1.102': 'workstation-C',
    '192.168.10.5': 'dev-machine',
    '10.0.0.1': 'core-router',
    '10.0.0.2': 'firewall-01',
  };
  return HOSTNAME_MAP[ip] || `node-${ip.split('.').pop()}`;
}

export default App;
