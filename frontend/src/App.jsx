import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Activity, ShieldAlert, Network, RefreshCw, FileText, Upload, Trash2, ShieldCheck, CheckCircle2, AlertTriangle, AlertCircle, Search, Shield, Zap, Eye, Lock } from 'lucide-react';
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
  const [protoSearchQuery, setProtoSearchQuery] = useState('');
  const [protoFilterRisk, setProtoFilterRisk] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  
  // Capture Controls
  const [captureStatus, setCaptureStatus] = useState({ active: false, packets_captured: 0 });
  const [uploading, setUploading] = useState(false);
  const [actionMessage, setActionMessage] = useState(null);
  
  // Digital asset protection threats
  const [threats, setThreats] = useState(null);
  
  // Custom reset confirmation modal state
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);

  // Timer progress (synced to real 4-hour UTC boundaries)
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

  const fetchThreats = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/threats');
      if (response.ok) {
        const json = await response.json();
        setThreats(json);
      }
    } catch {
      // Keep local defaults
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
        fetchThreats();
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
      await fetchThreats();
      setActionMessage({ type: 'success', text: 'Re-evaluating compliance datasets...' });
    } catch {
      await fetchData();
    }
  };

  // Real 4-hour window progress calculation
  // The window anchors to 4-hour UTC boundaries (00:00, 04:00, 08:00, 12:00, 16:00, 20:00)
  const WINDOW_SECONDS = 4 * 60 * 60; // 14400 seconds

  const computeWindowProgress = useCallback(() => {
    const now = Math.floor(Date.now() / 1000); // current epoch seconds
    const elapsed = now % WINDOW_SECONDS; // seconds elapsed in current 4h window
    return (elapsed / WINDOW_SECONDS) * 100;
  }, [WINDOW_SECONDS]);

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
    fetchThreats();
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
  }, [computeWindowProgress]);

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
    const isBypass = natBypassList.some(nb => nb.ip === asset.ip);
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
    viaGateway: !natBypassList.some(nb => nb.ip === a.ip),
    protosUsed: [...new Set(protocolsList.filter(p => p.ips.includes(a.ip)).map(p => p.proto))]
  }));

  const compliantCount = assetComplianceDetails.filter(a => a.score >= 80).length;
  const partialCount = assetComplianceDetails.filter(a => a.score > 50 && a.score < 80).length;
  const nonCompliantCount = assetComplianceDetails.filter(a => a.score <= 50).length;
  const overallScore = assetComplianceDetails.length > 0
    ? Math.round(assetComplianceDetails.reduce((acc, curr) => acc + curr.score, 0) / assetComplianceDetails.length)
    : null;

  const handleExportCSV = () => {
    let csvContent = "";

    // 1. Report Title & Meta
    csvContent += "=== HTC NETWORK COMPLIANCE DASHBOARD REPORT ===\n";
    csvContent += `Generated: ${new Date().toISOString()}\n`;
    csvContent += `Rolling Time Window: ${data?.window_hours || 4} Hours\n\n`;

    // 2. Section: Internal Asset Compliance Audit
    csvContent += "SECTION 1: INTERNAL ASSET COMPLIANCE AUDIT\n";
    const assetHeaders = ['IP Address', 'Hostname', 'Type', 'Compliance Score', 'Gateway Routing Status', 'Protocols Observed', 'Traffic Volume (Bytes)', 'Flow Count'];
    const assetRows = assetComplianceDetails.map(a => [
      a.ip,
      a.host,
      a.type,
      `${a.score}%`,
      a.viaGateway ? 'COMPLIANT (Via Gateway)' : 'NON-COMPLIANT (NAT Bypass)',
      a.protosUsed.join('|') || 'None',
      a.bytes || 0,
      a.flows || 0
    ]);
    csvContent += [assetHeaders, ...assetRows].map(e => e.join(",")).join("\n") + "\n\n";

    // 3. Section: Configured Gateway Routing
    csvContent += "SECTION 2: CONFIGURED GATEWAY ROUTING\n";
    const gwHeaders = ['Gateway IP', 'Hostname', 'Gateway Type', 'Status'];
    const gwRows = gatewaysList.map(g => [
      g.ip,
      g.host,
      g.type,
      'Active & Monitoring'
    ]);
    csvContent += [gwHeaders, ...gwRows].map(e => e.join(",")).join("\n") + "\n\n";

    // 4. Section: NAT Bypass Alarms
    csvContent += "SECTION 3: NAT BYPASS ALARMS (ROUTING INTEGRITY VIOLATIONS)\n";
    const bypassHeaders = ['Asset IP', 'Hostname', 'Observed NextHop', 'Example Destination IP', 'Risk Classification'];
    const bypassRows = natBypassList.map(b => [
      b.ip,
      b.host,
      b.nexthop,
      b.example_dst,
      b.risk
    ]);
    if (bypassRows.length === 0) {
      csvContent += "No routing integrity violations detected. All internal hosts comply with gateway routing.\n\n";
    } else {
      csvContent += [bypassHeaders, ...bypassRows].map(e => e.join(",")).join("\n") + "\n\n";
    }

    // 5. Section: External Public Peers
    csvContent += "SECTION 4: EXTERNAL PUBLIC PEERS AUDIT\n";
    const peerHeaders = ['Public IP', 'Geo-Location', 'Target Asset IPs', 'Protocols Used', 'Bytes Received', 'Threat Level'];
    const peerRows = publicIPsList.map(p => [
      p.ip,
      p.geo.replace(/,/g, " -"), // Clean commas to avoid breaking columns
      (p.talksto || []).join('|'),
      (p.proto || []).join('|'),
      p.bytesIn || 0,
      `${p.threat}/100`
    ]);
    csvContent += [peerHeaders, ...peerRows].map(e => e.join(",")).join("\n") + "\n\n";

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `htc_netflow_compliance_report_${new Date().toISOString().slice(0,10)}.csv`);
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
            onClick={() => setIsResetModalOpen(true)}
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
          { id: 'protection', label: 'Asset Protection', icon: <Shield className="w-3.5 h-3.5" />, alert: threats?.summary?.critical_count > 0 },
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
            {tab.alert && (
              <span className="h-1.5 w-1.5 rounded-full bg-rose-500 animate-pulse" />
            )}
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
                  natBypassList.map((bypass, idx) => (
                    <div key={idx} className="flex items-center justify-between border-b border-[#1e293b] pb-2">
                      <div className="flex items-center gap-3">
                        <span className="h-2 w-2 rounded-full bg-[#FF3366] animate-pulse"></span>
                        <span className="text-xs font-mono font-medium text-white">{bypass.ip}</span>
                        <span className="text-xs text-[#94A3B8] font-mono">({bypass.host})</span>
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
                          <td className="p-3 text-slate-300 text-[11px]">{(peer.talksto || []).join(', ')}</td>
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

          {/* Filters Bar */}
          <div className="flex flex-col md:flex-row gap-3">
            <div className="relative flex-grow">
              <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
              <input 
                type="text" 
                placeholder="Search protocol, port, or service name..." 
                value={protoSearchQuery}
                onChange={e => setProtoSearchQuery(e.target.value)}
                className="w-full bg-[#111622] border border-[#1e293b] rounded-md py-2 pl-9 pr-4 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-[#00F2FE]"
              />
            </div>
            <select
              value={protoFilterRisk}
              onChange={e => setProtoFilterRisk(e.target.value)}
              className="bg-[#111622] border border-[#1e293b] rounded-md py-2 px-3 text-xs font-mono text-slate-300 focus:outline-none focus:border-[#00F2FE]"
            >
              <option value="">All Risk Levels</option>
              <option value="Low">Low Risk</option>
              <option value="Medium">Medium Risk</option>
              <option value="High">High Risk</option>
              <option value="Critical">Critical Risk</option>
            </select>
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
                    protocolsList
                      .filter(service => {
                        const query = protoSearchQuery.toLowerCase();
                        const matchQuery = service.proto.toLowerCase().includes(query) || 
                                           String(service.port).includes(query) || 
                                           service.service.toLowerCase().includes(query);
                        const matchRisk = !protoFilterRisk || service.risk === protoFilterRisk;
                        return matchQuery && matchRisk;
                      })
                      .map((service, idx) => {
                        const riskBadge = service.risk === 'High' || service.risk === 'Critical' ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' :
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
        <div className="flex flex-col lg:flex-row gap-6 animate-fade-in">
          
          {/* Left Column: Visual Graph */}
          <div className="flex-grow flex flex-col gap-4">
            {/* Sub Navigation controls */}
            <div className="flex gap-2">
              {[
                { id: 'asset-pubip', label: 'Asset ↔ Public IPs' },
                { id: 'asset-proto', label: 'Asset ↔ Protocols' },
                { id: 'gateway-flow', label: 'Gateway Flow Topology' },
              ].map(nav => (
                <button
                  key={nav.id}
                  onClick={() => {
                    setActiveGraph(nav.id);
                    setSelectedNode(null); // Reset detail selector on tab change
                  }}
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
            <div className="h-[450px]">
              <NetworkGraph 
                type={activeGraph} 
                data={data} 
                onSelectNode={setSelectedNode} 
                selectedNode={selectedNode}
              />
            </div>
          </div>

          {/* Right Column: Node Telemetry Inspector Panel */}
          <div className="w-full lg:w-[320px] shrink-0 flex flex-col">
            <div className="bg-[#111622] border border-[#1e293b] rounded-lg p-5 h-full flex flex-col justify-between min-h-[280px] lg:min-h-[450px]">
              {selectedNode ? (
                <div>
                  <div className="border-b border-[#1e293b] pb-3 mb-4">
                    <span className="text-[9px] text-[#00F2FE] font-mono uppercase tracking-wider block mb-1">
                      {selectedNode.role}
                    </span>
                    <h3 className="text-base font-bold text-white font-mono break-all">
                      {selectedNode.ip}
                    </h3>
                    {selectedNode.host && (
                      <span className="text-xs text-[#94A3B8] font-mono mt-1.5 block">
                        Host: <span className="text-slate-300 font-semibold">{selectedNode.host}</span>
                      </span>
                    )}
                  </div>

                  <div className="space-y-4 font-mono text-xs">
                    {/* Geolocation */}
                    {selectedNode.geo && (
                      <div>
                        <span className="text-[#94A3B8] block text-[9px] uppercase tracking-wider">Geolocation</span>
                        <span className="text-slate-100 font-medium">{selectedNode.geo}</span>
                      </div>
                    )}

                    {/* Threat evaluation */}
                    {selectedNode.threat !== undefined && selectedNode.threat > 0 && (
                      <div>
                        <span className="text-[#94A3B8] block text-[9px] uppercase tracking-wider mb-1">Threat Score</span>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                          selectedNode.threat > 50 ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30' :
                          selectedNode.threat > 20 ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' :
                          'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {selectedNode.threat}/100 Risk Rating
                        </span>
                      </div>
                    )}

                    {/* Associated protocols */}
                    {selectedNode.protocols && selectedNode.protocols.length > 0 && (
                      <div>
                        <span className="text-[#94A3B8] block text-[9px] uppercase tracking-wider mb-1.5">Observed Protocols</span>
                        <div className="flex gap-1.5 flex-wrap">
                          {selectedNode.protocols.map((pr, pidx) => (
                            <span key={pidx} className="bg-[#185FA5]/15 text-[#00F2FE] text-[9px] px-1.5 py-0.2 rounded border border-[#185FA5]/30">
                              {pr}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Associated ports */}
                    {selectedNode.ports && selectedNode.ports.length > 0 && (
                      <div>
                        <span className="text-[#94A3B8] block text-[9px] uppercase tracking-wider mb-1">Audited Dest Ports</span>
                        <span className="text-slate-300 block max-h-[60px] overflow-y-auto pr-1">
                          {selectedNode.ports.join(', ')}
                        </span>
                      </div>
                    )}

                    {/* Traffic metrics for assets */}
                    {selectedNode.bytes !== undefined && (
                      <div>
                        <span className="text-[#94A3B8] block text-[9px] uppercase tracking-wider">Metrics</span>
                        <div className="mt-1.5 space-y-1.5">
                          <div className="flex justify-between border-b border-[#1e293b]/40 pb-1 text-slate-300">
                            <span>Traffic:</span>
                            <span className="font-bold text-slate-100">{fmtBytes(selectedNode.bytes)}</span>
                          </div>
                          <div className="flex justify-between border-b border-[#1e293b]/40 pb-1 text-slate-300">
                            <span>Flows:</span>
                            <span className="font-bold text-slate-100">{selectedNode.flows}</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Traffic metrics for peers */}
                    {selectedNode.bytesIn !== undefined && (
                      <div>
                        <span className="text-[#94A3B8] block text-[9px] uppercase tracking-wider">Metrics</span>
                        <div className="mt-1.5 space-y-1.5">
                          <div className="flex justify-between border-b border-[#1e293b]/40 pb-1 text-slate-300">
                            <span>Inbound Bytes:</span>
                            <span className="font-bold text-slate-100">{fmtBytes(selectedNode.bytesIn)}</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Peer connections */}
                    {selectedNode.talksto && selectedNode.talksto.length > 0 && (
                      <div>
                        <span className="text-[#94A3B8] block text-[9px] uppercase tracking-wider mb-1">Target Internal IPs</span>
                        <div className="max-h-[120px] overflow-y-auto space-y-1 pr-1">
                          {selectedNode.talksto.map((targetIp, idx) => (
                            <div key={idx} className="flex justify-between text-slate-300 border-b border-[#1e293b]/40 pb-1 text-[11px]">
                              <span className="text-white font-semibold">{targetIp}</span>
                              <span className="text-[#94A3B8] text-[9px]">({getHostname(targetIp)})</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col justify-center items-center h-full text-center py-10 my-auto">
                  <Network className="w-8 h-8 text-slate-500 mb-3 animate-pulse" />
                  <span className="text-slate-400 font-mono text-xs font-semibold mb-1">Telemetry Inspector</span>
                  <span className="text-slate-500 font-mono text-[10px] max-w-[200px] leading-relaxed">
                    Click any node in the topology visualization to display active telemetry, geolocation, threat levels, and traffic flow details.
                  </span>
                </div>
              )}

              {selectedNode && (
                <button 
                  onClick={() => setSelectedNode(null)}
                  className="w-full mt-4 bg-[#121722] hover:bg-[#1c2436] text-[10px] font-mono text-slate-400 border border-slate-700 py-1.5 rounded transition-colors cursor-pointer"
                >
                  Clear Selection
                </button>
              )}
            </div>
          </div>

        </div>
      )}

      {/* ─── ASSET PROTECTION TAB ─────────────────────────────────────── */}
      {activeTab === 'protection' && (
        <div className="flex flex-col gap-6 animate-fade-in">

          {/* Header */}
          <div className="flex flex-col md:flex-row justify-between md:items-start gap-3">
            <div>
              <h3 className="text-sm font-semibold tracking-tight text-white uppercase tracking-wider font-mono flex items-center gap-2">
                <Shield className="w-4 h-4 text-rose-400" />
                Digital Asset Protection
              </h3>
              <p className="text-[10px] text-[#94A3B8] font-mono mt-0.5">Real-time threat analysis derived from captured network traffic</p>
            </div>
            {threats?.summary && (
              <div className="flex gap-2 flex-wrap">
                <span className="bg-rose-500/15 text-rose-400 border border-rose-500/30 text-[10px] font-mono font-bold px-3 py-1.5 rounded flex items-center gap-1.5">
                  <AlertCircle className="w-3 h-3" />
                  {threats.summary.critical_count} Critical
                </span>
                <span className="bg-amber-500/15 text-amber-400 border border-amber-500/30 text-[10px] font-mono font-bold px-3 py-1.5 rounded flex items-center gap-1.5">
                  <AlertTriangle className="w-3 h-3" />
                  {threats.summary.high_count} High
                </span>
                <span className="bg-blue-500/15 text-blue-400 border border-blue-500/30 text-[10px] font-mono font-bold px-3 py-1.5 rounded flex items-center gap-1.5">
                  <Activity className="w-3 h-3" />
                  {threats.summary.medium_count} Medium
                </span>
              </div>
            )}
          </div>

          {/* Threat type summary strip */}
          {threats?.summary && threats.summary.total_threats > 0 && (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
              {[
                { key: 'PUBLIC_ACCESS',         label: 'Public Access',       icon: <Eye className="w-3.5 h-3.5" />,       color: 'text-amber-400 bg-amber-500/10 border-amber-500/20' },
                { key: 'MALICIOUS_IP',          label: 'Malicious IPs',       icon: <AlertCircle className="w-3.5 h-3.5" />, color: 'text-rose-400 bg-rose-500/10 border-rose-500/20' },
                { key: 'DANGEROUS_PROTOCOL',    label: 'Dangerous Protocols', icon: <Zap className="w-3.5 h-3.5" />,        color: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
                { key: 'PORT_SCAN',             label: 'Port Scans',          icon: <Search className="w-3.5 h-3.5" />,     color: 'text-purple-400 bg-purple-500/10 border-purple-500/20' },
                { key: 'EXCESSIVE_CONNECTIONS', label: 'Excessive Conns',     icon: <Activity className="w-3.5 h-3.5" />,   color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
                { key: 'LATERAL_MOVEMENT',      label: 'Lateral Movement',    icon: <Network className="w-3.5 h-3.5" />,    color: 'text-pink-400 bg-pink-500/10 border-pink-500/20' },
              ].map(item => (
                <div key={item.key} className={`border rounded-lg p-3 flex flex-col items-center gap-1.5 ${item.color}`}>
                  {item.icon}
                  <span className="text-[9px] font-mono uppercase tracking-wider text-center leading-tight">{item.label}</span>
                  <span className="text-lg font-bold font-mono">{threats.summary.by_type[item.key] || 0}</span>
                </div>
              ))}
            </div>
          )}

          {/* Empty state */}
          {(!threats || threats.threats.length === 0) && (
            <div className="bg-gradient-to-r from-emerald-900/10 to-teal-900/10 border border-emerald-500/20 rounded-lg p-10 text-center">
              <div className="flex flex-col items-center gap-3">
                <div className="h-12 w-12 rounded-full bg-emerald-500/10 flex items-center justify-center border border-emerald-500/20">
                  <ShieldCheck className="w-6 h-6 text-emerald-400" />
                </div>
                <h4 className="text-sm font-bold text-white font-mono">
                  {data ? 'No Threats Detected' : 'No Traffic Data Yet'}
                </h4>
                <p className="text-xs text-[#94A3B8] font-mono max-w-md mx-auto leading-relaxed">
                  {data
                    ? 'All captured traffic appears clean. No public IP access, malicious IPs, dangerous protocols, port scans, or lateral movement detected.'
                    : 'Upload a PCAP file or start live capture. The protection engine will automatically scan all flows for threats against your digital assets.'
                  }
                </p>
              </div>
            </div>
          )}

          {/* Per-asset threat cards */}
          {threats?.threats && threats.threats.length > 0 && (
            <div className="flex flex-col gap-4">
              {threats.threats.map((asset, assetIdx) => {
                const borderColor = asset.worst_severity === 'Critical' ? 'border-rose-500/40'
                                  : asset.worst_severity === 'High' ? 'border-amber-500/30'
                                  : 'border-blue-500/20';
                const headerBg = asset.worst_severity === 'Critical' ? 'bg-rose-500/10'
                               : asset.worst_severity === 'High' ? 'bg-amber-500/10'
                               : 'bg-blue-500/10';
                const severityColor = asset.worst_severity === 'Critical' ? 'text-rose-400'
                                    : asset.worst_severity === 'High' ? 'text-amber-400'
                                    : 'text-blue-400';

                return (
                  <div key={assetIdx} className={`bg-[#111622] border rounded-lg overflow-hidden ${borderColor}`}>
                    {/* Asset header */}
                    <div className={`${headerBg} border-b ${borderColor} px-4 py-3 flex items-center justify-between`}>
                      <div className="flex items-center gap-3">
                        <Lock className={`w-4 h-4 ${severityColor}`} />
                        <div>
                          <span className="text-white font-mono font-bold text-sm">{asset.asset_ip}</span>
                          <span className="text-[#94A3B8] font-mono text-[10px] ml-2">({asset.asset_host})</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {asset.critical_count > 0 && (
                          <span className="bg-rose-500/20 text-rose-400 border border-rose-500/30 text-[9px] font-mono font-bold px-2 py-0.5 rounded">
                            {asset.critical_count} CRITICAL
                          </span>
                        )}
                        {asset.high_count > 0 && (
                          <span className="bg-amber-500/20 text-amber-400 border border-amber-500/30 text-[9px] font-mono font-bold px-2 py-0.5 rounded">
                            {asset.high_count} HIGH
                          </span>
                        )}
                        {asset.medium_count > 0 && (
                          <span className="bg-blue-500/20 text-blue-400 border border-blue-500/30 text-[9px] font-mono font-bold px-2 py-0.5 rounded">
                            {asset.medium_count} MEDIUM
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Individual threats */}
                    <div className="divide-y divide-[#1e293b]/40">
                      {asset.threats.map((threat, threatIdx) => {
                        const tColor = threat.severity === 'Critical' ? 'text-rose-400 bg-rose-500/10 border-rose-500/20'
                                     : threat.severity === 'High' ? 'text-amber-400 bg-amber-500/10 border-amber-500/20'
                                     : 'text-blue-400 bg-blue-500/10 border-blue-500/20';
                        const typeIcons = {
                          'PUBLIC_ACCESS': <Eye className="w-3.5 h-3.5" />,
                          'MALICIOUS_IP': <AlertCircle className="w-3.5 h-3.5" />,
                          'DANGEROUS_PROTOCOL': <Zap className="w-3.5 h-3.5" />,
                          'PORT_SCAN': <Search className="w-3.5 h-3.5" />,
                          'EXCESSIVE_CONNECTIONS': <Activity className="w-3.5 h-3.5" />,
                          'LATERAL_MOVEMENT': <Network className="w-3.5 h-3.5" />,
                        };
                        return (
                          <div key={threatIdx} className="px-4 py-3">
                            <div className="flex items-start justify-between gap-3">
                              <div className="flex items-start gap-2.5 min-w-0">
                                <span className={`mt-0.5 flex-shrink-0 flex items-center justify-center rounded p-1 border ${tColor}`}>
                                  {typeIcons[threat.type] || <AlertTriangle className="w-3.5 h-3.5" />}
                                </span>
                                <div className="min-w-0">
                                  <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                                    <span className="text-[10px] font-mono font-bold text-slate-200 uppercase tracking-wider">
                                      {threat.type.replace(/_/g, ' ')}
                                    </span>
                                    {threat.source_ip && (
                                      <span className="text-[9px] font-mono text-[#94A3B8]">← {threat.source_ip}</span>
                                    )}
                                    {threat.source_geo && (
                                      <span className="text-[9px] font-mono text-slate-500">{threat.source_geo}</span>
                                    )}
                                    {threat.source_threat > 0 && (
                                      <span className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border ${tColor}`}>
                                        threat: {threat.source_threat}/100
                                      </span>
                                    )}
                                  </div>
                                  <p className="text-[11px] text-slate-400 font-mono leading-relaxed">{threat.description}</p>
                                </div>
                              </div>
                              <div className="flex-shrink-0">
                                <span className={`text-[9px] font-bold px-2 py-0.5 rounded border font-mono ${tColor}`}>
                                  {threat.severity}
                                </span>
                              </div>
                            </div>
                            {threat.recommendation && (
                              <div className="mt-2 ml-8 bg-[#0c101a] border border-[#1e293b] rounded p-2.5">
                                <span className="text-[9px] font-mono uppercase tracking-wider text-emerald-400 block mb-0.5">Recommendation</span>
                                <p className="text-[10px] font-mono text-slate-300 leading-relaxed">{threat.recommendation}</p>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
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

      {/* Sleek Custom Dark-Themed Reset Confirmation Modal */}
      {isResetModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm animate-fade-in px-4">
          <div className="bg-[#0c101a] border border-slate-800 rounded-xl p-6 w-full max-w-md shadow-2xl transition-all scale-100 select-none">
            <div className="flex items-center space-x-3 text-rose-500 mb-4">
              <AlertTriangle className="h-6 w-6 text-rose-500 animate-pulse" />
              <h3 className="text-lg font-bold text-slate-100 font-mono">Confirm Database Reset</h3>
            </div>
            
            <p className="text-xs md:text-sm text-slate-400 mb-6 leading-relaxed font-mono">
              Are you absolutely sure you want to clear all captured traffic flows and reset the database? This action cannot be undone.
            </p>
            
            <div className="flex justify-end space-x-3 font-mono text-xs">
              <button
                onClick={() => setIsResetModalOpen(false)}
                className="px-4 py-2 font-medium text-slate-400 bg-slate-900/60 border border-slate-800 rounded-lg hover:bg-slate-800 hover:text-slate-200 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  setIsResetModalOpen(false);
                  await handleClearDatabase(); 
                }}
                className="px-4 py-2 font-medium text-white bg-rose-600 rounded-lg hover:bg-rose-500 active:bg-rose-700 shadow-lg shadow-rose-950/20 transition-all cursor-pointer"
              >
                Delete Everything
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Hostname derived purely from the IP last-octet (no hardcoded topology)
function getHostname(ip) {
  if (!ip) return 'unknown';
  const last = ip.split('.').pop();
  return `node-${last}`;
}

export default App;
