import React, { useState, useEffect, useRef, useCallback } from 'react';
import { 
  Activity, ShieldAlert, Network, RefreshCw, FileText, Upload, Trash2, 
  ShieldCheck, CheckCircle2, AlertTriangle, AlertCircle, Search, Shield, 
  Zap, Eye, Lock, Server, Cpu, Database, Globe, Download, Plus, 
  ChevronRight, ArrowUpRight, Clock, Filter, Radio, Layers, Check, X
} from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, 
  Cell, PieChart, Pie, Legend 
} from 'recharts';
import NetworkGraph from './NetworkGraph';

const CHART_COLORS = ['#00F2FE', '#3B82F6', '#8B5CF6', '#EC4899', '#F59E0B', '#10B981', '#EF4444', '#64748B'];
const PROTO_COLORS = { 'TCP': '#8B5CF6', 'UDP': '#3B82F6', 'ICMP': '#EC4899', 'Other': '#64748B' };

function fmtBytes(n) {
  if (!n || isNaN(n)) return '0 B';
  if (n >= 1000000000) return (n / 1000000000).toFixed(2) + ' GB';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + ' MB';
  if (n >= 1000) return (n / 1000).toFixed(1) + ' KB';
  return n + ' B';
}

function fmtBps(bps) {
  if (!bps || isNaN(bps)) return '0 bps';
  if (bps >= 1000000) return (bps / 1000000).toFixed(2) + ' Mbps';
  if (bps >= 1000) return (bps / 1000).toFixed(1) + ' Kbps';
  return bps.toFixed(0) + ' bps';
}

function App() {
  const [data, setData] = useState(null);
  const [threats, setThreats] = useState(null);
  const [audit, setAudit] = useState(null);
  const [assetsInventory, setAssetsInventory] = useState([]);
  const [storedReports, setStoredReports] = useState([]);
  const [selectedReportId, setSelectedReportId] = useState('live');
  const [storedReport, setStoredReport] = useState(null);
  const [isOffline, setIsOffline] = useState(false);
  
  // Navigation & Time Window
  const [activeTab, setActiveTab] = useState('overview');
  const [activeGraph, setActiveGraph] = useState('topology');
  const [timeWindow, setTimeWindow] = useState('4h');
  const [refreshInterval, setRefreshInterval] = useState(15); // seconds
  
  // Search & Filtering
  const [searchQuery, setSearchQuery] = useState('');
  const [threatFilter, setThreatFilter] = useState('ALL');
  const [selectedNode, setSelectedNode] = useState(null);
  
  // Live Capture & Upload States
  const [captureStatus, setCaptureStatus] = useState({ active: false, packets_captured: 0 });
  const [uploading, setUploading] = useState(false);
  const [shiftToNow, setShiftToNow] = useState(true);
  const [actionMessage, setActionMessage] = useState(null);
  const [isResetModalOpen, setIsResetModalOpen] = useState(false);
  const [isAddAssetModalOpen, setIsAddAssetModalOpen] = useState(false);
  
  // New Asset Form State
  const [newAsset, setNewAsset] = useState({
    ip: '', hostname: '', expected_protocols: 'TCP,UDP',
    risk_tier: 'Medium', criticality: 'Tier 2 (Business)',
    department: 'Engineering', compliance_scope: 'PCI-DSS, NIST'
  });

  // 4-Hour Real-Time Progress Countdown
  const [windowProgress, setWindowProgress] = useState(0);
  const [timeRemainingStr, setTimeRemainingStr] = useState('');
  const fileInputRef = useRef(null);

  // ── Fetch Operations ───────────────────────────────────────────────────────
  const fetchReport = useCallback(async (windowVal = timeWindow) => {
    try {
      const res = await fetch(`http://localhost:8000/api/report?window=${windowVal}`);
      if (!res.ok) throw new Error('API Error');
      const json = await res.json();
      setData(json);
      setIsOffline(false);
    } catch {
      setIsOffline(true);
    }
  }, [timeWindow]);

  const fetchThreatsData = useCallback(async (windowVal = timeWindow) => {
    try {
      const res = await fetch(`http://localhost:8000/api/threats?window=${windowVal}`);
      if (res.ok) {
        const json = await res.json();
        setThreats(json);
      }
    } catch (e) {
      console.warn('Threats fetch error:', e);
    }
  }, [timeWindow]);

  const fetchAuditData = useCallback(async (windowVal = timeWindow) => {
    try {
      const res = await fetch(`http://localhost:8000/api/compliance/audit?window=${windowVal}`);
      if (res.ok) {
        const json = await res.json();
        setAudit(json);
      }
    } catch (e) {
      console.warn('Audit fetch error:', e);
    }
  }, [timeWindow]);

  const fetchAssets = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:8000/api/assets');
      if (res.ok) {
        const json = await res.json();
        setAssetsInventory(json);
      }
    } catch (e) {
      console.warn('Assets fetch error:', e);
    }
  }, []);

  const fetchStoredReports = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:8000/api/reports');
      if (res.ok) {
        const json = await res.json();
        setStoredReports(json.reports || []);
      }
    } catch (e) {
      console.warn('Reports fetch error:', e);
    }
  }, []);

  const handleSelectReport = async (id) => {
    setSelectedReportId(id);
    setStoredReport(null);
    if (id === 'live') return;
    try {
      const res = await fetch(`http://localhost:8000/api/reports/${id}`);
      if (res.ok) setStoredReport(await res.json());
    } catch {
      setActionMessage({ type: 'error', text: `Failed to load report #${id}.` });
    }
  };

  const handleGenerateSnapshot = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/reports/generate', { method: 'POST' });
      if (res.ok) {
        const meta = await res.json();
        setActionMessage({ type: 'success', text: `Stored report #${meta.id} (${meta.window_start} → ${meta.window_end} UTC).` });
        await fetchStoredReports();
        handleSelectReport(meta.id);
      }
    } catch {
      setActionMessage({ type: 'error', text: 'Report snapshot failed.' });
    }
  };

  const handleDownloadReport = () => {
    const payload = selectedReportId === 'live' ? data : storedReport;
    if (!payload) return;
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selectedReportId === 'live' ? 'compliance_report_live_4h.json' : `compliance_report_${selectedReportId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const fetchCaptureStatus = useCallback(async () => {
    try {
      const res = await fetch('http://localhost:8000/api/capture/status');
      if (res.ok) {
        const status = await res.json();
        setCaptureStatus(status);
      }
    } catch (e) {
      console.warn('Capture status error:', e);
    }
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.all([
      fetchReport(timeWindow),
      fetchThreatsData(timeWindow),
      fetchAuditData(timeWindow),
      fetchAssets(),
      fetchStoredReports(),
      fetchCaptureStatus()
    ]);
  }, [fetchReport, fetchThreatsData, fetchAuditData, fetchAssets, fetchStoredReports, fetchCaptureStatus, timeWindow]);

  // ── 4-Hour Report Cycle (schedule comes from the backend) ─────────────────
  const WINDOW_SECONDS = data?.cycle?.cycle_seconds || 4 * 60 * 60; // 14,400s
  const nextReportAt = data?.cycle?.next_report_at;

  const updateWindowCountdown = useCallback(() => {
    const now = Math.floor(Date.now() / 1000);
    const next = nextReportAt ? Math.floor(Date.parse(nextReportAt) / 1000) : now - (now % WINDOW_SECONDS) + WINDOW_SECONDS;
    const remaining = Math.max(0, next - now);
    const elapsed = WINDOW_SECONDS - remaining;
    const progress = (elapsed / WINDOW_SECONDS) * 100;
    
    setWindowProgress(progress);
    
    const h = Math.floor(remaining / 3600);
    const m = Math.floor((remaining % 3600) / 60);
    const s = remaining % 60;
    setTimeRemainingStr(`${h}h ${m}m ${s}s`);
  }, [WINDOW_SECONDS, nextReportAt]);

  // Interval hook
  useEffect(() => {
    refreshAll();
    updateWindowCountdown();

    const clockTimer = setInterval(updateWindowCountdown, 1000);
    
    let pollTimer = null;
    if (refreshInterval > 0) {
      pollTimer = setInterval(() => {
        refreshAll();
      }, refreshInterval * 1000);
    }

    return () => {
      clearInterval(clockTimer);
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [refreshAll, updateWindowCountdown, refreshInterval]);

  // Handle Window Switch
  const handleWindowChange = (newWin) => {
    setTimeWindow(newWin);
    fetchReport(newWin);
    fetchThreatsData(newWin);
    fetchAuditData(newWin);
  };

  // ── Capture & DB Actions ──────────────────────────────────────────────────
  const handleStartCapture = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/capture/start', { method: 'POST' });
      if (res.ok) {
        setActionMessage({ type: 'success', text: 'Live packet capture started on default adapter.' });
        fetchCaptureStatus();
      }
    } catch {
      setActionMessage({ type: 'error', text: 'Failed to start live sniffer.' });
    }
  };

  const handleStopCapture = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/capture/stop', { method: 'POST' });
      if (res.ok) {
        const body = await res.json();
        setActionMessage({ type: 'success', text: `Sniffer stopped. Captured ${body.captured || 0} packets.` });
        fetchCaptureStatus();
        refreshAll();
      }
    } catch {
      setActionMessage({ type: 'error', text: 'Failed to stop capture.' });
    }
  };

  const handleClearDatabase = async () => {
    try {
      const res = await fetch('http://localhost:8000/api/clear', { method: 'POST' });
      if (res.ok) {
        setData(null);
        setThreats(null);
        setAudit(null);
        setSelectedNode(null);
        setIsResetModalOpen(false);
        setActionMessage({ type: 'success', text: 'Database cleared. All flows flushed.' });
        refreshAll();
      }
    } catch {
      setActionMessage({ type: 'error', text: 'Database reset error.' });
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setUploading(true);
    setActionMessage({ type: 'info', text: `Ingesting ${file.name}...` });

    const formData = new FormData();
    formData.append('file', file);
    formData.append('shift_to_now', shiftToNow.toString());

    try {
      const res = await fetch('http://localhost:8000/api/upload-pcap', {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        const body = await res.json();
        setActionMessage({ type: 'success', text: body.message });
        refreshAll();
      } else {
        const body = await res.json();
        setActionMessage({ type: 'error', text: body.detail || 'Upload failed.' });
      }
    } catch {
      setActionMessage({ type: 'error', text: 'PCAP upload communication failed.' });
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleSaveAsset = async (e) => {
    e.preventDefault();
    if (!newAsset.ip || !newAsset.hostname) return;
    try {
      const res = await fetch('http://localhost:8000/api/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newAsset)
      });
      if (res.ok) {
        setActionMessage({ type: 'success', text: `Asset ${newAsset.ip} saved to inventory.` });
        setIsAddAssetModalOpen(false);
        setNewAsset({
          ip: '', hostname: '', expected_protocols: 'TCP,UDP',
          risk_tier: 'Medium', criticality: 'Tier 2 (Business)',
          department: 'Engineering', compliance_scope: 'PCI-DSS, NIST'
        });
        fetchAssets();
        fetchReport();
      }
    } catch {
      setActionMessage({ type: 'error', text: 'Failed to save asset.' });
    }
  };

  const handleDeleteAsset = async (ip) => {
    try {
      const res = await fetch(`http://localhost:8000/api/assets/${ip}`, { method: 'DELETE' });
      if (res.ok) {
        setActionMessage({ type: 'success', text: `Asset ${ip} removed from inventory.` });
        fetchAssets();
        fetchReport();
      }
    } catch {
      setActionMessage({ type: 'error', text: 'Failed to delete asset.' });
    }
  };

  // ── Derived View Metrics ───────────────────────────────────────────────────
  const assetsList     = data?.unique_assets || [];
  const publicIPsList  = data?.public_ips    || [];
  const gatewaysList   = data?.gateways      || [];
  const natBypassList  = data?.natBypass     || [];
  const protocolsList  = data?.protoPort     || [];
  const absentIPsList  = data?.absentIPs     || [];
  const threatsList    = threats?.threats    || [];

  // Compliance report source: live rolling 4h window, or a stored 4h report
  const reportData     = selectedReportId === 'live' ? data : storedReport?.report;
  const repAssets      = reportData?.unique_assets || [];
  const repProtoPorts  = reportData?.protoPort     || [];
  const repAbsent      = reportData?.absentIPs     || [];
  const repNat         = reportData?.natBypass     || [];
  const repProtocols   = [...new Set(repProtoPorts.map(p => p.proto))];
  const repPorts       = [...new Set(repProtoPorts.filter(p => p.port > 0).map(p => p.port))].sort((a, b) => a - b);
  const repPeriodLabel = selectedReportId === 'live'
    ? `live rolling 4h window (${reportData?.window_start || '…'} → ${reportData?.window_end || '…'} UTC)`
    : storedReport ? `stored report #${storedReport.id}, ${storedReport.window_start} → ${storedReport.window_end} UTC (${storedReport.trigger})` : 'loading…';

  const totalFlows     = data?.total_flows || 0;
  const totalBytes     = data?.total_bytes || 0;
  const avgBps         = data?.avg_bps || 0;
  const avgPps         = data?.avg_pps || 0;
  const complianceScore = data?.complianceScore ?? 100;
  const postureScore   = threats?.summary?.posture_score ?? 100;

  // Recharts Top Talkers
  const topTalkersData = [...assetsList]
    .sort((a, b) => (b.bytes || 0) - (a.bytes || 0))
    .slice(0, 7)
    .map(a => ({ ip: a.ip, bytes: a.bytes, host: a.host }));

  // Protocol Frequency
  const protocolDataMap = {};
  protocolsList.forEach(p => {
    protocolDataMap[p.proto] = (protocolDataMap[p.proto] || 0) + p.flows;
  });
  const protocolChartData = Object.entries(protocolDataMap).map(([name, value]) => ({ name, value }));

  // Filtered threats
  const filteredThreats = threatsList.filter(t => {
    if (threatFilter !== 'ALL' && t.severity !== threatFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        t.asset_ip?.toLowerCase().includes(q) ||
        t.target_ip?.toLowerCase().includes(q) ||
        t.mitre_name?.toLowerCase().includes(q) ||
        t.details?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="min-h-screen bg-[#070B13] text-slate-100 font-sans flex flex-col antialiased selection:bg-cyan-500 selection:text-black">
      
      {/* ── TOP INDUSTRIAL HEADER ─────────────────────────────────────────── */}
      <header className="sticky top-0 z-40 bg-[#0B101D]/90 backdrop-blur-md border-b border-slate-800/80 px-6 py-3">
        <div className="max-w-[1720px] mx-auto flex flex-wrap items-center justify-between gap-4">
          
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 p-0.5 shadow-lg shadow-cyan-500/20">
              <div className="w-full h-full bg-[#0B101D] rounded-[7px] flex items-center justify-center">
                <Network className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-white tracking-wide">HTC NetFlow Pro</h1>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">Enterprise NDR</span>
                {isOffline && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-ping" /> Offline
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 font-mono">Real-Time Traffic Analysis & Regulatory Compliance Platform</p>
            </div>
          </div>

          {/* 4-Hour Time Window Controller & Ingest Status */}
          <div className="flex flex-wrap items-center gap-3">
            
            {/* Window Selector */}
            <div className="flex items-center bg-[#070B13] p-1 rounded-lg border border-slate-800">
              <Clock className="w-3.5 h-3.5 text-slate-400 ml-2 mr-1" />
              {['15m', '1h', '4h', '12h', '24h', '7d', 'all'].map((w) => (
                <button
                  key={w}
                  onClick={() => handleWindowChange(w)}
                  className={`text-xs font-mono px-2.5 py-1 rounded transition-all ${
                    timeWindow === w
                      ? 'bg-cyan-500 text-black font-semibold shadow'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {w === '4h' ? '4h (Live)' : w.toUpperCase()}
                </button>
              ))}
            </div>

            {/* Live Real-Time 4h Progress Bar Pill */}
            {timeWindow === '4h' && (
              <div className="hidden lg:flex flex-col bg-[#070B13] border border-slate-800 rounded-lg px-3 py-1.5 min-w-[200px]">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
                  <span className="flex items-center gap-1.5 text-cyan-400">
                    <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" /> Next 4h report
                  </span>
                  <span>{timeRemainingStr}</span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-1000"
                    style={{ width: `${Math.min(windowProgress, 100)}%` }}
                  />
                </div>
              </div>
            )}

            {/* Adaptive Badge if viewing PCAP dataset */}
            {data?.is_adaptive && (
              <span className="text-[10px] font-mono px-2 py-1 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1">
                <Zap className="w-3 h-3 text-amber-400" /> PCAP-Adaptive Window
              </span>
            )}

            {/* Ingest Daemon Status Badges */}
            <div className="flex items-center gap-2 bg-[#070B13] border border-slate-800 rounded-lg px-3 py-1.5">
              <div className="flex items-center gap-1.5 text-xs font-mono">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="text-slate-400">UDP:2055:</span>
                <span className="text-emerald-400 font-semibold">Active</span>
              </div>
              <span className="text-slate-700">|</span>
              <div className="flex items-center gap-1.5 text-xs font-mono">
                <span className={`w-2 h-2 rounded-full ${captureStatus.active ? 'bg-cyan-400 animate-ping' : 'bg-slate-600'}`} />
                <span className="text-slate-400">Sniffer:</span>
                <span className={captureStatus.active ? 'text-cyan-400 font-semibold' : 'text-slate-400'}>
                  {captureStatus.active ? `${captureStatus.packets_captured} pkts` : 'Idle'}
                </span>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="flex items-center gap-1.5">
              {captureStatus.active ? (
                <button
                  onClick={handleStopCapture}
                  className="text-xs font-mono px-3 py-1.5 rounded-lg bg-red-500/20 text-red-400 border border-red-500/40 hover:bg-red-500/30 flex items-center gap-1.5 transition"
                >
                  <X className="w-3.5 h-3.5" /> Stop Sniffer
                </button>
              ) : (
                <button
                  onClick={handleStartCapture}
                  className="text-xs font-mono px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 flex items-center gap-1.5 transition"
                >
                  <Radio className="w-3.5 h-3.5" /> Live Sniff
                </button>
              )}

              <input 
                ref={fileInputRef} 
                type="file" 
                accept=".pcap,.pcapng,.cap" 
                className="hidden" 
                onChange={handleFileUpload} 
              />

              <button
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
                className="text-xs font-mono px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5 transition"
              >
                <Upload className="w-3.5 h-3.5 text-cyan-400" /> {uploading ? 'Parsing...' : 'Upload PCAP'}
              </button>

              <button
                onClick={refreshAll}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                title="Force Refresh"
              >
                <RefreshCw className="w-4 h-4" />
              </button>

              <button
                onClick={() => setIsResetModalOpen(true)}
                className="p-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 transition"
                title="Clear Flow Records"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>

          </div>
        </div>

        {/* Action Toast / Notification */}
        {actionMessage && (
          <div className="max-w-[1720px] mx-auto mt-2">
            <div className={`px-3 py-1.5 rounded-lg text-xs font-mono flex items-center justify-between ${
              actionMessage.type === 'success' ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/30' :
              actionMessage.type === 'error' ? 'bg-red-500/10 text-red-300 border border-red-500/30' :
              'bg-blue-500/10 text-blue-300 border border-blue-500/30'
            }`}>
              <span>{actionMessage.text}</span>
              <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>
          </div>
        )}

        {/* ── SUB-NAVIGATION TABS ──────────────────────────────────────────── */}
        <div className="max-w-[1720px] mx-auto mt-3 flex items-center gap-1 border-t border-slate-800/60 pt-2 overflow-x-auto">
          {[
            { id: 'overview',   label: 'NOC & Traffic Matrix',      icon: Activity },
            { id: 'threats',    label: 'SOC Threat Triage (MITRE)', icon: ShieldAlert, badge: threatsList.length },
            { id: 'topology',   label: 'Network Topology Map',      icon: Network },
            { id: 'compliance', label: 'Regulatory Compliance',     icon: ShieldCheck, score: `${complianceScore}%` },
            { id: 'inventory',  label: 'Asset Inventory Watchdog',  icon: Server, count: assetsList.length },
            { id: 'pcap',       label: 'PCAP Ingest & Collector Lab',icon: Upload },
            { id: 'exports',    label: 'Audit & PDF Exports',        icon: Download },
          ].map(tab => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono transition-all whitespace-nowrap ${
                  isActive 
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
                {tab.badge !== undefined && tab.badge > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full bg-red-500 text-white text-[10px] font-bold">
                    {tab.badge}
                  </span>
                )}
                {tab.score && (
                  <span className={`text-[10px] px-1 rounded ${
                    complianceScore >= 85 ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
                  }`}>
                    {tab.score}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </header>

      {/* ── MAIN CONTENT CONTAINER ────────────────────────────────────────── */}
      <main className="flex-grow max-w-[1720px] w-full mx-auto px-6 py-6 space-y-6">

        {/* ═══ TAB 1: NOC & TRAFFIC MATRIX (OVERVIEW) ════════════════════════ */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            
            {/* KPI Metrics Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-4">
              
              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-mono">Total Flows</span>
                  <Activity className="w-4 h-4 text-cyan-400" />
                </div>
                <div className="text-2xl font-bold text-white font-mono">{totalFlows.toLocaleString()}</div>
                <div className="text-[11px] text-slate-500 font-mono mt-1">In {timeWindow} window</div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-mono">Volume / Throughput</span>
                  <Cpu className="w-4 h-4 text-blue-400" />
                </div>
                <div className="text-2xl font-bold text-white font-mono">{fmtBytes(totalBytes)}</div>
                <div className="text-[11px] text-cyan-400 font-mono mt-1">Avg {fmtBps(avgBps)} ({avgPps} pps)</div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-mono">Active Assets</span>
                  <Server className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="text-2xl font-bold text-white font-mono">{assetsList.length}</div>
                <div className="text-[11px] text-slate-500 font-mono mt-1">Internal nodes seen</div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-mono">Public WAN Peers</span>
                  <Globe className="w-4 h-4 text-violet-400" />
                </div>
                <div className="text-2xl font-bold text-white font-mono">{publicIPsList.length}</div>
                <div className="text-[11px] text-slate-500 font-mono mt-1">External endpoints</div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-mono">Primary Gateway</span>
                  <Network className="w-4 h-4 text-amber-400" />
                </div>
                <div className="text-lg font-bold text-amber-400 font-mono truncate">{data?.gateway || 'Not identified'}</div>
                <div className="text-[11px] text-slate-500 font-mono mt-1">{gatewaysList.length} total gateways</div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-mono">NAT Bypass Alerts</span>
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                </div>
                <div className="text-2xl font-bold text-red-400 font-mono">{natBypassList.length}</div>
                <div className="text-[11px] text-slate-500 font-mono mt-1">Rogue router violations</div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-center justify-between text-slate-400 mb-2">
                  <span className="text-xs font-mono">Ghost Assets</span>
                  <Eye className="w-4 h-4 text-purple-400" />
                </div>
                <div className="text-2xl font-bold text-purple-400 font-mono">{absentIPsList.length}</div>
                <div className="text-[11px] text-slate-500 font-mono mt-1">Silent in current {timeWindow}</div>
              </div>

            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              {/* Top Talkers Bar Chart */}
              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-5">
                <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-4 flex items-center justify-between">
                  <span>Top Talkers (Byte Volume)</span>
                  <span className="text-[10px] text-cyan-400">REQ 1</span>
                </h3>
                <div className="h-[240px]">
                  {topTalkersData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={topTalkersData} layout="vertical" margin={{ left: 20, right: 20 }}>
                        <XAxis type="number" tickFormatter={fmtBytes} stroke="#475569" fontSize={10} />
                        <YAxis type="category" dataKey="ip" stroke="#94A3B8" fontSize={11} width={85} />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#070B13', borderColor: '#334155', borderRadius: '8px' }}
                          formatter={(val) => [fmtBytes(val), 'Volume']}
                          labelFormatter={(label) => `Host: ${label}`}
                        />
                        <Bar dataKey="bytes" radius={[0, 4, 4, 0]}>
                          {topTalkersData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500">No flow data recorded</div>
                  )}
                </div>
              </div>

              {/* Protocol Distribution */}
              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-5">
                <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-4 flex items-center justify-between">
                  <span>Protocol Breakdown</span>
                  <span className="text-[10px] text-cyan-400">REQ 5</span>
                </h3>
                <div className="h-[240px]">
                  {protocolChartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={protocolChartData}
                          dataKey="value"
                          nameKey="name"
                          cx="50%"
                          cy="50%"
                          outerRadius={80}
                          innerRadius={45}
                          label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                          labelLine={false}
                        >
                          {protocolChartData.map((entry, index) => (
                            <Cell key={`proto-${index}`} fill={PROTO_COLORS[entry.name] || CHART_COLORS[index % CHART_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#070B13', borderColor: '#334155', borderRadius: '8px' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500">No protocol telemetry</div>
                  )}
                </div>
              </div>

              {/* Destination Port Risk Distribution */}
              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-5">
                <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase tracking-wider mb-4 flex items-center justify-between">
                  <span>Top Destination Services</span>
                  <span className="text-[10px] text-cyan-400">Ports & Services</span>
                </h3>
                <div className="space-y-2 overflow-y-auto max-h-[240px] pr-1 font-mono">
                  {protocolsList.slice(0, 7).map((p, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-[#070B13] p-2 rounded border border-slate-800 text-xs">
                      <div className="flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          p.risk === 'Critical' ? 'bg-red-500/20 text-red-400' :
                          p.risk === 'High' ? 'bg-amber-500/20 text-amber-400' :
                          p.risk === 'Medium' ? 'bg-yellow-500/20 text-yellow-300' :
                          'bg-slate-700 text-slate-300'
                        }`}>
                          {p.service || `Port ${p.port}`}
                        </span>
                        <span className="text-slate-400">{p.port > 0 ? `${p.port}/${p.proto}` : p.proto}</span>
                      </div>
                      <div className="text-right">
                        <div className="text-slate-200 font-semibold">{p.flows} flows</div>
                        <div className="text-[10px] text-slate-500">{fmtBytes(p.bytes)}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>

            {/* Unique Assets Table (Deliverable 1) */}
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold text-white font-mono">Internal Assets Discovered ({assetsList.length})</h3>
                  <p className="text-xs text-slate-400 font-mono">Requirement 1: Private IP addresses, hostnames, protocols, and port bindings</p>
                </div>
                <div className="flex items-center gap-3">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
                    <input
                      type="text"
                      placeholder="Search IP or Host..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="bg-[#070B13] border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#070B13] text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="px-6 py-3">Asset IP</th>
                      <th className="px-6 py-3">Hostname</th>
                      <th className="px-6 py-3">Criticality</th>
                      <th className="px-6 py-3">Department</th>
                      <th className="px-6 py-3">Traffic Volume</th>
                      <th className="px-6 py-3">Protocols Observed</th>
                      <th className="px-6 py-3">Service Ports</th>
                      <th className="px-6 py-3">Last Seen</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {assetsList
                      .filter(a => !searchQuery || a.ip.includes(searchQuery) || a.host.toLowerCase().includes(searchQuery.toLowerCase()))
                      .map((asset, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30 transition">
                          <td className="px-6 py-3.5 text-cyan-400 font-semibold">{asset.ip}</td>
                          <td className="px-6 py-3.5 text-white">{asset.host}</td>
                          <td className="px-6 py-3.5">
                            <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 text-slate-300">
                              {asset.criticality || 'Tier 2'}
                            </span>
                          </td>
                          <td className="px-6 py-3.5 text-slate-400">{asset.department || 'Infrastructure'}</td>
                          <td className="px-6 py-3.5 text-slate-200">
                            {fmtBytes(asset.bytes)} <span className="text-slate-500 text-[10px]">({asset.flows} flows)</span>
                          </td>
                          <td className="px-6 py-3.5">
                            <div className="flex flex-wrap gap-1">
                              {asset.protocols?.map((pr, pidx) => (
                                <span key={pidx} className="px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 text-[10px]">
                                  {pr}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-6 py-3.5 text-slate-400">
                            {asset.ports?.length ? asset.ports.slice(0, 8).join(', ') + (asset.ports.length > 8 ? ` +${asset.ports.length - 8}` : '') : 'None'}
                          </td>
                          <td className="px-6 py-3.5 text-slate-400">{asset.lastSeen}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        )}

        {/* ═══ TAB 2: SOC THREAT TRIAGE (MITRE ATT&CK) ═══════════════════════ */}
        {activeTab === 'threats' && (
          <div className="space-y-6">
            
            {/* Posture Score & MITRE Overview */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
              
              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
                <div>
                  <h3 className="text-xs font-semibold text-slate-400 font-mono uppercase tracking-wider mb-2">SOC Security Posture</h3>
                  <div className="flex items-baseline gap-2">
                    <span className={`text-4xl font-bold font-mono ${
                      postureScore >= 80 ? 'text-emerald-400' : postureScore >= 50 ? 'text-amber-400' : 'text-red-400'
                    }`}>
                      {postureScore}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">/ 100 Index</span>
                  </div>
                </div>
                <div className="text-xs text-slate-400 font-mono mt-4">
                  {threatsList.length === 0 ? 'No active MITRE ATT&CK violations.' : `${threatsList.length} active indicators requiring SOC triage.`}
                </div>
              </div>

              <div className="lg:col-span-3 bg-[#0B101D] border border-slate-800 rounded-xl p-5">
                <h3 className="text-xs font-semibold text-slate-400 font-mono uppercase tracking-wider mb-3">MITRE ATT&CK Enterprise Matrix Coverage</h3>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 font-mono">
                  {threats?.mitre_coverage?.map((m, idx) => (
                    <div key={idx} className="bg-[#070B13] p-3 rounded-lg border border-slate-800">
                      <div className="text-[10px] text-slate-500 uppercase">{m.tactic}</div>
                      <div className="text-xs font-semibold text-slate-200 mt-1 truncate" title={m.technique}>{m.technique}</div>
                      <div className="mt-2">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                          m.status.includes('Critical') ? 'bg-red-500/20 text-red-400' :
                          m.status.includes('Alert') ? 'bg-amber-500/20 text-amber-400' :
                          m.status.includes('Detected') ? 'bg-cyan-500/20 text-cyan-400' :
                          'bg-emerald-500/20 text-emerald-400'
                        }`}>
                          {m.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

            </div>

            {/* Threat Incident Stream */}
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <ShieldAlert className="w-5 h-5 text-red-400" />
                  <div>
                    <h3 className="text-sm font-bold text-white font-mono">Active Threat Incidents ({filteredThreats.length})</h3>
                    <p className="text-xs text-slate-400 font-mono">MITRE ATT&CK techniques, lateral movements, and unauthorized perimeter bypasses</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {['ALL', 'Critical', 'High', 'Medium'].map(sev => (
                    <button
                      key={sev}
                      onClick={() => setThreatFilter(sev)}
                      className={`text-xs font-mono px-3 py-1 rounded-lg transition ${
                        threatFilter === sev ? 'bg-cyan-500 text-black font-bold' : 'bg-slate-800 text-slate-400 hover:text-white'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              <div className="divide-y divide-slate-800">
                {filteredThreats.length > 0 ? (
                  filteredThreats.map((t, idx) => (
                    <div key={idx} className="p-5 hover:bg-slate-800/30 transition font-mono text-xs">
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            t.severity === 'Critical' ? 'bg-red-500/20 text-red-400 border border-red-500/40' :
                            t.severity === 'High' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
                            'bg-yellow-500/20 text-yellow-300 border border-yellow-500/40'
                          }`}>
                            {t.severity.toUpperCase()}
                          </span>
                          <span className="text-cyan-400 font-semibold">{t.mitre_id}</span>
                          <span className="text-white font-medium">{t.mitre_name}</span>
                        </div>
                        <span className="text-slate-500 text-[11px]">{t.id}</span>
                      </div>
                      
                      <p className="text-slate-300 text-xs mb-3">{t.details}</p>

                      <div className="bg-[#070B13] p-3 rounded-lg border border-slate-800/80 flex flex-wrap items-center justify-between gap-4">
                        <div className="flex flex-wrap items-center gap-4 text-[11px] text-slate-400">
                          <div><span className="text-slate-500">Asset:</span> <span className="text-cyan-400 font-semibold">{t.asset_ip}</span></div>
                          {t.target_ip && <div><span className="text-slate-500">Target/Attacker:</span> <span className="text-red-400 font-semibold">{t.target_ip}</span></div>}
                          {t.flows > 0 && <div><span className="text-slate-500">Flows:</span> <span className="text-white">{t.flows}</span></div>}
                          {t.bytes > 0 && <div><span className="text-slate-500">Bytes:</span> <span className="text-white">{fmtBytes(t.bytes)}</span></div>}
                        </div>
                        <div className="text-[11px] text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20">
                          <span className="font-semibold text-emerald-300">Remediation:</span> {t.remediation}
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="p-12 text-center text-slate-500 font-mono text-xs">
                    <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                    No threats detected in the selected filter. Network operating within compliance bounds.
                  </div>
                )}
              </div>
            </div>

          </div>
        )}

        {/* ═══ TAB 3: NETWORK TOPOLOGY VISUALIZER ════════════════════════════ */}
        {activeTab === 'topology' && (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            
            <div className="lg:col-span-3 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 bg-[#0B101D] border border-slate-800 rounded-xl p-3">
                <div className="flex items-center gap-2">
                  <Network className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-mono font-bold text-white uppercase">Topology Projection:</span>
                </div>
                <div className="flex items-center gap-1.5 font-mono text-xs">
                  {[
                    { id: 'topology', label: 'Full Mesh' },
                    { id: 'asset-pubip', label: 'Asset ↔ Public WAN' },
                    { id: 'gateway-flow', label: 'Gateway Perimeter' },
                  ].map(v => (
                    <button
                      key={v.id}
                      onClick={() => setActiveGraph(v.id)}
                      className={`px-3 py-1 rounded-lg transition ${
                        activeGraph === v.id ? 'bg-cyan-500 text-black font-semibold' : 'bg-[#070B13] text-slate-400 hover:text-white'
                      }`}
                    >
                      {v.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Interactive Network Topology Visualizer */}
              <div className="h-[640px] min-h-[580px]">
                <NetworkGraph 
                  type={activeGraph} 
                  data={data} 
                  selectedNode={selectedNode}
                  onSelectNode={(node) => setSelectedNode(node)} 
                />
              </div>
            </div>

            {/* Node Inspector Drawer */}
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-5 flex flex-col justify-between font-mono text-xs">
              <div>
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-4 flex items-center justify-between border-b border-slate-800 pb-3">
                  <span>Node Telemetry Inspector</span>
                  {selectedNode && <span className="text-cyan-400">ACTIVE</span>}
                </h3>

                {selectedNode ? (
                  <div className="space-y-4">
                    <div>
                      <div className="text-[10px] text-slate-500 uppercase">IP Address</div>
                      <div className="text-lg font-bold text-cyan-400">{selectedNode.ip || selectedNode.id}</div>
                      <div className="text-xs text-slate-400">{selectedNode.host || selectedNode.role}</div>
                    </div>

                    <div className="bg-[#070B13] p-3 rounded-lg border border-slate-800 space-y-2">
                      <div className="flex justify-between">
                        <span className="text-slate-500">Role:</span>
                        <span className="text-white font-semibold">{selectedNode.role || 'Host'}</span>
                      </div>
                      {selectedNode.threat !== undefined && selectedNode.threat > 0 && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">Threat Score:</span>
                          <span className={`font-bold ${selectedNode.threat >= 60 ? 'text-red-400' : 'text-amber-400'}`}>
                            {selectedNode.threat} / 100
                          </span>
                        </div>
                      )}
                      {selectedNode.bytes && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">Bytes Volume:</span>
                          <span className="text-white">{fmtBytes(selectedNode.bytes)}</span>
                        </div>
                      )}
                      {selectedNode.flows && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">Flow Count:</span>
                          <span className="text-white">{selectedNode.flows}</span>
                        </div>
                      )}
                      {selectedNode.geo && (
                        <div className="flex justify-between">
                          <span className="text-slate-500">Location/ASN:</span>
                          <span className="text-slate-300">{selectedNode.geo}</span>
                        </div>
                      )}
                    </div>

                    {selectedNode.protocols && (
                      <div>
                        <div className="text-[10px] text-slate-500 uppercase mb-1">Protocols Bound</div>
                        <div className="flex flex-wrap gap-1">
                          {selectedNode.protocols.map((pr, idx) => (
                            <span key={idx} className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 text-[10px]">
                              {pr}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-8 text-center text-slate-500">
                    <Search className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                    Click any node in the topology canvas to inspect real-time flow telemetry, ports, and risk metrics.
                  </div>
                )}
              </div>

              {selectedNode && (
                <button
                  onClick={() => setSelectedNode(null)}
                  className="w-full mt-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
                >
                  Clear Selection
                </button>
              )}
            </div>

          </div>
        )}

        {/* ═══ TAB 4: REGULATORY COMPLIANCE AUDITOR ══════════════════════════ */}
        {activeTab === 'compliance' && (
          <div className="space-y-6">

            {/* Report Period (4-hour cycle) */}
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-5 font-mono text-xs flex flex-wrap items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Clock className="w-4 h-4 text-cyan-400" /> Compliance Report Period
                </h3>
                <p className="text-slate-400 mt-1">
                  Showing {repPeriodLabel}. A report is stored automatically at every 4-hour UTC boundary
                  {nextReportAt ? ` — next at ${nextReportAt.replace('T', ' ').replace('Z', ' UTC')} (in ${timeRemainingStr})` : ''}.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={selectedReportId}
                  onChange={(e) => handleSelectReport(e.target.value === 'live' ? 'live' : Number(e.target.value))}
                  className="bg-[#070B13] border border-slate-800 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="live">Live — rolling 4h window</option>
                  {storedReports.map(r => (
                    <option key={r.id} value={r.id}>
                      #{r.id} {r.window_start.slice(0, 16)} → {r.window_end.slice(11, 16)} UTC ({r.trigger})
                    </option>
                  ))}
                </select>
                <button
                  onClick={handleGenerateSnapshot}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 transition"
                >
                  Snapshot current period
                </button>
                <button
                  onClick={handleDownloadReport}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold transition flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" /> Download JSON
                </button>
              </div>
            </div>

            {/* Report Summary */}
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 font-mono">
              {[
                { label: 'Internal Assets Identified', value: repAssets.length, color: 'text-cyan-400' },
                { label: 'Protocols Identified', value: repProtocols.length, sub: repProtocols.join(', ') || '—', color: 'text-violet-400' },
                { label: 'Service Ports Identified', value: repPorts.length, sub: repPorts.slice(0, 12).join(', ') || '—', color: 'text-blue-400' },
                { label: 'IPs Not Seen in Traffic', value: repAbsent.length, color: 'text-purple-400' },
                { label: 'Inventory Seen', value: `${reportData?.complianceScore ?? 0}%`, color: (reportData?.complianceScore ?? 0) >= 85 ? 'text-emerald-400' : 'text-amber-400' },
              ].map((k, idx) => (
                <div key={idx} className="bg-[#0B101D] border border-slate-800 rounded-xl p-4">
                  <div className="text-[11px] text-slate-400">{k.label}</div>
                  <div className={`text-2xl font-bold mt-1 ${k.color}`}>{k.value}</div>
                  {k.sub && <div className="text-[10px] text-slate-500 mt-1 truncate" title={k.sub}>{k.sub}</div>}
                </div>
              ))}
            </div>

            {/* Per-IP Protocols & Ports */}
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800">
                <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  Identified Internal Assets — Protocols & Ports per IP ({repAssets.length})
                </h3>
                <p className="text-xs text-slate-400 font-mono">Listening = services the IP provides; Connects to = services it uses. Client ephemeral ports are excluded.</p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#070B13] text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="px-6 py-3">Asset IP</th>
                      <th className="px-6 py-3">Hostname</th>
                      <th className="px-6 py-3">Protocols</th>
                      <th className="px-6 py-3">Listening Ports</th>
                      <th className="px-6 py-3">Connects To Ports</th>
                      <th className="px-6 py-3">Flows</th>
                      <th className="px-6 py-3">Last Seen</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {repAssets.length > 0 ? repAssets.map((a, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30 transition">
                        <td className="px-6 py-3 text-cyan-400 font-semibold">{a.ip}</td>
                        <td className="px-6 py-3 text-white">{a.host}</td>
                        <td className="px-6 py-3 text-purple-300">{a.protocols?.join(', ')}</td>
                        <td className="px-6 py-3 text-emerald-300">{a.listeningPorts?.join(', ') || '—'}</td>
                        <td className="px-6 py-3 text-slate-300">{a.clientPorts?.join(', ') || '—'}</td>
                        <td className="px-6 py-3 text-slate-400">{a.flows}</td>
                        <td className="px-6 py-3 text-slate-400">{a.lastSeen}</td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan={7} className="px-6 py-8 text-center text-slate-500">No internal assets observed in this period.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Protocols & Ports in the period */}
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800">
                <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <Layers className="w-4 h-4 text-violet-400" />
                  Identified Protocols & Ports ({repProtoPorts.length})
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#070B13] text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="px-6 py-3">Protocol</th>
                      <th className="px-6 py-3">Port</th>
                      <th className="px-6 py-3">Service</th>
                      <th className="px-6 py-3">Flows</th>
                      <th className="px-6 py-3">Volume</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {repProtoPorts.map((p, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30 transition">
                        <td className="px-6 py-3 text-purple-300">{p.proto}</td>
                        <td className="px-6 py-3 text-white">{p.port > 0 ? p.port : '—'}</td>
                        <td className="px-6 py-3 text-slate-300">{p.service}</td>
                        <td className="px-6 py-3 text-slate-400">{p.flows}</td>
                        <td className="px-6 py-3 text-slate-400">{fmtBytes(p.bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Framework Scorecards (live) */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {audit?.frameworks && Object.entries(audit.frameworks).map(([key, f]) => (
                <div key={key} className="bg-[#0B101D] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-mono font-bold text-white">{f.name}</span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        f.grade === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' :
                        f.grade === 'WARN' ? 'bg-amber-500/20 text-amber-400' :
                        'bg-red-500/20 text-red-400'
                      }`}>
                        {f.grade}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono mb-4">{f.scope}</p>
                  </div>
                  <div>
                    <div className="flex items-baseline justify-between text-xs font-mono mb-1">
                      <span className="text-slate-400">Score</span>
                      <span className="font-bold text-white">{f.score}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                      <div 
                        className={`h-full ${f.score >= 80 ? 'bg-emerald-500' : f.score >= 60 ? 'bg-amber-500' : 'bg-red-500'}`}
                        style={{ width: `${f.score}%` }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Ghost Asset Watchdog & Absent IPs (Requirement 7) */}
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                    <Eye className="w-4 h-4 text-purple-400" />
                    Ghost / Absent Asset Watchdog ({repAbsent.length})
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">Requirement 7: Configured inventory assets with zero observed traffic in the selected 4h period</p>
                </div>
                <span className="text-xs font-mono px-2.5 py-1 rounded bg-purple-500/10 text-purple-400 border border-purple-500/30">
                  NIST CM-8 / CIS 1.1
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#070B13] text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="px-6 py-3">Asset IP</th>
                      <th className="px-6 py-3">Expected Hostname</th>
                      <th className="px-6 py-3">Criticality</th>
                      <th className="px-6 py-3">Department</th>
                      <th className="px-6 py-3">Expected Protocols</th>
                      <th className="px-6 py-3">Downtime Duration</th>
                      <th className="px-6 py-3">Compliance Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {repAbsent.length > 0 ? (
                      repAbsent.map((a, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30 transition">
                          <td className="px-6 py-3.5 text-purple-400 font-semibold">{a.ip}</td>
                          <td className="px-6 py-3.5 text-white">{a.host}</td>
                          <td className="px-6 py-3.5">
                            <span className="px-2 py-0.5 rounded text-[10px] bg-red-500/10 text-red-300 border border-red-500/20">
                              {a.criticality || 'Tier 2'}
                            </span>
                          </td>
                          <td className="px-6 py-3.5 text-slate-400">{a.department || 'IT Ops'}</td>
                          <td className="px-6 py-3.5 text-slate-300">{a.expectedProtos}</td>
                          <td className="px-6 py-3.5 text-amber-400 font-semibold">{a.lastSeen}</td>
                          <td className="px-6 py-3.5">
                            <span className="px-2 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300">
                              {a.status}
                            </span>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={7} className="px-6 py-8 text-center text-slate-500 font-mono">
                          All registered inventory assets are actively communicating in this period.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* NAT Bypass Rogue Router Table (Requirement 4) */}
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                    Paths Not Through the Gateway — Proposed NAT ({repNat.length})
                  </h3>
                  <p className="text-xs text-slate-400 font-mono">Requirement 4: Internal endpoints reaching public IPs via a next hop other than gateway {reportData?.gateway || '(not identified)'}</p>
                </div>
                <span className="text-xs font-mono px-2.5 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/30">
                  PCI 1.2.1 / NIST AC-4
                </span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#070B13] text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="px-6 py-3">Source Host</th>
                      <th className="px-6 py-3">Unauthorized Nexthop</th>
                      <th className="px-6 py-3">External Destination</th>
                      <th className="px-6 py-3">Bypass Flows</th>
                      <th className="px-6 py-3">Bytes Egressed</th>
                      <th className="px-6 py-3">Remediation Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {repNat.length > 0 ? (
                      repNat.map((nb, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30 transition">
                          <td className="px-6 py-3.5 text-red-400 font-semibold">{nb.src} ({nb.host})</td>
                          <td className="px-6 py-3.5 text-amber-400 font-bold">{nb.nexthop}</td>
                          <td className="px-6 py-3.5 text-white">{nb.dst}</td>
                          <td className="px-6 py-3.5 text-slate-300">{nb.flows}</td>
                          <td className="px-6 py-3.5 text-slate-200">{fmtBytes(nb.bytes)}</td>
                          <td className="px-6 py-3.5 text-emerald-400">{nb.recommendation}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={6} className="px-6 py-8 text-center text-slate-500 font-mono">
                          {reportData?.gateway ? `All egress routes through ${reportData.gateway}.` : 'No next-hop information in this period, so the gateway cannot be identified.'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        )}

        {/* ═══ TAB 5: ASSET INVENTORY MANAGEMENT ═════════════════════════════ */}
        {activeTab === 'inventory' && (
          <div className="space-y-6 font-mono">
            
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-6 flex flex-wrap items-center justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-white">Enterprise Asset Inventory ({assetsInventory.length})</h3>
                <p className="text-xs text-slate-400 mt-1">Configure mission-critical assets, departments, compliance scopes, and expected services.</p>
              </div>
              <button
                onClick={() => setIsAddAssetModalOpen(true)}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs flex items-center gap-1.5 transition"
              >
                <Plus className="w-4 h-4" /> Add Asset
              </button>
            </div>

            <div className="bg-[#0B101D] border border-slate-800 rounded-xl overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#070B13] text-slate-400 uppercase text-[10px] border-b border-slate-800">
                  <tr>
                    <th className="px-6 py-3">IP Address</th>
                    <th className="px-6 py-3">Hostname</th>
                    <th className="px-6 py-3">Criticality Tier</th>
                    <th className="px-6 py-3">Department</th>
                    <th className="px-6 py-3">Expected Protocols</th>
                    <th className="px-6 py-3">Compliance Scope</th>
                    <th className="px-6 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {assetsInventory.map((a, idx) => (
                    <tr key={idx} className="hover:bg-slate-800/30 transition">
                      <td className="px-6 py-3.5 text-cyan-400 font-semibold">{a.ip}</td>
                      <td className="px-6 py-3.5 text-white">{a.hostname}</td>
                      <td className="px-6 py-3.5">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 text-slate-300">
                          {a.criticality}
                        </span>
                      </td>
                      <td className="px-6 py-3.5 text-slate-400">{a.department}</td>
                      <td className="px-6 py-3.5 text-purple-300">{a.expected_protocols}</td>
                      <td className="px-6 py-3.5 text-slate-400">{a.compliance_scope}</td>
                      <td className="px-6 py-3.5 text-right">
                        <button
                          onClick={() => handleDeleteAsset(a.ip)}
                          className="text-red-400 hover:text-red-300 p-1 transition"
                          title="Delete"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

          </div>
        )}

        {/* ═══ TAB 6: PCAP INGEST & COLLECTOR LAB ════════════════════════════ */}
        {activeTab === 'pcap' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 font-mono text-xs">
            
            {/* Upload Zone */}
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-6 space-y-5">
              <div>
                <h3 className="text-sm font-bold text-white mb-1">PCAP Ingestion & Parsing</h3>
                <p className="text-slate-400 text-xs">Upload raw Ethernet packet captures or NetFlow v5 UDP collector dumps.</p>
              </div>

              <div className="bg-[#070B13] p-4 rounded-xl border border-slate-800 space-y-3">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={shiftToNow}
                    onChange={(e) => setShiftToNow(e.target.checked)}
                    className="w-4 h-4 rounded text-cyan-500 focus:ring-0"
                  />
                  <span className="text-slate-200 text-xs font-semibold">
                    Auto-normalize timestamps to active 4h window (Recommended)
                  </span>
                </label>
                <p className="text-[11px] text-slate-400 ml-6">
                  Shifts historical PCAP packet times so they land right within the current 4-hour window, immediately lighting up live charts and ghost asset watchdogs.
                </p>
              </div>

              <div 
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-xl p-10 text-center cursor-pointer transition bg-[#070B13]/50"
              >
                <Upload className="w-8 h-8 text-cyan-400 mx-auto mb-3 animate-bounce" />
                <div className="text-slate-200 font-semibold">Click to select PCAP / PCAPng file</div>
                <div className="text-slate-500 text-[11px] mt-1">Supports test_traffic.pcap, Cisco/Juniper dumps, Wireshark files</div>
              </div>
            </div>

            {/* Replay Instructions & CLI */}
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-6 space-y-4">
              <div>
                <h3 className="text-sm font-bold text-white mb-1">NetFlow Replay Daemon (UDP:2055)</h3>
                <p className="text-slate-400 text-xs">Stream test traffic over UDP into the active background collector daemon.</p>
              </div>

              <div className="space-y-3">
                <div className="bg-[#070B13] p-3 rounded-lg border border-slate-800">
                  <div className="text-[11px] text-slate-400 mb-1">1. Generate test traffic PCAP:</div>
                  <code className="text-cyan-400 text-xs">python backend/generate_test_pcap.py</code>
                </div>

                <div className="bg-[#070B13] p-3 rounded-lg border border-slate-800">
                  <div className="text-[11px] text-slate-400 mb-1">2. Replay PCAP to local collector:</div>
                  <code className="text-cyan-400 text-xs">python backend/replay_pcap.py backend/test_traffic.pcap</code>
                </div>

                <div className="bg-[#070B13] p-3 rounded-lg border border-slate-800">
                  <div className="text-[11px] text-slate-400 mb-1">3. Live capture with Scapy:</div>
                  <code className="text-cyan-400 text-xs">Click "Live Sniff" in top navigation bar</code>
                </div>
              </div>
            </div>

          </div>
        )}

        {/* ═══ TAB 7: EXECUTIVE AUDIT & PDF EXPORTS ══════════════════════════ */}
        {activeTab === 'exports' && (
          <div className="space-y-6 font-mono">
            
            <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-6 flex flex-wrap items-center justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-white">Executive Compliance & Audit Suite</h3>
                <p className="text-xs text-slate-400 mt-1">Export full compliance audits, raw flow datasets, and MITRE incident logs.</p>
              </div>
              <button
                onClick={() => window.print()}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs flex items-center gap-1.5 transition"
              >
                <Download className="w-4 h-4" /> Print / Save Executive Audit PDF
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              
              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
                <div>
                  <h4 className="text-sm font-bold text-white mb-1">Flow Telemetry CSV</h4>
                  <p className="text-xs text-slate-400 mb-4">Complete 5-tuple flow dataset (Source, Destination, Ports, Nexthops, Bytes).</p>
                </div>
                <a
                  href="http://localhost:8000/api/export/csv?dataset=flows"
                  className="w-full py-2 text-center rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-bold border border-slate-700 transition"
                >
                  Download Flows CSV
                </a>
              </div>

              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
                <div>
                  <h4 className="text-sm font-bold text-white mb-1">Asset Inventory CSV</h4>
                  <p className="text-xs text-slate-400 mb-4">Export enterprise asset registry, departments, and compliance mappings.</p>
                </div>
                <a
                  href="http://localhost:8000/api/export/csv?dataset=assets"
                  className="w-full py-2 text-center rounded-lg bg-slate-800 hover:bg-slate-700 text-emerald-400 text-xs font-bold border border-slate-700 transition"
                >
                  Download Assets CSV
                </a>
              </div>

              <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
                <div>
                  <h4 className="text-sm font-bold text-white mb-1">MITRE ATT&CK Incidents CSV</h4>
                  <p className="text-xs text-slate-400 mb-4">Export all active security incidents and remediation playbooks.</p>
                </div>
                <a
                  href="http://localhost:8000/api/export/csv?dataset=threats"
                  className="w-full py-2 text-center rounded-lg bg-slate-800 hover:bg-slate-700 text-red-400 text-xs font-bold border border-slate-700 transition"
                >
                  Download Threat Log CSV
                </a>
              </div>

            </div>

          </div>
        )}

      </main>

      {/* ── RESET MODAL ───────────────────────────────────────────────────── */}
      {isResetModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-6 max-w-md w-full font-mono text-xs">
            <h3 className="text-sm font-bold text-white mb-2 flex items-center gap-2 text-red-400">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              Reset Database & Flows?
            </h3>
            <p className="text-slate-400 mb-6">
              This will permanently delete all ingested NetFlow records from DuckDB. Asset inventory configurations will be preserved.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setIsResetModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleClearDatabase}
                className="px-4 py-2 rounded-lg bg-red-500 hover:bg-red-600 text-white font-bold transition"
              >
                Confirm Reset
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── ADD ASSET MODAL ───────────────────────────────────────────────── */}
      {isAddAssetModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0B101D] border border-slate-800 rounded-xl p-6 max-w-lg w-full font-mono text-xs">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-white">Register Enterprise Asset</h3>
              <button onClick={() => setIsAddAssetModalOpen(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>
            
            <form onSubmit={handleSaveAsset} className="space-y-4">
              <div>
                <label className="text-[10px] text-slate-400 uppercase">IP Address</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 10.0.0.99"
                  value={newAsset.ip}
                  onChange={(e) => setNewAsset({ ...newAsset, ip: e.target.value })}
                  className="w-full bg-[#070B13] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 mt-1 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase">Hostname</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. core-auth-srv"
                  value={newAsset.hostname}
                  onChange={(e) => setNewAsset({ ...newAsset, hostname: e.target.value })}
                  className="w-full bg-[#070B13] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 mt-1 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-[10px] text-slate-400 uppercase">Criticality Tier</label>
                  <select
                    value={newAsset.criticality}
                    onChange={(e) => setNewAsset({ ...newAsset, criticality: e.target.value })}
                    className="w-full bg-[#070B13] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 mt-1 focus:outline-none focus:border-cyan-500"
                  >
                    <option>Tier 1 (Mission-Critical)</option>
                    <option>Tier 2 (Business)</option>
                    <option>Tier 3 (Internal)</option>
                    <option>Tier 4 (Peripheral)</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-400 uppercase">Department</label>
                  <input
                    type="text"
                    placeholder="e.g. IT Ops"
                    value={newAsset.department}
                    onChange={(e) => setNewAsset({ ...newAsset, department: e.target.value })}
                    className="w-full bg-[#070B13] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 mt-1 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase">Expected Protocols</label>
                <input
                  type="text"
                  placeholder="e.g. TCP,UDP,HTTPS"
                  value={newAsset.expected_protocols}
                  onChange={(e) => setNewAsset({ ...newAsset, expected_protocols: e.target.value })}
                  className="w-full bg-[#070B13] border border-slate-800 rounded-lg px-3 py-2 text-slate-200 mt-1 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAddAssetModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-bold transition"
                >
                  Save Asset
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── FOOTER ────────────────────────────────────────────────────────── */}
      <footer className="border-t border-slate-800/80 px-6 py-4 bg-[#0B101D] text-xs font-mono text-slate-500 flex flex-wrap items-center justify-between gap-4">
        <div>HTC NetFlow Analyzer Pro — Enterprise Industrial Edition</div>
        <div className="flex items-center gap-4">
          <span>Storage: DuckDB Columnar</span>
          <span>Window: {timeWindow}</span>
          <span>Refresh: {refreshInterval}s</span>
          <span className="text-cyan-400">{data?.timestamp || 'Ready'}</span>
        </div>
      </footer>

    </div>
  );
}

export default App;
