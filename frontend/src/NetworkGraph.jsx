import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { 
  ZoomIn, ZoomOut, Maximize2, RotateCcw, Search, Filter, 
  Layers, Play, Pause, Zap, Shield, Server, Globe, AlertTriangle, 
  Cpu, Eye, Sliders, Compass
} from 'lucide-react';

// Helper for human-readable byte sizes
function fmtBytes(n) {
  if (!n || isNaN(n)) return '0 B';
  if (n >= 1000000000) return (n / 1000000000).toFixed(2) + ' GB';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + ' MB';
  if (n >= 1000) return (n / 1000).toFixed(1) + ' KB';
  return n + ' B';
}

function getSubnetGroup(ip) {
  if (!ip) return 'Other';
  if (ip.startsWith('10.')) return '10.0.0.0/8 (Core Private)';
  if (ip.startsWith('192.168.')) return '192.168.0.0/16 (Office LAN)';
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 16 && second <= 31) return '172.16.0.0/12 (DMZ/Lab)';
  }
  if (ip.startsWith('224.') || ip.startsWith('239.')) return 'Multicast (224.0.0.0/4)';
  if (ip.startsWith('169.254.')) return 'Link-Local (169.254.0.0/16)';
  return 'Public WAN Endpoints';
}

export default function NetworkGraph({ 
  type = 'topology', 
  data, 
  onSelectNode, 
  selectedNode, 
  filterQuery = '' 
}) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);

  // Layout & Control States
  const [layoutMode, setLayoutMode] = useState('force'); // 'force' | 'subnet' | 'concentric' | 'hierarchical'
  const [nodeLimit, setNodeLimit] = useState(40); // 25, 40, 75, 150
  const [search, setSearch] = useState('');
  const [physicsActive, setPhysicsActive] = useState(true);
  const [showParticles, setShowParticles] = useState(true);
  const [showLabels, setShowLabels] = useState(true);
  const [showMinimap, setShowMinimap] = useState(true);

  // Category Filters
  const [visibleCategories, setVisibleCategories] = useState({
    gateway: true,
    internal: true,
    external: true,
    bypass: true,
    multicast: true
  });

  // Viewport Transform (Pan & Zoom)
  const transformRef = useRef({ x: 0, y: 0, k: 1 });
  const [zoomLevel, setZoomLevel] = useState(1);

  // Sync external type prop
  useEffect(() => {
    if (type === 'asset-pubip') {
      setLayoutMode('hierarchical');
      setVisibleCategories({ gateway: true, internal: true, external: true, bypass: false, multicast: false });
    } else if (type === 'gateway-flow') {
      setLayoutMode('concentric');
      setVisibleCategories({ gateway: true, internal: true, external: false, bypass: true, multicast: false });
    } else {
      setLayoutMode('force');
      setVisibleCategories({ gateway: true, internal: true, external: true, bypass: true, multicast: true });
    }
  }, [type]);

  // Interaction States
  const isDraggingRef = useRef(false);
  const dragTargetNodeRef = useRef(null);
  const lastMousePosRef = useRef({ x: 0, y: 0 });
  const hoveredNodeRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0, visible: false });

  // Animation & Particle state
  const particlesRef = useRef([]);
  const animFrameIdRef = useRef(null);

  const hasAssets = data && data.unique_assets && data.unique_assets.length > 0;
  const hasGraph  = data && data.graph && data.graph.nodes && data.graph.nodes.length > 0;

  // ── 1. PARSE & NORMALIZE GRAPH DATA ──────────────────────────────────────────
  const graphModel = useMemo(() => {
    if (!data) return { nodes: [], links: [], nodeMap: new Map() };

    const rawNodes = data.graph?.nodes || [];
    const rawEdges = data.graph?.edges || [];
    const assets = data.unique_assets || [];
    const publicIps = data.public_ips || [];
    const gateway = data.gateway || null;
    const natBypassList = data.natBypass || [];
    const natBypassSet = new Set(natBypassList.map(n => n.src));

    // Lookup asset metrics
    const assetMap = new Map();
    assets.forEach(a => assetMap.set(a.ip, a));
    const pubMap = new Map();
    publicIps.forEach(p => pubMap.set(p.ip, p));

    // Collect all candidate nodes
    const nodeMap = new Map();

    const addOrUpdateNode = (ip, defaults = {}) => {
      if (!ip) return null;
      if (nodeMap.has(ip)) {
        const existing = nodeMap.get(ip);
        Object.assign(existing, defaults);
        return existing;
      }

      const isGw = (ip === gateway) || defaults.is_gw;
      const isBypass = natBypassSet.has(ip) || defaults.is_bypass;
      const isMulticast = ip.startsWith('224.') || ip.startsWith('239.');
      const isLinkLocal = ip.startsWith('169.254.');
      
      const assetData = assetMap.get(ip);
      const pubData = pubMap.get(ip);
      const isPriv = defaults.is_priv !== undefined ? defaults.is_priv : (
        ip.startsWith('10.') || ip.startsWith('192.168.') || 
        (ip.startsWith('172.') && parseInt(ip.split('.')[1], 10) >= 16 && parseInt(ip.split('.')[1], 10) <= 31)
      );

      let category = 'external';
      if (isGw) category = 'gateway';
      else if (isBypass) category = 'bypass';
      else if (isMulticast || isLinkLocal) category = 'multicast';
      else if (isPriv) category = 'internal';

      const totalBytes = (assetData?.bytes) || (pubData?.bytesIn) || defaults.bytes || 0;
      const flowCount = (assetData?.flows) || defaults.flows || 0;

      const nodeObj = {
        id: ip,
        ip: ip,
        label: assetData?.host || defaults.label || ip,
        category: category,
        is_gw: isGw,
        is_bypass: isBypass,
        is_priv: isPriv,
        role: isGw ? 'Primary Gateway' : (isBypass ? 'Rogue NAT Bypass' : (isPriv ? 'Internal Asset' : 'Public WAN Endpoint')),
        threat: pubData?.threat || defaults.threat || (isBypass ? 85 : 0),
        bytes: totalBytes,
        flows: flowCount,
        geo: pubData?.geo || defaults.geo || (isPriv ? 'LAN Enterprise' : 'WAN Cloud'),
        protocols: assetData?.protocols || pubData?.proto || (defaults.proto ? [defaults.proto] : ['TCP']),
        subnet: getSubnetGroup(ip),
        x: (Math.random() - 0.5) * 400,
        y: (Math.random() - 0.5) * 400,
        vx: 0,
        vy: 0,
        fx: null,
        fy: null,
        degree: 0,
        radius: isGw ? 24 : (isBypass ? 20 : 16)
      };

      nodeMap.set(ip, nodeObj);
      return nodeObj;
    };

    // Ensure Gateway exists
    if (gateway) {
      addOrUpdateNode(gateway, { is_gw: true, label: `GW (${gateway})` });
    }

    // Add nodes from graph
    rawNodes.forEach(n => {
      addOrUpdateNode(n.id || n.ip, {
        label: n.label,
        is_gw: n.is_gw,
        is_bypass: n.is_bypass,
        is_priv: n.is_priv,
        threat: n.threat
      });
    });

    // Add nodes from assets & public IPs if not in graph
    assets.forEach(a => addOrUpdateNode(a.ip, { label: a.host, bytes: a.bytes, flows: a.flows }));
    publicIps.forEach(p => addOrUpdateNode(p.ip, { bytes: p.bytesIn, threat: p.threat, geo: p.geo }));

    // Build & score links
    const linkList = [];
    const edgeKeySet = new Set();

    rawEdges.forEach(e => {
      const srcNode = nodeMap.get(e.source);
      const dstNode = nodeMap.get(e.target);
      if (!srcNode || !dstNode) return;

      const key = `${e.source}->${e.target}`;
      if (edgeKeySet.has(key)) return;
      edgeKeySet.add(key);

      srcNode.degree += 1;
      dstNode.degree += 1;

      linkList.push({
        source: srcNode,
        target: dstNode,
        bytes: e.bytes || 0,
        flows: e.flows || 1,
        proto: e.proto || 'TCP',
        is_bypass: e.is_bypass || (srcNode.is_bypass && !dstNode.is_priv)
      });
    });

    // If no explicit edges were passed, synthesize edges between assets & gateway/public IPs
    if (linkList.length === 0) {
      const gwNode = nodeMap.get(gateway);
      nodeMap.forEach(n => {
        if (n.id !== gateway && gwNode && n.is_priv) {
          linkList.push({
            source: n,
            target: gwNode,
            bytes: n.bytes,
            flows: n.flows || 1,
            proto: 'TCP',
            is_bypass: n.is_bypass
          });
        }
      });
      publicIps.forEach(p => {
        const pNode = nodeMap.get(p.ip);
        if (pNode && p.talksto) {
          p.talksto.forEach(tIp => {
            const tNode = nodeMap.get(tIp);
            if (tNode) {
              linkList.push({
                source: tNode,
                target: pNode,
                bytes: p.bytesIn,
                flows: 5,
                proto: (p.proto && p.proto[0]) || 'TCP',
                is_bypass: tNode.is_bypass
              });
            }
          });
        }
      });
    }

    // Sort nodes by importance (Gateway first, then high traffic/threat)
    const sortedNodes = Array.from(nodeMap.values()).sort((a, b) => {
      if (a.is_gw) return -1;
      if (b.is_gw) return 1;
      if (a.is_bypass && !b.is_bypass) return -1;
      if (!a.is_bypass && b.is_bypass) return 1;
      return (b.bytes + b.degree * 10000) - (a.bytes + a.degree * 10000);
    });

    return { nodes: sortedNodes, links: linkList, nodeMap };
  }, [data]);

  // ── 2. FILTER NODES & LINKS (CLUTTER REDUCTION) ─────────────────────────────
  const filteredGraph = useMemo(() => {
    let nodes = graphModel.nodes;

    // Filter by Category
    nodes = nodes.filter(n => {
      if (n.category === 'gateway' && !visibleCategories.gateway) return false;
      if (n.category === 'internal' && !visibleCategories.internal) return false;
      if (n.category === 'external' && !visibleCategories.external) return false;
      if (n.category === 'bypass' && !visibleCategories.bypass) return false;
      if (n.category === 'multicast' && !visibleCategories.multicast) return false;
      return true;
    });

    // Apply Node Limit (Preserve Gateways and Rogue Bypasses always)
    if (nodeLimit < nodes.length) {
      const mustKeep = nodes.filter(n => n.is_gw || n.is_bypass);
      const rest = nodes.filter(n => !n.is_gw && !n.is_bypass);
      const allowedRest = rest.slice(0, Math.max(0, nodeLimit - mustKeep.length));
      nodes = [...mustKeep, ...allowedRest];
    }

    const activeNodeSet = new Set(nodes.map(n => n.id));

    // Filter links
    const links = graphModel.links.filter(l => 
      activeNodeSet.has(l.source.id) && activeNodeSet.has(l.target.id)
    );

    return { nodes, links };
  }, [graphModel, visibleCategories, nodeLimit]);

  // ── 3. LAYOUT INITIALIZATION & POSITIONING ENGINE ────────────────────────────
  const applyLayout = useCallback((mode, nodes, links, width, height) => {
    const cx = width / 2;
    const cy = height / 2;
    if (nodes.length === 0) return;

    if (mode === 'subnet') {
      // Group nodes by Subnet zone
      const groups = {};
      nodes.forEach(n => {
        if (!groups[n.subnet]) groups[n.subnet] = [];
        groups[n.subnet].push(n);
      });

      const groupNames = Object.keys(groups);
      const cols = Math.min(3, groupNames.length);
      const colWidth = width / cols;
      const rows = Math.ceil(groupNames.length / cols);
      const rowHeight = height / rows;

      groupNames.forEach((gName, gIdx) => {
        const c = gIdx % cols;
        const r = Math.floor(gIdx / cols);
        const gCenter = {
          x: c * colWidth + colWidth / 2 - width / 2,
          y: r * rowHeight + rowHeight / 2 - height / 2
        };

        const gNodes = groups[gName];
        const gRadius = Math.min(colWidth, rowHeight) * 0.35;

        gNodes.forEach((n, i) => {
          if (n.is_gw) {
            n.x = gCenter.x;
            n.y = gCenter.y;
          } else {
            const angle = (i / Math.max(1, gNodes.length)) * Math.PI * 2;
            const dist = Math.min(gRadius, 35 + (i * 12));
            n.x = gCenter.x + dist * Math.cos(angle);
            n.y = gCenter.y + dist * Math.sin(angle);
          }
          n.vx = 0;
          n.vy = 0;
        });
      });

    } else if (mode === 'concentric') {
      // Concentric Security Perimeter Rings
      const gws = nodes.filter(n => n.is_gw);
      const internals = nodes.filter(n => n.is_priv && !n.is_gw && !n.is_bypass);
      const bypasses = nodes.filter(n => n.is_bypass);
      const externals = nodes.filter(n => !n.is_priv && !n.is_gw && n.category !== 'multicast');
      const multicasts = nodes.filter(n => n.category === 'multicast');

      // Center: Gateway
      gws.forEach((n, i) => {
        n.x = (i - (gws.length - 1) / 2) * 40;
        n.y = 0;
      });

      // Ring 1: Internals (adaptive spiral to prevent crowding)
      internals.forEach((n, i) => {
        const ring = Math.floor(i / 16);
        const r = 120 + ring * 55;
        const countOnRing = Math.min(16, internals.length - ring * 16);
        const angle = ((i % 16) / countOnRing) * Math.PI * 2;
        n.x = r * Math.cos(angle);
        n.y = r * Math.sin(angle);
      });

      // Ring 2: Rogue Bypasses (Highlighted perimeter)
      bypasses.forEach((n, i) => {
        const r = 210;
        const angle = (i / Math.max(1, bypasses.length)) * Math.PI * 2 + Math.PI / 6;
        n.x = r * Math.cos(angle);
        n.y = r * Math.sin(angle);
      });

      // Ring 3: Multicast / Broadcast
      multicasts.forEach((n, i) => {
        const r = 260;
        const angle = (i / Math.max(1, multicasts.length)) * Math.PI * 2 - Math.PI / 4;
        n.x = r * Math.cos(angle);
        n.y = r * Math.sin(angle);
      });

      // Ring 4: Public WAN Cloud
      externals.forEach((n, i) => {
        const ring = Math.floor(i / 20);
        const r = 320 + ring * 60;
        const countOnRing = Math.min(20, externals.length - ring * 20);
        const angle = ((i % 20) / countOnRing) * Math.PI * 2;
        n.x = r * Math.cos(angle);
        n.y = r * Math.sin(angle);
      });

    } else if (mode === 'hierarchical') {
      // Top-to-Bottom Ingress/Egress Tiering
      const externals = nodes.filter(n => !n.is_priv && !n.is_gw);
      const gws = nodes.filter(n => n.is_gw);
      const bypasses = nodes.filter(n => n.is_bypass);
      const internals = nodes.filter(n => n.is_priv && !n.is_gw && !n.is_bypass);

      const placeRow = (list, yPos) => {
        const count = list.length;
        const spacing = Math.min(90, (width * 0.85) / Math.max(1, count));
        const startX = -((count - 1) * spacing) / 2;
        list.forEach((n, i) => {
          n.x = startX + i * spacing;
          n.y = yPos;
        });
      };

      placeRow(externals, -220);
      placeRow(gws, -90);
      placeRow(bypasses, 40);
      placeRow(internals, 180);

    } else {
      // Organic Force-Directed starting distribution
      nodes.forEach((n, i) => {
        if (n.is_gw) {
          n.x = 0;
          n.y = 0;
        } else {
          const angle = (i / nodes.length) * Math.PI * 2;
          const radius = 100 + Math.sqrt(i) * 35;
          n.x = radius * Math.cos(angle);
          n.y = radius * Math.sin(angle);
        }
      });
    }

    nodes.forEach(n => { n.vx = 0; n.vy = 0; });
  }, []);

  // Recalculate layout on mode or dataset change
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const w = canvas.width || 900;
    const h = canvas.height || 600;
    applyLayout(layoutMode, filteredGraph.nodes, filteredGraph.links, w, h);
  }, [layoutMode, filteredGraph, applyLayout]);

  // ── 4. PHYSICS SIMULATION STEP (PREVENT OVERLAPPING) ──────────────────────────
  const stepPhysics = useCallback((nodes, links) => {
    if (!physicsActive) return;

    const repulsionK = 2800;
    const springK = 0.04;
    const springLength = 110;
    const centerGravity = 0.015;
    const damping = 0.82;

    // 1. Repulsion between all node pairs (Charge Force) + Anti-Collision
    for (let i = 0; i < nodes.length; i++) {
      const n1 = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const n2 = nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const distSq = dx * dx + dy * dy || 1;
        const dist = Math.sqrt(distSq);

        // Standard Coulomb Repulsion
        const force = repulsionK / distSq;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;

        if (!n1.fx) { n1.vx -= fx; n1.vy -= fy; }
        if (!n2.fx) { n2.vx += fx; n2.vy += fy; }

        // Hard collision avoidance buffer
        const minDist = n1.radius + n2.radius + 28; // Padding to ensure clean separation
        if (dist < minDist) {
          const overlap = (minDist - dist) * 0.5;
          const pushX = (dx / dist) * overlap;
          const pushY = (dy / dist) * overlap;
          if (!n1.fx) { n1.vx -= pushX * 0.6; n1.vy -= pushY * 0.6; }
          if (!n2.fx) { n2.vx += pushX * 0.6; n2.vy += pushY * 0.6; }
        }
      }
    }

    // 2. Spring Forces on Links
    links.forEach(l => {
      const s = l.source;
      const t = l.target;
      const dx = t.x - s.x;
      const dy = t.y - s.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const displacement = dist - springLength;
      const force = displacement * springK;

      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      if (!s.fx) { s.vx += fx; s.vy += fy; }
      if (!t.fx) { t.vx -= fx; t.vy -= fy; }
    });

    // 3. Center Gravity & Velocity Integration
    nodes.forEach(n => {
      if (n.fx !== null && n.fy !== null) {
        n.x = n.fx;
        n.y = n.fy;
        n.vx = 0;
        n.vy = 0;
        return;
      }

      // Gentle centering force
      n.vx -= n.x * centerGravity;
      n.vy -= n.y * centerGravity;

      // Apply velocity with damping
      n.vx *= damping;
      n.vy *= damping;

      // Velocity cap to avoid violent explosions
      const maxV = 18;
      const speed = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
      if (speed > maxV) {
        n.vx = (n.vx / speed) * maxV;
        n.vy = (n.vy / speed) * maxV;
      }

      n.x += n.vx;
      n.y += n.vy;
    });
  }, [physicsActive]);

  // ── 5. FLOW PARTICLES SIMULATION ─────────────────────────────────────────────
  useEffect(() => {
    // Generate particles for high-traffic links
    const newParticles = [];
    filteredGraph.links.forEach((link, idx) => {
      const count = link.is_bypass ? 2 : (link.bytes > 500000 ? 2 : 1);
      for (let i = 0; i < count; i++) {
        newParticles.push({
          linkIndex: idx,
          progress: Math.random(),
          speed: 0.006 + Math.min(0.015, (link.bytes / 5000000) * 0.01),
          color: link.is_bypass ? '#EF4444' : (link.proto === 'UDP' ? '#38BDF8' : '#00F2FE')
        });
      }
    });
    particlesRef.current = newParticles;
  }, [filteredGraph.links]);

  // ── 6. MAIN HIGH-PERFORMANCE CANVAS RENDERER ────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let isRunning = true;

    const render = () => {
      if (!isRunning) return;

      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      const w = rect.width;
      const h = rect.height;

      if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
        canvas.width = w * dpr;
        canvas.height = h * dpr;
      }

      ctx.save();
      ctx.scale(dpr, dpr);

      // Clear Canvas Background
      ctx.fillStyle = '#080B10';
      ctx.fillRect(0, 0, w, h);

      // Background Cyber Grid
      const t = transformRef.current;
      const cx = w / 2 + t.x;
      const cy = h / 2 + t.y;

      ctx.save();
      ctx.strokeStyle = 'rgba(30, 41, 59, 0.45)';
      ctx.lineWidth = 1;
      const gridSize = 40 * t.k;
      const offsetX = (cx % gridSize);
      const offsetY = (cy % gridSize);

      ctx.beginPath();
      for (let x = offsetX; x < w; x += gridSize) {
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
      }
      for (let y = offsetY; y < h; y += gridSize) {
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
      }
      ctx.stroke();
      ctx.restore();

      // Physics update step (organic mode)
      if (layoutMode === 'force') {
        stepPhysics(filteredGraph.nodes, filteredGraph.links);
      }

      // Apply Pan & Zoom Transform
      ctx.save();
      ctx.translate(cx, cy);
      ctx.scale(t.k, t.k);

      // Render Subnet Bounding Enclosures in 'subnet' mode
      if (layoutMode === 'subnet') {
        const groups = {};
        filteredGraph.nodes.forEach(n => {
          if (!groups[n.subnet]) groups[n.subnet] = [];
          groups[n.subnet].push(n);
        });

        Object.entries(groups).forEach(([gName, gNodes]) => {
          if (gNodes.length === 0) return;
          let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
          gNodes.forEach(n => {
            minX = Math.min(minX, n.x);
            maxX = Math.max(maxX, n.x);
            minY = Math.min(minY, n.y);
            maxY = Math.max(maxY, n.y);
          });
          const pad = 45;
          const boxW = Math.max(120, (maxX - minX) + pad * 2);
          const boxH = Math.max(100, (maxY - minY) + pad * 2);
          const boxX = (minX + maxX) / 2 - boxW / 2;
          const boxY = (minY + maxY) / 2 - boxH / 2;

          ctx.fillStyle = 'rgba(15, 23, 42, 0.55)';
          ctx.strokeStyle = 'rgba(56, 189, 248, 0.25)';
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.roundRect(boxX, boxY, boxW, boxH, 14);
          ctx.fill();
          ctx.stroke();

          // Subnet Header Label
          ctx.fillStyle = '#94A3B8';
          ctx.font = '10px JetBrains Mono, monospace';
          ctx.fillText(gName, boxX + 12, boxY + 18);
        });
      }

      // Render Concentric Orbit Rings in 'concentric' mode
      if (layoutMode === 'concentric') {
        [120, 210, 260, 320].forEach((r, idx) => {
          ctx.save();
          ctx.strokeStyle = idx === 1 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(56, 189, 248, 0.12)';
          ctx.lineWidth = 1;
          ctx.setLineDash([4, 6]);
          ctx.beginPath();
          ctx.arc(0, 0, r, 0, Math.PI * 2);
          ctx.stroke();
          ctx.restore();
        });
      }

      // ── A. DRAW LINKS ──────────────────────────────────────────────────────
      const activeHover = hoveredNodeRef.current;
      const activeSelect = selectedNode;
      const searchLower = search.trim().toLowerCase();

      filteredGraph.links.forEach((link) => {
        const s = link.source;
        const t = link.target;
        const isBypass = link.is_bypass;

        const isConnectedToHover = activeHover && (s.id === activeHover.id || t.id === activeHover.id);
        const isConnectedToSelect = activeSelect && (s.id === activeSelect.id || s.ip === activeSelect.ip || t.id === activeSelect.id || t.ip === activeSelect.ip);

        // Alpha calculation
        let alpha = 0.22;
        if (activeHover || activeSelect) {
          alpha = (isConnectedToHover || isConnectedToSelect) ? 0.95 : 0.04;
        }

        ctx.save();
        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);

        if (isBypass) {
          ctx.strokeStyle = `rgba(239, 68, 68, ${alpha})`;
          ctx.lineWidth = (isConnectedToHover || isConnectedToSelect) ? 2.8 : 1.8;
          ctx.setLineDash([6, 4]);
        } else {
          const baseColor = link.proto === 'UDP' ? `56, 189, 248` : `0, 242, 254`;
          ctx.strokeStyle = `rgba(${baseColor}, ${alpha})`;
          ctx.lineWidth = (isConnectedToHover || isConnectedToSelect) ? 2.4 : 1.2;
        }
        ctx.stroke();
        ctx.restore();
      });

      // ── B. DRAW PACKET FLOW PARTICLES ──────────────────────────────────────
      if (showParticles) {
        particlesRef.current.forEach(p => {
          const link = filteredGraph.links[p.linkIndex];
          if (!link) return;

          p.progress = (p.progress + p.speed) % 1;
          const s = link.source;
          const t = link.target;
          const px = s.x + (t.x - s.x) * p.progress;
          const py = s.y + (t.y - s.y) * p.progress;

          ctx.save();
          ctx.fillStyle = p.color;
          ctx.shadowColor = p.color;
          ctx.shadowBlur = 8;
          ctx.beginPath();
          ctx.arc(px, py, 2.5, 0, Math.PI * 2);
          ctx.fill();
          ctx.restore();
        });
      }

      // ── C. DRAW NODES ──────────────────────────────────────────────────────
      filteredGraph.nodes.forEach(node => {
        const isHovered = activeHover && activeHover.id === node.id;
        const isSelected = activeSelect && (activeSelect.id === node.id || activeSelect.ip === node.ip);
        const matchesSearch = searchLower && (node.ip.toLowerCase().includes(searchLower) || node.label.toLowerCase().includes(searchLower));

        // Node Styling by category
        let fillColor = '#00F2FE';
        let strokeColor = '#00B4D8';
        let glyphText = '💻';

        if (node.is_gw) {
          fillColor = '#F59E0B';
          strokeColor = '#D97706';
          glyphText = '⚡';
        } else if (node.is_bypass) {
          fillColor = '#EF4444';
          strokeColor = '#DC2626';
          glyphText = '⚠';
        } else if (node.category === 'multicast') {
          fillColor = '#A855F7';
          strokeColor = '#9333EA';
          glyphText = '📡';
        } else if (node.category === 'external') {
          fillColor = '#EC4899';
          strokeColor = '#DB2777';
          glyphText = '🌐';
        }

        // Highlight ring on Selection / Search Match
        if (isSelected || matchesSearch) {
          ctx.save();
          ctx.strokeStyle = isSelected ? '#00F2FE' : '#FBBF24';
          ctx.lineWidth = 2.5;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 8, 0, Math.PI * 2);
          ctx.stroke();
          ctx.restore();
        }

        // Rogue NAT Bypass Pulse
        if (node.is_bypass) {
          ctx.save();
          const pulseR = node.radius + 6 + Math.sin(Date.now() * 0.005) * 3;
          ctx.strokeStyle = 'rgba(239, 68, 68, 0.6)';
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.arc(node.x, node.y, pulseR, 0, Math.PI * 2);
          ctx.stroke();
          ctx.restore();
        }

        // Base Node Body
        ctx.save();
        ctx.fillStyle = fillColor;
        ctx.strokeStyle = isHovered ? '#FFFFFF' : strokeColor;
        ctx.lineWidth = isHovered ? 2.5 : 1.8;
        ctx.shadowColor = fillColor;
        ctx.shadowBlur = (isHovered || isSelected) ? 16 : 8;

        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.restore();

        // Node Inner Glyph / Text
        ctx.save();
        ctx.fillStyle = '#080B10';
        ctx.font = 'bold 9px JetBrains Mono, monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        const shortLabel = node.is_gw ? 'GW' : node.ip.split('.').pop();
        ctx.fillText(shortLabel, node.x, node.y);
        ctx.restore();

        // Node Labels (Smart Level of Detail)
        if (showLabels || isHovered || isSelected || matchesSearch) {
          ctx.save();
          ctx.font = '10px JetBrains Mono, monospace';
          ctx.textAlign = 'center';
          ctx.fillStyle = isHovered || isSelected ? '#FFFFFF' : '#CBD5E1';
          
          // IP / Hostname text below node
          const displayText = node.label !== node.ip ? `${node.label} (${node.ip})` : node.ip;
          ctx.fillText(displayText, node.x, node.y + node.radius + 13);

          // Subtitle / Volume badge
          if (node.bytes > 0 && (isHovered || isSelected || t.k > 1.1)) {
            ctx.font = '9px JetBrains Mono, monospace';
            ctx.fillStyle = '#94A3B8';
            ctx.fillText(fmtBytes(node.bytes), node.x, node.y + node.radius + 24);
          }
          ctx.restore();
        }
      });

      ctx.restore(); // Restore Pan & Zoom

      // Minimap Overlay
      if (showMinimap) {
        renderMinimap(ctx, w, h, filteredGraph.nodes, t);
      }

      ctx.restore(); // Restore DPR scaling

      animFrameIdRef.current = requestAnimationFrame(render);
    };

    animFrameIdRef.current = requestAnimationFrame(render);

    return () => {
      isRunning = false;
      if (animFrameIdRef.current) {
        cancelAnimationFrame(animFrameIdRef.current);
      }
    };
  }, [
    filteredGraph, 
    layoutMode, 
    showParticles, 
    showLabels, 
    showMinimap, 
    search, 
    selectedNode, 
    stepPhysics
  ]);

  // ── 7. MINIMAP / RADAR HELPER ───────────────────────────────────────────────
  const renderMinimap = (ctx, w, h, nodes, t) => {
    const mw = 140;
    const mh = 90;
    const mx = w - mw - 16;
    const my = h - mh - 16;

    ctx.save();
    ctx.fillStyle = 'rgba(11, 16, 29, 0.85)';
    ctx.strokeStyle = 'rgba(56, 189, 248, 0.3)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.roundRect(mx, my, mw, mh, 8);
    ctx.fill();
    ctx.stroke();

    // Map bounds
    const scale = 0.12;
    const mcx = mx + mw / 2;
    const mcy = my + mh / 2;

    nodes.forEach(n => {
      const nx = mcx + n.x * scale;
      const ny = mcy + n.y * scale;
      if (nx >= mx && nx <= mx + mw && ny >= my && ny <= my + mh) {
        ctx.fillStyle = n.is_gw ? '#F59E0B' : (n.is_bypass ? '#EF4444' : '#00F2FE');
        ctx.beginPath();
        ctx.arc(nx, ny, 2, 0, Math.PI * 2);
        ctx.fill();
      }
    });

    // Viewport box
    const vw = (w / t.k) * scale;
    const vh = (h / t.k) * scale;
    const vx = mcx - (t.x / t.k) * scale - vw / 2;
    const vy = mcy - (t.y / t.k) * scale - vh / 2;

    ctx.strokeStyle = 'rgba(255, 255, 255, 0.5)';
    ctx.strokeRect(vx, vy, vw, vh);

    ctx.fillStyle = '#64748B';
    ctx.font = '8px JetBrains Mono, monospace';
    ctx.fillText('TOPOLOGY RADAR', mx + 8, my + 12);

    ctx.restore();
  };

  // ── 8. MOUSE & TOUCH INTERACTION HANDLERS ───────────────────────────────────
  const getCanvasCoords = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    const t = transformRef.current;
    const cx = rect.width / 2 + t.x;
    const cy = rect.height / 2 + t.y;

    const worldX = (mouseX - cx) / t.k;
    const worldY = (mouseY - cy) / t.k;

    return { worldX, worldY, screenX: mouseX, screenY: mouseY };
  };

  const findNodeAt = (wx, wy) => {
    for (let i = filteredGraph.nodes.length - 1; i >= 0; i--) {
      const n = filteredGraph.nodes[i];
      const dx = n.x - wx;
      const dy = n.y - wy;
      if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 6) {
        return n;
      }
    }
    return null;
  };

  const handleMouseDown = (e) => {
    const { worldX, worldY, screenX, screenY } = getCanvasCoords(e);
    const hitNode = findNodeAt(worldX, worldY);

    if (hitNode) {
      dragTargetNodeRef.current = hitNode;
      hitNode.fx = hitNode.x;
      hitNode.fy = hitNode.y;
    } else {
      isDraggingRef.current = true;
      lastMousePosRef.current = { x: screenX, y: screenY };
    }
  };

  const handleMouseMove = (e) => {
    const { worldX, worldY, screenX, screenY } = getCanvasCoords(e);

    // Node Dragging
    if (dragTargetNodeRef.current) {
      const n = dragTargetNodeRef.current;
      n.fx = worldX;
      n.fy = worldY;
      n.x = worldX;
      n.y = worldY;
      return;
    }

    // Canvas Panning
    if (isDraggingRef.current) {
      const dx = screenX - lastMousePosRef.current.x;
      const dy = screenY - lastMousePosRef.current.y;
      transformRef.current.x += dx;
      transformRef.current.y += dy;
      lastMousePosRef.current = { x: screenX, y: screenY };
      return;
    }

    // Hover Detection
    const hitNode = findNodeAt(worldX, worldY);
    hoveredNodeRef.current = hitNode;
    setHoveredNode(hitNode);

    if (hitNode) {
      setTooltipPos({
        x: screenX + 15,
        y: screenY - 10,
        visible: true
      });
    } else {
      setTooltipPos(prev => ({ ...prev, visible: false }));
    }
  };

  const handleMouseUp = () => {
    if (dragTargetNodeRef.current) {
      // Release node or keep pinned if organic
      if (layoutMode === 'force') {
        dragTargetNodeRef.current.fx = null;
        dragTargetNodeRef.current.fy = null;
      }
      dragTargetNodeRef.current = null;
    }
    isDraggingRef.current = false;
  };

  const handleClick = (e) => {
    const { worldX, worldY } = getCanvasCoords(e);
    const hitNode = findNodeAt(worldX, worldY);
    if (hitNode && onSelectNode) {
      onSelectNode(hitNode);
    }
  };

  const handleWheel = (e) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
    const newK = Math.max(0.2, Math.min(3.5, transformRef.current.k * zoomFactor));
    transformRef.current.k = newK;
    setZoomLevel(newK);
  };

  const handleZoomBtn = (factor) => {
    const newK = Math.max(0.2, Math.min(3.5, transformRef.current.k * factor));
    transformRef.current.k = newK;
    setZoomLevel(newK);
  };

  const handleResetView = () => {
    transformRef.current = { x: 0, y: 0, k: 1 };
    setZoomLevel(1);
    const canvas = canvasRef.current;
    if (canvas) {
      applyLayout(layoutMode, filteredGraph.nodes, filteredGraph.links, canvas.width, canvas.height);
    }
  };

  // ── 9. NO-DATA EMPTY STATE ──────────────────────────────────────────────────
  if (!hasAssets && !hasGraph) {
    return (
      <div className="w-full h-full min-h-[480px] flex flex-col justify-center items-center bg-[#080B10] border border-slate-800 rounded-xl p-10 text-center font-mono">
        <div className="w-14 h-14 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center mb-4 animate-pulse">
          <Zap className="text-cyan-400 w-6 h-6" />
        </div>
        <span className="text-slate-200 text-sm font-bold mb-1">No Active Traffic Flows in Selected Window</span>
        <span className="text-slate-500 text-xs max-w-md">Live topology will dynamically stream once NetFlow UDP packets arrive on port 2055 or a PCAP file is ingested.</span>
      </div>
    );
  }

  // ── 10. RENDER COMPLETE UI & CONTROLS HUD ────────────────────────────────────
  return (
    <div ref={containerRef} className="w-full h-full flex flex-col bg-[#080B10] border border-slate-800/90 rounded-xl overflow-hidden shadow-2xl relative font-mono">
      
      {/* ── TOP CONTROL HUD TOOLBAR ────────────────────────────────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 bg-[#0B101D] border-b border-slate-800/80 z-10 text-xs select-none">
        
        {/* Left: Layout Projection Switcher */}
        <div className="flex items-center gap-1.5 bg-[#070B13] p-1 rounded-lg border border-slate-800">
          {[
            { id: 'force', label: 'Organic Force', icon: Compass },
            { id: 'subnet', label: 'Subnet Zones', icon: Layers },
            { id: 'concentric', label: 'Security Rings', icon: Shield },
            { id: 'hierarchical', label: 'Ingress Tree', icon: Sliders },
          ].map(m => {
            const Icon = m.icon;
            const active = layoutMode === m.id;
            return (
              <button
                key={m.id}
                onClick={() => setLayoutMode(m.id)}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md transition ${
                  active 
                    ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
                title={`Switch layout to ${m.label}`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{m.label}</span>
              </button>
            );
          })}
        </div>

        {/* Center: Search & Filter */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IP or Host..."
              className="bg-[#070B13] text-slate-200 text-xs pl-8 pr-3 py-1 rounded-lg border border-slate-800 focus:outline-none focus:border-cyan-500 w-44 placeholder:text-slate-600"
            />
            {search && (
              <button 
                onClick={() => setSearch('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              >
                ✕
              </button>
            )}
          </div>

          {/* Node Density Limiter */}
          <select
            value={nodeLimit}
            onChange={(e) => setNodeLimit(Number(e.target.value))}
            className="bg-[#070B13] text-slate-300 text-xs px-2.5 py-1 rounded-lg border border-slate-800 focus:outline-none focus:border-cyan-500 cursor-pointer"
            title="Limit displayed nodes to prevent clutter"
          >
            <option value={25}>Top 25 Nodes</option>
            <option value={40}>Top 40 Nodes</option>
            <option value={75}>Top 75 Nodes</option>
            <option value={200}>All Nodes</option>
          </select>
        </div>

        {/* Right: Quick Toggles (Physics, Particles, Minimap, Reset) */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setPhysicsActive(!physicsActive)}
            className={`p-1.5 rounded-lg border transition ${
              physicsActive ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' : 'bg-slate-800 text-slate-500 border-slate-700'
            }`}
            title={physicsActive ? 'Pause Dynamic Physics' : 'Resume Dynamic Physics'}
          >
            {physicsActive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          </button>

          <button
            onClick={() => setShowParticles(!showParticles)}
            className={`p-1.5 rounded-lg border transition ${
              showParticles ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' : 'bg-slate-800 text-slate-500 border-slate-700'
            }`}
            title="Toggle Live Flow Packet Pulses"
          >
            <Zap className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={() => setShowLabels(!showLabels)}
            className={`p-1.5 rounded-lg border transition ${
              showLabels ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' : 'bg-slate-800 text-slate-500 border-slate-700'
            }`}
            title="Toggle IP / Host Labels"
          >
            <Eye className="w-3.5 h-3.5" />
          </button>

          <div className="h-4 w-[1px] bg-slate-800 mx-1" />

          {/* Zoom Controls */}
          <button
            onClick={() => handleZoomBtn(1.2)}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => handleZoomBtn(0.8)}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleResetView}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
            title="Reset View & Recenter"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>

      </div>

      {/* ── CANVAS VIEWPORT ────────────────────────────────────────────────── */}
      <div className="flex-grow relative overflow-hidden bg-[#080B10] cursor-grab active:cursor-grabbing min-h-[480px]">
        <canvas
          ref={canvasRef}
          className="w-full h-full block"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onClick={handleClick}
          onWheel={handleWheel}
        />

        {/* ── FLOATING CATEGORY FILTER BAR (BOTTOM LEFT) ───────────────────── */}
        <div className="absolute bottom-3 left-3 bg-[#0B101D]/90 backdrop-blur-md border border-slate-800/90 rounded-xl p-2 flex items-center gap-2.5 text-[11px] shadow-lg z-10 select-none">
          <span className="text-slate-500 font-bold px-1 uppercase text-[10px]">Tiers:</span>
          
          <label className="flex items-center gap-1.5 cursor-pointer text-amber-400 hover:opacity-90">
            <input
              type="checkbox"
              checked={visibleCategories.gateway}
              onChange={(e) => setVisibleCategories({ ...visibleCategories, gateway: e.target.checked })}
              className="accent-amber-500 rounded cursor-pointer"
            />
            <span>Gateway</span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer text-cyan-400 hover:opacity-90">
            <input
              type="checkbox"
              checked={visibleCategories.internal}
              onChange={(e) => setVisibleCategories({ ...visibleCategories, internal: e.target.checked })}
              className="accent-cyan-500 rounded cursor-pointer"
            />
            <span>Internal Assets</span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer text-rose-400 hover:opacity-90">
            <input
              type="checkbox"
              checked={visibleCategories.external}
              onChange={(e) => setVisibleCategories({ ...visibleCategories, external: e.target.checked })}
              className="accent-rose-500 rounded cursor-pointer"
            />
            <span>Public WAN</span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer text-red-400 hover:opacity-90">
            <input
              type="checkbox"
              checked={visibleCategories.bypass}
              onChange={(e) => setVisibleCategories({ ...visibleCategories, bypass: e.target.checked })}
              className="accent-red-500 rounded cursor-pointer"
            />
            <span>⚠ Rogue Bypass</span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer text-purple-400 hover:opacity-90">
            <input
              type="checkbox"
              checked={visibleCategories.multicast}
              onChange={(e) => setVisibleCategories({ ...visibleCategories, multicast: e.target.checked })}
              className="accent-purple-500 rounded cursor-pointer"
            />
            <span>Multicast</span>
          </label>
        </div>

        {/* ── STATS HUD BADGE (TOP LEFT) ────────────────────────────────────── */}
        <div className="absolute top-3 left-3 bg-[#0B101D]/90 backdrop-blur-md border border-slate-800/90 rounded-lg px-3 py-1.5 text-[11px] text-slate-400 flex items-center gap-3 z-10 select-none">
          <div><span className="text-cyan-400 font-bold">{filteredGraph.nodes.length}</span> nodes</div>
          <div className="h-3 w-[1px] bg-slate-800" />
          <div><span className="text-blue-400 font-bold">{filteredGraph.links.length}</span> active edges</div>
          <div className="h-3 w-[1px] bg-slate-800" />
          <div className="text-slate-500">Zoom: {(zoomLevel * 100).toFixed(0)}%</div>
        </div>

        {/* ── INTERACTIVE HOVER TELEMETRY TOOLTIP ────────────────────────────── */}
        {tooltipPos.visible && hoveredNode && (
          <div 
            className="absolute z-30 pointer-events-none bg-[#0B101D]/95 backdrop-blur-md border border-cyan-500/40 rounded-xl p-3.5 shadow-2xl text-xs font-mono max-w-xs transition-opacity duration-75"
            style={{ left: `${tooltipPos.x}px`, top: `${tooltipPos.y}px` }}
          >
            <div className="flex items-center justify-between gap-2 border-b border-slate-800 pb-2 mb-2">
              <span className="font-bold text-white text-sm">{hoveredNode.ip}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                hoveredNode.is_bypass ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                hoveredNode.is_gw ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                hoveredNode.is_priv ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' :
                'bg-purple-500/20 text-purple-400 border border-purple-500/30'
              }`}>
                {hoveredNode.role}
              </span>
            </div>

            <div className="space-y-1.5 text-[11px]">
              {hoveredNode.label !== hoveredNode.ip && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Hostname:</span>
                  <span className="text-slate-200">{hoveredNode.label}</span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-slate-500">Subnet Zone:</span>
                <span className="text-slate-300">{hoveredNode.subnet}</span>
              </div>
              {hoveredNode.bytes > 0 && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Throughput:</span>
                  <span className="text-emerald-400 font-semibold">{fmtBytes(hoveredNode.bytes)}</span>
                </div>
              )}
              {hoveredNode.flows > 0 && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Flow Count:</span>
                  <span className="text-white">{hoveredNode.flows}</span>
                </div>
              )}
              {hoveredNode.threat > 0 && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Threat Risk:</span>
                  <span className="text-red-400 font-bold">{hoveredNode.threat} / 100</span>
                </div>
              )}
              {hoveredNode.geo && (
                <div className="flex justify-between">
                  <span className="text-slate-500">Location/ASN:</span>
                  <span className="text-slate-300">{hoveredNode.geo}</span>
                </div>
              )}
            </div>

            <div className="mt-2 pt-2 border-t border-slate-800/80 text-[10px] text-cyan-400/80 italic">
              Click node to pin in Inspector
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
