import React from 'react';

function NetworkGraph({ type, data, onSelectNode, selectedNode }) {
  // Allow render if we have either classic asset data or graph topology data
  const hasAssets = data && data.unique_assets && data.unique_assets.length > 0;
  const hasGraph  = data && data.graph && data.graph.nodes && data.graph.nodes.length > 0;

  if (!hasAssets && !hasGraph) {
    return (
      <div className="w-full h-full flex flex-col justify-center items-center bg-[#0c101a] border border-[#1e293b] rounded-lg p-10 text-center">
        <span className="text-slate-500 font-mono text-sm mb-2">No active flows mapped</span>
        <span className="text-slate-600 font-mono text-xs max-w-md">Topology graphs will dynamically render once traffic is captured or a NetFlow PCAP file is uploaded.</span>
      </div>
    );
  }

  const W = 720;
  const H = 480;
  const cx = W / 2;
  const cy = H / 2;

  // Retrieve data structures
  const assets    = data.unique_assets || [];
  const publicIPs = data.public_ips    || [];
  const gateway   = data.gateway       || null;
  const natBypass = data.natBypass     || [];

  // Custom protocol port list from data
  const protoPorts = data.protoPort || [];

  // ── Node type visual config ──────────────────────────────────────────────
  const NODE_STYLE = {
    internal:  { fill: '#00F2FE', stroke: '#00B4D8', color: '#080B10', r: 18 },
    external:  { fill: '#FF3366', stroke: '#C21B4C', color: '#F8FAFC', r: 13 },
    gateway:   { fill: '#E5A93C', stroke: '#B27A1C', color: '#111622', r: 26 },
    nat_bypass:{ fill: '#FF5C00', stroke: '#CC4400', color: '#F8FAFC', r: 16, alert: true },
  };

  const getStyle = (nodeType) => NODE_STYLE[nodeType] || NODE_STYLE.internal;

  if (type === 'asset-pubip') {
    // Top 8 assets to prevent screen clutter
    const displayAssets = assets.slice(0, 8);
    const nodes = [];
    const links = [];

    // Gateway (Center)
    nodes.push({ 
      id: 'gateway', 
      x: cx, y: cy, 
      label: 'Gateway', 
      subtitle: gateway, 
      r: 24, 
      fill: '#E5A93C', 
      stroke: '#B27A1C', 
      color: '#111622',
      ip: gateway,
      role: 'Gateway',
      host: 'core-router'
    });

    displayAssets.forEach((asset, idx) => {
      const angle = (idx / displayAssets.length) * 2 * Math.PI - Math.PI / 2;
      const ax = cx + 130 * Math.cos(angle);
      const ay = cy + 130 * Math.sin(angle);
      const assetId = `asset-${asset.ip}`;

      // Connect Asset to Gateway
      links.push({ x1: cx, y1: cy, x2: ax, y2: ay, color: 'rgba(0, 242, 254, 0.25)', dash: false });

      // Identify public IPs communicating with this asset
      const peers = publicIPs.filter(p => p.talksto && p.talksto.includes(asset.ip)).slice(0, 3);
      peers.forEach((peer, pidx) => {
        const peerAngle = angle + (pidx - (peers.length - 1) / 2) * 0.4;
        const px = ax + 90 * Math.cos(peerAngle);
        const py = ay + 90 * Math.sin(peerAngle);
        // Use asset index (idx) + peer index (pidx) to guarantee key uniqueness
        const peerId = `peer-${idx}-${pidx}-${peer.ip}`;

        // Connect Asset to Peer
        links.push({ x1: ax, y1: ay, x2: px, y2: py, color: 'rgba(255, 51, 102, 0.25)', dash: true });

        // Add Peer Node
        nodes.push({
          id: peerId,
          x: px,
          y: py,
          label: peer.ip.split('.').pop() + '.*',
          subtitle: peer.geo.split('/')[0].trim(),
          r: 14,
          fill: '#FF3366',
          stroke: '#C21B4C',
          color: '#F8FAFC',
          isPeer: true,
          ip: peer.ip,
          role: 'Public Peer',
          geo: peer.geo,
          threat: peer.threat,
          bytesIn: peer.bytesIn,
          protocols: peer.proto,
          talksto: peer.talksto
        });
      });

      // Add Asset Node
      nodes.push({
        id: assetId,
        x: ax,
        y: ay,
        label: '.' + asset.ip.split('.').pop(),
        subtitle: asset.host,
        r: 18,
        fill: '#00F2FE',
        stroke: '#00B4D8',
        color: '#080B10',
        ip: asset.ip,
        role: 'Asset',
        host: asset.host,
        bytes: asset.bytes,
        flows: asset.flows,
        protocols: asset.protocols,
        ports: asset.ports
      });
    });

    return renderSvg(nodes, links, "Flow Mapping: Private Assets (Cyan) ↔ External Public IPs (Coral)");
  }

  if (type === 'asset-proto') {
    const displayAssets = assets.slice(0, 8);
    const protocols = ['TCP', 'UDP', 'ICMP'];
    const nodes = [];
    const links = [];

    // Protocol Nodes (Right Column)
    const protoX = W - 100;
    const protoColors = { 'TCP': '#8B5CF6', 'UDP': '#3B82F6', 'ICMP': '#EC4899' };
    
    protocols.forEach((proto, idx) => {
      const py = 100 + idx * (H - 200) / (protocols.length - 1 || 1);
      nodes.push({ 
        id: `proto-${proto}`, 
        x: protoX, 
        y: py, 
        label: proto, 
        subtitle: 'Protocol', 
        r: 20, 
        fill: protoColors[proto], 
        stroke: protoColors[proto], 
        color: '#F8FAFC',
        ip: proto,
        role: 'Protocol'
      });
    });

    // Asset Nodes (Left Column)
    const assetX = 100;
    displayAssets.forEach((asset, idx) => {
      const ay = 60 + idx * (H - 120) / (displayAssets.length - 1 || 1);
      nodes.push({ 
        id: `asset-${asset.ip}`, 
        x: assetX, 
        y: ay, 
        label: '.' + asset.ip.split('.').pop(), 
        subtitle: asset.host, 
        r: 16, 
        fill: '#00F2FE', 
        stroke: '#00B4D8', 
        color: '#080B10',
        ip: asset.ip,
        role: 'Asset',
        host: asset.host,
        bytes: asset.bytes,
        flows: asset.flows,
        protocols: asset.protocols,
        ports: asset.ports
      });

      // Determine which protocols this asset uses
      const usedProtos = new Set();
      protoPorts.forEach(pp => {
        if (pp.ips.includes(asset.ip)) {
          usedProtos.add(pp.proto);
        }
      });

      protocols.forEach((proto) => {
        if (usedProtos.has(proto)) {
          const py = 100 + protocols.indexOf(proto) * (H - 200) / (protocols.length - 1 || 1);
          links.push({ x1: assetX, y1: ay, x2: protoX, y2: py, color: 'rgba(139, 92, 246, 0.25)', dash: false });
        }
      });
    });

    return renderSvg(nodes, links, "Port Compliance: Internal Endpoints ↔ Active Protocol Bindings");
  }

  if (type === 'gateway-flow') {
    const nodes = [];
    const links = [];

    // Gateway (Center)
    nodes.push({ 
      id: 'gateway', 
      x: cx, y: cy, 
      label: 'GW', 
      subtitle: gateway, 
      r: 26, 
      fill: '#E5A93C', 
      stroke: '#B27A1C', 
      color: '#111622',
      ip: gateway,
      role: 'Gateway',
      host: 'core-router'
    });

    // Separate normal assets and bypass assets
    const bypassAssets = assets.filter(a => natBypass.some(nb => nb.ip === a.ip));
    const normalAssets = assets.filter(a => !natBypass.some(nb => nb.ip === a.ip));

    // Render normal assets in inner circle (Solid Blue Links)
    normalAssets.slice(0, 10).forEach((asset, idx) => {
      const angle = (idx / normalAssets.slice(0, 10).length) * 2 * Math.PI;
      const ax = cx + 120 * Math.cos(angle);
      const ay = cy + 120 * Math.sin(angle);
      links.push({ x1: cx, y1: cy, x2: ax, y2: ay, color: 'rgba(0, 242, 254, 0.3)', dash: false });
      nodes.push({ 
        id: `asset-${asset.ip}`, 
        x: ax, 
        y: ay, 
        label: '.' + asset.ip.split('.').pop(), 
        subtitle: asset.host, 
        r: 16, 
        fill: '#00F2FE', 
        stroke: '#00B4D8', 
        color: '#080B10',
        ip: asset.ip,
        role: 'Asset',
        host: asset.host,
        bytes: asset.bytes,
        flows: asset.flows,
        protocols: asset.protocols,
        ports: asset.ports
      });
    });

    // Render bypass assets in outer circle (Animated Dotted Amber/Coral Links)
    bypassAssets.forEach((asset, idx) => {
      const angle = (idx / (bypassAssets.length || 1)) * 2 * Math.PI + Math.PI / 4;
      const ax = cx + 200 * Math.cos(angle);
      const ay = cy + 200 * Math.sin(angle);
      links.push({ x1: cx, y1: cy, x2: ax, y2: ay, color: '#E5A93C', dash: true });
      nodes.push({ 
        id: `asset-${asset.ip}`, 
        x: ax, 
        y: ay, 
        label: '.' + asset.ip.split('.').pop(), 
        subtitle: 'NAT Bypass', 
        r: 16, 
        fill: '#FF3366', 
        stroke: '#C21B4C', 
        color: '#F8FAFC', 
        alert: true,
        ip: asset.ip,
        role: 'Asset (NAT Bypass)',
        host: asset.host,
        bytes: asset.bytes,
        flows: asset.flows,
        protocols: asset.protocols,
        ports: asset.ports
      });
    });

    return renderSvg(nodes, links, "Gateway Routing Integrity: Compliant Flows (Solid Cyan) vs Bypasses (Dashed Coral)");
  }

  // ══════════════════════════════════════════════════════════════════════
  // TOPOLOGY VIEW — consumes data.graph.nodes + data.graph.edges from API
  // Node types: internal | external | gateway | nat_bypass
  // ══════════════════════════════════════════════════════════════════════
  if (type === 'topology') {
    const graphNodes = (data.graph && data.graph.nodes) ? data.graph.nodes : [];
    const graphEdges = (data.graph && data.graph.edges) ? data.graph.edges : [];

    if (graphNodes.length === 0) {
      return (
        <div className="w-full h-full flex flex-col justify-center items-center bg-[#0c101a] border border-[#1e293b] rounded-lg p-10 text-center">
          <span className="text-slate-500 font-mono text-sm mb-2">No topology data available</span>
          <span className="text-slate-600 font-mono text-xs max-w-md">Capture traffic or upload a PCAP file to generate the network topology map.</span>
        </div>
      );
    }

    // ── Force-directed layout: cluster by node type ──────────────────────
    // Gateway → center, internal → inner ring, external → outer ring, bypass → outer ring (offset)
    const gatewayNodes  = graphNodes.filter(n => n.type === 'gateway');
    const internalNodes = graphNodes.filter(n => n.type === 'internal');
    const bypassNodes   = graphNodes.filter(n => n.type === 'nat_bypass');
    const externalNodes = graphNodes.filter(n => n.type === 'external');

    const nodePos = {};

    // Gateway at center
    gatewayNodes.forEach(n => { nodePos[n.id] = { x: cx, y: cy }; });

    // Internal assets: inner ring
    const innerR = 130;
    internalNodes.forEach((n, i) => {
      const angle = (i / Math.max(internalNodes.length, 1)) * 2 * Math.PI - Math.PI / 2;
      nodePos[n.id] = { x: cx + innerR * Math.cos(angle), y: cy + innerR * Math.sin(angle) };
    });

    // NAT bypass assets: mid ring with offset angle (orange, visually separated)
    const bypassR = 180;
    bypassNodes.forEach((n, i) => {
      const angle = (i / Math.max(bypassNodes.length, 1)) * 2 * Math.PI + Math.PI / 4;
      nodePos[n.id] = { x: cx + bypassR * Math.cos(angle), y: cy + bypassR * Math.sin(angle) };
    });

    // External / public WAN: outer ring
    const outerR = 300;
    const topExternal = externalNodes.slice(0, 12); // cap to prevent clutter
    topExternal.forEach((n, i) => {
      const angle = (i / Math.max(topExternal.length, 1)) * 2 * Math.PI - Math.PI / 3;
      nodePos[n.id] = { x: cx + outerR * Math.cos(angle), y: cy + outerR * Math.sin(angle) };
    });

    // ── Build link list from edges ───────────────────────────────────────
    const maxBytes = Math.max(...graphEdges.map(e => e.bytes || 0), 1);
    const links = graphEdges
      .filter(e => nodePos[e.source] && nodePos[e.target])
      .map((edge, idx) => {
        const s = nodePos[edge.source];
        const t = nodePos[edge.target];
        const isBypass = edge.is_bypass === true;
        // Scale stroke width (1–4px) by byte volume
        const normalized = Math.sqrt((edge.bytes || 0) / maxBytes);
        const strokeW = 0.8 + normalized * 3;
        return {
          x1: s.x, y1: s.y, x2: t.x, y2: t.y,
          color: isBypass ? 'rgba(255, 92, 0, 0.7)' : 'rgba(0, 242, 254, 0.2)',
          dash: isBypass,
          strokeWidth: strokeW,
          label: edge.proto,
          key: `topo-edge-${idx}`,
        };
      });

    // ── Build renderable node list ────────────────────────────────────────
    const renderedNodes = [
      ...gatewayNodes,
      ...internalNodes,
      ...bypassNodes,
      ...topExternal,
    ].filter(n => nodePos[n.id]).map(n => {
      const pos   = nodePos[n.id];
      const style = getStyle(n.type);
      return {
        id:       n.id,
        x:        pos.x,
        y:        pos.y,
        label:    n.label || n.id.split('.').pop(),
        subtitle: n.type === 'gateway'    ? `GW: ${n.id}`
                : n.type === 'nat_bypass' ? `⚠ NAT Bypass`
                : n.type === 'external'   ? (n.geo || n.id)
                : n.id,
        r:        style.r,
        fill:     style.fill,
        stroke:   style.stroke,
        color:    style.color,
        alert:    style.alert || false,
        ip:       n.id,
        role:     n.type,
        geo:      n.geo,
        threat:   n.threat,
      };
    });

    const legendItems = [
      { color: '#E5A93C', label: 'Detected Gateway' },
      { color: '#00F2FE', label: 'Internal Asset' },
      { color: '#FF3366', label: 'Public WAN IP' },
      { color: '#FF5C00', label: '⚠ NAT Bypass' },
    ];

    return (
      <div className="w-full h-full flex flex-col justify-between">
        <div className="text-[11px] text-slate-400 font-mono text-center mb-1">
          Live Topology Map — Backend Graph (nodes: {graphNodes.length}, edges: {graphEdges.length})
        </div>
        {/* Legend */}
        <div className="flex flex-row gap-4 justify-center mb-1">
          {legendItems.map(li => (
            <div key={li.label} className="flex items-center gap-1">
              <span style={{ display:'inline-block', width:10, height:10, borderRadius:'50%', background: li.color }} />
              <span className="text-[10px] font-mono text-slate-400">{li.label}</span>
            </div>
          ))}
        </div>
        <div className="flex-grow relative overflow-hidden bg-[#0c101a] border border-[#1e293b] rounded-lg">
          <svg className="w-full h-full min-h-[360px]" viewBox={`0 0 ${W} ${H}`}>
            <defs>
              <radialGradient id="topo-glow" cx="50%" cy="50%" r="50%">
                <stop offset="0%"   stopColor="#E5A93C" stopOpacity="0.10" />
                <stop offset="100%" stopColor="#E5A93C" stopOpacity="0" />
              </radialGradient>
              {/* Animated stroke for bypass edges */}
              <style>{`.bypass-dash { stroke-dasharray: 6 4; animation: dash-move 1.2s linear infinite; } @keyframes dash-move { to { stroke-dashoffset: -20; } }`}</style>
            </defs>

            {/* Soft center glow */}
            <circle cx={cx} cy={cy} r={200} fill="url(#topo-glow)" />

            {/* Edges */}
            {links.map((link) => (
              <line
                key={link.key}
                x1={link.x1} y1={link.y1}
                x2={link.x2} y2={link.y2}
                stroke={link.color}
                strokeWidth={link.strokeWidth || 1.2}
                className={link.dash ? 'bypass-dash' : ''}
              />
            ))}

            {/* Nodes */}
            {renderedNodes.map((node) => {
              const isSelected = selectedNode && selectedNode.id === node.id;
              return (
                <g
                  key={node.id}
                  className="cursor-pointer group"
                  onClick={() => onSelectNode && onSelectNode(node)}
                >
                  {/* Selected glow ring */}
                  {isSelected && (
                    <circle cx={node.x} cy={node.y} r={node.r + 6}
                      fill="transparent" stroke="#00F2FE" strokeWidth={1.5}
                      className="animate-pulse" />
                  )}
                  {/* NAT bypass alert pulse ring */}
                  {node.alert && (
                    <circle cx={node.x} cy={node.y} r={node.r + 4}
                      fill="transparent" stroke="#FF5C00" strokeWidth={1}
                      className="warning-pulse" />
                  )}
                  <circle
                    cx={node.x} cy={node.y} r={node.r}
                    fill={node.fill} stroke={node.stroke} strokeWidth={2}
                  />
                  <text
                    x={node.x} y={node.y}
                    textAnchor="middle" dominantBaseline="central"
                    fontSize={node.r > 18 ? 10 : 8}
                    fill={node.color} fontWeight="bold"
                    className="select-none font-mono"
                  >
                    {node.label}
                  </text>
                  <text
                    x={node.x} y={node.y + node.r + 14}
                    textAnchor="middle" fontSize={9} fill="#94A3B8"
                    className="pointer-events-none opacity-80 group-hover:opacity-100 font-mono"
                  >
                    {node.subtitle}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
      </div>
    );
  }

  return null;

  function renderSvg(nodes, links, titleText) {
    return (
      <div className="w-full h-full flex flex-col justify-between">
        <div className="text-[11px] text-slate-400 font-mono text-center mb-1">{titleText}</div>
        <div className="flex-grow relative overflow-hidden bg-[#0c101a] border border-[#1e293b] rounded-lg">
          <svg className="w-full h-full min-h-[360px]" viewBox={`0 0 ${W} ${H}`}>
            <defs>
              <radialGradient id="glow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#00F2FE" stopOpacity="0.15" />
                <stop offset="100%" stopColor="#00F2FE" stopOpacity="0" />
              </radialGradient>
            </defs>

            {/* Glowing background in center */}
            <circle cx={cx} cy={cy} r={220} fill="url(#glow)" />

            {/* Link Lines */}
            {links.map((link, idx) => (
              <line
                key={`link-${idx}`}
                x1={link.x1}
                y1={link.y1}
                x2={link.x2}
                y2={link.y2}
                stroke={link.color}
                strokeWidth={link.dash ? 1.5 : 1.2}
                className={link.dash ? "flow-animate" : ""}
              />
            ))}

            {/* Node Shapes & Texts */}
            {nodes.map((node) => {
              const isSelected = selectedNode && selectedNode.id === node.id;
              return (
                <g 
                  key={node.id} 
                  className="cursor-pointer group"
                  onClick={() => onSelectNode && onSelectNode(node)}
                >
                  {/* Selected Glow Ring */}
                  {isSelected && (
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={node.r + 5}
                      fill="transparent"
                      stroke="#00F2FE"
                      strokeWidth={1.5}
                      className="animate-pulse"
                    />
                  )}
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={node.r}
                    fill={node.fill}
                    stroke={node.stroke}
                    strokeWidth={2}
                    className={node.alert ? "warning-pulse" : ""}
                  />
                  
                  {/* Node labels */}
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r={node.r}
                    fill="transparent"
                    className="group-hover:stroke-slate-100 group-hover:stroke-1"
                  />

                  <text
                    x={node.x}
                    y={node.y}
                    textAnchor="middle"
                    dominantBaseline="central"
                    fontSize={node.r > 18 ? 10 : 8}
                    fill={node.color}
                    fontWeight="bold"
                    className="select-none font-mono"
                  >
                    {node.label}
                  </text>

                  {/* Popover / Telemetry Label Hover Overlay */}
                  <text
                    x={node.x}
                    y={node.y + node.r + 14}
                    textAnchor="middle"
                    fontSize={9}
                    fill="#94A3B8"
                    fontWeight="normal"
                    className="pointer-events-none opacity-80 group-hover:opacity-100 font-mono transition-opacity"
                  >
                    {node.subtitle}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
      </div>
    );
  }
}

export default NetworkGraph;
