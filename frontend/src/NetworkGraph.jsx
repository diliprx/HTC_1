import React from 'react';

function NetworkGraph({ type, data }) {
  if (!data || !data.unique_assets || data.unique_assets.length === 0) {
    return (
      <div className="w-full h-full flex flex-col justify-center items-center bg-[#0c101a] border border-[#1e293b] rounded-lg p-10 text-center">
        <span className="text-slate-500 font-mono text-sm mb-2">No active flows mapped</span>
        <span className="text-slate-600 font-mono text-xs max-w-md">Topology graphs will dynamically render once traffic is captured or a NetFlow PCAP file is uploaded.</span>
      </div>
    );
  }

  const W = 700;
  const H = 450;
  const cx = W / 2;
  const cy = H / 2;

  // Retrieve data structures
  const assets = data.unique_assets || [];
  const publicIPs = data.public_ips || [];
  const gateway = data.gateway || "10.0.0.1";
  const natBypass = data.natBypass || [];
  
  // Custom protocol port list from data
  const protoPorts = data.protoPort || [];

  if (type === 'asset-pubip') {
    // Top 8 assets to prevent screen clutter
    const displayAssets = assets.slice(0, 8);
    const nodes = [];
    const links = [];

    // Gateway (Center)
    nodes.push({ id: 'gateway', x: cx, y: cy, label: 'Gateway', subtitle: gateway, r: 24, fill: '#E5A93C', stroke: '#B27A1C', color: '#111622' });

    displayAssets.forEach((asset, idx) => {
      const angle = (idx / displayAssets.length) * 2 * Math.PI - Math.PI / 2;
      const ax = cx + 130 * Math.cos(angle);
      const ay = cy + 130 * Math.sin(angle);
      const assetId = `asset-${asset.ip}`;

      // Connect Asset to Gateway
      links.push({ x1: cx, y1: cy, x2: ax, y2: ay, color: 'rgba(0, 242, 254, 0.25)', dash: false });

      // Identify public IPs communicating with this asset
      const peers = publicIPs.filter(p => p.talks.includes(asset.ip)).slice(0, 3);
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
          isPeer: true
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
        color: '#080B10'
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
      nodes.push({ id: `proto-${proto}`, x: protoX, y: py, label: proto, subtitle: 'Protocol', r: 20, fill: protoColors[proto], stroke: protoColors[proto], color: '#F8FAFC' });
    });

    // Asset Nodes (Left Column)
    const assetX = 100;
    displayAssets.forEach((asset, idx) => {
      const ay = 60 + idx * (H - 120) / (displayAssets.length - 1 || 1);
      nodes.push({ id: `asset-${asset.ip}`, x: assetX, y: ay, label: '.' + asset.ip.split('.').pop(), subtitle: asset.host, r: 16, fill: '#00F2FE', stroke: '#00B4D8', color: '#080B10' });

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
    nodes.push({ id: 'gateway', x: cx, y: cy, label: 'GW', subtitle: gateway, r: 26, fill: '#E5A93C', stroke: '#B27A1C', color: '#111622' });

    // Separate normal assets and bypass assets
    const bypassAssets = assets.filter(a => natBypass.includes(a.ip));
    const normalAssets = assets.filter(a => !natBypass.includes(a.ip));

    // Render normal assets in inner circle (Solid Blue Links)
    normalAssets.slice(0, 10).forEach((asset, idx) => {
      const angle = (idx / normalAssets.slice(0, 10).length) * 2 * Math.PI;
      const ax = cx + 120 * Math.cos(angle);
      const ay = cy + 120 * Math.sin(angle);
      links.push({ x1: cx, y1: cy, x2: ax, y2: ay, color: 'rgba(0, 242, 254, 0.3)', dash: false });
      nodes.push({ id: `asset-${asset.ip}`, x: ax, y: ay, label: '.' + asset.ip.split('.').pop(), subtitle: asset.host, r: 16, fill: '#00F2FE', stroke: '#00B4D8', color: '#080B10' });
    });

    // Render bypass assets in outer circle (Animated Dotted Amber/Coral Links)
    bypassAssets.forEach((asset, idx) => {
      const angle = (idx / (bypassAssets.length || 1)) * 2 * Math.PI + Math.PI / 4;
      const ax = cx + 200 * Math.cos(angle);
      const ay = cy + 200 * Math.sin(angle);
      links.push({ x1: cx, y1: cy, x2: ax, y2: ay, color: '#E5A93C', dash: true });
      nodes.push({ id: `asset-${asset.ip}`, x: ax, y: ay, label: '.' + asset.ip.split('.').pop(), subtitle: 'NAT Bypass', r: 16, fill: '#FF3366', stroke: '#C21B4C', color: '#F8FAFC', alert: true });
    });

    return renderSvg(nodes, links, "Gateway Routing Integrity: Compliant Flows (Solid Cyan) vs Bypasses (Dashed Coral)");
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
            {nodes.map((node) => (
              <g key={node.id} className="cursor-pointer group">
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
            ))}
          </svg>
        </div>
      </div>
    );
  }
}

export default NetworkGraph;
