import { useRef, useEffect, useState, useCallback } from 'react';

const ENTITY_COLOR: Record<string, string> = {
  domain:          '#ef4444',
  subdomain:       '#f97316',
  ip:              '#3b82f6',
  cidr:            '#6366f1',
  email:           '#a855f7',
  phone:           '#ec4899',
  username:        '#14b8a6',
  person:          '#10b981',
  company:         '#f59e0b',
  app:             '#84cc16',
  repo:            '#06b6d4',
  cloud_account:   '#8b5cf6',
  bucket:          '#d946ef',
  api_endpoint:    '#f43f5e',
  credential:      '#dc2626',
  certificate:     '#0ea5e9',
  social_profile:  '#22c55e',
  url:             '#fb923c',
  port:            '#64748b',
  vulnerability:   '#b91c1c',
  default:         '#71717a',
};

const ENTITY_ICON: Record<string, string> = {
  domain: '🌐', subdomain: '↳', ip: '📡', cidr: '🕸', email: '✉',
  phone: '📞', username: '👤', person: '🧑', company: '🏢', app: '📱',
  repo: '📦', cloud_account: '☁', bucket: '🪣', api_endpoint: '⚡',
  credential: '🔑', certificate: '📜', social_profile: '👥', url: '🔗',
  port: '🔌', vulnerability: '🐛', default: '○',
};

interface Node {
  id: string; type: string; value: string; label?: string;
  risk_overall?: number; is_seed: boolean;
  x: number; y: number; vx: number; vy: number;
}
interface Edge { id: string; from_entity_id: string; to_entity_id: string; type: string; }

function runForce(nodes: Node[], edges: Edge[], iterations = 120) {
  const k = Math.sqrt((600 * 600) / Math.max(nodes.length, 1));
  for (let i = 0; i < iterations; i++) {
    // Repulsion
    for (let a = 0; a < nodes.length; a++) {
      for (let b = a + 1; b < nodes.length; b++) {
        const dx = nodes[b].x - nodes[a].x;
        const dy = nodes[b].y - nodes[a].y;
        const d = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (k * k) / d;
        const fx = (dx / d) * f * 0.5;
        const fy = (dy / d) * f * 0.5;
        nodes[a].vx -= fx; nodes[a].vy -= fy;
        nodes[b].vx += fx; nodes[b].vy += fy;
      }
    }
    // Attraction along edges
    for (const e of edges) {
      const a = nodes.find(n => n.id === e.from_entity_id);
      const b = nodes.find(n => n.id === e.to_entity_id);
      if (!a || !b) continue;
      const dx = b.x - a.x; const dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const f = (d * d) / k * 0.3;
      const fx = (dx / d) * f; const fy = (dy / d) * f;
      a.vx += fx; a.vy += fy;
      b.vx -= fx; b.vy -= fy;
    }
    // Gravity + damping
    for (const n of nodes) {
      n.vx += (300 - n.x) * 0.01;
      n.vy += (300 - n.y) * 0.01;
      n.vx *= 0.85; n.vy *= 0.85;
      n.x += n.vx; n.y += n.vy;
      n.x = Math.max(30, Math.min(570, n.x));
      n.y = Math.max(30, Math.min(570, n.y));
    }
  }
}

export default function EntityGraph({
  nodes: rawNodes,
  edges,
  onSelectNode,
}: {
  nodes: any[];
  edges: any[];
  onSelectNode?: (node: any) => void;
}) {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    if (!rawNodes.length) return;
    const initialized: Node[] = rawNodes.map((n, i) => ({
      ...n,
      x: 300 + (Math.random() - 0.5) * 400,
      y: 300 + (Math.random() - 0.5) * 400,
      vx: 0, vy: 0,
    }));
    runForce(initialized, edges, 200);
    setNodes(initialized);
  }, [rawNodes.length, edges.length]);

  if (!nodes.length) {
    return (
      <div className="flex items-center justify-center h-64 text-zinc-600">
        <div className="text-center">
          <div className="text-4xl mb-2">🕸</div>
          <div>No entities discovered yet</div>
        </div>
      </div>
    );
  }

  const nodeMap = new Map(nodes.map(n => [n.id, n]));

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
      <div className="p-3 border-b border-zinc-800 flex items-center gap-4 flex-wrap">
        <span className="text-xs text-zinc-400">{nodes.length} entities • {edges.length} relationships</span>
        <div className="flex gap-3 flex-wrap">
          {[...new Set(nodes.map(n => n.type))].map(t => (
            <span key={t} className="flex items-center gap-1 text-xs text-zinc-400">
              <span style={{ color: ENTITY_COLOR[t] ?? ENTITY_COLOR.default }}>●</span>
              {t}
            </span>
          ))}
        </div>
      </div>
      <svg
        viewBox="0 0 600 600"
        className="w-full"
        style={{ maxHeight: '600px' }}
      >
        {/* Edges */}
        {edges.map(e => {
          const a = nodeMap.get(e.from_entity_id);
          const b = nodeMap.get(e.to_entity_id);
          if (!a || !b) return null;
          return (
            <line
              key={e.id}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke="#3f3f46"
              strokeWidth="1"
              strokeOpacity="0.8"
            />
          );
        })}
        {/* Edge labels */}
        {edges.slice(0, 30).map(e => {
          const a = nodeMap.get(e.from_entity_id);
          const b = nodeMap.get(e.to_entity_id);
          if (!a || !b) return null;
          return (
            <text
              key={`lbl-${e.id}`}
              x={(a.x + b.x) / 2}
              y={(a.y + b.y) / 2}
              fontSize="7"
              fill="#52525b"
              textAnchor="middle"
            >
              {e.type}
            </text>
          );
        })}
        {/* Nodes */}
        {nodes.map(n => {
          const color = ENTITY_COLOR[n.type] ?? ENTITY_COLOR.default;
          const isSelected = selected === n.id;
          const r = n.is_seed ? 18 : n.risk_overall && n.risk_overall > 70 ? 14 : 10;
          return (
            <g
              key={n.id}
              transform={`translate(${n.x},${n.y})`}
              className="cursor-pointer"
              onClick={() => {
                setSelected(isSelected ? null : n.id);
                onSelectNode?.(isSelected ? null : n);
              }}
            >
              {isSelected && (
                <circle r={r + 6} fill="none" stroke={color} strokeWidth="2" strokeOpacity="0.5" />
              )}
              <circle
                r={r}
                fill={color}
                fillOpacity={isSelected ? 1 : 0.75}
                stroke={isSelected ? color : '#27272a'}
                strokeWidth={n.is_seed ? 2 : 1}
              />
              <text fontSize="8" textAnchor="middle" dy="3" fill="white" fontWeight="bold" pointerEvents="none">
                {ENTITY_ICON[n.type] ?? '○'}
              </text>
              {(n.is_seed || r >= 14) && (
                <text
                  y={r + 10}
                  fontSize="8"
                  textAnchor="middle"
                  fill="#a1a1aa"
                  pointerEvents="none"
                >
                  {n.value.length > 20 ? n.value.slice(0, 18) + '…' : n.value}
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
