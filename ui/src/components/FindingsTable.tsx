import { useState } from 'react';

const SEV_STYLE: Record<string, string> = {
  critical: 'bg-red-600/20 text-red-400 border-red-600/30',
  high:     'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low:      'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info:     'bg-zinc-500/20 text-zinc-400 border-zinc-500/30',
};

export default function FindingsTable({ findings }: { findings: any[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filter, setFilter] = useState('all');

  const severities = ['all', 'critical', 'high', 'medium', 'low', 'info'];
  const filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter);

  if (!findings.length) {
    return (
      <div className="text-center py-16 text-zinc-600">
        <div className="text-4xl mb-3">🔍</div>
        <div>No findings yet</div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex gap-2 flex-wrap">
        {severities.map(s => {
          const count = s === 'all' ? findings.length : findings.filter(f => f.severity === s).length;
          return (
            <button
              key={s}
              onClick={() => setFilter(s)}
              className={`px-3 py-1 rounded text-xs font-medium border capitalize transition-colors ${
                filter === s
                  ? (SEV_STYLE[s] ?? 'bg-zinc-700 text-white border-zinc-600')
                  : 'bg-transparent text-zinc-500 border-zinc-700 hover:text-zinc-300'
              }`}
            >
              {s} {count > 0 && `(${count})`}
            </button>
          );
        })}
      </div>

      <div className="space-y-2">
        {filtered.map((f: any) => (
          <div key={f.id} className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
            <button
              className="w-full text-left px-4 py-3 flex items-start gap-3 hover:bg-zinc-800/50 transition-colors"
              onClick={() => setExpanded(expanded === f.id ? null : f.id)}
            >
              <span className={`mt-0.5 shrink-0 text-xs font-semibold px-2 py-0.5 rounded border uppercase ${SEV_STYLE[f.severity] ?? SEV_STYLE.info}`}>
                {f.severity}
              </span>
              <div className="flex-1 min-w-0">
                <div className="font-medium text-sm">{f.title}</div>
                <div className="flex gap-3 text-xs text-zinc-500 mt-0.5 flex-wrap">
                  {f.entity_type && (
                    <span className="text-zinc-600">{f.entity_type}: <span className="text-zinc-400">{f.entity_value}</span></span>
                  )}
                  {f.url && <span className="truncate max-w-xs">{f.url}</span>}
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className="text-xs text-zinc-600 bg-zinc-800 px-2 py-0.5 rounded">{f.module}</span>
                <span className="text-xs text-zinc-600">{f.tool}</span>
                <span className="text-zinc-600 text-sm">{expanded === f.id ? '▲' : '▼'}</span>
              </div>
            </button>

            {expanded === f.id && (
              <div className="px-4 pb-4 border-t border-zinc-800 space-y-3 pt-3">
                {f.description && <p className="text-sm text-zinc-300">{f.description}</p>}
                {f.proof && (
                  <div>
                    <div className="text-xs text-zinc-500 mb-1 uppercase tracking-wide">Proof of Concept</div>
                    <pre className="bg-zinc-950 border border-zinc-800 rounded p-3 text-xs text-green-400 overflow-x-auto whitespace-pre-wrap">{f.proof}</pre>
                  </div>
                )}
                {f.remediation && (
                  <div>
                    <div className="text-xs text-zinc-500 mb-1 uppercase tracking-wide">Remediation</div>
                    <p className="text-sm text-zinc-300">{f.remediation}</p>
                  </div>
                )}
                <div className="flex gap-4 text-xs text-zinc-600 flex-wrap">
                  {f.cve && <span className="text-red-400">CVE: {f.cve}</span>}
                  {f.cwe && <span>CWE: {f.cwe}</span>}
                  {f.category && <span>Category: {f.category}</span>}
                  <span>{new Date(f.created_at).toLocaleString()}</span>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
