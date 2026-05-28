import { useState } from 'react';

const TYPE_ICON: Record<string, string> = {
  screenshot:   '🖼',
  http_response:'📄',
  dns_record:   '📋',
  certificate:  '📜',
  secret:       '🔑',
  file:         '📁',
  raw_output:   '🖥',
  api_response: '⚡',
  git_content:  '📦',
  cloud_object: '☁',
  default:      '📎',
};

export default function EvidenceLocker({ evidence }: { evidence: any[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filter, setFilter] = useState('all');

  const types = ['all', ...new Set(evidence.map(e => e.type))];
  const filtered = filter === 'all' ? evidence : evidence.filter(e => e.type === filter);

  if (!evidence.length) {
    return (
      <div className="text-center py-16 text-zinc-600">
        <div className="text-4xl mb-2">🗄</div>
        <div>No evidence collected yet</div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Filter tabs */}
      <div className="flex gap-2 flex-wrap">
        {types.map(t => (
          <button
            key={t}
            onClick={() => setFilter(t)}
            className={`px-3 py-1 rounded text-xs font-medium border capitalize transition-colors ${
              filter === t
                ? 'bg-zinc-700 text-white border-zinc-600'
                : 'bg-transparent text-zinc-500 border-zinc-700 hover:text-zinc-300'
            }`}
          >
            {t === 'all' ? `All (${evidence.length})` : `${t} (${evidence.filter(e => e.type === t).length})`}
          </button>
        ))}
      </div>

      {/* Evidence items */}
      <div className="space-y-2">
        {filtered.map(ev => (
          <div key={ev.id} className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
            <button
              className="w-full text-left px-4 py-3 flex items-start gap-3 hover:bg-zinc-800/50 transition-colors"
              onClick={() => setExpanded(expanded === ev.id ? null : ev.id)}
            >
              <span className="text-lg shrink-0 mt-0.5">{TYPE_ICON[ev.type] ?? TYPE_ICON.default}</span>
              <div className="flex-1 min-w-0">
                <div className="font-medium text-sm">{ev.title}</div>
                <div className="text-xs text-zinc-500 mt-0.5 flex gap-3">
                  {ev.entity_type && <span>{ev.entity_type}: {ev.entity_value}</span>}
                  <span>{ev.tool}</span>
                  <span>{new Date(ev.timestamp).toLocaleString()}</span>
                </div>
              </div>
              <span className="text-xs text-zinc-600 shrink-0 capitalize bg-zinc-800 px-2 py-0.5 rounded">{ev.type}</span>
            </button>

            {expanded === ev.id && (
              <div className="px-4 pb-4 border-t border-zinc-800 pt-3 space-y-2">
                {ev.source_url && (
                  <div className="text-xs">
                    <span className="text-zinc-500">Source: </span>
                    <span className="text-blue-400 break-all">{ev.source_url}</span>
                  </div>
                )}
                {ev.content && (
                  <pre className="bg-zinc-950 border border-zinc-800 rounded p-3 text-xs text-green-400 overflow-x-auto whitespace-pre-wrap max-h-64">
                    {ev.content}
                  </pre>
                )}
                {ev.file_path && (
                  <div className="text-xs text-zinc-500">File: {ev.file_path}</div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
