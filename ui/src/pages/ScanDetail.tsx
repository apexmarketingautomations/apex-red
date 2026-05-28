import { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import PhaseTimeline from '../components/PhaseTimeline';
import FindingsTable from '../components/FindingsTable';
import HostMap from '../components/HostMap';
import LiveFeed from '../components/LiveFeed';

const API = import.meta.env.VITE_API_URL ?? '';

const STATUS_COLOR: Record<string, string> = {
  running: 'text-yellow-400', completed: 'text-green-400',
  failed: 'text-red-400', paused: 'text-blue-400', pending: 'text-zinc-400',
};

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<any>(null);
  const [tab, setTab] = useState<'findings' | 'hosts' | 'live'>('findings');
  const [loading, setLoading] = useState(true);

  const fetchScan = () =>
    fetch(`${API}/api/scans/${id}`)
      .then(r => r.json())
      .then(data => { setScan(data); setLoading(false); });

  useEffect(() => {
    fetchScan();
    // Poll every 5s while running
    const iv = setInterval(() => {
      if (scan?.status === 'running') fetchScan();
    }, 5000);
    return () => clearInterval(iv);
  }, [id, scan?.status]);

  const pause = () => fetch(`${API}/api/scans/${id}/pause`, { method: 'POST' }).then(fetchScan);
  const resume = () => fetch(`${API}/api/scans/${id}/resume`, { method: 'POST' }).then(fetchScan);

  if (loading) return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center text-zinc-500">
      Loading...
    </div>
  );

  if (!scan) return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center text-zinc-500">
      Scan not found.
    </div>
  );

  const critical = scan.findings?.filter((f: any) => f.severity === 'critical').length ?? 0;
  const high     = scan.findings?.filter((f: any) => f.severity === 'high').length ?? 0;
  const medium   = scan.findings?.filter((f: any) => f.severity === 'medium').length ?? 0;
  const low      = scan.findings?.filter((f: any) => f.severity === 'low').length ?? 0;

  return (
    <div className="min-h-screen bg-zinc-950 text-white">
      {/* Header */}
      <header className="border-b border-zinc-800 px-8 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link to="/" className="text-zinc-500 hover:text-white text-sm">← Back</Link>
          <div className="w-px h-4 bg-zinc-700" />
          <div className="w-7 h-7 bg-red-600 rounded flex items-center justify-center font-bold text-xs">AR</div>
          <span className="font-semibold">{scan.name}</span>
          <span className={`text-sm font-medium capitalize ${STATUS_COLOR[scan.status]}`}>
            {scan.status === 'running' && <span className="inline-flex items-center gap-1.5"><span className="live-dot" />{scan.status}</span>}
            {scan.status !== 'running' && scan.status}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {scan.status === 'running' && (
            <button onClick={pause} className="text-sm px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 rounded transition-colors">
              Pause
            </button>
          )}
          {scan.status === 'paused' && (
            <button onClick={resume} className="text-sm px-3 py-1.5 bg-green-700 hover:bg-green-600 rounded transition-colors">
              Resume
            </button>
          )}
          <a
            href={`${API}/api/scans/${id}/report?format=html`}
            className="text-sm px-3 py-1.5 bg-red-600 hover:bg-red-500 rounded transition-colors"
          >
            Export Report
          </a>
        </div>
      </header>

      <div className="px-8 py-6 max-w-7xl mx-auto space-y-6">

        {/* Summary cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: 'Critical', value: critical, color: 'text-red-500' },
            { label: 'High',     value: high,     color: 'text-orange-400' },
            { label: 'Medium',   value: medium,   color: 'text-yellow-400' },
            { label: 'Low',      value: low,      color: 'text-blue-400' },
            { label: 'Hosts',    value: scan.hosts?.length ?? 0, color: 'text-zinc-300' },
          ].map(s => (
            <div key={s.label} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 text-center">
              <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-zinc-500 text-xs mt-1">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Phase timeline */}
        <PhaseTimeline phases={scan.phases ?? []} />

        {/* Tabs */}
        <div className="border-b border-zinc-800">
          {(['findings', 'hosts', 'live'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm capitalize border-b-2 transition-colors mr-2 ${
                tab === t
                  ? 'border-red-500 text-white'
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {t === 'findings' ? `Findings (${scan.findings?.length ?? 0})` :
               t === 'hosts'    ? `Hosts (${scan.hosts?.length ?? 0})` :
               'Live Feed'}
            </button>
          ))}
        </div>

        {tab === 'findings' && <FindingsTable findings={scan.findings ?? []} />}
        {tab === 'hosts'    && <HostMap hosts={scan.hosts ?? []} />}
        {tab === 'live'     && <LiveFeed scanId={id!} />}
      </div>
    </div>
  );
}
