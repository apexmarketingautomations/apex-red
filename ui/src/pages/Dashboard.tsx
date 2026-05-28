import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import NewInvestigation from '../components/NewInvestigation';

const API = import.meta.env.VITE_API_URL ?? '';

const STATUS_STYLE: Record<string, string> = {
  running:   'text-yellow-400 bg-yellow-400/10',
  completed: 'text-green-400 bg-green-400/10',
  failed:    'text-red-400 bg-red-400/10',
  paused:    'text-blue-400 bg-blue-400/10',
  pending:   'text-zinc-400 bg-zinc-400/10',
};

export default function Dashboard() {
  const navigate = useNavigate();
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [showNew, setShowNew] = useState(false);

  useEffect(() => {
    fetch(`${API}/api/investigations`)
      .then(r => { if (!r.ok) throw new Error(r.statusText); return r.json(); })
      .then(setInvestigations)
      .catch(() => setInvestigations([]));

    fetch(`${API}/api/stats`)
      .then(r => r.ok ? r.json() : null)
      .then(setStats)
      .catch(() => {});
  }, []);

  const totalFindings = investigations.reduce((sum, i) => sum + (parseInt(i.finding_count) || 0), 0);
  const criticalTotal = investigations.reduce((sum, i) => sum + (parseInt(i.critical_count) || 0), 0);
  const entityTotal   = investigations.reduce((sum, i) => sum + (parseInt(i.entity_count) || 0), 0);
  const running = investigations.filter(i => i.status === 'running').length;

  return (
    <div className="min-h-screen bg-zinc-950 text-white">
      <header className="border-b border-zinc-800 px-8 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-sm select-none">AR</div>
          <div>
            <span className="font-semibold text-lg">Apex Red</span>
            <span className="text-zinc-500 text-sm ml-3">Autonomous Attack Surface Intelligence</span>
          </div>
        </div>
        <button
          onClick={() => setShowNew(true)}
          className="bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded text-sm font-medium transition-colors"
        >
          + New Investigation
        </button>
      </header>

      <div className="px-8 py-6 max-w-7xl mx-auto">
        {/* Stats row */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
          {[
            { label: 'Investigations', value: investigations.length, color: 'text-white' },
            { label: 'Running',        value: running,              color: 'text-yellow-400' },
            { label: 'Entities Found', value: entityTotal,          color: 'text-blue-400' },
            { label: 'Total Findings', value: totalFindings,        color: 'text-orange-400' },
            { label: 'Critical',       value: criticalTotal,        color: 'text-red-500' },
          ].map(s => (
            <div key={s.label} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <div className={`text-3xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-zinc-400 text-xs mt-1">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Investigations list */}
        <h2 className="text-zinc-400 text-xs font-semibold uppercase tracking-wider mb-3">
          Investigations
        </h2>

        {investigations.length === 0 ? (
          <div className="text-center py-24 text-zinc-600">
            <div className="text-5xl mb-4">🎯</div>
            <div className="text-lg font-medium text-zinc-500">No investigations yet</div>
            <div className="text-sm mt-1">Start by entering any target — domain, email, person, phone, company, IP, or GitHub repo</div>
            <button
              onClick={() => setShowNew(true)}
              className="mt-6 bg-red-600 hover:bg-red-500 text-white px-6 py-2.5 rounded font-medium text-sm transition-colors"
            >
              Start First Investigation
            </button>
          </div>
        ) : (
          <div className="space-y-2">
            {investigations.map(inv => (
              <div
                key={inv.id}
                onClick={() => navigate(`/investigations/${inv.id}`)}
                className="bg-zinc-900 border border-zinc-800 rounded-lg px-5 py-4 flex items-center gap-4 cursor-pointer hover:border-zinc-600 transition-colors group"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3">
                    <span className="font-medium group-hover:text-white transition-colors">{inv.name}</span>
                    <span className={`text-xs px-2 py-0.5 rounded font-medium capitalize ${STATUS_STYLE[inv.status] ?? STATUS_STYLE.pending}`}>
                      {inv.status === 'running' && <span className="inline-block w-1.5 h-1.5 bg-yellow-400 rounded-full mr-1 animate-pulse" />}
                      {inv.status}
                    </span>
                  </div>
                  <div className="text-xs text-zinc-500 mt-1">
                    {inv.config?.seeds?.map((s: any) => `${s.type}:${s.value}`).join(', ')}
                  </div>
                </div>

                <div className="flex items-center gap-6 shrink-0 text-sm">
                  <div className="text-center">
                    <div className="text-blue-400 font-semibold">{inv.entity_count ?? 0}</div>
                    <div className="text-zinc-600 text-xs">entities</div>
                  </div>
                  <div className="text-center">
                    <div className="text-orange-400 font-semibold">{inv.finding_count ?? 0}</div>
                    <div className="text-zinc-600 text-xs">findings</div>
                  </div>
                  <div className="text-center">
                    <div className={`font-semibold ${(inv.critical_count > 0) ? 'text-red-500' : 'text-zinc-500'}`}>
                      {inv.critical_count ?? 0}
                    </div>
                    <div className="text-zinc-600 text-xs">critical</div>
                  </div>
                  <div className="text-zinc-600 text-xs whitespace-nowrap">
                    {new Date(inv.created_at).toLocaleDateString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {showNew && (
        <NewInvestigation
          onClose={() => setShowNew(false)}
          onCreated={inv => {
            setInvestigations(prev => [inv, ...prev]);
            setShowNew(false);
            navigate(`/investigations/${inv.id}`);
          }}
        />
      )}
    </div>
  );
}
