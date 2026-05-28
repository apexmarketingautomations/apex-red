import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import FindingsTable from '../components/FindingsTable';
import LiveFeed from '../components/LiveFeed';
import EntityGraph from '../components/EntityGraph';
import EvidenceLocker from '../components/EvidenceLocker';
import AIReport from '../components/AIReport';
import RiskScoreGauge from '../components/RiskScoreGauge';

const API = import.meta.env.VITE_API_URL ?? '';

const STATUS_COLOR: Record<string, string> = {
  running:   'text-yellow-400',
  completed: 'text-green-400',
  failed:    'text-red-400',
  paused:    'text-blue-400',
  pending:   'text-zinc-400',
};

const MODULE_LABEL: Record<string, string> = {
  recon:        'Recon',
  osint:        'OSINT',
  code_intel:   'Code Intel',
  cloud:        'Cloud',
  vuln_engine:  'Vuln Engine',
  risk_scoring: 'Risk Scoring',
  ai_analyst:   'AI Analyst',
};

const ENTITY_ICON: Record<string, string> = {
  domain: '🌐', subdomain: '↳', ip: '📡', cidr: '🕸', email: '✉', phone: '📞',
  username: '👤', person: '🧑', company: '🏢', app: '📱', repo: '📦',
  cloud_account: '☁', bucket: '🪣', api_endpoint: '⚡', credential: '🔑',
  certificate: '📜', social_profile: '👥', url: '🔗', port: '🔌',
  vulnerability: '🐛', default: '○',
};

type Tab = 'graph' | 'entities' | 'findings' | 'evidence' | 'report' | 'live';

export default function InvestigationDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [inv, setInv] = useState<any>(null);
  const [graph, setGraph] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [tab, setTab] = useState<Tab>('graph');
  const [loading, setLoading] = useState(true);
  const [selectedEntity, setSelectedEntity] = useState<any>(null);
  const [deleting, setDeleting] = useState(false);

  const fetchInv = () =>
    fetch(`${API}/api/investigations/${id}`)
      .then(r => { if (!r.ok) throw new Error(r.statusText); return r.json(); })
      .then(data => { setInv(data); setLoading(false); })
      .catch(() => setLoading(false));

  const fetchGraph = () =>
    fetch(`${API}/api/investigations/${id}/graph`)
      .then(r => r.ok ? r.json() : { nodes: [], edges: [] })
      .then(setGraph)
      .catch(() => {});

  useEffect(() => {
    fetchInv();
    fetchGraph();
    const iv = setInterval(() => {
      if (document.visibilityState === 'visible') {
        fetchInv();
        fetchGraph();
      }
    }, 8000);
    return () => clearInterval(iv);
  }, [id]);

  const pause = () =>
    fetch(`${API}/api/investigations/${id}/pause`, { method: 'POST' }).then(fetchInv);
  const resume = () =>
    fetch(`${API}/api/investigations/${id}/resume`, { method: 'POST' }).then(fetchInv);
  const deleteInv = async () => {
    if (!confirm('Delete this investigation? This cannot be undone.')) return;
    setDeleting(true);
    await fetch(`${API}/api/investigations/${id}`, { method: 'DELETE' });
    navigate('/');
  };

  if (loading) return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center text-zinc-500">
      Loading investigation...
    </div>
  );
  if (!inv) return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center text-zinc-500">
      <div className="text-center">
        <div className="text-4xl mb-3">404</div>
        <div>Investigation not found</div>
        <Link to="/" className="text-red-400 text-sm mt-3 inline-block hover:text-red-300">← Back to dashboard</Link>
      </div>
    </div>
  );

  const findings = inv.findings ?? [];
  const entities = inv.entities ?? [];
  const evidence = inv.evidence ?? [];
  const modules  = inv.modules  ?? [];
  const riskScores = inv.riskScores ?? [];

  const critCount = findings.filter((f: any) => f.severity === 'critical').length;
  const highCount = findings.filter((f: any) => f.severity === 'high').length;
  const seeds = (inv.config?.seeds ?? []) as any[];

  const tabs: { key: Tab; label: string }[] = [
    { key: 'graph',    label: `Graph (${graph.nodes.length})` },
    { key: 'entities', label: `Entities (${entities.length})` },
    { key: 'findings', label: `Findings (${findings.length})` },
    { key: 'evidence', label: `Evidence (${evidence.length})` },
    { key: 'report',   label: 'AI Report' },
    { key: 'live',     label: 'Live Feed' },
  ];

  return (
    <div className="min-h-screen bg-zinc-950 text-white">
      {/* Header */}
      <header className="border-b border-zinc-800 px-6 py-3 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 min-w-0">
          <Link to="/" className="text-zinc-500 hover:text-white text-sm shrink-0">← Back</Link>
          <div className="w-px h-4 bg-zinc-700 shrink-0" />
          <div className="w-7 h-7 bg-red-600 rounded flex items-center justify-center font-bold text-xs shrink-0">AR</div>
          <span className="font-semibold truncate">{inv.name}</span>
          <span className={`text-sm font-medium capitalize shrink-0 ${STATUS_COLOR[inv.status]}`}>
            {inv.status === 'running' && (
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse" />
                running
              </span>
            )}
            {inv.status !== 'running' && inv.status}
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {inv.status === 'running' && (
            <button onClick={pause} className="text-xs px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 rounded border border-zinc-700 transition-colors">
              Pause
            </button>
          )}
          {inv.status === 'paused' && (
            <button onClick={resume} className="text-xs px-3 py-1.5 bg-green-700 hover:bg-green-600 rounded transition-colors">
              Resume
            </button>
          )}
          <a
            href={`${API}/api/investigations/${id}/report?format=md`}
            download
            className="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-500 rounded transition-colors"
          >
            Export Report
          </a>
          <button
            onClick={deleteInv}
            disabled={deleting}
            className="text-xs px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 rounded text-zinc-500 hover:text-red-400 transition-colors"
          >
            Delete
          </button>
        </div>
      </header>

      <div className="px-6 py-5 max-w-7xl mx-auto space-y-5">

        {/* Summary row */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          {[
            { label: 'Entities',  value: entities.length,  color: 'text-blue-400' },
            { label: 'Findings',  value: findings.length,  color: 'text-orange-400' },
            { label: 'Critical',  value: critCount,        color: critCount > 0 ? 'text-red-500' : 'text-zinc-500' },
            { label: 'High',      value: highCount,        color: highCount > 0 ? 'text-orange-400' : 'text-zinc-500' },
            { label: 'Evidence',  value: evidence.length,  color: 'text-zinc-300' },
            { label: 'Modules',   value: modules.filter((m: any) => m.status === 'completed').length + '/' + modules.length, color: 'text-green-400' },
          ].map(s => (
            <div key={s.label} className="bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-center">
              <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-zinc-600 text-xs mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Module pipeline */}
        {modules.length > 0 && (
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <div className="text-xs text-zinc-500 uppercase tracking-wider mb-3">Module Pipeline</div>
            <div className="flex gap-2 flex-wrap">
              {modules.map((m: any) => (
                <div
                  key={m.module}
                  className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border ${
                    m.status === 'completed' ? 'border-green-600/40 bg-green-600/10 text-green-400' :
                    m.status === 'running'   ? 'border-yellow-600/40 bg-yellow-600/10 text-yellow-400' :
                    m.status === 'failed'    ? 'border-red-600/40 bg-red-600/10 text-red-400' :
                                              'border-zinc-700 bg-zinc-800/50 text-zinc-500'
                  }`}
                >
                  {m.status === 'running' && <span className="w-1.5 h-1.5 bg-yellow-400 rounded-full animate-pulse" />}
                  {m.status === 'completed' && <span>✓</span>}
                  {m.status === 'failed'    && <span>✗</span>}
                  <span>{MODULE_LABEL[m.module] ?? m.module}</span>
                  {m.entities_discovered > 0 && (
                    <span className="text-zinc-600">+{m.entities_discovered}</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Seed entities */}
        {seeds.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-zinc-500">Seeds:</span>
            {seeds.map((s: any, i: number) => (
              <span key={i} className="text-xs bg-zinc-800 border border-zinc-700 px-2 py-1 rounded text-zinc-300">
                {ENTITY_ICON[s.type] ?? '○'} {s.type}:{s.value}
              </span>
            ))}
          </div>
        )}

        {/* Tabs */}
        <div className="border-b border-zinc-800">
          {tabs.map(t => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`px-4 py-2.5 text-sm border-b-2 transition-colors mr-1 ${
                tab === t.key
                  ? 'border-red-500 text-white'
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {tab === 'graph' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <EntityGraph
                nodes={graph.nodes}
                edges={graph.edges}
                onSelectNode={setSelectedEntity}
              />
            </div>
            <div className="space-y-3">
              {selectedEntity ? (
                <EntityDetailPanel entity={selectedEntity} riskScores={riskScores} findings={findings} />
              ) : (
                <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 text-center text-zinc-600 text-sm py-12">
                  Click a node to inspect it
                </div>
              )}
              {/* Top risks */}
              {riskScores.length > 0 && (
                <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
                  <div className="text-xs text-zinc-500 uppercase tracking-wider mb-3">Top Risks</div>
                  <div className="space-y-2">
                    {riskScores.slice(0, 5).map((r: any) => (
                      <div key={r.entity_id} className="flex items-center gap-2">
                        <RiskScoreGauge score={r.overall} size="sm" />
                        <div className="flex-1 min-w-0">
                          <div className="text-xs font-medium truncate">{r.value}</div>
                          <div className="text-xs text-zinc-600">{r.type}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {tab === 'entities' && (
          <div className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {entities.map((e: any) => (
                <EntityCard key={e.id} entity={e} findings={findings} />
              ))}
            </div>
          </div>
        )}

        {tab === 'findings' && <FindingsTable findings={findings} />}
        {tab === 'evidence' && <EvidenceLocker evidence={evidence} />}
        {tab === 'report'   && <AIReport report={inv.ai_report} invId={id!} name={inv.name} />}
        {tab === 'live'     && <LiveFeed invId={id!} />}
      </div>
    </div>
  );
}

function EntityCard({ entity, findings }: { entity: any; findings: any[] }) {
  const ef = findings.filter(f => f.entity_id === entity.id);
  const crit = ef.filter(f => f.severity === 'critical').length;
  const high = ef.filter(f => f.severity === 'high').length;
  const risk = entity.risk_overall ?? 0;
  const riskColor = risk >= 80 ? 'text-red-500' : risk >= 60 ? 'text-orange-400' : risk >= 40 ? 'text-yellow-400' : 'text-zinc-500';

  return (
    <div className={`bg-zinc-900 border rounded-lg p-4 space-y-2 ${
      entity.is_seed ? 'border-red-600/40' : 'border-zinc-800'
    }`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-base">{ENTITY_ICON[entity.type] ?? '○'}</span>
          <div className="min-w-0">
            <div className="text-xs text-zinc-500 uppercase">{entity.type}</div>
            <div className="text-sm font-medium truncate" title={entity.value}>{entity.value}</div>
          </div>
        </div>
        {risk > 0 && (
          <div className={`text-lg font-bold shrink-0 ${riskColor}`}>{Math.round(risk)}</div>
        )}
      </div>
      {entity.label && entity.label !== entity.value && (
        <div className="text-xs text-zinc-500">{entity.label}</div>
      )}
      <div className="flex items-center gap-3 text-xs">
        {crit > 0 && <span className="text-red-400">{crit} critical</span>}
        {high > 0 && <span className="text-orange-400">{high} high</span>}
        {ef.length > 0 && crit === 0 && high === 0 && <span className="text-zinc-500">{ef.length} findings</span>}
        {entity.is_seed && <span className="bg-red-600/20 text-red-400 px-1.5 py-0.5 rounded text-xs">seed</span>}
        <span className="ml-auto text-zinc-700">{Math.round(entity.confidence * 100)}%</span>
      </div>
    </div>
  );
}

function EntityDetailPanel({ entity, riskScores, findings }: { entity: any; riskScores: any[]; findings: any[] }) {
  const rs = riskScores.find(r => r.entity_id === entity.id);
  const ef = findings.filter(f => f.entity_id === entity.id);
  const factors: string[] = rs?.factors ? JSON.parse(rs.factors) : [];

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 space-y-4">
      <div className="flex items-start gap-3">
        <span className="text-2xl">{ENTITY_ICON[entity.type] ?? '○'}</span>
        <div className="flex-1 min-w-0">
          <div className="text-xs text-zinc-500 uppercase">{entity.type}</div>
          <div className="font-medium break-all">{entity.value}</div>
          {entity.label && entity.label !== entity.value && (
            <div className="text-xs text-zinc-400 mt-0.5">{entity.label}</div>
          )}
        </div>
        {rs && <RiskScoreGauge score={rs.overall} size="md" />}
      </div>

      {factors.length > 0 && (
        <div>
          <div className="text-xs text-zinc-500 uppercase tracking-wider mb-1.5">Risk Factors</div>
          <div className="flex gap-1.5 flex-wrap">
            {factors.map((f, i) => (
              <span key={i} className="text-xs bg-zinc-800 text-zinc-300 px-2 py-0.5 rounded">{f}</span>
            ))}
          </div>
        </div>
      )}

      {ef.length > 0 && (
        <div>
          <div className="text-xs text-zinc-500 uppercase tracking-wider mb-1.5">Findings ({ef.length})</div>
          <div className="space-y-1">
            {ef.slice(0, 4).map(f => (
              <div key={f.id} className="text-xs flex items-center gap-2">
                <span className={
                  f.severity === 'critical' ? 'text-red-400' :
                  f.severity === 'high'     ? 'text-orange-400' :
                  f.severity === 'medium'   ? 'text-yellow-400' : 'text-blue-400'
                }>{f.severity}</span>
                <span className="text-zinc-400 truncate">{f.title}</span>
              </div>
            ))}
            {ef.length > 4 && <div className="text-xs text-zinc-600">+{ef.length - 4} more</div>}
          </div>
        </div>
      )}

      <div className="text-xs text-zinc-600 space-y-0.5">
        <div>Confidence: {Math.round(entity.confidence * 100)}%</div>
        {entity.discovered_by && <div>Discovered by: {entity.discovered_by}</div>}
        {entity.is_seed && <div className="text-red-400">Seed entity</div>}
      </div>
    </div>
  );
}
