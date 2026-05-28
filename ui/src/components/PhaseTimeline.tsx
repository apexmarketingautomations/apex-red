const PHASE_LABELS: Record<string, string> = {
  recon: 'Recon', surface_mapping: 'Surface Map', vuln_scan: 'Nuclei Scan',
  pentest: 'AI Pentest', post_exploit: 'Post-Exploit',
  ad_mapping: 'AD Map', report: 'Report',
};

const STATUS_STYLE: Record<string, string> = {
  completed: 'bg-green-500',
  running:   'bg-yellow-400 animate-pulse',
  failed:    'bg-red-500',
  skipped:   'bg-zinc-600',
  pending:   'bg-zinc-700',
};

export default function PhaseTimeline({ phases }: { phases: any[] }) {
  const order = ['recon', 'surface_mapping', 'vuln_scan', 'pentest', 'post_exploit', 'ad_mapping', 'report'];

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
      <div className="text-xs text-zinc-500 uppercase tracking-wider mb-4">Pipeline</div>
      <div className="flex items-center gap-0 overflow-x-auto pb-1">
        {order.map((phase, i) => {
          const p = phases.find((x: any) => x.phase === phase);
          const status = p?.status ?? 'pending';
          return (
            <div key={phase} className="flex items-center shrink-0">
              <div className="flex flex-col items-center gap-1.5">
                <div className={`w-3 h-3 rounded-full ${STATUS_STYLE[status]}`} />
                <span className="text-xs text-zinc-400 whitespace-nowrap">{PHASE_LABELS[phase] ?? phase}</span>
                {p?.findings_count > 0 && (
                  <span className="text-xs text-red-400 font-medium">{p.findings_count}</span>
                )}
              </div>
              {i < order.length - 1 && (
                <div className={`w-12 h-px mx-1 mb-4 ${status === 'completed' ? 'bg-green-700' : 'bg-zinc-700'}`} />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
