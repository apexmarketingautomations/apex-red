const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-600',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  info: 'bg-zinc-500',
};

const STATUS_COLORS: Record<string, string> = {
  pending: 'text-zinc-400',
  running: 'text-yellow-400',
  completed: 'text-green-400',
  failed: 'text-red-400',
  paused: 'text-blue-400',
};

export default function ScanCard({ scan }: { scan: any }) {
  const critical = scan.findings?.filter((f: any) => f.severity === 'critical').length ?? 0;
  const high = scan.findings?.filter((f: any) => f.severity === 'high').length ?? 0;
  const total = scan.findings?.length ?? 0;

  return (
    <a href={`/scans/${scan.id}`} className="block bg-zinc-900 border border-zinc-800 hover:border-zinc-600 rounded-lg p-4 transition-colors">
      <div className="flex items-center justify-between">
        <div>
          <div className="font-medium">{scan.name}</div>
          <div className="text-xs text-zinc-500 mt-0.5">
            {new Date(scan.created_at).toLocaleString()}
          </div>
        </div>
        <div className="flex items-center gap-4">
          {/* Severity badges */}
          {total > 0 && (
            <div className="flex gap-1.5">
              {critical > 0 && (
                <span className="bg-red-600/20 text-red-400 text-xs px-2 py-0.5 rounded font-medium">
                  {critical} CRIT
                </span>
              )}
              {high > 0 && (
                <span className="bg-orange-500/20 text-orange-400 text-xs px-2 py-0.5 rounded font-medium">
                  {high} HIGH
                </span>
              )}
              <span className="bg-zinc-800 text-zinc-400 text-xs px-2 py-0.5 rounded">
                {total} total
              </span>
            </div>
          )}
          <span className={`text-sm font-medium capitalize ${STATUS_COLORS[scan.status] ?? 'text-zinc-400'}`}>
            {scan.status}
          </span>
        </div>
      </div>
    </a>
  );
}
