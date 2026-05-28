export default function HostMap({ hosts }: { hosts: any[] }) {
  if (!hosts.length) return (
    <div className="text-center py-16 text-zinc-600">
      <div className="text-4xl mb-3">🌐</div>
      <div>No hosts discovered yet</div>
    </div>
  );

  return (
    <div className="grid gap-3 md:grid-cols-2">
      {hosts.map((h: any) => (
        <div key={h.id} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <div className="flex items-start justify-between mb-2">
            <div>
              <div className="font-medium text-sm">{h.hostname ?? h.ip ?? 'Unknown'}</div>
              {h.hostname && h.ip && <div className="text-xs text-zinc-500 mt-0.5">{h.ip}</div>}
            </div>
            <div className="flex items-center gap-2">
              {h.finding_count > 0 && (
                <span className="text-xs bg-red-600/20 text-red-400 border border-red-600/30 px-2 py-0.5 rounded">
                  {h.finding_count} findings
                </span>
              )}
              <span className="text-xs text-zinc-600">{h.discovered_by}</span>
            </div>
          </div>

          {/* Ports */}
          {h.ports?.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2">
              {h.ports.map((p: any) => (
                <span key={p.port} className="text-xs bg-zinc-800 text-zinc-300 px-2 py-0.5 rounded font-mono">
                  {p.port}/{p.protocol}
                  {p.service && <span className="text-zinc-500"> {p.service}</span>}
                </span>
              ))}
            </div>
          )}

          {/* Technologies */}
          {h.technologies?.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2">
              {h.technologies.map((t: string) => (
                <span key={t} className="text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded">
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
