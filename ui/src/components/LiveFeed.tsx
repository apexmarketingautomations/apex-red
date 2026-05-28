import { useState, useEffect, useRef } from 'react';

const API = import.meta.env.VITE_API_URL ?? '';

const EVENT_ICON: Record<string, string> = {
  finding:       '🔴',
  host_found:    '🌐',
  phase_update:  '⚙️',
  scan_started:  '🚀',
  scan_completed:'✅',
  recon_done:    '🔍',
  vuln_scan_done:'🧪',
  pentest_done:  '💥',
  osint_done:    '👤',
  wifi_done:     '📡',
};

interface LiveEvent {
  id: string;
  ts: Date;
  event: string;
  data: any;
}

export default function LiveFeed({ scanId }: { scanId: string }) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const es = new EventSource(`${API}/api/scans/${scanId}/live`);

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    const handler = (event: MessageEvent, name: string) => {
      const data = JSON.parse(event.data);
      setEvents(prev => [
        ...prev,
        { id: crypto.randomUUID(), ts: new Date(), event: name, data },
      ]);
    };

    const eventNames = Object.keys(EVENT_ICON);
    for (const name of eventNames) {
      es.addEventListener(name, (e: any) => handler(e, name));
    }

    return () => es.close();
  }, [scanId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-zinc-800 flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-zinc-600'}`} />
        <span className="text-xs text-zinc-400">{connected ? 'Live' : 'Disconnected'}</span>
        <span className="text-xs text-zinc-600 ml-auto">{events.length} events</span>
      </div>
      <div className="h-96 overflow-y-auto p-4 font-mono text-xs space-y-1.5">
        {events.length === 0 && (
          <div className="text-zinc-600 text-center pt-8">Waiting for events...</div>
        )}
        {events.map(e => (
          <div key={e.id} className="flex gap-3 items-start">
            <span className="text-zinc-600 shrink-0">
              {e.ts.toLocaleTimeString()}
            </span>
            <span className="shrink-0">{EVENT_ICON[e.event] ?? '•'}</span>
            <span className="text-zinc-300">
              <span className="text-zinc-500">[{e.event}]</span>{' '}
              {e.event === 'finding'
                ? <span className={e.data.severity === 'critical' ? 'text-red-400' : e.data.severity === 'high' ? 'text-orange-400' : 'text-zinc-300'}>
                    [{e.data.severity?.toUpperCase()}] {e.data.title}
                  </span>
                : e.event === 'host_found'
                ? <span className="text-blue-400">{e.data.hostname ?? e.data.ip}</span>
                : JSON.stringify(e.data)
              }
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
