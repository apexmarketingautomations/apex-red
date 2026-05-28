import { useState, useEffect, useRef } from 'react';

const API = import.meta.env.VITE_API_URL ?? '';

const EVENT_ICON: Record<string, string> = {
  finding:                '🔴',
  entity_found:           '🔵',
  investigation_started:  '🚀',
  investigation_completed:'✅',
  investigation_failed:   '❌',
  ai_report_ready:        '🤖',
  status:                 '⚙️',
};

interface LiveEvent {
  id: string;
  ts: Date;
  event: string;
  data: any;
}

export default function LiveFeed({ invId }: { invId: string }) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const es = new EventSource(`${API}/api/investigations/${invId}/live`);
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    const addEvent = (event: MessageEvent, name: string) => {
      let data: any;
      try { data = JSON.parse(event.data); } catch { data = event.data; }
      setEvents(prev => [...prev.slice(-200), { id: crypto.randomUUID(), ts: new Date(), event: name, data }]);
    };

    const names = [
      'finding', 'entity_found', 'investigation_started', 'investigation_completed',
      'investigation_failed', 'ai_report_ready', 'status',
    ];
    for (const n of names) es.addEventListener(n, (e: any) => addEvent(e, n));

    return () => es.close();
  }, [invId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  const formatEvent = (e: LiveEvent) => {
    if (e.event === 'finding') {
      const sev = e.data.severity?.toUpperCase();
      const cls = sev === 'CRITICAL' ? 'text-red-400' : sev === 'HIGH' ? 'text-orange-400' : 'text-zinc-300';
      return <span className={cls}>[{sev}] {e.data.title}</span>;
    }
    if (e.event === 'entity_found') {
      return <span className="text-blue-400">{e.data.type}: {e.data.value}</span>;
    }
    if (e.event === 'status') {
      return <span className="text-zinc-400">status → {e.data.status}</span>;
    }
    return <span className="text-zinc-400">{JSON.stringify(e.data)}</span>;
  };

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-zinc-800 flex items-center gap-2">
        <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-zinc-600'}`} />
        <span className="text-xs text-zinc-400">{connected ? 'Live' : 'Disconnected'}</span>
        <span className="text-xs text-zinc-600 ml-auto">{events.length} events</span>
      </div>
      <div className="h-80 overflow-y-auto p-4 font-mono text-xs space-y-1.5">
        {events.length === 0 && (
          <div className="text-zinc-600 text-center pt-8">Waiting for events...</div>
        )}
        {events.map(e => (
          <div key={e.id} className="flex gap-3 items-baseline">
            <span className="text-zinc-600 shrink-0 tabular-nums">{e.ts.toLocaleTimeString()}</span>
            <span className="shrink-0">{EVENT_ICON[e.event] ?? '•'}</span>
            <span>
              <span className="text-zinc-600">[{e.event}] </span>
              {formatEvent(e)}
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
