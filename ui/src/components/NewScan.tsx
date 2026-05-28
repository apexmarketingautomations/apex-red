import { useState } from 'react';
import type { TargetType } from '../../../shared/src/types/index';

const TARGET_TYPES: TargetType[] = [
  'domain', 'ip', 'cidr', 'url', 'company',
  'email', 'phone', 'github_org', 'wifi_ssid', 'person',
];

export default function NewScan({ onClose, onCreated }: {
  onClose: () => void;
  onCreated: (scan: any) => void;
}) {
  const [name, setName] = useState('');
  const [targets, setTargets] = useState([{ type: 'domain' as TargetType, value: '' }]);
  const [depth, setDepth] = useState<'surface' | 'standard' | 'deep'>('standard');
  const [phases, setPhases] = useState({
    recon: true, vulnScan: true, pentest: true,
    postExploit: false, adMapping: false, wifi: false,
  });
  const [loading, setLoading] = useState(false);

  const addTarget = () => setTargets(t => [...t, { type: 'domain', value: '' }]);

  const submit = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name || `Scan ${new Date().toLocaleDateString()}`,
          targets,
          depth,
          phases,
          maxHosts: 200,
          maxDuration: 480,
          reportFormat: 'json',
        }),
      });
      const data = await res.json();
      onCreated(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl w-full max-w-xl p-6 space-y-5">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold text-lg">New Scan</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-white text-xl leading-none">×</button>
        </div>

        {/* Name */}
        <div>
          <label className="text-xs text-zinc-400 mb-1 block">Scan Name</label>
          <input
            className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-red-500"
            placeholder="Q2 Red Team Engagement"
            value={name}
            onChange={e => setName(e.target.value)}
          />
        </div>

        {/* Targets */}
        <div>
          <label className="text-xs text-zinc-400 mb-2 block">Targets</label>
          <div className="space-y-2">
            {targets.map((t, i) => (
              <div key={i} className="flex gap-2">
                <select
                  className="bg-zinc-800 border border-zinc-700 rounded px-2 py-2 text-sm focus:outline-none focus:border-red-500"
                  value={t.type}
                  onChange={e => setTargets(ts => ts.map((x, j) => j === i ? { ...x, type: e.target.value as TargetType } : x))}
                >
                  {TARGET_TYPES.map(ty => <option key={ty} value={ty}>{ty}</option>)}
                </select>
                <input
                  className="flex-1 bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-red-500"
                  placeholder={t.type === 'domain' ? 'example.com' : t.type === 'ip' ? '192.168.1.1' : 'value...'}
                  value={t.value}
                  onChange={e => setTargets(ts => ts.map((x, j) => j === i ? { ...x, value: e.target.value } : x))}
                />
              </div>
            ))}
          </div>
          <button onClick={addTarget} className="text-xs text-red-500 hover:text-red-400 mt-2">+ Add target</button>
        </div>

        {/* Depth */}
        <div>
          <label className="text-xs text-zinc-400 mb-2 block">Depth</label>
          <div className="flex gap-2">
            {(['surface', 'standard', 'deep'] as const).map(d => (
              <button
                key={d}
                onClick={() => setDepth(d)}
                className={`flex-1 py-2 rounded text-sm capitalize transition-colors ${
                  depth === d ? 'bg-red-600 text-white' : 'bg-zinc-800 text-zinc-400 hover:text-white'
                }`}
              >
                {d}
              </button>
            ))}
          </div>
        </div>

        {/* Phases */}
        <div>
          <label className="text-xs text-zinc-400 mb-2 block">Phases</label>
          <div className="grid grid-cols-2 gap-2">
            {Object.entries(phases).map(([key, val]) => (
              <label key={key} className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={val}
                  onChange={e => setPhases(p => ({ ...p, [key]: e.target.checked }))}
                  className="accent-red-500"
                />
                <span className="capitalize text-zinc-300">{key.replace(/([A-Z])/g, ' $1')}</span>
              </label>
            ))}
          </div>
        </div>

        <button
          onClick={submit}
          disabled={loading || !targets.some(t => t.value)}
          className="w-full bg-red-600 hover:bg-red-500 disabled:bg-zinc-700 disabled:text-zinc-500 text-white py-2.5 rounded font-medium text-sm transition-colors"
        >
          {loading ? 'Starting...' : 'Launch Scan'}
        </button>
      </div>
    </div>
  );
}
