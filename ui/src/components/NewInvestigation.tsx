import { useState } from 'react';

const API = import.meta.env.VITE_API_URL ?? '';

const SEED_TYPES = [
  { value: 'domain',        label: 'Domain',        placeholder: 'example.com' },
  { value: 'ip',            label: 'IP Address',    placeholder: '192.168.1.1' },
  { value: 'cidr',          label: 'CIDR',          placeholder: '10.0.0.0/24' },
  { value: 'email',         label: 'Email',         placeholder: 'user@example.com' },
  { value: 'phone',         label: 'Phone',         placeholder: '+14155551234' },
  { value: 'username',      label: 'Username',      placeholder: 'johndoe' },
  { value: 'person',        label: 'Person',        placeholder: 'John Doe' },
  { value: 'company',       label: 'Company',       placeholder: 'Acme Corp' },
  { value: 'app',           label: 'App / URL',     placeholder: 'https://app.example.com' },
  { value: 'repo',          label: 'GitHub Repo',   placeholder: 'org/repo' },
  { value: 'cloud_account', label: 'Cloud Account', placeholder: 'aws-account-id or GCP project' },
];

const MODULES = [
  { key: 'recon',     label: 'Recon',        desc: 'Subdomain enum, DNS, certs, ports, HTTP' },
  { key: 'osint',     label: 'OSINT',        desc: 'Phone/email/username/social intel' },
  { key: 'codeIntel', label: 'Code Intel',   desc: 'Secret scanning, SAST, dependency CVEs' },
  { key: 'cloud',     label: 'Cloud',        desc: 'Bucket exposure, leaked cloud creds' },
  { key: 'vulns',     label: 'Vuln Engine',  desc: 'Nuclei + Shannon AI pentest' },
];

export default function NewInvestigation({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (inv: any) => void;
}) {
  const [name, setName] = useState('');
  const [seeds, setSeeds] = useState([{ type: 'domain', value: '' }]);
  const [depth, setDepth] = useState<'surface' | 'standard' | 'deep'>('standard');
  const [modules, setModules] = useState({
    recon: true, osint: true, codeIntel: false, cloud: false, vulns: true,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const addSeed = () => setSeeds(s => [...s, { type: 'domain', value: '' }]);
  const removeSeed = (i: number) => setSeeds(s => s.filter((_, j) => j !== i));

  const submit = async () => {
    const validSeeds = seeds.filter(s => s.value.trim());
    if (!validSeeds.length) { setError('Add at least one target'); return; }

    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API}/api/investigations`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim() || `Investigation ${new Date().toLocaleDateString()}`,
          seeds: validSeeds,
          depth,
          modules,
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      onCreated(data);
    } catch (e: any) {
      setError(e.message ?? 'Failed to start investigation');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl w-full max-w-2xl p-6 space-y-5 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-semibold text-lg">New Investigation</h2>
            <p className="text-xs text-zinc-500 mt-0.5">Any entity — domain, email, person, phone, IP, company, repo, or cloud account</p>
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-white text-2xl leading-none w-8 h-8 flex items-center justify-center">×</button>
        </div>

        {/* Name */}
        <div>
          <label className="text-xs text-zinc-400 mb-1.5 block">Investigation Name</label>
          <input
            className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500 transition-colors"
            placeholder="Q2 Red Team — Acme Corp"
            value={name}
            onChange={e => setName(e.target.value)}
          />
        </div>

        {/* Seeds */}
        <div>
          <label className="text-xs text-zinc-400 mb-2 block">Seed Entities</label>
          <div className="space-y-2">
            {seeds.map((s, i) => {
              const def = SEED_TYPES.find(t => t.value === s.type);
              return (
                <div key={i} className="flex gap-2">
                  <select
                    className="bg-zinc-800 border border-zinc-700 rounded-lg px-2 py-2 text-sm focus:outline-none focus:border-red-500 text-zinc-300"
                    value={s.type}
                    onChange={e => setSeeds(ts => ts.map((x, j) => j === i ? { ...x, type: e.target.value } : x))}
                  >
                    {SEED_TYPES.map(t => (
                      <option key={t.value} value={t.value}>{t.label}</option>
                    ))}
                  </select>
                  <input
                    className="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500 transition-colors"
                    placeholder={def?.placeholder ?? 'value...'}
                    value={s.value}
                    onChange={e => setSeeds(ts => ts.map((x, j) => j === i ? { ...x, value: e.target.value } : x))}
                  />
                  {seeds.length > 1 && (
                    <button
                      onClick={() => removeSeed(i)}
                      className="text-zinc-600 hover:text-red-400 px-2 transition-colors"
                    >
                      ×
                    </button>
                  )}
                </div>
              );
            })}
          </div>
          <button
            onClick={addSeed}
            className="text-xs text-red-500 hover:text-red-400 mt-2 transition-colors"
          >
            + Add entity
          </button>
        </div>

        {/* Depth */}
        <div>
          <label className="text-xs text-zinc-400 mb-2 block">Depth</label>
          <div className="flex gap-2">
            {([
              { v: 'surface',  label: 'Surface',  desc: 'Fast — 30 min' },
              { v: 'standard', label: 'Standard', desc: 'Balanced — 2 hr' },
              { v: 'deep',     label: 'Deep',     desc: 'Full sweep — 8 hr' },
            ] as const).map(d => (
              <button
                key={d.v}
                onClick={() => setDepth(d.v)}
                className={`flex-1 py-2.5 px-3 rounded-lg text-sm transition-colors text-left ${
                  depth === d.v
                    ? 'bg-red-600 text-white'
                    : 'bg-zinc-800 text-zinc-400 hover:text-white border border-zinc-700'
                }`}
              >
                <div className="font-medium">{d.label}</div>
                <div className={`text-xs mt-0.5 ${depth === d.v ? 'text-red-200' : 'text-zinc-600'}`}>{d.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Modules */}
        <div>
          <label className="text-xs text-zinc-400 mb-2 block">Modules</label>
          <div className="space-y-2">
            {MODULES.map(m => (
              <label
                key={m.key}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg border cursor-pointer transition-colors ${
                  modules[m.key as keyof typeof modules]
                    ? 'border-red-600/40 bg-red-600/5'
                    : 'border-zinc-800 bg-zinc-800/30'
                }`}
              >
                <input
                  type="checkbox"
                  checked={modules[m.key as keyof typeof modules]}
                  onChange={e => setModules(p => ({ ...p, [m.key]: e.target.checked }))}
                  className="accent-red-500 w-4 h-4"
                />
                <div className="flex-1">
                  <span className="text-sm font-medium text-zinc-200">{m.label}</span>
                  <span className="text-xs text-zinc-500 ml-2">{m.desc}</span>
                </div>
              </label>
            ))}
          </div>
        </div>

        {error && (
          <div className="text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded-lg px-3 py-2">
            {error}
          </div>
        )}

        <div className="flex gap-3 pt-1">
          <button
            onClick={onClose}
            className="flex-1 border border-zinc-700 text-zinc-400 hover:text-white py-2.5 rounded-lg text-sm transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={loading || !seeds.some(s => s.value.trim())}
            className="flex-1 bg-red-600 hover:bg-red-500 disabled:bg-zinc-700 disabled:text-zinc-500 text-white py-2.5 rounded-lg font-medium text-sm transition-colors"
          >
            {loading ? 'Launching...' : 'Launch Investigation'}
          </button>
        </div>
      </div>
    </div>
  );
}
