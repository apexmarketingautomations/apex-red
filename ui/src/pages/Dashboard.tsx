import { useState, useEffect } from 'react';
import NewScan from '../components/NewScan';
import ScanCard from '../components/ScanCard';

export default function Dashboard() {
  const [scans, setScans] = useState<any[]>([]);
  const [showNew, setShowNew] = useState(false);

  useEffect(() => {
    fetch(`${import.meta.env.VITE_API_URL}/api/scans`)
      .then(r => r.json())
      .then(setScans)
      .catch(console.error);
  }, []);

  const stats = {
    total: scans.length,
    running: scans.filter(s => s.status === 'running').length,
    completed: scans.filter(s => s.status === 'completed').length,
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-white">
      {/* Header */}
      <header className="border-b border-zinc-800 px-8 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-sm">AR</div>
          <span className="font-semibold text-lg">Apex Red</span>
          <span className="text-zinc-500 text-sm">Autonomous Red Team Platform</span>
        </div>
        <button
          onClick={() => setShowNew(true)}
          className="bg-red-600 hover:bg-red-500 text-white px-4 py-2 rounded text-sm font-medium transition-colors"
        >
          + New Scan
        </button>
      </header>

      <div className="px-8 py-6 max-w-7xl mx-auto">
        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          {[
            { label: 'Total Scans', value: stats.total, color: 'text-white' },
            { label: 'Running', value: stats.running, color: 'text-yellow-400' },
            { label: 'Completed', value: stats.completed, color: 'text-green-400' },
          ].map(s => (
            <div key={s.label} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
              <div className={`text-3xl font-bold ${s.color}`}>{s.value}</div>
              <div className="text-zinc-400 text-sm mt-1">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Scans list */}
        <h2 className="text-zinc-400 text-xs font-semibold uppercase tracking-wider mb-3">Scans</h2>
        {scans.length === 0 ? (
          <div className="text-center py-20 text-zinc-600">
            <div className="text-5xl mb-4">🎯</div>
            <div className="text-lg">No scans yet</div>
            <div className="text-sm mt-1">Click "New Scan" to start your first red team engagement</div>
          </div>
        ) : (
          <div className="space-y-3">
            {scans.map(scan => <ScanCard key={scan.id} scan={scan} />)}
          </div>
        )}
      </div>

      {showNew && <NewScan onClose={() => setShowNew(false)} onCreated={s => {
        setScans(prev => [s, ...prev]);
        setShowNew(false);
      }} />}
    </div>
  );
}
