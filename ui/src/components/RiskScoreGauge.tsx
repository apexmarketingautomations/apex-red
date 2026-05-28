export default function RiskScoreGauge({ score, size = 'md' }: { score: number; size?: 'sm' | 'md' | 'lg' }) {
  const clamp = Math.min(100, Math.max(0, score ?? 0));
  const color = clamp >= 80 ? '#ef4444' : clamp >= 60 ? '#f97316' : clamp >= 40 ? '#eab308' : clamp >= 20 ? '#3b82f6' : '#52525b';

  const sizes = { sm: 48, md: 72, lg: 96 };
  const dim = sizes[size];
  const r = (dim / 2) - 6;
  const circumference = Math.PI * r;
  const offset = circumference * (1 - clamp / 100);
  const fontSize = size === 'sm' ? 12 : size === 'md' ? 16 : 22;

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={dim} height={dim / 2 + 8} viewBox={`0 0 ${dim} ${dim / 2 + 8}`}>
        {/* Track */}
        <path
          d={`M 6,${dim / 2} A ${r},${r} 0 0 1 ${dim - 6},${dim / 2}`}
          fill="none"
          stroke="#27272a"
          strokeWidth="6"
          strokeLinecap="round"
        />
        {/* Fill */}
        <path
          d={`M 6,${dim / 2} A ${r},${r} 0 0 1 ${dim - 6},${dim / 2}`}
          fill="none"
          stroke={color}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.3s ease' }}
        />
        <text
          x={dim / 2}
          y={dim / 2}
          textAnchor="middle"
          dominantBaseline="middle"
          fill={color}
          fontSize={fontSize}
          fontWeight="700"
        >
          {Math.round(clamp)}
        </text>
      </svg>
      {size !== 'sm' && (
        <div className="text-xs" style={{ color }}>
          {clamp >= 80 ? 'Critical' : clamp >= 60 ? 'High' : clamp >= 40 ? 'Medium' : clamp >= 20 ? 'Low' : 'Minimal'}
        </div>
      )}
    </div>
  );
}
