
import React from 'react';

interface RiskMeterProps {
  score: number;
}

export const RiskMeter: React.FC<RiskMeterProps> = ({ score }) => {
  const getRiskLevel = (s: number) => {
    if (s < 0.3) return { label: 'LOW', color: 'bg-emerald-500', text: 'text-emerald-700' };
    if (s < 0.7) return { label: 'MEDIUM', color: 'bg-amber-500', text: 'text-amber-700' };
    return { label: 'HIGH', color: 'bg-rose-500', text: 'text-rose-700' };
  };

  const risk = getRiskLevel(score);
  const percentage = score * 100;

  return (
    <div className="mt-4 p-4 bg-slate-50 rounded-lg border border-slate-200">
      <div className="flex justify-between items-center mb-2">
        <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Computed Risk Score</span>
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full ${risk.color} text-white`}>{risk.label}</span>
      </div>
      <div className="relative h-4 w-full bg-slate-200 rounded-full overflow-hidden">
        <div 
          className={`absolute top-0 left-0 h-full transition-all duration-1000 ${risk.color}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <div className="flex justify-between mt-1 text-[10px] text-slate-400 font-medium">
        <span>0.0</span>
        <span>0.5</span>
        <span>1.0</span>
      </div>
      <p className="mt-2 text-[10px] text-slate-500 italic">
        "Risk is dynamically computed from operation sensitivity, context, and security policy."
      </p>
    </div>
  );
};
