
import React, { useState } from 'react';
import { Api } from '../services/api';
import { ArrowLeft, Hash, Filter, ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';
import { AuditLogEntry } from '../types';
import { useEffect } from 'react';

interface AuditLogsProps {
  onBack: () => void;
}

const AuditLogs: React.FC<AuditLogsProps> = ({ onBack }) => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);

  useEffect(() => {
    Api.getLogs().then(setLogs);
  }, []);

  const [filter, setFilter] = useState<'ALL' | 'DENIED' | 'HIGH_RISK'>('ALL');

  const filteredLogs = logs.filter(log => {
    if (filter === 'DENIED') return log.result === 'DENIED';
    if (filter === 'HIGH_RISK') return log.riskScore > 0.7;
    return true;
  }).reverse();

  return (
    <div className="space-y-6 max-w-6xl mx-auto py-8">
      <div className="flex items-center justify-between">
        <button onClick={onBack} className="flex items-center gap-2 text-slate-500 hover:text-slate-800 font-medium">
          <ArrowLeft size={18} /> Back
        </button>
        <div className="flex gap-2">
          <button 
            onClick={() => setFilter('ALL')}
            className={`px-3 py-1.5 rounded-full text-xs font-bold transition-all ${filter === 'ALL' ? 'bg-slate-900 text-white' : 'bg-white border border-slate-200 text-slate-500'}`}
          >
            All Logs
          </button>
          <button 
            onClick={() => setFilter('DENIED')}
            className={`px-3 py-1.5 rounded-full text-xs font-bold transition-all ${filter === 'DENIED' ? 'bg-rose-600 text-white' : 'bg-white border border-slate-200 text-slate-500'}`}
          >
            Denied Only
          </button>
          <button 
            onClick={() => setFilter('HIGH_RISK')}
            className={`px-3 py-1.5 rounded-full text-xs font-bold transition-all ${filter === 'HIGH_RISK' ? 'bg-amber-600 text-white' : 'bg-white border border-slate-200 text-slate-500'}`}
          >
            High Risk
          </button>
        </div>
      </div>

      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden shadow-sm">
        <div className="p-6 bg-slate-50 border-b border-slate-200 flex justify-between items-center">
          <div>
            <h2 className="text-lg font-bold text-slate-800">Tamper-Evident Audit Chain</h2>
            <p className="text-xs text-slate-500">Every operation is cryptographically hashed and linked to the previous entry.</p>
          </div>
          <ShieldCheck className="text-emerald-500" size={24} />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="text-[10px] font-bold text-slate-400 uppercase tracking-widest border-b border-slate-100">
                <th className="px-6 py-4">Status</th>
                <th className="px-6 py-4">Action</th>
                <th className="px-6 py-4">User</th>
                <th className="px-6 py-4">Risk</th>
                <th className="px-6 py-4">Timestamp</th>
                <th className="px-6 py-4">Chain Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center text-slate-400 italic text-sm">No log entries found.</td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50/50 transition-colors">
                    <td className="px-6 py-4">
                      {log.result === 'SUCCESS' ? (
                        <span className="flex items-center gap-1.5 text-emerald-600 font-bold text-xs">
                          <ShieldCheck size={14} /> Success
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5 text-rose-600 font-bold text-xs">
                          <AlertTriangle size={14} /> Denied
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-xs font-mono font-bold text-slate-700">{log.action}</span>
                    </td>
                    <td className="px-6 py-4 text-xs font-medium text-slate-600">{log.user}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-12 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                          <div 
                            className={`h-full ${log.riskScore > 0.7 ? 'bg-rose-500' : log.riskScore > 0.3 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                            style={{ width: `${log.riskScore * 100}%` }}
                          />
                        </div>
                        <span className="text-[10px] font-mono text-slate-400">{log.riskScore.toFixed(2)}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-[10px] text-slate-500 font-mono">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      <div className="group relative flex items-center gap-1.5 text-[10px] font-mono text-blue-500 bg-blue-50 px-2 py-1 rounded w-fit cursor-help">
                        <Hash size={10} />
                        {log.hash.substring(0, 12)}...
                        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 p-2 bg-slate-800 text-white rounded text-[8px] opacity-0 group-hover:opacity-100 transition-opacity z-10 w-48 break-all">
                          Full Chain Hash: {log.hash}
                        </div>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default AuditLogs;
