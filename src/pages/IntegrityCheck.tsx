
import React, { useState } from 'react';
import { Api } from '../services/api';
import { ArrowLeft, ShieldCheck, ShieldAlert, Loader2, RefreshCw, Lock } from 'lucide-react';
import { InfoTooltip } from '../components/InfoTooltip';
import { SECURITY_INFO } from '../constants';

interface IntegrityCheckProps {
  onBack: () => void;
}

const IntegrityCheck: React.FC<IntegrityCheckProps> = ({ onBack }) => {
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState<'IDLE' | 'SUCCESS' | 'FAILED'>('IDLE');

  const handleVerify = async () => {
    setVerifying(true);
    setResult('IDLE');
    const isValid = await Api.verifyLogIntegrity();
    setResult(isValid ? 'SUCCESS' : 'FAILED');
    setVerifying(false);
  };

  return (
    <div className="max-w-2xl mx-auto py-12 space-y-8">
      <button onClick={onBack} className="flex items-center gap-2 text-slate-500 hover:text-slate-800 font-medium">
        <ArrowLeft size={18} /> Back
      </button>

      <div className="bg-white rounded-3xl border border-slate-200 p-10 text-center shadow-xl shadow-slate-200/50">
        <div className="mx-auto w-24 h-24 bg-blue-50 rounded-3xl flex items-center justify-center mb-6">
          {verifying ? (
            <Loader2 className="animate-spin text-blue-600" size={48} />
          ) : result === 'SUCCESS' ? (
            <ShieldCheck className="text-emerald-500" size={48} />
          ) : result === 'FAILED' ? (
            <ShieldAlert className="text-rose-500" size={48} />
          ) : (
            <Lock className="text-blue-600" size={48} />
          )}
        </div>

        <h1 className="text-2xl font-bold text-slate-900 mb-2">Audit Log Integrity</h1>
        <p className="text-slate-500 mb-8 max-w-sm mx-auto">
          Verify that your transaction logs haven't been tampered with since they were recorded.
          <InfoTooltip title={SECURITY_INFO.HASH_CHAIN.title} content={SECURITY_INFO.HASH_CHAIN.description} />
        </p>

        {result === 'SUCCESS' && (
          <div className="mb-8 p-4 bg-emerald-50 border border-emerald-100 rounded-xl text-emerald-800 font-bold flex items-center justify-center gap-2 animate-in slide-in-from-bottom duration-500">
            <ShieldCheck size={20} /> Logs Intact – No Tampering Detected
          </div>
        )}

        {result === 'FAILED' && (
          <div className="mb-8 p-4 bg-rose-50 border border-rose-100 rounded-xl text-rose-800 font-bold flex items-center justify-center gap-2 animate-in slide-in-from-bottom duration-500">
            <ShieldAlert size={20} /> Tampering Detected in Audit Chain
          </div>
        )}

        <div className="space-y-4">
          <button 
            onClick={handleVerify}
            disabled={verifying}
            className="w-full py-4 bg-slate-900 text-white font-bold rounded-2xl flex items-center justify-center gap-2 hover:bg-slate-800 transition-all disabled:opacity-50 shadow-lg shadow-slate-200"
          >
            {verifying ? 'Verifying Chain Hashes...' : 'Verify Log Integrity Now'}
          </button>
          
          <p className="text-[10px] text-slate-400 leading-relaxed max-w-md mx-auto">
            Each log entry contains a hash of its own data combined with the hash of the previous record. 
            Changing even a single byte in any past log would break the entire chain.
          </p>
        </div>
      </div>
    </div>
  );
};

export default IntegrityCheck;
