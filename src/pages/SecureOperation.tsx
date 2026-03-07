
import React, { useState, useEffect } from 'react';
import { 
  ArrowLeft, 
  ShieldCheck, 
  ShieldAlert, 
  Clock, 
  Loader2, 
  ChevronRight,
  Hash,
  Database,
  User,
  Activity
} from 'lucide-react';
import { OperationType, SecurityContext } from '../types';
import { Api } from '../services/api';
import { RiskMeter } from '../components/RiskMeter';
import { InfoTooltip } from '../components/InfoTooltip';
import { SECURITY_INFO } from '../constants';

interface SecureOperationProps {
  type: OperationType;
  username: string;
  onBack: () => void;
}

const SecureOperation: React.FC<SecureOperationProps> = ({ type, username, onBack }) => {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [loading, setLoading] = useState(false);
  const [context, setContext] = useState<SecurityContext | null>(null);
  const [timeLeft, setTimeLeft] = useState(60);
  const [result, setResult] = useState<{ success: boolean; score: number; reason?: string } | null>(null);

  // Form states
  const [target, setTarget] = useState('');
  const [amount, setAmount] = useState('');

  useEffect(() => {
    let timer: any;
    if (step === 2 && timeLeft > 0) {
      timer = setInterval(() => setTimeLeft(prev => prev - 1), 1000);
    }
    return () => clearInterval(timer);
  }, [step, timeLeft]);

  const requestChallenge = async () => {
    setLoading(true);
    const challenge = await Api.getChallenge(username);
    setContext({
      ...challenge,
      targetResource: target || 'ACCOUNT_001',
      amount: amount ? parseFloat(amount) : undefined
    });
    setLoading(false);
    setStep(2);
    setTimeLeft(60);
  };

  const signAndAuthorize = async () => {
    if (!context) return;
    setLoading(true);
    const authResult = await Api.verifyLogin(username, "SIGNED_CONTEXT_HASH");
    setResult({
        success: authResult.success,
        score: authResult.riskScore,
        reason: authResult.reason
    });
    setLoading(false);
    setStep(3);
  };

  const getOpTitle = () => {
    switch(type) {
      case OperationType.TRANSFER: return "Transfer Funds";
      case OperationType.READ: return "View Sensitive Data";
      case OperationType.WRITE: return "Update Details";
      case OperationType.DELETE: return "Delete Account";
      default: return "Secure Action";
    }
  };

  return (
    <div className="max-w-3xl mx-auto py-8">
      <button 
        onClick={onBack}
        className="flex items-center gap-2 text-slate-500 hover:text-slate-800 mb-6 transition-colors font-medium"
      >
        <ArrowLeft size={18} /> Back to Dashboard
      </button>

      {/* Header */}
      <div className="bg-white rounded-2xl border border-slate-200 overflow-hidden mb-8">
        <div className="bg-slate-900 p-8 text-white">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-2xl font-bold">{getOpTitle()}</h2>
            <span className="text-xs bg-blue-600 px-3 py-1 rounded-full font-bold tracking-widest uppercase">Context Aware</span>
          </div>
          <div className="flex gap-4">
            {[1, 2, 3].map((s) => (
              <div key={s} className="flex items-center gap-2">
                <div className={`w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold border ${step === s ? 'bg-blue-600 border-blue-600' : 'border-slate-700 text-slate-500'}`}>
                  {s}
                </div>
                <span className={`text-[10px] font-bold uppercase tracking-widest ${step === s ? 'text-white' : 'text-slate-500'}`}>
                  {s === 1 ? 'Configure' : s === 2 ? 'Authorize' : 'Result'}
                </span>
                {s < 3 && <ChevronRight size={14} className="text-slate-700" />}
              </div>
            ))}
          </div>
        </div>

        <div className="p-8">
          {/* STEP 1: CONFIGURE */}
          {step === 1 && (
            <div className="space-y-6">
              {type === OperationType.TRANSFER && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Recipient Username</label>
                    <input 
                      type="text" value={target} onChange={e => setTarget(e.target.value)}
                      className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="e.g. jdoe88"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-bold text-slate-500 uppercase mb-2">Amount (USD)</label>
                    <input 
                      type="number" value={amount} onChange={e => setAmount(e.target.value)}
                      className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-blue-500"
                      placeholder="0.00"
                    />
                  </div>
                </div>
              )}
              
              {type === OperationType.WRITE && (
                <div className="space-y-4">
                  <div className="p-4 bg-amber-50 rounded-lg border border-amber-100 flex gap-3">
                    <Activity size={20} className="text-amber-600 shrink-0" />
                    <p className="text-xs text-amber-700">Updating account details is considered a <strong>Medium Risk</strong> action and requires bound context signing.</p>
                  </div>
                  <input type="text" placeholder="New Email Address" className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg" />
                </div>
              )}

              {type === OperationType.DELETE && (
                <div className="space-y-4">
                  <div className="p-6 bg-rose-50 border border-rose-200 rounded-xl">
                    <h3 className="text-rose-900 font-bold mb-2">Danger Zone</h3>
                    <p className="text-sm text-rose-700 leading-relaxed">
                      You are about to permanently delete your account. This is a <strong>High Risk</strong> operation that requires verified context-aware signing.
                    </p>
                  </div>
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input type="checkbox" className="w-4 h-4 rounded text-blue-600" />
                    <span className="text-sm text-slate-600 font-medium">I understand that this action is irreversible.</span>
                  </label>
                </div>
              )}

              {type === OperationType.READ && (
                <div className="p-6 bg-blue-50 border border-blue-100 rounded-xl text-center">
                  <FileText className="mx-auto text-blue-600 mb-2" size={32} />
                  <p className="text-sm text-blue-800 font-medium">Requesting access to confidential financial logs...</p>
                </div>
              )}

              <button 
                onClick={requestChallenge}
                disabled={loading}
                className="w-full py-4 bg-slate-900 text-white font-bold rounded-lg flex items-center justify-center gap-2 hover:bg-slate-800 transition-all disabled:opacity-50"
              >
                {loading ? <Loader2 className="animate-spin" /> : 'Proceed Securely'}
              </button>
            </div>
          )}

          {/* STEP 2: AUTHORIZE */}
          {step === 2 && context && (
            <div className="space-y-6">
              <div className="bg-slate-50 rounded-xl border border-slate-200 p-6">
                <div className="flex justify-between items-center mb-6">
                  <h3 className="font-bold text-slate-800 flex items-center gap-2">
                    <Hash size={18} className="text-blue-600" />
                    Bound Transaction Context
                    <InfoTooltip title={SECURITY_INFO.CONTEXT_BINDING.title} content={SECURITY_INFO.CONTEXT_BINDING.description} />
                  </h3>
                  <div className="flex items-center gap-2 px-3 py-1 bg-amber-100 text-amber-700 rounded-full font-bold text-[10px] animate-pulse">
                    <Clock size={12} /> NONCE EXPIRES IN {timeLeft}s
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-y-4 text-xs font-mono">
                  <div className="text-slate-400">NONCE_CHALLENGE</div>
                  <div className="text-slate-800 font-bold truncate">{context.nonce}</div>
                  <div className="text-slate-400">OPERATION_TYPE</div>
                  <div className="text-slate-800 font-bold">{context.operation}</div>
                  <div className="text-slate-400">SENDER_PRINCIPAL</div>
                  <div className="text-slate-800 font-bold">{context.user}</div>
                  <div className="text-slate-400">TARGET_RESOURCE</div>
                  <div className="text-slate-800 font-bold">{context.targetResource}</div>
                  {context.amount && (
                    <>
                      <div className="text-slate-400">TXN_AMOUNT</div>
                      <div className="text-slate-800 font-bold">${context.amount.toFixed(2)}</div>
                    </>
                  )}
                  <div className="text-slate-400">TIMESTAMP</div>
                  <div className="text-slate-800 font-bold">{context.timestamp}</div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex items-center gap-3 p-4 bg-blue-50 border border-blue-100 rounded-lg">
                  <ShieldCheck size={20} className="text-blue-600 shrink-0" />
                  <p className="text-[11px] text-blue-800 leading-relaxed">
                    By clicking <strong>Sign & Authorize</strong>, your private key will generate a cryptographic signature over the JSON context displayed above. The server will verify this signature and the bound nonce.
                  </p>
                </div>
                
                <button 
                  onClick={signAndAuthorize}
                  disabled={loading || timeLeft <= 0}
                  className="w-full py-4 bg-blue-600 text-white font-bold rounded-lg flex items-center justify-center gap-2 hover:bg-blue-700 transition-all disabled:opacity-50"
                >
                  {loading ? <Loader2 className="animate-spin" /> : 'Sign & Authorize'}
                </button>
              </div>
            </div>
          )}

          {/* STEP 3: RESULT */}
          {step === 3 && result && (
            <div className="text-center py-4 space-y-8 animate-in fade-in zoom-in duration-300">
              <div className={`mx-auto w-20 h-20 rounded-full flex items-center justify-center ${result.success ? 'bg-emerald-100 text-emerald-600' : 'bg-rose-100 text-rose-600'}`}>
                {result.success ? <ShieldCheck size={48} /> : <ShieldAlert size={48} />}
              </div>

              <div className="space-y-2">
                <h3 className="text-2xl font-bold text-slate-800">
                  {result.success ? 'Operation Authorized' : 'Authorization Denied'}
                </h3>
                <p className="text-slate-500">
                  {result.success 
                    ? `The context-aware signature was verified successfully for ${type}.` 
                    : result.reason || 'The security server rejected this request.'}
                </p>
              </div>

              <RiskMeter score={result.score} />

              {result.success && type === OperationType.READ && (
                <div className="p-6 bg-slate-900 text-white rounded-xl text-left font-mono text-xs space-y-2 border border-slate-700">
                  <p className="text-slate-500 border-b border-slate-800 pb-2 mb-2 uppercase">Decrypted Sensitive Data</p>
                  <p>RECORD_ID: SEC-88921-X</p>
                  <p>CREDIT_SCORE: 782</p>
                  <p>INTERNAL_NOTES: Demo user session is for academic purposes only.</p>
                </div>
              )}

              <button 
                onClick={onBack}
                className="w-full py-3 border border-slate-200 text-slate-600 font-bold rounded-lg hover:bg-slate-50 transition-all"
              >
                Return to Dashboard
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const FileText: React.FC<any> = (props) => (
  <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14.5 2 14.5 7.5 20 7.5"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/></svg>
);

export default SecureOperation;
