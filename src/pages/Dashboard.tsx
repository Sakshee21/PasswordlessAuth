
import React from 'react';
import { Api } from '../services/api';
import { 
  ArrowRightLeft, 
  FileText, 
  UserCircle, 
  Trash2, 
  History, 
  ShieldCheck,
  CreditCard,
  Lock
} from 'lucide-react';
import { OperationType, RiskLevel } from '../types';

interface DashboardProps {
  user: string;
  onNavigate: (page: string, params?: any) => void;
}

const Dashboard: React.FC<DashboardProps> = ({ user, onNavigate }) => {
  const operations = [
    {
      id: OperationType.READ,
      title: "Sensitive Records",
      desc: "View confidential profile and activity data.",
      icon: <FileText className="text-blue-600" />,
      risk: RiskLevel.LOW,
      color: "blue"
    },
    {
      id: OperationType.WRITE,
      title: "Account Details",
      desc: "Update personal settings and contact info.",
      icon: <UserCircle className="text-amber-600" />,
      risk: RiskLevel.MEDIUM,
      color: "amber"
    },
    {
      id: OperationType.TRANSFER,
      title: "Transfer Money",
      desc: "Send funds to other accounts securely.",
      icon: <ArrowRightLeft className="text-blue-600" />,
      risk: RiskLevel.MEDIUM,
      color: "blue"
    },
    {
      id: OperationType.DELETE,
      title: "Close Account",
      desc: "Permanently delete account and all data.",
      icon: <Trash2 className="text-rose-600" />,
      risk: RiskLevel.HIGH,
      color: "rose"
    }
  ];
  const handleSecureOperation = async (operation: string) => {
    const context = {}
  try {
    // 1️⃣ Request context-aware nonce
    const challenge = await Api.getOperationChallenge(user, operation,context);

    // 2️⃣ Send back nonce for execution
    const result = await Api.executeOperation(
      user,
      operation,
      challenge.nonce,
      context
    );

    if (result.status === "ALLOW") {
      alert(`✅ ${operation} allowed (Risk: ${result.risk})`);
      if (operation === "TRANSFER") {
        onNavigate("transfer");
      }

    } else if (result.status === "STEP_UP") {
      onNavigate("stepup", { operation });
      // You can later redirect to re-auth page here

    } else {
      alert(`❌ Operation denied (Risk: ${result.risk})`);
    }

  } catch (err) {
    console.error(err);
    alert("Security validation failed.");
  }
};
  return (
    <div className="space-y-8">
      {/* Welcome Banner */}
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Welcome, {user}</h1>
          <p className="text-slate-500">Academic Demo Session • {new Date().toLocaleDateString()}</p>
        </div>
        <div className="flex gap-2">
          <button 
            onClick={() => onNavigate('logs')}
            className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
          >
            <History size={16} /> Audit Logs
          </button>
          <button 
            onClick={() => onNavigate('integrity')}
            className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors"
          >
            <ShieldCheck size={16} /> Verify Integrity
          </button>
        </div>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Balance Card */}
        <div className="lg:col-span-1 bg-slate-900 rounded-2xl p-8 text-white relative overflow-hidden">
          <div className="relative z-10">
            <p className="text-slate-400 text-sm font-medium uppercase tracking-wider mb-2">Available Balance</p>
            <h2 className="text-4xl font-bold">$12,450.80</h2>
            <div className="mt-8 flex items-center gap-3">
              <div className="p-2 bg-emerald-500/20 rounded-lg">
                <Lock size={20} className="text-emerald-400" />
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Your account is protected by <strong>Context-Aware Nonce Binding</strong> and <strong>MFA</strong>.
              </p>
            </div>
          </div>
          {/* Decorative circles */}
          <div className="absolute -right-10 -bottom-10 w-40 h-40 bg-blue-600/20 rounded-full blur-3xl"></div>
          <div className="absolute -left-10 -top-10 w-40 h-40 bg-blue-400/10 rounded-full blur-3xl"></div>
        </div>

        {/* Secure Operations */}
        <div className="lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-bold text-slate-800 flex items-center gap-2">
              <ShieldCheck className="text-blue-600" size={20} />
              Secure Operations
            </h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {operations.map((op) => (
              <button
                key={op.id}
                onClick={() => handleSecureOperation(op.id)}
                //onClick={() => onNavigate('operation', { type: op.id })}
                className="group flex flex-col items-start p-6 bg-white border border-slate-200 rounded-xl hover:shadow-lg hover:border-blue-200 transition-all text-left"
              >
                <div className={`p-3 rounded-xl mb-4 bg-slate-50 group-hover:bg-white group-hover:scale-110 transition-transform`}>
                  {op.icon}
                </div>
                <h4 className="font-bold text-slate-800 mb-1">{op.title}</h4>
                <p className="text-xs text-slate-500 mb-4">{op.desc}</p>
                <div className="mt-auto flex items-center gap-2">
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase border
                    ${op.risk === RiskLevel.LOW ? 'bg-emerald-50 border-emerald-200 text-emerald-600' : ''}
                    ${op.risk === RiskLevel.MEDIUM ? 'bg-amber-50 border-amber-200 text-amber-600' : ''}
                    ${op.risk === RiskLevel.HIGH ? 'bg-rose-50 border-rose-200 text-rose-600' : ''}
                  `}>
                    {op.risk} RISK
                  </span>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Security Tip */}
      <div className="p-6 bg-blue-50 border border-blue-100 rounded-2xl flex gap-4">
        <div className="p-3 bg-blue-100 rounded-full h-fit">
          <ShieldCheck className="text-blue-600" size={24} />
        </div>
        <div>
          <h4 className="font-bold text-blue-900 mb-1 text-sm">Security Mechanism Active</h4>
          <p className="text-xs text-blue-700/80 leading-relaxed">
            Every sensitive operation requires a unique server-generated nonce bound to the specific action context. 
            This ensures that even if a network request is captured, it cannot be reused (Replay Attack Prevention).
          </p>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
