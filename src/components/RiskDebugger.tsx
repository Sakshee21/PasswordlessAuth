import React from "react";

interface Props {
  amount: number;
  risk: number;
}

const RiskDebugger: React.FC<Props> = ({ amount, risk }) => {
  const baseRisk = 0.2;

  let amountRisk = 0;
  if (amount > 10000) amountRisk = 0.5;
  else if (amount > 5000) amountRisk = 0.3;
  else if (amount > 1000) amountRisk = 0.1;

  return (
    <div className="mt-6 p-6 bg-gray-100 rounded-xl">
      <h3 className="font-bold mb-4">🔍 Risk Analysis Breakdown</h3>

      <div className="space-y-2 text-sm">
        <p>Base Operation Risk: {baseRisk}</p>
        <p>Transaction Amount Risk: {amountRisk}</p>
        <p>IP Anomaly Risk: Dynamic</p>
        <p>Unusual Time Risk: Dynamic</p>
        <p>Rapid Activity Risk: Dynamic</p>
      </div>

      <div className="mt-4 font-bold">
        Final Risk Score: {risk.toFixed(2)}
      </div>
    </div>
  );
};

export default RiskDebugger;