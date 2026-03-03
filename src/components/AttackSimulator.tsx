import React from "react";
import { Api } from "../services/api";

interface Props {
  user: string;
  operation: string;
  lastNonce: string | null;
  recipient: string;
  amount: number;
  setStatus: (msg: string) => void;
  setRisk: (risk: number) => void;
}

const AttackSimulator: React.FC<Props> = ({
  user,
  operation,
  lastNonce,
  recipient,
  amount,
  setStatus,
  setRisk,
}) => {
  const simulateReplay = async () => {
    if (!lastNonce) {
      setStatus("No previous nonce available.");
      return;
    }

    const context = { recipient, amount };

    const result = await Api.executeOperation(
      user,
      operation,
      lastNonce,
      context
    );

    setStatus(`🔴 Replay Attack Result: ${result.status}`);
    setRisk(result.risk || 0);
  };

  const simulateTampering = async () => {
    if (!lastNonce) {
      setStatus("No previous nonce available.");
      return;
    }

    const tamperedContext = {
      recipient,
      amount: amount + 5000,
    };

    const result = await Api.executeOperation(
      user,
      operation,
      lastNonce,
      tamperedContext
    );

    setStatus(`🟠 Tampering Result: ${result.status}`);
    setRisk(result.risk || 0);
  };

  return (
    <div className="bg-red-50 p-6 rounded-2xl border border-red-200">
      <h3 className="font-bold text-red-700 mb-4">
        🔐 Attack Simulation Panel
      </h3>

      <div className="space-y-3">
        <button
          onClick={simulateReplay}
          className="w-full bg-red-600 text-white py-2 rounded-lg"
        >
          Simulate Replay Attack
        </button>

        <button
          onClick={simulateTampering}
          className="w-full bg-orange-500 text-white py-2 rounded-lg"
        >
          Simulate Context Tampering
        </button>
      </div>

      <p className="text-xs text-red-600 mt-4">
        These simulations demonstrate replay prevention and context-aware
        nonce binding.
      </p>
    </div>
  );
};

export default AttackSimulator;