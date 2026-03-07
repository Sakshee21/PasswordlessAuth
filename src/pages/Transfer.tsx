// import React, { useState } from "react";
// import { Api } from "../services/api";

// interface Props {
//   user: string;
// }

// const Transfer: React.FC<Props> = ({ user }) => {
//   const [recipient, setRecipient] = useState("");
//   const [amount, setAmount] = useState<number>(0);
//   const [status, setStatus] = useState("");

//   const handleTransfer = async () => {
//     try {
//       const context = { recipient, amount };

//       // 1️⃣ Request context-bound nonce
//       const challenge = await Api.getOperationChallenge(
//         user,
//         "TRANSFER",
//         context
//       );

//       // 2️⃣ Execute operation
//       const result = await Api.executeOperation(
//         user,
//         "TRANSFER",
//         challenge.nonce,
//         context
//       );

//       if (result.status === "ALLOW") {
//         setStatus(`✅ Transfer Allowed (Risk: ${result.risk})`);
//       } else if (result.status === "STEP_UP") {
//         setStatus(`⚠ Step-Up Required (Risk: ${result.risk})`);
//       } else {
//         setStatus(`❌ Transfer Denied (Risk: ${result.risk})`);
//       }
//     } catch (err) {
//       setStatus("Security validation failed.");
//     }
//   };

//   return (
//     <div className="bg-white p-8 rounded-2xl shadow-md max-w-md">
//       <h2 className="text-xl font-bold mb-6">Secure Fund Transfer</h2>

//       <div className="space-y-4">
//         <input
//           type="text"
//           placeholder="Recipient Name"
//           value={recipient}
//           onChange={(e) => setRecipient(e.target.value)}
//           className="w-full border p-3 rounded-lg"
//         />

//         <input
//           type="number"
//           placeholder="Amount"
//           value={amount}
//           onChange={(e) => setAmount(Number(e.target.value))}
//           className="w-full border p-3 rounded-lg"
//         />

//         <button
//           onClick={handleTransfer}
//           className="w-full bg-blue-600 text-white py-3 rounded-lg font-bold"
//         >
//           Execute Secure Transfer
//         </button>

//         {status && (
//           <div className="mt-4 text-sm font-semibold text-center">
//             {status}
//           </div>
//         )}
//       </div>
//     </div>
//   );
// };

// export default Transfer;

import React, { useState } from "react";
import { Api } from "../services/api";
import AttackSimulator from "../components/AttackSimulator";
import RiskDebugger from "../components/RiskDebugger";
interface Props {
  user: string;
}

const Transfer: React.FC<Props> = ({ user }) => {
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState<number>(0);
  const [status, setStatus] = useState("");
  const [risk, setRisk] = useState<number>(0);
  const [lastNonce, setLastNonce] = useState<string | null>(null);

  const handleTransfer = async () => {
    try {
      const context = { recipient, amount };

      const challenge = await Api.getOperationChallenge(
        user,
        "TRANSFER",
        context
      );

      setLastNonce(challenge.nonce);

      const result = await Api.executeOperation(
        user,
        "TRANSFER",
        challenge.nonce,
        context
      );

      setRisk(result.risk || 0);

      if (result.status === "ALLOW") {
        setStatus(`✅ Transfer Allowed`);
      } else if (result.status === "STEP_UP") {
        setStatus(`⚠ Step-Up Authentication Required`);
      } else {
        setStatus(`❌ Transfer Denied`);
      }
    } catch (err) {
      setStatus("Security validation failed.");
    }
  };

  return (
    <div className="space-y-8 max-w-2xl mx-auto">

      {/* 🟢 Secure Transfer Panel */}
      <div className="bg-white p-8 rounded-2xl shadow-md">
        <h2 className="text-xl font-bold mb-6">
          💳 Secure Fund Transfer
        </h2>

        <div className="space-y-4">
          <input
            type="text"
            placeholder="Recipient Name"
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            className="w-full border p-3 rounded-lg"
          />

          <input
            type="number"
            placeholder="Amount"
            value={amount}
            onChange={(e) => setAmount(Number(e.target.value))}
            className="w-full border p-3 rounded-lg"
          />

          <button
            onClick={handleTransfer}
            className="w-full bg-blue-600 text-white py-3 rounded-lg font-bold"
          >
            Execute Secure Transfer
          </button>

          {status && (
            <div className="mt-4 text-center font-semibold">
              {status}
            </div>
          )}
        </div>

        {/* 📊 Risk Meter */}
        <div className="mt-6">
          <p className="text-sm font-medium mb-2">
            Risk Score: {risk}
          </p>

          <div className="w-full bg-gray-200 rounded-full h-3">
            <div
              className="h-3 rounded-full"
              style={{
                width: `${risk * 100}%`,
                backgroundColor:
                  risk < 0.3
                    ? "green"
                    : risk < 0.7
                    ? "orange"
                    : "red",
              }}
            />
          </div>
        </div>
        <RiskDebugger risk={risk} amount={amount} />
      </div>
      {/* 🔴 Attack Simulator */}
      <AttackSimulator
        user={user}
        operation="TRANSFER"
        lastNonce={lastNonce}
        recipient={recipient}
        amount={amount}
        setStatus={setStatus}
        setRisk={setRisk}
      />

    </div>
  );
};

export default Transfer;