import React, { useState } from "react";
import { Api } from "../services/api";

interface Props {
  user: string;
  operation: string;
  onSuccess: () => void;
}

const StepUp: React.FC<Props> = ({ user, operation, onSuccess }) => {
  const [privateKeyFile, setPrivateKeyFile] = useState<File | null>(null);
  const [status, setStatus] = useState("");

  async function loadPrivateKey(file: File): Promise<CryptoKey> {
    const text = await file.text();

    const keyData = text
      .replace(/-----BEGIN PRIVATE KEY-----/, "")
      .replace(/-----END PRIVATE KEY-----/, "")
      .replace(/\n/g, "");

    const binary = Uint8Array.from(atob(keyData), (c) =>
      c.charCodeAt(0)
    );

    return window.crypto.subtle.importKey(
      "pkcs8",
      binary.buffer,
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["sign"]
    );
  }

  async function signNonce(privateKey: CryptoKey, nonceBase64: string) {
    const nonceBytes = Uint8Array.from(atob(nonceBase64), (c) =>
      c.charCodeAt(0)
    );

    const signatureBuffer = await window.crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      privateKey,
      nonceBytes
    );

    const signatureBytes = new Uint8Array(signatureBuffer);
    let binary = "";
    signatureBytes.forEach((b) => (binary += String.fromCharCode(b)));

    return btoa(binary);
  }

  const handleStepUp = async () => {
    if (!privateKeyFile) {
      setStatus("Private key required.");
      return;
    }

    try {
      setStatus("Requesting Step-Up Challenge...");

      const challenge = await Api.getStepUpChallenge(user, operation);

      const privateKey = await loadPrivateKey(privateKeyFile);

      const signature = await signNonce(privateKey, challenge.nonce);

      setStatus("Verifying Step-Up...");

      const result = await Api.verifyStepUp(
        user,
        operation,
        signature
      );

      if (result.status === "UPGRADED_ALLOW") {
        setStatus("✅ Step-Up Successful.");
        setTimeout(() => onSuccess(), 1000);
      } else {
        setStatus("❌ Step-Up Failed.");
      }

    } catch (err) {
      console.error(err);
      setStatus("Security verification failed.");
    }
  };

  return (
    <div className="max-w-md mx-auto bg-white p-8 rounded-2xl shadow-lg">
      <h2 className="text-xl font-bold mb-6">
        Step-Up Authentication Required
      </h2>

      <p className="text-sm text-gray-600 mb-4">
        Medium risk detected for <strong>{operation}</strong>.  
        Please re-authenticate using your private key.
      </p>

      <input
        type="file"
        accept=".pem"
        onChange={(e) =>
          setPrivateKeyFile(e.target.files?.[0] || null)
        }
        className="w-full border p-3 rounded-lg mb-4"
      />

      <button
        onClick={handleStepUp}
        className="w-full bg-blue-600 text-white py-3 rounded-lg font-bold"
      >
        Perform Step-Up Authentication
      </button>

      {status && (
        <div className="mt-4 text-center text-sm font-semibold">
          {status}
        </div>
      )}
    </div>
  );
};

export default StepUp;