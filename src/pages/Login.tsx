

import React, { useState } from 'react';
import { User, Key, ShieldCheck, ShieldAlert, Loader2 } from 'lucide-react';
import { InfoTooltip } from '../components/InfoTooltip';
import { SECURITY_INFO } from '../constants';

import { Api } from '../services/api';
import { generateKeyPair, exportPrivateKeyPEM, exportPublicKeyPEM } from '../utils/keygen';

interface LoginProps {
  onLoginSuccess: (username: string) => void;
}

const Login: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [privateKeyFile, setPrivateKeyFile] = useState<File | null>(null);

  const [step, setStep] = useState<
    'idle' | 'requesting' | 'signing' | 'verifying' | 'success' | 'failed'
  >('idle');

  const [errorMessage, setErrorMessage] = useState('');

  // 🔐 Load private key from uploaded PEM
  async function loadPrivateKey(file: File): Promise<CryptoKey> {
    const text = await file.text();

    const keyData = text
      .replace(/-----BEGIN PRIVATE KEY-----/, '')
      .replace(/-----END PRIVATE KEY-----/, '')
      .replace(/\n/g, '');

    const binary = Uint8Array.from(atob(keyData), (c) => c.charCodeAt(0));

    return window.crypto.subtle.importKey(
      'pkcs8',
      binary.buffer,
      { name: 'RSA-PSS', hash: 'SHA-256' },
      false,
      ['sign']
    );
  }

  // 🔐 Sign server nonce
  async function signNonce(
    privateKey: CryptoKey,
    nonceBase64: string
  ): Promise<string> {
    const nonceBytes = Uint8Array.from(atob(nonceBase64), (c) =>
      c.charCodeAt(0)
    );

    const signatureBuffer = await window.crypto.subtle.sign(
      { name: 'RSA-PSS', saltLength: 32 },
      privateKey,
      nonceBytes
    );

    // safe Base64 conversion
    const signatureBytes = new Uint8Array(signatureBuffer);
    let binary = '';
    signatureBytes.forEach((b) => (binary += String.fromCharCode(b)));

    return btoa(binary);
  }

  // 🔑 Generate key pair in browser + register public key
  // const handleGenerateKeys = async () => {
  //   if (!username) {
  //     alert('Enter username first.');
  //     return;
  //   }

  //   try {
  //     const keyPair = await generateKeyPair();

  //     const privatePem = await exportPrivateKeyPEM(keyPair.privateKey);
  //     const publicPem = await exportPublicKeyPEM(keyPair.publicKey);

  //     // download private key
  //     const blob = new Blob([privatePem], { type: 'application/x-pem-file' });
  //     const url = URL.createObjectURL(blob);
  //     const a = document.createElement('a');
  //     a.href = url;
  //     a.download = `${username}_private.pem`;
  //     a.click();

  //     // register public key in backend DB
  //     const result = await Api.registerUser(username, publicPem);

  //     if (result.status === 'REGISTERED') {
  //       alert('Keys generated & user registered.');
  //     } else {
  //       alert('User already exists.');
  //     }
  //   } catch (err) {
  //     console.error(err);
  //     alert('Key generation failed.');
  //   }
  // };
  const handleGenerateKeys = async () => {
  if (!username) {
    alert("Enter username first.");
    return;
  }

  try {
    const keyPair = await generateKeyPair();

    const privatePem = await exportPrivateKeyPEM(keyPair.privateKey);
    const publicPem = await exportPublicKeyPEM(keyPair.publicKey);

    // download private key
    const blob = new Blob([privatePem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${username}_private.pem`;
    a.click();

    alert("Keys generated locally ✔");

    // now backend call separately
    try {
      const result = await Api.registerUser(username, publicPem);
      console.log("Register response:", result);
      alert("Backend registration: " + result.status);
    } catch (apiErr) {
      console.error("Backend error:", apiErr);
      alert("Backend connection failed.");
    }

  } catch (err) {
    console.error("Crypto error:", err);
    alert("Crypto generation failed.");
  }
};

  // 🔐 Login handler
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!username || !privateKeyFile) {
      setErrorMessage('Username and private key required.');
      return;
    }

    try {
      setErrorMessage('');

      // 1️⃣ Request nonce from Flask
      setStep('requesting');
      const nonceResponse = await Api.getLoginNonce(username);

      if (!nonceResponse.nonce) {
        setStep('failed');
        setErrorMessage('User not found.');
        return;
      }

      // 2️⃣ Sign nonce locally
      setStep('signing');
      const privateKey = await loadPrivateKey(privateKeyFile);
      const signature = await signNonce(privateKey, nonceResponse.nonce);

      // 3️⃣ Verify with backend
      setStep('verifying');
      const result = await Api.verifyLogin(username, signature);

      if (result.status === 'SUCCESS') {
        setStep('success');
        setTimeout(() => onLoginSuccess(username), 1000);
      } else {
        setStep('failed');
        setErrorMessage('Invalid signature or expired nonce.');
      }
    } catch (err) {
      console.error(err);
      setStep('failed');
      setErrorMessage('Security connection error.');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100 p-4">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-xl overflow-hidden">
        {/* HEADER */}
        <div className="bg-slate-900 p-8 text-white text-center">
          <div className="inline-block p-3 bg-blue-600 rounded-xl mb-4">
            <ShieldCheck size={32} />
          </div>
          <h1 className="text-2xl font-bold">SecureBank Demo</h1>
          <p className="text-slate-400 text-sm mt-1">
            Public-Key Academic Authentication
          </p>
        </div>

        <div className="p-8">
          {/* LOGIN FORM */}
          {step === 'idle' && (
            <>
              <form onSubmit={handleLogin} className="space-y-6">
                {/* USERNAME */}
                <div>
                  <label className="block text-xs font-semibold text-slate-500 uppercase mb-2">
                    Username
                  </label>
                  <div className="relative">
                    <User
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                      size={18}
                    />
                    <input
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="w-full pl-10 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-lg"
                      required
                    />
                  </div>
                </div>

                {/* PRIVATE KEY */}
                <div>
                  <label className="block text-xs font-semibold text-slate-500 uppercase mb-2">
                    Private Key File
                    <InfoTooltip
                      title={SECURITY_INFO.NONCE.title}
                      content={SECURITY_INFO.NONCE.description}
                    />
                  </label>
                  <div className="relative">
                    <Key
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                      size={18}
                    />
                    <input
                      type="file"
                      accept=".pem"
                      onChange={(e) =>
                        setPrivateKeyFile(e.target.files?.[0] || null)
                      }
                      className="w-full pl-10 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-lg cursor-pointer"
                      required
                    />
                  </div>
                </div>

                {/* LOGIN BUTTON */}
                <button
                  type="submit"
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-4 rounded-lg"
                >
                  Authenticate Securely
                </button>
              </form>

              {/* GENERATE KEY BUTTON */}
              <button
                type="button"
                onClick={handleGenerateKeys}
                className="w-full mt-4 bg-slate-700 hover:bg-slate-800 text-white font-semibold py-3 rounded-lg"
              >
                Generate New Key Pair
              </button>
            </>
          )}

          {/* STATUS SCREEN */}
          {step !== 'idle' && (
            <div className="text-center py-8 space-y-6">
              {step === 'success' ? (
                <div className="inline-block p-4 bg-emerald-100 text-emerald-600 rounded-full">
                  <ShieldCheck size={48} />
                </div>
              ) : step === 'failed' ? (
                <div className="inline-block p-4 bg-rose-100 text-rose-600 rounded-full">
                  <ShieldAlert size={48} />
                </div>
              ) : (
                <Loader2 className="animate-spin text-blue-600 w-16 h-16 mx-auto" />
              )}

              <p className="font-semibold text-lg text-slate-800">
                {step === 'requesting' && 'Requesting Server Nonce...'}
                {step === 'signing' && 'Signing Nonce Locally...'}
                {step === 'verifying' && 'Verifying Signature...'}
                {step === 'success' && 'Access Granted'}
                {step === 'failed' && 'Access Denied'}
              </p>

              {errorMessage && (
                <p className="text-sm text-rose-600">{errorMessage}</p>
              )}

              {step === 'failed' && (
                <button
                  onClick={() => setStep('idle')}
                  className="px-6 py-2 border border-slate-300 rounded-full"
                >
                  Try Again
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Login;
