import React, { useState } from "react";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import { AuditProvider, SecurityAuditPanel } from "./components/SecurityAuditPanel";

export default function App() {

  const [user, setUser] = useState<string | null>(null);
  const [stepUpPending, setStepUpPending] = useState<string | null>(null);

  const handleStepUp = (operationId: string) => {
    setStepUpPending(operationId);
    setUser(null);
  };

  return (
    <AuditProvider>

      {!user ? (
        <Login
          onLoginSuccess={setUser}
          stepUpOperation={stepUpPending}
        />
      ) : (
        <Dashboard
          user={user}
          onNavigate={() => {}}
          onStepUp={handleStepUp}
          pendingOperation={stepUpPending}
          onStepUpComplete={() => setStepUpPending(null)}
        />
      )}

      {/* Floating audit panel — visible on every page */}
      <SecurityAuditPanel />

    </AuditProvider>
  );
}