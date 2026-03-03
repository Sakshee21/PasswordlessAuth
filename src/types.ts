
export enum OperationType {
  LOGIN = 'LOGIN',
  // READ = 'READ_SENSITIVE_DATA',
  // WRITE = 'UPDATE_ACCOUNT_DETAILS',
  // DELETE = 'DELETE_ACCOUNT',
  // TRANSFER = 'TRANSFER_FUNDS'
  READ = "READ",
  WRITE = "WRITE",
  TRANSFER = "TRANSFER",
  DELETE = "DELETE"
}

export enum RiskLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH'
}

export interface SecurityContext {
  nonce: string;
  user: string;
  operation: OperationType;
  timestamp: string;
  targetResource?: string;
  amount?: number;
  expiry: number;
}

export interface AuditLogEntry {
  id: string;
  user: string;
  action: OperationType;
  result: 'SUCCESS' | 'DENIED' | 'TAMPERED';
  riskScore: number;
  reason?: string;
  timestamp: string;
  hash: string;
}

export interface User {
  username: string;
  publicKey: string;
  balance: number;
}
