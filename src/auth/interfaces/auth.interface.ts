export interface JwtPayload {
  sub: number;
  email: string;
  iat?: number;
  exp?: number;
}

export interface LoginResponse {
  access_token: string;
  refresh_token?: string;
  user: {
    id: number;
    email: string;
    isEmailVerified: boolean;
    isMfaEnabled: boolean;
  };
}

export interface MfaRequiredResponse {
  mfaRequired: true;
  message: string;
}

export interface MfaSetupResponse {
  secret: string;
  qrCodeDataURL: string;
  backupCodes: string[];
}

export interface PasswordResetResponse {
  message: string;
}

export interface UserSafeData {
  id: number;
  email: string;
  isEmailVerified: boolean;
  isMfaEnabled: boolean;
  isActive: boolean;
  lastLoginAt?: Date;
  createdAt: Date;
}