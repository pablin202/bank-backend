export const SESSION_CONFIG = {
  // Timeouts por tipo de operación (en milisegundos)
  IDLE_TIMEOUT: 15 * 60 * 1000, // 15 minutos sin actividad
  MAX_SESSION_DURATION: 8 * 60 * 60 * 1000, // 8 horas máximo
  HIGH_SECURITY_TIMEOUT: 5 * 60 * 1000, // 5 min para operaciones críticas
  CRITICAL_SECURITY_TIMEOUT: 2 * 60 * 1000, // 2 min para operaciones muy críticas
  
  // Warning timers
  WARNING_BEFORE_TIMEOUT: 2 * 60 * 1000, // Warning 2 minutos antes
  FINAL_WARNING_TIMEOUT: 30 * 1000, // Warning final 30 segundos antes
  
  // Límites de dispositivos
  MAX_ACTIVE_SESSIONS: 3, // Máximo 3 dispositivos activos simultáneos
  MAX_DEVICES_PER_USER: 5, // Máximo 5 dispositivos registrados por usuario
  
  // Renovación de tokens
  REFRESH_TOKEN_EXPIRY: 30 * 24 * 60 * 60 * 1000, // 30 días
  ACCESS_TOKEN_EXPIRY: 15 * 60 * 1000, // 15 minutos
  
  // Límites de intentos
  MAX_LOGIN_ATTEMPTS_PER_DEVICE: 5, // Máximo 5 intentos por dispositivo
  DEVICE_LOCK_DURATION: 30 * 60 * 1000, // 30 minutos de bloqueo
  
  // Configuración de seguridad
  REQUIRE_REAUTH_FOR_TRANSFERS: true,
  REQUIRE_REAUTH_FOR_SETTINGS: true,
  REQUIRE_REAUTH_FOR_CRITICAL_OPS: true,
  
  // Configuración de notificaciones
  NOTIFY_NEW_DEVICE_LOGIN: true,
  NOTIFY_SUSPICIOUS_ACTIVITY: true,
  NOTIFY_SESSION_TIMEOUT: true,
  
  // Configuración de auditoría
  LOG_ALL_SESSIONS: true,
  LOG_DEVICE_CHANGES: true,
  LOG_SECURITY_EVENTS: true,
};

export const SECURITY_LEVELS = {
  NORMAL: {
    name: 'NORMAL',
    idleTimeout: SESSION_CONFIG.IDLE_TIMEOUT,
    maxDuration: SESSION_CONFIG.MAX_SESSION_DURATION,
    requireReauth: false,
  },
  HIGH: {
    name: 'HIGH',
    idleTimeout: SESSION_CONFIG.HIGH_SECURITY_TIMEOUT,
    maxDuration: SESSION_CONFIG.HIGH_SECURITY_TIMEOUT * 6, // 30 minutos
    requireReauth: true,
  },
  CRITICAL: {
    name: 'CRITICAL',
    idleTimeout: SESSION_CONFIG.CRITICAL_SECURITY_TIMEOUT,
    maxDuration: SESSION_CONFIG.CRITICAL_SECURITY_TIMEOUT * 5, // 10 minutos
    requireReauth: true,
  },
};

export const DEVICE_APPROVAL_METHODS = {
  EMAIL: 'EMAIL',
  SMS: 'SMS',
  BIOMETRIC: 'BIOMETRIC',
  ADMIN: 'ADMIN',
  AUTO: 'AUTO',
} as const;

export const CRITICAL_OPERATIONS = [
  'TRANSFER',
  'CHANGE_PASSWORD',
  'CHANGE_EMAIL',
  'ENABLE_MFA',
  'DISABLE_MFA',
  'ADD_BENEFICIARY',
  'CHANGE_LIMITS',
  'EXPORT_DATA',
];

export const HIGH_SECURITY_OPERATIONS = [
  'VIEW_ACCOUNT_DETAILS',
  'CHANGE_PROFILE',
  'VIEW_STATEMENTS',
  'CHANGE_NOTIFICATIONS',
];