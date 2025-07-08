# Guía Completa de Implementación Android Kotlin para el Sistema de Autenticación

Esta guía proporciona un prompt detallado y completo para implementar el frontend de Android en Kotlin que se conecte con el sistema de autenticación mejorado del backend.

## 📱 Prompt Completo para Implementación Android Kotlin

```
Necesito implementar una aplicación Android en Kotlin que se conecte con mi API de autenticación bancaria. 
El backend tiene las siguientes características y endpoints mejorados:

### ENDPOINTS DE LA API:

**Autenticación:**
- POST /auth/register - Registro de usuario
- POST /auth/login - Login con email/password
- GET /auth/verify-email?token={token} - Verificación de email
- POST /auth/forgot-password - Solicitar reset de contraseña
- POST /auth/reset-password - Resetear contraseña con token
- GET /auth/profile - Obtener perfil del usuario
- POST /auth/logout - Cerrar sesión

**MFA (Autenticación de Dos Factores):**
- POST /auth/mfa/setup - Configurar MFA
- POST /auth/mfa/enable - Habilitar MFA después de verificación
- POST /auth/mfa/disable - Deshabilitar MFA
- POST /auth/mfa/verify - Verificar código MFA durante login

**Usuarios:**
- GET /users/profile - Obtener perfil actual
- PUT /users/profile - Actualizar perfil

### MODELOS DE DATOS:

**RegisterDto:**
```json
{
  "email": "user@example.com",
  "password": "StrongPassword123!"
}
```

**LoginDto:**
```json
{
  "email": "user@example.com", 
  "password": "MySecurePassword123!"
}
```

**LoginResponse:**
```json
{
  "access_token": "jwt_token_here",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "isEmailVerified": true,
    "isMfaEnabled": false
  }
}
```

**MfaRequiredResponse:**
```json
{
  "mfaRequired": true,
  "message": "Please provide your MFA code to complete login"
}
```

**MfaVerifyDto:**
```json
{
  "email": "user@example.com",
  "code": "123456"
}
```

**MfaSetupResponse:**
```json
{
  "secret": "base32_secret",
  "qrCodeDataURL": "data:image/png;base64,...",
  "backupCodes": ["ABC123", "DEF456", ...]
}
```

**UserSafeData:**
```json
{
  "id": 1,
  "email": "user@example.com",
  "isEmailVerified": true,
  "isMfaEnabled": false,
  "isActive": true,
  "lastLoginAt": "2025-01-07T08:00:00Z",
  "createdAt": "2025-01-01T00:00:00Z"
}
```

### VALIDACIONES REQUERIDAS:

**Password Requirements:**
- Mínimo 8 caracteres
- Al menos una letra mayúscula
- Al menos una letra minúscula  
- Al menos un número
- Al menos un carácter especial (@$!%*?&)

**Email:**
- Formato de email válido
- Normalización a lowercase

**MFA Code:**
- Exactamente 6 dígitos numéricos

### CARACTERÍSTICAS DE SEGURIDAD:

**Rate Limiting:**
- Login: 5 intentos por 15 minutos
- Password reset: 3 intentos por hora
- MFA verification: 10 intentos por 15 minutos

**Account Security:**
- Bloqueo de cuenta después de 5 intentos fallidos
- Duración de bloqueo: 2 horas
- Verificación de email requerida antes del login

**JWT Token:**
- Bearer token en header Authorization
- Expiración configurable
- Validación automática en cada request

### REQUERIMIENTOS DE LA APP ANDROID:

1. **Arquitectura MVVM** con:
   - Repository pattern
   - Retrofit para networking
   - Room para almacenamiento local
   - Hilt para dependency injection
   - Coroutines para operaciones asíncronas
   - StateFlow/LiveData para UI state management

2. **Pantallas Requeridas:**
   - Splash Screen con verificación de token
   - Login Screen
   - Register Screen
   - Email Verification Screen
   - Forgot Password Screen
   - Reset Password Screen
   - MFA Setup Screen con QR Scanner
   - MFA Verification Screen
   - Dashboard/Home Screen
   - Profile Screen
   - Settings Screen

3. **Funcionalidades de Seguridad:**
   - Almacenamiento seguro de tokens (EncryptedSharedPreferences)
   - Biometric authentication (opcional)
   - Certificate pinning para HTTPS
   - Ofuscación de código
   - Root detection
   - Screen recording protection

4. **Manejo de Estados:**
   - Loading states
   - Error handling con retry
   - Network connectivity monitoring
   - Token refresh automático
   - Session timeout handling

5. **UI/UX Requirements:**
   - Material Design 3
   - Dark/Light theme support
   - Responsive design
   - Accessibility support
   - Smooth animations
   - Progress indicators
   - Error messages user-friendly

6. **Networking:**
   - Base URL configurable
   - Request/Response interceptors
   - Automatic token attachment
   - Error response handling
   - Timeout configuration
   - Retry mechanism

7. **Local Storage:**
   - User session data
   - App preferences
   - Offline capability (básica)
   - Cache management

8. **Testing:**
   - Unit tests para ViewModels
   - Repository tests con mocks
   - UI tests para flujos críticos
   - Integration tests para API

### ESTRUCTURA DE PROYECTO SUGERIDA:

```
app/
├── src/main/java/com/bank/app/
│   ├── data/
│   │   ├── api/
│   │   │   ├── AuthApiService.kt
│   │   │   ├── UserApiService.kt
│   │   │   └── interceptors/
│   │   ├── repository/
│   │   │   ├── AuthRepository.kt
│   │   │   └── UserRepository.kt
│   │   ├── local/
│   │   │   ├── database/
│   │   │   ├── preferences/
│   │   │   └── entities/
│   │   └── models/
│   │       ├── request/
│   │       ├── response/
│   │       └── domain/
│   ├── domain/
│   │   ├── usecase/
│   │   └── repository/
│   ├── presentation/
│   │   ├── ui/
│   │   │   ├── auth/
│   │   │   ├── profile/
│   │   │   ├── dashboard/
│   │   │   └── settings/
│   │   ├── viewmodel/
│   │   └── common/
│   ├── di/
│   └── utils/
```

### CASOS DE USO ESPECÍFICOS A IMPLEMENTAR:

1. **Registro de Usuario:**
   - Validación de email y password en tiempo real
   - Manejo de errores (usuario ya existe, etc.)
   - Redirección a verificación de email

2. **Login Flow:**
   - Login normal con email/password
   - Detección de MFA requerido
   - Manejo de cuenta bloqueada
   - Almacenamiento seguro de token

3. **MFA Setup:**
   - Escaneo de QR code
   - Verificación de código de prueba
   - Almacenamiento de backup codes
   - Habilitación de MFA

4. **Password Recovery:**
   - Solicitud de reset
   - Validación de token
   - Cambio de contraseña

5. **Session Management:**
   - Auto-login con token válido
   - Logout automático en token expirado
   - Refresh token handling

### CONFIGURACIÓN DE SEGURIDAD:

```kotlin
// Network Security Config
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">your-api-domain.com</domain>
        <pin-set>
            <pin digest="SHA-256">your-certificate-pin</pin>
        </pin-set>
    </domain-config>
</network-security-config>

// Proguard Rules
-keep class com.bank.app.data.models.** { *; }
-keepclassmembers class com.bank.app.data.models.** { *; }
```

### DEPENDENCIAS GRADLE RECOMENDADAS:

```kotlin
// Networking
implementation 'com.squareup.retrofit2:retrofit:2.9.0'
implementation 'com.squareup.retrofit2:converter-gson:2.9.0'
implementation 'com.squareup.okhttp3:logging-interceptor:4.11.0'

// Dependency Injection
implementation 'com.google.dagger:hilt-android:2.48'
kapt 'com.google.dagger:hilt-compiler:2.48'

// Database
implementation 'androidx.room:room-runtime:2.5.0'
implementation 'androidx.room:room-ktx:2.5.0'
kapt 'androidx.room:room-compiler:2.5.0'

// Security
implementation 'androidx.security:security-crypto:1.1.0-alpha06'
implementation 'androidx.biometric:biometric:1.1.0'

// UI
implementation 'androidx.compose.ui:ui:1.5.4'
implementation 'androidx.compose.material3:material3:1.1.2'
implementation 'androidx.navigation:navigation-compose:2.7.5'

// QR Code
implementation 'com.journeyapps:zxing-android-embedded:4.3.0'

// Testing
testImplementation 'junit:junit:4.13.2'
testImplementation 'org.mockito:mockito-core:5.1.1'
testImplementation 'androidx.arch.core:core-testing:2.2.0'
androidTestImplementation 'androidx.test.espresso:espresso-core:3.5.1'
```

Por favor, implementa esta aplicación Android siguiendo las mejores prácticas de seguridad, 
arquitectura limpia y experiencia de usuario. Incluye manejo robusto de errores, 
validaciones del lado cliente, y asegúrate de que la app sea resiliente a fallos de red.

La app debe ser production-ready con todas las características de seguridad implementadas 
y debe pasar por testing exhaustivo antes del deployment.
```

## 🔧 Configuraciones Adicionales Requeridas

### 1. **Configuración de Red**
```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">your-api-domain.com</domain>
        <pin-set expiration="2026-01-01">
            <pin digest="SHA-256">your-certificate-pin-here</pin>
            <pin digest="SHA-256">backup-certificate-pin-here</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

### 2. **Configuración de Seguridad en Manifest**
```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:allowBackup="false"
    android:fullBackupContent="false"
    android:dataExtractionRules="@xml/data_extraction_rules">
```

### 3. **Variables de Entorno**
```kotlin
// BuildConfig.kt
object BuildConfig {
    const val BASE_URL = "https://your-api-domain.com/api/"
    const val API_VERSION = "v1"
    const val TIMEOUT_SECONDS = 30L
    const val DEBUG = BuildConfig.DEBUG
}
```

## 📋 Checklist de Implementación

### Fase 1: Setup Básico
- [ ] Configurar proyecto con arquitectura MVVM
- [ ] Implementar Hilt para DI
- [ ] Configurar Retrofit y OkHttp
- [ ] Implementar Room database
- [ ] Configurar navegación con Navigation Component

### Fase 2: Autenticación Básica
- [ ] Implementar pantallas de Login y Register
- [ ] Crear AuthRepository y AuthViewModel
- [ ] Implementar almacenamiento seguro de tokens
- [ ] Manejar estados de loading y error

### Fase 3: Funcionalidades Avanzadas
- [ ] Implementar MFA setup y verification
- [ ] Agregar QR code scanner
- [ ] Implementar password recovery
- [ ] Crear pantalla de perfil de usuario

### Fase 4: Seguridad
- [ ] Implementar certificate pinning
- [ ] Agregar biometric authentication
- [ ] Implementar root detection
- [ ] Configurar ofuscación de código

### Fase 5: Testing y Optimización
- [ ] Escribir unit tests
- [ ] Implementar UI tests
- [ ] Optimizar performance
- [ ] Testing de seguridad

## 🚀 Comandos de Desarrollo

```bash
# Generar APK de debug
./gradlew assembleDebug

# Ejecutar tests
./gradlew test

# Ejecutar tests de UI
./gradlew connectedAndroidTest

# Generar APK firmado para producción
./gradlew assembleRelease

# Análisis de código
./gradlew lint
```

## 📞 Soporte y Recursos

- **Documentación de API**: Swagger UI en `https://your-api-domain.com/api/docs`
- **Postman Collection**: Disponible para testing de endpoints
- **Figma Design**: [Link a diseños de UI/UX]
- **Slack Channel**: #mobile-development para soporte

---

**Nota de Seguridad**: Esta implementación debe seguir las mejores prácticas de seguridad móvil. Realizar auditorías de seguridad regulares y mantener las dependencias actualizadas.