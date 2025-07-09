# Configuración de Email para Verificación

## Resumen
Se ha implementado un sistema completo de envío de emails para:
- ✅ Verificación de email al registrarse
- ✅ Restablecimiento de contraseña
- ✅ Email de bienvenida después de verificar
- ✅ Reenvío de email de verificación

## Archivos Creados/Modificados

### Nuevos Archivos:
- `src/email/email.service.ts` - Servicio principal de email
- `src/email/email.module.ts` - Módulo de email
- `src/templates/emails/verification.hbs` - Plantilla de verificación
- `src/templates/emails/password-reset.hbs` - Plantilla de reset de contraseña
- `src/templates/emails/welcome.hbs` - Plantilla de bienvenida
- `.env.example` - Variables de entorno necesarias

### Archivos Modificados:
- `src/auth/auth.service.ts` - Integración con EmailService
- `src/auth/auth.module.ts` - Importa EmailModule
- `src/auth/auth.controller.ts` - Nuevo endpoint para reenviar verificación
- `src/user/user.service.ts` - Método para generar tokens de verificación
- `src/app.module.ts` - Importa EmailModule
- `package.json` - Nuevas dependencias

## Configuración Requerida

### 1. Variables de Entorno
Copia `.env.example` a `.env` y configura:

```bash
# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER=tu_email@gmail.com
EMAIL_PASSWORD=tu_contraseña_de_aplicacion
EMAIL_FROM=noreply@tuapp.com

# Application Configuration
APP_NAME=Bank App
FRONTEND_URL=http://localhost:3000
```

### 2. Configuración de Gmail (Recomendado)

#### Opción A: Contraseña de Aplicación (Recomendado)
1. Habilita la verificación en 2 pasos en tu cuenta de Google
2. Ve a [Contraseñas de aplicación](https://myaccount.google.com/apppasswords)
3. Genera una contraseña de aplicación para "Mail"
4. Usa esta contraseña en `EMAIL_PASSWORD`

#### Opción B: OAuth2 (Más Seguro)
Para producción, considera implementar OAuth2:
```bash
npm install googleapis
```

### 3. Otros Proveedores de Email

#### SendGrid
```env
EMAIL_HOST=smtp.sendgrid.net
EMAIL_PORT=587
EMAIL_USER=apikey
EMAIL_PASSWORD=tu_api_key_de_sendgrid
```

#### Mailgun
```env
EMAIL_HOST=smtp.mailgun.org
EMAIL_PORT=587
EMAIL_USER=tu_usuario_mailgun
EMAIL_PASSWORD=tu_contraseña_mailgun
```

#### AWS SES
```env
EMAIL_HOST=email-smtp.us-east-1.amazonaws.com
EMAIL_PORT=587
EMAIL_USER=tu_access_key_id
EMAIL_PASSWORD=tu_secret_access_key
```

## Endpoints Disponibles

### 1. Registro (Envía email de verificación)
```http
POST /auth/register
Content-Type: application/json

{
  "email": "usuario@ejemplo.com",
  "password": "MiContraseña123!"
}
```

### 2. Verificar Email
```http
GET /auth/verify-email?token=TOKEN_DE_VERIFICACION
```

### 3. Reenviar Email de Verificación
```http
POST /auth/resend-verification
Content-Type: application/json

{
  "email": "usuario@ejemplo.com"
}
```

### 4. Solicitar Reset de Contraseña
```http
POST /auth/forgot-password
Content-Type: application/json

{
  "email": "usuario@ejemplo.com"
}
```

## Características de Seguridad

### Rate Limiting
- **Login**: 5 intentos por 15 minutos
- **Forgot Password**: 3 intentos por hora
- **Resend Verification**: 3 intentos por hora

### Tokens
- **Verificación de Email**: Expira en 24 horas
- **Reset de Contraseña**: Expira en 1 hora
- Tokens generados con `crypto.randomBytes(32)`

### Plantillas de Email
- Diseño responsive
- Textos en español
- Botones de acción claros
- URLs de fallback
- Consejos de seguridad

## Testing

### Desarrollo Local
Para testing local, puedes usar:
- [Mailtrap](https://mailtrap.io/) - Email testing
- [MailHog](https://github.com/mailhog/MailHog) - Local SMTP server

### Configuración Mailtrap
```env
EMAIL_HOST=smtp.mailtrap.io
EMAIL_PORT=2525
EMAIL_USER=tu_usuario_mailtrap
EMAIL_PASSWORD=tu_contraseña_mailtrap
```

## Troubleshooting

### Error: "Invalid login"
- Verifica que la autenticación en 2 pasos esté habilitada
- Usa contraseña de aplicación, no tu contraseña normal
- Verifica que `EMAIL_USER` y `EMAIL_PASSWORD` sean correctos

### Error: "Connection timeout"
- Verifica `EMAIL_HOST` y `EMAIL_PORT`
- Algunos ISPs bloquean el puerto 587, prueba 465 con `EMAIL_SECURE=true`

### Emails no llegan
- Revisa la carpeta de spam
- Verifica que `EMAIL_FROM` sea un email válido
- Algunos proveedores requieren verificar el dominio

### Logs
El servicio registra todos los eventos importantes:
```bash
# Ver logs en desarrollo
npm run start:dev
```

## Próximos Pasos

### Mejoras Recomendadas:
1. **Implementar OAuth2** para mayor seguridad
2. **Queue de emails** con Redis/Bull para mejor rendimiento
3. **Templates más avanzados** con imágenes y branding
4. **Métricas de email** (abiertos, clicks, etc.)
5. **Notificaciones por SMS** como alternativa

### Monitoreo:
- Implementar alertas para fallos de email
- Métricas de deliverability
- Dashboard de emails enviados

## Soporte
Si tienes problemas con la configuración, revisa:
1. Los logs de la aplicación
2. Las variables de entorno
3. La configuración del proveedor de email
4. Los firewalls/puertos bloqueados