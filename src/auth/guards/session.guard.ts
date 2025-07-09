import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { SessionService } from '../../session/session.service';
import { DeviceService } from '../../device/device.service';

@Injectable()
export class SessionGuard implements CanActivate {
  private readonly logger = new Logger(SessionGuard.name);

  constructor(
    private jwtService: JwtService,
    private sessionService: SessionService,
    private deviceService: DeviceService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    
    try {
      // 1. Obtener token del header
      const authHeader = request.headers['authorization'];
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new UnauthorizedException('No token provided');
      }

      const token = authHeader.substring(7);
      
      // 2. Verificar y decodificar JWT
      const payload = this.jwtService.verify(token);
      
      // 3. Obtener información del dispositivo
      const deviceFingerprint = request.headers['x-device-fingerprint'] as string;
      const ipAddress = request.ip || request.connection.remoteAddress;
      
      if (!deviceFingerprint) {
        throw new UnauthorizedException('Device fingerprint required');
      }

      // 4. Validar sesión
      const sessionValidation = await this.sessionService.validateSession({
        sessionId: payload.sessionId,
        deviceFingerprint,
        ipAddress,
      });

      if (!sessionValidation.isValid) {
        throw new UnauthorizedException(sessionValidation.warningMessage || 'Session invalid');
      }

      // 5. Validar dispositivo
      const device = await this.deviceService.validateDevice(
        payload.userId,
        deviceFingerprint,
        { ipAddress, userAgent: request.headers['user-agent'] }
      );

      if (!device) {
        throw new UnauthorizedException('Device not found or not approved');
      }

      // 6. Agregar información del usuario a la request
      request.user = {
        id: payload.userId,
        sessionId: payload.sessionId,
        deviceId: payload.deviceId,
        deviceFingerprint: payload.deviceFingerprint,
        securityLevel: payload.securityLevel,
        device: {
          id: device.id,
          name: device.deviceName,
          type: device.deviceType,
          isTrusted: device.isTrusted,
        },
        session: {
          timeUntilExpiry: sessionValidation.timeUntilExpiry,
          securityLevel: sessionValidation.securityLevel,
          requiresReauth: sessionValidation.requiresReauth,
        },
      };

      // 7. Registrar actividad para auditoría
      this.logger.log(`Session validated for user ${payload.userId}, device ${device.deviceName}`);

      return true;

    } catch (error) {
      this.logger.error('Session validation failed:', error);
      throw new UnauthorizedException('Session validation failed');
    }
  }
}