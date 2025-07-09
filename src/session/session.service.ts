import { Injectable, UnauthorizedException, BadRequestException, Logger, Inject, forwardRef } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan, MoreThan, Not } from 'typeorm';
import { JwtService } from '@nestjs/jwt';
import { UserSession } from './entities/user-session.entity';
import { Device } from '../device/entities/device.entity';
import { DeviceService } from '../device/device.service';
import { NotificationService } from '../notification/notification.service';
import { AuditService } from '../audit/audit.service';
import { SESSION_CONFIG, SECURITY_LEVELS } from './entities/session-config.entity';
import { CreateSessionDto, SessionResponseDto, ValidateSessionDto, RefreshTokenDto, SessionValidationResponseDto, ActiveSessionDto } from './dto/session.dto';
import * as crypto from 'crypto';
import * as geoip from 'geoip-lite';

@Injectable()
export class SessionService {
  private readonly logger = new Logger(SessionService.name);

  constructor(
    @InjectRepository(UserSession)
    private sessionRepository: Repository<UserSession>,
    @InjectRepository(Device)
    private deviceRepository: Repository<Device>,
    @Inject(forwardRef(() => DeviceService))
    private deviceService: DeviceService,
    private jwtService: JwtService,
    private notificationService: NotificationService,
    private auditService: AuditService,
  ) {}

  async createSession(
    userId: string,
    createSessionDto: CreateSessionDto,
  ): Promise<SessionResponseDto> {
    try {
      const { deviceFingerprint, ipAddress, userAgent, deviceInfo, locationInfo, securityLevel = 'NORMAL' } = createSessionDto;

      // 1. Validar y obtener dispositivo
      const device = await this.deviceService.validateDevice(
        userId,
        deviceFingerprint,
        {
          ipAddress,
          userAgent,
          deviceInfo,
          locationInfo,
        }
      );

      if (!device || device.status !== 'APPROVED') {
        throw new UnauthorizedException('Device not approved for banking operations');
      }

      // 2. Verificar límite de sesiones activas
      await this.enforceSessionLimits(userId);

      // 3. Generar tokens seguros
      const sessionToken = this.generateSecureToken();
      const refreshToken = this.generateSecureToken();

      // 4. Determinar expiración según nivel de seguridad
      const securityConfig = SECURITY_LEVELS[securityLevel];
      const expiresAt = new Date(Date.now() + securityConfig.maxDuration);

      // 5. Obtener información de ubicación
      const geoLocation = this.getLocationInfo(ipAddress);

      // 6. Crear sesión
      const session = this.sessionRepository.create({
        userId,
        deviceId: device.id,
        sessionToken,
        refreshToken,
        ipAddress,
        userAgent,
        deviceFingerprint,
        isActive: true,
        lastActivityAt: new Date(),
        expiresAt,
        deviceInfo,
        locationInfo: locationInfo || geoLocation,
        securityLevel,
        warningCount: 0,
      });

      const savedSession = await this.sessionRepository.save(session);

      // 7. Actualizar última actividad del dispositivo
      await this.deviceService.updateLastUsed(device.id);

      // 8. Generar JWT con información extendida
      const accessToken = this.jwtService.sign(
        {
          userId,
          sessionId: savedSession.id,
          deviceId: device.id,
          securityLevel,
          deviceFingerprint,
        },
        { expiresIn: `${SESSION_CONFIG.ACCESS_TOKEN_EXPIRY}ms` }
      );

      // 9. Auditar creación de sesión
      await this.auditService.logSessionEvent(userId, 'SESSION_CREATED', {
        sessionId: savedSession.id,
        deviceId: device.id,
        ipAddress,
        userAgent,
        securityLevel,
      });

      // 10. Notificar nuevo login si es necesario
      if (SESSION_CONFIG.NOTIFY_NEW_DEVICE_LOGIN) {
        await this.notificationService.notifyNewDeviceLogin(userId, device, geoLocation);
      }

      return {
        accessToken,
        refreshToken,
        sessionId: savedSession.id,
        expiresIn: SESSION_CONFIG.ACCESS_TOKEN_EXPIRY,
        sessionExpiresAt: expiresAt,
        securityLevel,
        deviceInfo: {
          deviceName: device.deviceName,
          deviceType: device.deviceType,
          isApproved: device.status === 'APPROVED',
          isTrusted: device.isTrusted,
        },
      };

    } catch (error) {
      this.logger.error(`Failed to create session for user ${userId}:`, error);
      throw error;
    }
  }

  async validateSession(validateSessionDto: ValidateSessionDto): Promise<SessionValidationResponseDto> {
    try {
      const { sessionId, deviceFingerprint, ipAddress } = validateSessionDto;

      const session = await this.sessionRepository.findOne({
        where: { id: sessionId, isActive: true },
        relations: ['device'],
      });

      if (!session) {
        return { isValid: false, warningMessage: 'Session not found' };
      }

      // Verificar expiración absoluta
      if (session.expiresAt < new Date()) {
        await this.terminateSession(sessionId, 'SESSION_EXPIRED');
        return { isValid: false, warningMessage: 'Session expired' };
      }

      // Verificar timeout de inactividad
      const securityConfig = SECURITY_LEVELS[session.securityLevel];
      const timeSinceLastActivity = Date.now() - session.lastActivityAt.getTime();
      
      if (timeSinceLastActivity > securityConfig.idleTimeout) {
        await this.terminateSession(sessionId, 'IDLE_TIMEOUT');
        return { isValid: false, warningMessage: 'Session timed out due to inactivity' };
      }

      // Verificar device fingerprint
      if (session.deviceFingerprint !== deviceFingerprint) {
        await this.terminateSession(sessionId, 'DEVICE_FINGERPRINT_MISMATCH');
        await this.auditService.logSecurityEvent(session.userId, 'DEVICE_FINGERPRINT_MISMATCH', {
          sessionId,
          expectedFingerprint: session.deviceFingerprint,
          actualFingerprint: deviceFingerprint,
        });
        throw new UnauthorizedException('Device fingerprint mismatch - possible security breach');
      }

      // Verificar cambio de IP sospechoso
      if (session.ipAddress !== ipAddress) {
        await this.handleSuspiciousIPChange(session, ipAddress);
      }

      // Verificar estado del dispositivo
      const device = await this.deviceRepository.findOne({
        where: { id: session.deviceId }
      });
      
      if (!device || device.status !== 'APPROVED') {
        await this.terminateSession(sessionId, 'DEVICE_NOT_APPROVED');
        return { isValid: false, warningMessage: 'Device no longer approved' };
      }

      // Actualizar última actividad
      await this.updateLastActivity(sessionId);

      // Calcular tiempo restante
      const timeUntilExpiry = session.expiresAt.getTime() - Date.now();
      const timeUntilIdleExpiry = securityConfig.idleTimeout - timeSinceLastActivity;
      const actualTimeUntilExpiry = Math.min(timeUntilExpiry, timeUntilIdleExpiry);

      // Verificar si necesita warning
      const needsWarning = actualTimeUntilExpiry <= SESSION_CONFIG.WARNING_BEFORE_TIMEOUT;
      let warningMessage: string | undefined;

      if (needsWarning) {
        warningMessage = `Session will expire in ${Math.ceil(actualTimeUntilExpiry / 1000 / 60)} minutes`;
        await this.incrementWarningCount(sessionId);
      }

      return {
        isValid: true,
        timeUntilExpiry: actualTimeUntilExpiry,
        timeUntilWarning: needsWarning ? 0 : actualTimeUntilExpiry - SESSION_CONFIG.WARNING_BEFORE_TIMEOUT,
        securityLevel: session.securityLevel,
        warningMessage,
        requiresReauth: securityConfig.requireReauth,
      };

    } catch (error) {
      this.logger.error(`Session validation failed:`, error);
      throw error;
    }
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto): Promise<SessionResponseDto> {
    try {
      const { refreshToken, deviceFingerprint } = refreshTokenDto;

      const session = await this.sessionRepository.findOne({
        where: { refreshToken, isActive: true },
      });

      if (!session || session.expiresAt < new Date()) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      // Verificar device fingerprint
      if (session.deviceFingerprint !== deviceFingerprint) {
        await this.terminateSession(session.id, 'DEVICE_FINGERPRINT_MISMATCH');
        throw new UnauthorizedException('Device fingerprint mismatch');
      }

      // Generar nuevo access token
      const newAccessToken = this.jwtService.sign(
        {
          userId: session.userId,
          sessionId: session.id,
          deviceId: session.deviceId,
          securityLevel: session.securityLevel,
          deviceFingerprint,
        },
        { expiresIn: `${SESSION_CONFIG.ACCESS_TOKEN_EXPIRY}ms` }
      );

      // Obtener información del dispositivo
      const device = await this.deviceRepository.findOne({
        where: { id: session.deviceId }
      });

      // Actualizar última actividad
      await this.updateLastActivity(session.id);

      // Auditar renovación de token
      await this.auditService.logSessionEvent(session.userId, 'TOKEN_REFRESHED', {
        sessionId: session.id,
        deviceId: session.deviceId,
      });

      return {
        accessToken: newAccessToken,
        refreshToken,
        sessionId: session.id,
        expiresIn: SESSION_CONFIG.ACCESS_TOKEN_EXPIRY,
        sessionExpiresAt: session.expiresAt,
        securityLevel: session.securityLevel,
        deviceInfo: {
          deviceName: device?.deviceName || 'Unknown Device',
          deviceType: device?.deviceType || 'UNKNOWN',
          isApproved: device?.status === 'APPROVED',
          isTrusted: device?.isTrusted || false,
        },
      };

    } catch (error) {
      this.logger.error(`Token refresh failed:`, error);
      throw error;
    }
  }

  async terminateSession(sessionId: string, reason: string): Promise<void> {
    try {
      const session = await this.sessionRepository.findOne({
        where: { id: sessionId },
      });

      if (session) {
        await this.sessionRepository.update(sessionId, {
          isActive: false,
          updatedAt: new Date(),
        });

        // Auditar terminación de sesión
        await this.auditService.logSessionEvent(session.userId, 'SESSION_TERMINATED', {
          sessionId,
          reason,
          deviceId: session.deviceId,
        });

        // Notificar terminación si es por motivos de seguridad
        if (['DEVICE_FINGERPRINT_MISMATCH', 'SUSPICIOUS_IP_CHANGE', 'SECURITY_BREACH'].includes(reason)) {
          await this.notificationService.notifySessionTerminated(session.userId, reason);
        }
      }
    } catch (error) {
      this.logger.error(`Failed to terminate session ${sessionId}:`, error);
      throw error;
    }
  }

  async terminateAllUserSessions(userId: string, excludeSessionId?: string): Promise<void> {
    try {
      let whereClause: any = { userId, isActive: true };
      if (excludeSessionId) {
        whereClause = [
          { userId, isActive: true, id: Not(excludeSessionId) }
        ];
      }

      const sessions = await this.sessionRepository.find({
        where: whereClause,
      });

      await this.sessionRepository.update(
        whereClause,
        { isActive: false, updatedAt: new Date() }
      );

      // Auditar terminación masiva
      await this.auditService.logSessionEvent(userId, 'ALL_SESSIONS_TERMINATED', {
        terminatedSessions: sessions.map(s => s.id),
        excludedSession: excludeSessionId,
      });

      // Notificar terminación
      await this.notificationService.notifyAllSessionsTerminated(userId);

    } catch (error) {
      this.logger.error(`Failed to terminate all sessions for user ${userId}:`, error);
      throw error;
    }
  }

  async getActiveSessions(userId: string): Promise<ActiveSessionDto[]> {
    try {
      const sessions = await this.sessionRepository.find({
        where: { userId, isActive: true },
        order: { lastActivityAt: 'DESC' },
      });

      const sessionsWithDevices = await Promise.all(
        sessions.map(async (session) => {
          const device = await this.deviceRepository.findOne({
            where: { id: session.deviceId }
          });
          
          return {
            id: session.id,
            deviceName: device?.deviceName || 'Unknown Device',
            deviceType: device?.deviceType || 'UNKNOWN',
            operatingSystem: device?.operatingSystem || 'Unknown',
            ipAddress: session.ipAddress,
            locationInfo: session.locationInfo,
            lastActivityAt: session.lastActivityAt,
            createdAt: session.createdAt,
            isCurrent: false, // This will be set by the controller
            securityLevel: session.securityLevel,
          };
        })
      );

      return sessionsWithDevices;

    } catch (error) {
      this.logger.error(`Failed to get active sessions for user ${userId}:`, error);
      throw error;
    }
  }

  async updateSecurityLevel(sessionId: string, securityLevel: 'NORMAL' | 'HIGH' | 'CRITICAL'): Promise<void> {
    try {
      const session = await this.sessionRepository.findOne({
        where: { id: sessionId, isActive: true },
      });

      if (!session) {
        throw new UnauthorizedException('Session not found');
      }

      const securityConfig = SECURITY_LEVELS[securityLevel];
      const newExpiresAt = new Date(Date.now() + securityConfig.maxDuration);

      await this.sessionRepository.update(sessionId, {
        securityLevel,
        expiresAt: newExpiresAt,
        updatedAt: new Date(),
      });

      // Auditar cambio de nivel de seguridad
      await this.auditService.logSessionEvent(session.userId, 'SECURITY_LEVEL_CHANGED', {
        sessionId,
        oldLevel: session.securityLevel,
        newLevel: securityLevel,
      });

    } catch (error) {
      this.logger.error(`Failed to update security level for session ${sessionId}:`, error);
      throw error;
    }
  }

  private async enforceSessionLimits(userId: string): Promise<void> {
    const activeSessions = await this.sessionRepository.find({
      where: { userId, isActive: true },
      order: { lastActivityAt: 'ASC' },
    });

    if (activeSessions.length >= SESSION_CONFIG.MAX_ACTIVE_SESSIONS) {
      // Terminar sesiones más antiguas
      const sessionsToTerminate = activeSessions.slice(0, activeSessions.length - SESSION_CONFIG.MAX_ACTIVE_SESSIONS + 1);
      
      for (const session of sessionsToTerminate) {
        await this.terminateSession(session.id, 'SESSION_LIMIT_EXCEEDED');
      }
    }
  }

  private async updateLastActivity(sessionId: string): Promise<void> {
    await this.sessionRepository.update(sessionId, {
      lastActivityAt: new Date(),
      updatedAt: new Date(),
    });
  }

  private async incrementWarningCount(sessionId: string): Promise<void> {
    await this.sessionRepository.increment({ id: sessionId }, 'warningCount', 1);
    await this.sessionRepository.update(sessionId, {
      lastWarningAt: new Date(),
    });
  }

  private async handleSuspiciousIPChange(session: UserSession, newIpAddress: string): Promise<void> {
    // Obtener información de geolocalización
    const oldLocation = this.getLocationInfo(session.ipAddress);
    const newLocation = this.getLocationInfo(newIpAddress);

    // Si el cambio es de país diferente, es sospechoso
    if (oldLocation?.country !== newLocation?.country) {
      await this.auditService.logSecurityEvent(session.userId, 'SUSPICIOUS_IP_CHANGE', {
        sessionId: session.id,
        oldIp: session.ipAddress,
        newIp: newIpAddress,
        oldLocation,
        newLocation,
      });

      // Notificar cambio sospechoso
      await this.notificationService.notifySuspiciousActivity(session.userId, {
        type: 'IP_CHANGE',
        details: { oldLocation, newLocation },
      });

      // Elevar nivel de seguridad
      await this.updateSecurityLevel(session.id, 'HIGH');
    }

    // Actualizar IP de la sesión
    await this.sessionRepository.update(session.id, {
      ipAddress: newIpAddress,
      locationInfo: newLocation,
    });
  }

  private generateSecureToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private getLocationInfo(ipAddress: string): any {
    try {
      const geo = geoip.lookup(ipAddress);
      return geo ? {
        country: geo.country,
        city: geo.city,
        region: geo.region,
        timezone: geo.timezone,
        ll: geo.ll,
      } : null;
    } catch (error) {
      this.logger.warn(`Failed to get location for IP ${ipAddress}:`, error);
      return null;
    }
  }

  async cleanupExpiredSessions(): Promise<void> {
    try {
      const expiredSessions = await this.sessionRepository.find({
        where: {
          isActive: true,
          expiresAt: LessThan(new Date()),
        },
      });

      for (const session of expiredSessions) {
        await this.terminateSession(session.id, 'SESSION_EXPIRED');
      }

      this.logger.log(`Cleaned up ${expiredSessions.length} expired sessions`);
    } catch (error) {
      this.logger.error('Failed to cleanup expired sessions:', error);
    }
  }
}