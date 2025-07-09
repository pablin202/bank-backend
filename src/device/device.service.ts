import { Injectable, UnauthorizedException, BadRequestException, NotFoundException, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Device, DeviceStatus, DeviceType } from './entities/device.entity';
import { User } from '../user/user.entity';
import { NotificationService } from '../notification/notification.service';
import { AuditService } from '../audit/audit.service';
import { SESSION_CONFIG } from '../session/entities/session-config.entity';
import { 
  RegisterDeviceDto, 
  ApproveDeviceDto, 
  UpdateDeviceDto, 
  DeviceRegistrationResponseDto, 
  DeviceResponseDto,
  DeviceSecurityAlertDto 
} from './dto/device.dto';
import * as crypto from 'crypto';
import * as geoip from 'geoip-lite';

@Injectable()
export class DeviceService {
  private readonly logger = new Logger(DeviceService.name);

  constructor(
    @InjectRepository(Device)
    private deviceRepository: Repository<Device>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private notificationService: NotificationService,
    private auditService: AuditService,
  ) {}

  async registerDevice(userId: string, registerDeviceDto: RegisterDeviceDto): Promise<DeviceRegistrationResponseDto> {
    try {
      const { deviceFingerprint, deviceName, deviceType, operatingSystem, browserInfo, deviceCapabilities, securityInfo, locationInfo, ipAddress, userAgent } = registerDeviceDto;

      // 1. Verificar si el dispositivo ya existe
      const existingDevice = await this.deviceRepository.findOne({
        where: { userId, deviceFingerprint },
      });

      if (existingDevice) {
        return this.handleExistingDevice(existingDevice);
      }

      // 2. Verificar límite de dispositivos por usuario
      const userDeviceCount = await this.deviceRepository.count({
        where: { userId },
      });

      if (userDeviceCount >= SESSION_CONFIG.MAX_DEVICES_PER_USER) {
        throw new BadRequestException(`Maximum device limit (${SESSION_CONFIG.MAX_DEVICES_PER_USER}) reached`);
      }

      // 3. Generar ID único del dispositivo
      const deviceId = this.generateDeviceId();

      // 4. Analizar seguridad del dispositivo
      const securityAnalysis = this.analyzeDeviceSecurity(securityInfo);

      // 5. Obtener información de geolocalización
      const geoLocation = this.getLocationInfo(ipAddress);

      // 6. Determinar método de aprobación
      const approvalMethod = this.determineApprovalMethod(securityAnalysis, userDeviceCount === 0);

      // 7. Crear dispositivo
      const device = this.deviceRepository.create({
        userId,
        deviceId,
        deviceFingerprint,
        deviceName,
        deviceType,
        operatingSystem,
        browserInfo,
        status: approvalMethod.autoApprove ? DeviceStatus.APPROVED : DeviceStatus.PENDING,
        isPrimary: userDeviceCount === 0, // Primer dispositivo es primario
        isTrusted: approvalMethod.autoApprove && userDeviceCount === 0,
        deviceCapabilities,
        securityInfo,
        locationInfo: locationInfo || geoLocation,
        loginAttempts: 0,
        approvedAt: approvalMethod.autoApprove ? new Date() : null,
        approvalMethod: approvalMethod.autoApprove ? {
          type: 'AUTO',
          timestamp: new Date(),
          ipAddress,
        } : null,
      });

      const savedDevice = await this.deviceRepository.save(device);

      // 8. Auditar registro de dispositivo
      await this.auditService.logDeviceEvent(userId, 'DEVICE_REGISTERED', {
        deviceId: savedDevice.id,
        deviceName,
        deviceType,
        operatingSystem,
        ipAddress,
        autoApproved: approvalMethod.autoApprove,
        securityAnalysis,
      });

      // 9. Manejar proceso de aprobación
      if (approvalMethod.autoApprove) {
        // Notificar dispositivo aprobado automáticamente
        await this.notificationService.notifyDeviceAutoApproved(userId, savedDevice);
        
        return {
          status: 'APPROVED',
          device: this.mapToDeviceResponse(savedDevice),
          message: 'Device automatically approved and ready for use',
        };
      } else {
        // Enviar notificación de aprobación pendiente
        const approvalToken = this.generateApprovalToken();
        await this.notificationService.sendDeviceApprovalRequest(userId, savedDevice, approvalToken);
        
        return {
          status: 'PENDING_APPROVAL',
          device: this.mapToDeviceResponse(savedDevice),
          message: 'Device registration pending approval. Check your email for approval instructions.',
          approvalToken,
          estimatedApprovalTime: this.getEstimatedApprovalTime(approvalMethod.method),
        };
      }

    } catch (error) {
      this.logger.error(`Device registration failed for user ${userId}:`, error);
      throw error;
    }
  }

  async approveDevice(userId: string, approveDeviceDto: ApproveDeviceDto): Promise<DeviceResponseDto> {
    try {
      const { deviceId, approvalMethod, additionalInfo, setAsTrusted = false } = approveDeviceDto;

      const device = await this.deviceRepository.findOne({
        where: { userId, id: deviceId },
      });

      if (!device) {
        throw new NotFoundException('Device not found');
      }

      if (device.status !== DeviceStatus.PENDING) {
        throw new BadRequestException('Device is not pending approval');
      }

      // Actualizar dispositivo
      await this.deviceRepository.update(deviceId, {
        status: DeviceStatus.APPROVED,
        approvedAt: new Date(),
        approvedBy: userId, // En un sistema real, esto sería el ID del administrador
        isTrusted: setAsTrusted,
        approvalMethod: {
          type: approvalMethod,
          timestamp: new Date(),
          additionalInfo,
        },
        updatedAt: new Date(),
      });

      const updatedDevice = await this.deviceRepository.findOne({
        where: { id: deviceId },
      });

      // Auditar aprobación
      await this.auditService.logDeviceEvent(userId, 'DEVICE_APPROVED', {
        deviceId,
        approvalMethod,
        setAsTrusted,
        approvedBy: userId,
      });

      // Notificar aprobación
      await this.notificationService.notifyDeviceApproved(userId, updatedDevice);

      return this.mapToDeviceResponse(updatedDevice);

    } catch (error) {
      this.logger.error(`Device approval failed:`, error);
      throw error;
    }
  }

  async rejectDevice(userId: string, deviceId: string, reason: string): Promise<void> {
    try {
      const device = await this.deviceRepository.findOne({
        where: { userId, id: deviceId },
      });

      if (!device) {
        throw new NotFoundException('Device not found');
      }

      await this.deviceRepository.update(deviceId, {
        status: DeviceStatus.REJECTED,
        notes: reason,
        updatedAt: new Date(),
      });

      // Auditar rechazo
      await this.auditService.logDeviceEvent(userId, 'DEVICE_REJECTED', {
        deviceId,
        reason,
      });

      // Notificar rechazo
      await this.notificationService.notifyDeviceRejected(userId, device, reason);

    } catch (error) {
      this.logger.error(`Device rejection failed:`, error);
      throw error;
    }
  }

  async updateDevice(userId: string, deviceId: string, updateDeviceDto: UpdateDeviceDto): Promise<DeviceResponseDto> {
    try {
      const device = await this.deviceRepository.findOne({
        where: { userId, id: deviceId },
      });

      if (!device) {
        throw new NotFoundException('Device not found');
      }

      // Si se está cambiando a primario, remover primario de otros dispositivos
      if (updateDeviceDto.isPrimary === true) {
        await this.deviceRepository.update(
          { userId, isPrimary: true },
          { isPrimary: false }
        );
      }

      await this.deviceRepository.update(deviceId, {
        ...updateDeviceDto,
        updatedAt: new Date(),
      });

      const updatedDevice = await this.deviceRepository.findOne({
        where: { id: deviceId },
      });

      // Auditar actualización
      await this.auditService.logDeviceEvent(userId, 'DEVICE_UPDATED', {
        deviceId,
        changes: updateDeviceDto,
      });

      return this.mapToDeviceResponse(updatedDevice);

    } catch (error) {
      this.logger.error(`Device update failed:`, error);
      throw error;
    }
  }

  async suspendDevice(userId: string, deviceId: string, reason: string): Promise<void> {
    try {
      const device = await this.deviceRepository.findOne({
        where: { userId, id: deviceId },
      });

      if (!device) {
        throw new NotFoundException('Device not found');
      }

      await this.deviceRepository.update(deviceId, {
        status: DeviceStatus.SUSPENDED,
        notes: reason,
        updatedAt: new Date(),
      });

      // Terminar todas las sesiones activas del dispositivo
      // Esta llamada se implementaría en el SessionService
      // await this.sessionService.terminateDeviceSessions(deviceId);

      // Auditar suspensión
      await this.auditService.logDeviceEvent(userId, 'DEVICE_SUSPENDED', {
        deviceId,
        reason,
      });

      // Notificar suspensión
      await this.notificationService.notifyDeviceSuspended(userId, device, reason);

    } catch (error) {
      this.logger.error(`Device suspension failed:`, error);
      throw error;
    }
  }

  async deleteDevice(userId: string, deviceId: string): Promise<void> {
    try {
      const device = await this.deviceRepository.findOne({
        where: { userId, id: deviceId },
      });

      if (!device) {
        throw new NotFoundException('Device not found');
      }

      if (device.isPrimary) {
        throw new BadRequestException('Cannot delete primary device');
      }

      // Terminar todas las sesiones activas del dispositivo
      // await this.sessionService.terminateDeviceSessions(deviceId);

      await this.deviceRepository.delete(deviceId);

      // Auditar eliminación
      await this.auditService.logDeviceEvent(userId, 'DEVICE_DELETED', {
        deviceId,
        deviceName: device.deviceName,
      });

      // Notificar eliminación
      await this.notificationService.notifyDeviceDeleted(userId, device);

    } catch (error) {
      this.logger.error(`Device deletion failed:`, error);
      throw error;
    }
  }

  async getUserDevices(userId: string): Promise<DeviceResponseDto[]> {
    try {
      const devices = await this.deviceRepository.find({
        where: { userId },
        order: { createdAt: 'DESC' },
      });

      return devices.map(device => this.mapToDeviceResponse(device));

    } catch (error) {
      this.logger.error(`Failed to get user devices:`, error);
      throw error;
    }
  }

  async validateDevice(userId: string, deviceFingerprint: string, additionalInfo: any): Promise<Device> {
    try {
      const device = await this.deviceRepository.findOne({
        where: { userId, deviceFingerprint },
      });

      if (!device) {
        throw new UnauthorizedException('Device not found');
      }

      if (device.status !== DeviceStatus.APPROVED) {
        throw new UnauthorizedException('Device not approved');
      }

      // Verificar si el dispositivo está bloqueado
      if (device.lockedUntil && device.lockedUntil > new Date()) {
        throw new UnauthorizedException('Device is temporarily locked');
      }

      // Actualizar información adicional si es necesario
      if (additionalInfo) {
        await this.updateDeviceInfo(device.id, additionalInfo);
      }

      return device;

    } catch (error) {
      this.logger.error(`Device validation failed:`, error);
      throw error;
    }
  }

  async updateLastUsed(deviceId: string): Promise<void> {
    try {
      await this.deviceRepository.update(deviceId, {
        lastUsedAt: new Date(),
        updatedAt: new Date(),
      });
    } catch (error) {
      this.logger.error(`Failed to update last used for device ${deviceId}:`, error);
    }
  }

  async incrementLoginAttempts(deviceId: string): Promise<void> {
    try {
      await this.deviceRepository.increment({ id: deviceId }, 'loginAttempts', 1);
      await this.deviceRepository.update(deviceId, {
        lastLoginAttempt: new Date(),
        updatedAt: new Date(),
      });

      // Verificar si se debe bloquear el dispositivo
      const device = await this.deviceRepository.findOne({
        where: { id: deviceId },
      });

      if (device && device.loginAttempts >= SESSION_CONFIG.MAX_LOGIN_ATTEMPTS_PER_DEVICE) {
        await this.lockDevice(deviceId);
      }

    } catch (error) {
      this.logger.error(`Failed to increment login attempts for device ${deviceId}:`, error);
    }
  }

  async resetLoginAttempts(deviceId: string): Promise<void> {
    try {
      await this.deviceRepository.update(deviceId, {
        loginAttempts: 0,
        lockedUntil: null,
        updatedAt: new Date(),
      });
    } catch (error) {
      this.logger.error(`Failed to reset login attempts for device ${deviceId}:`, error);
    }
  }

  async generateDeviceFingerprint(deviceInfo: any): Promise<string> {
    const data = [
      deviceInfo.userAgent,
      deviceInfo.screenResolution,
      deviceInfo.timezone,
      deviceInfo.language,
      deviceInfo.platform,
      deviceInfo.hardwareConcurrency,
      deviceInfo.maxTouchPoints,
      deviceInfo.canvasFingerprint,
      deviceInfo.webglFingerprint,
      deviceInfo.audioFingerprint,
    ].join('|');

    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private handleExistingDevice(device: Device): DeviceRegistrationResponseDto {
    switch (device.status) {
      case DeviceStatus.APPROVED:
        return {
          status: 'APPROVED',
          device: this.mapToDeviceResponse(device),
          message: 'Device already approved and ready for use',
        };
      case DeviceStatus.PENDING:
        return {
          status: 'PENDING_APPROVAL',
          device: this.mapToDeviceResponse(device),
          message: 'Device registration is still pending approval',
        };
      case DeviceStatus.REJECTED:
        throw new UnauthorizedException('Device has been rejected and cannot be used');
      case DeviceStatus.SUSPENDED:
        throw new UnauthorizedException('Device is suspended and cannot be used');
      default:
        throw new BadRequestException('Device is in an unknown state');
    }
  }

  private analyzeDeviceSecurity(securityInfo: any): any {
    const risks = [];
    let riskLevel = 'LOW';

    if (securityInfo.isRooted || securityInfo.isJailbroken) {
      risks.push('Device is rooted/jailbroken');
      riskLevel = 'HIGH';
    }

    if (securityInfo.hasVPN) {
      risks.push('VPN detected');
      riskLevel = riskLevel === 'HIGH' ? 'HIGH' : 'MEDIUM';
    }

    if (securityInfo.hasProxy) {
      risks.push('Proxy detected');
      riskLevel = riskLevel === 'HIGH' ? 'HIGH' : 'MEDIUM';
    }

    return {
      riskLevel,
      risks,
      requiresManualApproval: riskLevel === 'HIGH',
    };
  }

  private determineApprovalMethod(securityAnalysis: any, isFirstDevice: boolean): any {
    // Primer dispositivo con seguridad baja se aprueba automáticamente
    if (isFirstDevice && securityAnalysis.riskLevel === 'LOW') {
      return {
        autoApprove: true,
        method: 'AUTO',
      };
    }

    // Dispositivos con riesgo alto requieren aprobación manual
    if (securityAnalysis.riskLevel === 'HIGH') {
      return {
        autoApprove: false,
        method: 'EMAIL',
      };
    }

    // Dispositivos con riesgo medio requieren aprobación por email
    return {
      autoApprove: false,
      method: 'EMAIL',
    };
  }

  private async updateDeviceInfo(deviceId: string, additionalInfo: any): Promise<void> {
    try {
      await this.deviceRepository.update(deviceId, {
        locationInfo: additionalInfo.locationInfo,
        updatedAt: new Date(),
      });
    } catch (error) {
      this.logger.error(`Failed to update device info for ${deviceId}:`, error);
    }
  }

  private async lockDevice(deviceId: string): Promise<void> {
    const lockUntil = new Date(Date.now() + SESSION_CONFIG.DEVICE_LOCK_DURATION);
    
    await this.deviceRepository.update(deviceId, {
      lockedUntil: lockUntil,
      updatedAt: new Date(),
    });

    // Terminar todas las sesiones activas del dispositivo
    // await this.sessionService.terminateDeviceSessions(deviceId);

    // Auditar bloqueo
    const device = await this.deviceRepository.findOne({
      where: { id: deviceId },
    });

    if (device) {
      await this.auditService.logDeviceEvent(device.userId, 'DEVICE_LOCKED', {
        deviceId,
        reason: 'Too many failed login attempts',
        lockUntil,
      });

      // Notificar bloqueo
      await this.notificationService.notifyDeviceLocked(device.userId, device);
    }
  }

  private generateDeviceId(): string {
    return crypto.randomBytes(16).toString('hex');
  }

  private generateApprovalToken(): string {
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
        coordinates: geo.ll,
      } : null;
    } catch (error) {
      this.logger.warn(`Failed to get location for IP ${ipAddress}:`, error);
      return null;
    }
  }

  private getEstimatedApprovalTime(method: string): string {
    switch (method) {
      case 'EMAIL':
        return '5-15 minutes';
      case 'SMS':
        return '2-5 minutes';
      case 'ADMIN':
        return '1-24 hours';
      default:
        return '5-15 minutes';
    }
  }

  private mapToDeviceResponse(device: Device): DeviceResponseDto {
    return {
      id: device.id,
      deviceName: device.deviceName,
      deviceType: device.deviceType,
      operatingSystem: device.operatingSystem,
      status: device.status,
      isPrimary: device.isPrimary,
      isTrusted: device.isTrusted,
      lastUsedAt: device.lastUsedAt,
      approvedAt: device.approvedAt,
      deviceCapabilities: device.deviceCapabilities,
      securityInfo: device.securityInfo,
      locationInfo: device.locationInfo,
      createdAt: device.createdAt,
    };
  }
}