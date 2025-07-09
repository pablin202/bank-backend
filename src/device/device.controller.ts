import {
  Controller,
  Post,
  Get,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { DeviceService } from './device.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { SessionGuard } from '../auth/guards/session.guard';
import { RateLimitGuard } from '../auth/guards/rate-limit.guard';
import {
  RegisterDeviceDto,
  ApproveDeviceDto,
  UpdateDeviceDto,
  DeviceRegistrationResponseDto,
  DeviceResponseDto,
  DeviceSecurityAlertDto,
} from './dto/device.dto';

@ApiTags('Device Management')
@Controller('device')
export class DeviceController {
  constructor(private readonly deviceService: DeviceService) {}

  @Post('register')
  @UseGuards(RateLimitGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register new device' })
  @ApiResponse({ 
    status: 201, 
    description: 'Device registered successfully',
    type: DeviceRegistrationResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid device data or limit exceeded' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  async registerDevice(
    @Body() registerDeviceDto: RegisterDeviceDto,
    @Request() req
  ): Promise<DeviceRegistrationResponseDto> {
    const userId = req.user?.id || req.userId;
    
    // Agregar información de la request
    const deviceData = {
      ...registerDeviceDto,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.headers['user-agent'] || '',
    };

    return await this.deviceService.registerDevice(userId, deviceData);
  }

  @Post(':deviceId/approve')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Approve device for banking operations' })
  @ApiResponse({ 
    status: 200, 
    description: 'Device approved successfully',
    type: DeviceResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Device not pending approval' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Device not found' })
  async approveDevice(
    @Param('deviceId') deviceId: string,
    @Body() approveDeviceDto: ApproveDeviceDto,
    @Request() req
  ): Promise<DeviceResponseDto> {
    const userId = req.user.id;
    
    const approvalData = {
      ...approveDeviceDto,
      deviceId,
    };

    return await this.deviceService.approveDevice(userId, approvalData);
  }

  @Post(':deviceId/reject')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reject device registration' })
  @ApiResponse({ status: 200, description: 'Device rejected successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Device not found' })
  async rejectDevice(
    @Param('deviceId') deviceId: string,
    @Body() body: { reason: string },
    @Request() req
  ): Promise<{ message: string }> {
    const userId = req.user.id;
    
    await this.deviceService.rejectDevice(userId, deviceId, body.reason);
    
    return { message: 'Device rejected successfully' };
  }

  @Get()
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get all user devices' })
  @ApiResponse({ 
    status: 200, 
    description: 'List of user devices',
    type: [DeviceResponseDto] 
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getUserDevices(@Request() req): Promise<DeviceResponseDto[]> {
    const userId = req.user.id;
    const currentDeviceId = req.user.deviceId;
    
    const devices = await this.deviceService.getUserDevices(userId);
    
    // Marcar el dispositivo actual
    return devices.map(device => ({
      ...device,
      isCurrentDevice: device.id === currentDeviceId,
    }));
  }

  @Get(':deviceId')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get device details' })
  @ApiResponse({ 
    status: 200, 
    description: 'Device details',
    type: DeviceResponseDto 
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Device not found' })
  async getDevice(
    @Param('deviceId') deviceId: string,
    @Request() req
  ): Promise<DeviceResponseDto> {
    const userId = req.user.id;
    
    const devices = await this.deviceService.getUserDevices(userId);
    const device = devices.find(d => d.id === deviceId);
    
    if (!device) {
      throw new Error('Device not found or access denied');
    }

    return {
      ...device,
      isCurrentDevice: device.id === req.user.deviceId,
    };
  }

  @Put(':deviceId')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update device settings' })
  @ApiResponse({ 
    status: 200, 
    description: 'Device updated successfully',
    type: DeviceResponseDto 
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Device not found' })
  async updateDevice(
    @Param('deviceId') deviceId: string,
    @Body() updateDeviceDto: UpdateDeviceDto,
    @Request() req
  ): Promise<DeviceResponseDto> {
    const userId = req.user.id;
    
    return await this.deviceService.updateDevice(userId, deviceId, updateDeviceDto);
  }

  @Post(':deviceId/suspend')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Suspend device' })
  @ApiResponse({ status: 200, description: 'Device suspended successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Device not found' })
  async suspendDevice(
    @Param('deviceId') deviceId: string,
    @Body() body: { reason: string },
    @Request() req
  ): Promise<{ message: string }> {
    const userId = req.user.id;
    
    // No permitir suspender el dispositivo actual
    if (deviceId === req.user.deviceId) {
      throw new Error('Cannot suspend current device');
    }

    await this.deviceService.suspendDevice(userId, deviceId, body.reason);
    
    return { message: 'Device suspended successfully' };
  }

  @Delete(':deviceId')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete device' })
  @ApiResponse({ status: 204, description: 'Device deleted successfully' })
  @ApiResponse({ status: 400, description: 'Cannot delete primary device' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Device not found' })
  async deleteDevice(
    @Param('deviceId') deviceId: string,
    @Request() req
  ): Promise<void> {
    const userId = req.user.id;
    
    // No permitir eliminar el dispositivo actual
    if (deviceId === req.user.deviceId) {
      throw new Error('Cannot delete current device');
    }

    await this.deviceService.deleteDevice(userId, deviceId);
  }

  @Post(':deviceId/trust')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Mark device as trusted' })
  @ApiResponse({ status: 200, description: 'Device marked as trusted' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Device not found' })
  async trustDevice(
    @Param('deviceId') deviceId: string,
    @Request() req
  ): Promise<{ message: string }> {
    const userId = req.user.id;
    
    await this.deviceService.updateDevice(userId, deviceId, { isTrusted: true });
    
    return { message: 'Device marked as trusted' };
  }

  @Post(':deviceId/untrust')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Remove trusted status from device' })
  @ApiResponse({ status: 200, description: 'Device untrusted successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Device not found' })
  async untrustDevice(
    @Param('deviceId') deviceId: string,
    @Request() req
  ): Promise<{ message: string }> {
    const userId = req.user.id;
    
    await this.deviceService.updateDevice(userId, deviceId, { isTrusted: false });
    
    return { message: 'Device untrusted successfully' };
  }

  @Get(':deviceId/security-status')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get device security status' })
  @ApiResponse({ 
    status: 200, 
    description: 'Device security status',
    type: DeviceSecurityAlertDto 
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Device not found' })
  async getDeviceSecurityStatus(
    @Param('deviceId') deviceId: string,
    @Request() req
  ): Promise<any> {
    const userId = req.user.id;
    
    const devices = await this.deviceService.getUserDevices(userId);
    const device = devices.find(d => d.id === deviceId);
    
    if (!device) {
      throw new Error('Device not found or access denied');
    }

    // Analizar estado de seguridad
    const securityStatus = this.analyzeDeviceSecurityStatus(device);
    
    return securityStatus;
  }

  @Post('fingerprint')
  @UseGuards(RateLimitGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Generate device fingerprint' })
  @ApiResponse({ 
    status: 200, 
    description: 'Device fingerprint generated',
    schema: {
      type: 'object',
      properties: {
        fingerprint: { type: 'string' },
        components: { type: 'object' }
      }
    }
  })
  @ApiResponse({ status: 400, description: 'Invalid device information' })
  async generateFingerprint(
    @Body() deviceInfo: any
  ): Promise<{ fingerprint: string; components: any }> {
    const fingerprint = await this.deviceService.generateDeviceFingerprint(deviceInfo);
    
    return {
      fingerprint,
      components: {
        userAgent: deviceInfo.userAgent,
        screenResolution: deviceInfo.screenResolution,
        timezone: deviceInfo.timezone,
        language: deviceInfo.language,
        platform: deviceInfo.platform,
      }
    };
  }

  private analyzeDeviceSecurityStatus(device: any): any {
    const alerts = [];
    let severity = 'LOW';

    if (device.securityInfo?.isRooted || device.securityInfo?.isJailbroken) {
      alerts.push({
        type: 'ROOTED_DEVICE',
        message: 'Device is rooted or jailbroken',
        severity: 'HIGH',
      });
      severity = 'HIGH';
    }

    if (device.securityInfo?.hasVPN) {
      alerts.push({
        type: 'VPN_DETECTED',
        message: 'VPN connection detected',
        severity: 'MEDIUM',
      });
      if (severity === 'LOW') severity = 'MEDIUM';
    }

    if (device.loginAttempts > 3) {
      alerts.push({
        type: 'MULTIPLE_FAILED_ATTEMPTS',
        message: 'Multiple failed login attempts detected',
        severity: 'MEDIUM',
      });
      if (severity === 'LOW') severity = 'MEDIUM';
    }

    if (device.lockedUntil && device.lockedUntil > new Date()) {
      alerts.push({
        type: 'DEVICE_LOCKED',
        message: 'Device is temporarily locked',
        severity: 'HIGH',
      });
      severity = 'HIGH';
    }

    return {
      deviceId: device.id,
      overallSeverity: severity,
      alerts,
      lastSecurityCheck: new Date(),
      recommendedActions: this.getRecommendedActions(alerts),
    };
  }

  private getRecommendedActions(alerts: any[]): string[] {
    const actions = [];

    if (alerts.some(a => a.type === 'ROOTED_DEVICE')) {
      actions.push('Consider removing root access or using a different device');
    }

    if (alerts.some(a => a.type === 'VPN_DETECTED')) {
      actions.push('Disable VPN for banking operations');
    }

    if (alerts.some(a => a.type === 'MULTIPLE_FAILED_ATTEMPTS')) {
      actions.push('Reset password and enable additional security measures');
    }

    if (actions.length === 0) {
      actions.push('No immediate actions required');
    }

    return actions;
  }
}