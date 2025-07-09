import { IsString, IsNotEmpty, IsOptional, IsObject, IsEnum, IsBoolean, IsNumber } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { DeviceType, DeviceStatus, DeviceCapabilities, ApprovalMethod, DeviceSecurityInfo } from '../entities/device.entity';

export class RegisterDeviceDto {
  @ApiProperty({ description: 'Device fingerprint' })
  @IsString()
  @IsNotEmpty()
  deviceFingerprint: string;

  @ApiProperty({ description: 'Device name' })
  @IsString()
  @IsNotEmpty()
  deviceName: string;

  @ApiProperty({ description: 'Device type', enum: DeviceType })
  @IsEnum(DeviceType)
  deviceType: DeviceType;

  @ApiProperty({ description: 'Operating system' })
  @IsString()
  @IsNotEmpty()
  operatingSystem: string;

  @ApiProperty({ description: 'Browser information' })
  @IsString()
  @IsNotEmpty()
  browserInfo: string;

  @ApiProperty({ description: 'Device capabilities' })
  @IsObject()
  deviceCapabilities: DeviceCapabilities;

  @ApiProperty({ description: 'Security information' })
  @IsObject()
  securityInfo: DeviceSecurityInfo;

  @ApiProperty({ description: 'Location information', required: false })
  @IsOptional()
  @IsObject()
  locationInfo?: any;

  @ApiProperty({ description: 'IP address' })
  @IsString()
  @IsNotEmpty()
  ipAddress: string;

  @ApiProperty({ description: 'User agent' })
  @IsString()
  @IsNotEmpty()
  userAgent: string;
}

export class ApproveDeviceDto {
  @ApiProperty({ description: 'Device ID' })
  @IsString()
  @IsNotEmpty()
  deviceId: string;

  @ApiProperty({ description: 'Approval method', enum: ['EMAIL', 'SMS', 'BIOMETRIC', 'ADMIN', 'AUTO'] })
  @IsEnum(['EMAIL', 'SMS', 'BIOMETRIC', 'ADMIN', 'AUTO'])
  approvalMethod: 'EMAIL' | 'SMS' | 'BIOMETRIC' | 'ADMIN' | 'AUTO';

  @ApiProperty({ description: 'Additional approval info', required: false })
  @IsOptional()
  @IsObject()
  additionalInfo?: any;

  @ApiProperty({ description: 'Set as trusted device', default: false })
  @IsOptional()
  @IsBoolean()
  setAsTrusted?: boolean;
}

export class UpdateDeviceDto {
  @ApiProperty({ description: 'Device name', required: false })
  @IsOptional()
  @IsString()
  deviceName?: string;

  @ApiProperty({ description: 'Set as primary device', required: false })
  @IsOptional()
  @IsBoolean()
  isPrimary?: boolean;

  @ApiProperty({ description: 'Set as trusted device', required: false })
  @IsOptional()
  @IsBoolean()
  isTrusted?: boolean;

  @ApiProperty({ description: 'Device status', enum: DeviceStatus, required: false })
  @IsOptional()
  @IsEnum(DeviceStatus)
  status?: DeviceStatus;

  @ApiProperty({ description: 'Admin notes', required: false })
  @IsOptional()
  @IsString()
  notes?: string;
}

export class DeviceRegistrationResponseDto {
  @ApiProperty({ description: 'Registration status', enum: ['APPROVED', 'PENDING_APPROVAL', 'REJECTED'] })
  status: 'APPROVED' | 'PENDING_APPROVAL' | 'REJECTED';

  @ApiProperty({ description: 'Device information' })
  device: any;

  @ApiProperty({ description: 'Message' })
  message: string;

  @ApiProperty({ description: 'Approval token for email/SMS verification', required: false })
  approvalToken?: string;

  @ApiProperty({ description: 'Estimated approval time', required: false })
  estimatedApprovalTime?: string;
}

export class DeviceResponseDto {
  @ApiProperty({ description: 'Device ID' })
  id: string;

  @ApiProperty({ description: 'Device name' })
  deviceName: string;

  @ApiProperty({ description: 'Device type' })
  deviceType: DeviceType;

  @ApiProperty({ description: 'Operating system' })
  operatingSystem: string;

  @ApiProperty({ description: 'Device status' })
  status: DeviceStatus;

  @ApiProperty({ description: 'Is primary device' })
  isPrimary: boolean;

  @ApiProperty({ description: 'Is trusted device' })
  isTrusted: boolean;

  @ApiProperty({ description: 'Last used timestamp' })
  lastUsedAt: Date;

  @ApiProperty({ description: 'Approved timestamp' })
  approvedAt: Date;

  @ApiProperty({ description: 'Device capabilities' })
  deviceCapabilities: DeviceCapabilities;

  @ApiProperty({ description: 'Security information' })
  securityInfo: DeviceSecurityInfo;

  @ApiProperty({ description: 'Location information' })
  locationInfo: any;

  @ApiProperty({ description: 'Created timestamp' })
  createdAt: Date;

  @ApiProperty({ description: 'Is current device' })
  isCurrentDevice?: boolean;

  @ApiProperty({ description: 'Active sessions count' })
  activeSessionsCount?: number;
}

export class DeviceApprovalNotificationDto {
  @ApiProperty({ description: 'Device ID' })
  deviceId: string;

  @ApiProperty({ description: 'Device name' })
  deviceName: string;

  @ApiProperty({ description: 'Device type' })
  deviceType: string;

  @ApiProperty({ description: 'Operating system' })
  operatingSystem: string;

  @ApiProperty({ description: 'Location information' })
  locationInfo: any;

  @ApiProperty({ description: 'IP address' })
  ipAddress: string;

  @ApiProperty({ description: 'Timestamp of registration' })
  registrationTime: Date;

  @ApiProperty({ description: 'Approval token' })
  approvalToken: string;

  @ApiProperty({ description: 'Approval expires at' })
  approvalExpiresAt: Date;
}

export class DeviceSecurityAlertDto {
  @ApiProperty({ description: 'Alert type' })
  alertType: 'ROOTED_DEVICE' | 'VPN_DETECTED' | 'SUSPICIOUS_LOCATION' | 'MULTIPLE_FAILED_ATTEMPTS' | 'DEVICE_COMPROMISED';

  @ApiProperty({ description: 'Device ID' })
  deviceId: string;

  @ApiProperty({ description: 'Device name' })
  deviceName: string;

  @ApiProperty({ description: 'Alert message' })
  message: string;

  @ApiProperty({ description: 'Severity level' })
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  @ApiProperty({ description: 'Additional details' })
  details: any;

  @ApiProperty({ description: 'Timestamp' })
  timestamp: Date;

  @ApiProperty({ description: 'Recommended action' })
  recommendedAction: string;
}