import { IsString, IsNotEmpty, IsOptional, IsObject, IsEnum, IsNumber, IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { DeviceInfo, LocationInfo } from '../entities/user-session.entity';

export class CreateSessionDto {
  @ApiProperty({ description: 'Device fingerprint' })
  @IsString()
  @IsNotEmpty()
  deviceFingerprint: string;

  @ApiProperty({ description: 'IP address' })
  @IsString()
  @IsNotEmpty()
  ipAddress: string;

  @ApiProperty({ description: 'User agent string' })
  @IsString()
  @IsNotEmpty()
  userAgent: string;

  @ApiProperty({ description: 'Device information' })
  @IsObject()
  deviceInfo: DeviceInfo;

  @ApiProperty({ description: 'Location information', required: false })
  @IsOptional()
  @IsObject()
  locationInfo?: LocationInfo;

  @ApiProperty({ description: 'Security level', enum: ['NORMAL', 'HIGH', 'CRITICAL'], default: 'NORMAL' })
  @IsOptional()
  @IsEnum(['NORMAL', 'HIGH', 'CRITICAL'])
  securityLevel?: 'NORMAL' | 'HIGH' | 'CRITICAL';
}

export class ValidateSessionDto {
  @ApiProperty({ description: 'Session ID' })
  @IsString()
  @IsNotEmpty()
  sessionId: string;

  @ApiProperty({ description: 'Device fingerprint' })
  @IsString()
  @IsNotEmpty()
  deviceFingerprint: string;

  @ApiProperty({ description: 'Current IP address' })
  @IsString()
  @IsNotEmpty()
  ipAddress: string;
}

export class RefreshTokenDto {
  @ApiProperty({ description: 'Refresh token' })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;

  @ApiProperty({ description: 'Device fingerprint' })
  @IsString()
  @IsNotEmpty()
  deviceFingerprint: string;
}

export class UpdateSessionSecurityDto {
  @ApiProperty({ description: 'Session ID' })
  @IsString()
  @IsNotEmpty()
  sessionId: string;

  @ApiProperty({ description: 'New security level', enum: ['NORMAL', 'HIGH', 'CRITICAL'] })
  @IsEnum(['NORMAL', 'HIGH', 'CRITICAL'])
  securityLevel: 'NORMAL' | 'HIGH' | 'CRITICAL';
}

export class SessionResponseDto {
  @ApiProperty({ description: 'Access token' })
  accessToken: string;

  @ApiProperty({ description: 'Refresh token' })
  refreshToken: string;

  @ApiProperty({ description: 'Session ID' })
  sessionId: string;

  @ApiProperty({ description: 'Token expiry in milliseconds' })
  expiresIn: number;

  @ApiProperty({ description: 'Session expires at' })
  sessionExpiresAt: Date;

  @ApiProperty({ description: 'Security level' })
  securityLevel: string;

  @ApiProperty({ description: 'Device information' })
  deviceInfo: any;

  @ApiProperty({ description: 'Warning if session will expire soon' })
  warningMessage?: string;
}

export class SessionValidationResponseDto {
  @ApiProperty({ description: 'Is session valid' })
  isValid: boolean;

  @ApiProperty({ description: 'Time until expiry in milliseconds' })
  timeUntilExpiry?: number;

  @ApiProperty({ description: 'Time until warning in milliseconds' })
  timeUntilWarning?: number;

  @ApiProperty({ description: 'Current security level' })
  securityLevel?: string;

  @ApiProperty({ description: 'Warning message if applicable' })
  warningMessage?: string;

  @ApiProperty({ description: 'Requires re-authentication' })
  requiresReauth?: boolean;
}

export class ActiveSessionDto {
  @ApiProperty({ description: 'Session ID' })
  id: string;

  @ApiProperty({ description: 'Device name' })
  deviceName: string;

  @ApiProperty({ description: 'Device type' })
  deviceType: string;

  @ApiProperty({ description: 'Operating system' })
  operatingSystem: string;

  @ApiProperty({ description: 'IP address' })
  ipAddress: string;

  @ApiProperty({ description: 'Location information' })
  locationInfo: LocationInfo;

  @ApiProperty({ description: 'Last activity timestamp' })
  lastActivityAt: Date;

  @ApiProperty({ description: 'Created timestamp' })
  createdAt: Date;

  @ApiProperty({ description: 'Is current session' })
  isCurrent: boolean;

  @ApiProperty({ description: 'Security level' })
  securityLevel: string;
}