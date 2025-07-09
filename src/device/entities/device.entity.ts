import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
// Import types to avoid circular dependencies
type User = import('../../user/user.entity').User;
type UserSession = import('../../session/entities/user-session.entity').UserSession;

export enum DeviceType {
  MOBILE = 'MOBILE',
  TABLET = 'TABLET',
  DESKTOP = 'DESKTOP',
  UNKNOWN = 'UNKNOWN'
}

export enum DeviceStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
  SUSPENDED = 'SUSPENDED'
}

export interface DeviceCapabilities {
  hasBiometric: boolean;
  hasNFC: boolean;
  hasCamera: boolean;
  hasGPS: boolean;
  hasPushNotifications: boolean;
}

export interface ApprovalMethod {
  type: 'EMAIL' | 'SMS' | 'BIOMETRIC' | 'ADMIN' | 'AUTO';
  timestamp: Date;
  ipAddress?: string;
  additionalInfo?: any;
}

export interface DeviceSecurityInfo {
  isRooted: boolean;
  isJailbroken: boolean;
  hasVPN: boolean;
  hasProxy: boolean;
  appVersion: string;
  osVersion: string;
  securityPatch?: string;
}

@Entity('user_devices')
@Index(['userId', 'status'])
@Index(['deviceFingerprint'])
@Index(['deviceId'])
export class Device {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  userId: string;

  @Column({ unique: true })
  deviceId: string;

  @Column({ unique: true })
  deviceFingerprint: string;

  @Column()
  deviceName: string;

  @Column({
    type: 'enum',
    enum: DeviceType,
    default: DeviceType.UNKNOWN
  })
  deviceType: DeviceType;

  @Column({
    type: 'enum',
    enum: DeviceStatus,
    default: DeviceStatus.PENDING
  })
  status: DeviceStatus;

  @Column()
  operatingSystem: string;

  @Column({ type: 'text' })
  browserInfo: string;

  @Column({ default: false })
  isPrimary: boolean;

  @Column({ default: false })
  isTrusted: boolean;

  @Column({ type: 'timestamp', nullable: true })
  lastUsedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  approvedAt: Date;

  @Column({ nullable: true })
  approvedBy: string;

  @Column({ type: 'json', nullable: true })
  deviceCapabilities: DeviceCapabilities;

  @Column({ type: 'json', nullable: true })
  approvalMethod: ApprovalMethod;

  @Column({ type: 'json', nullable: true })
  securityInfo: DeviceSecurityInfo;

  @Column({ type: 'json', nullable: true })
  locationInfo: any;

  @Column({ default: 0 })
  loginAttempts: number;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAttempt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lockedUntil: Date;

  @Column({ type: 'text', nullable: true })
  notes: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}