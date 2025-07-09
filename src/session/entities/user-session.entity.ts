import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';
import { User } from '../../user/user.entity';
import { Device } from '../../device/entities/device.entity';

export interface LocationInfo {
  country?: string;
  city?: string;
  region?: string;
  ip: string;
  timezone?: string;
}

export interface DeviceInfo {
  userAgent: string;
  screenResolution: string;
  timezone: string;
  language: string;
  platform: string;
  hardwareConcurrency: number;
  maxTouchPoints: number;
  canvasFingerprint?: string;
}

@Entity('user_sessions')
@Index(['userId', 'isActive'])
@Index(['sessionToken'])
@Index(['deviceFingerprint'])
export class UserSession {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  userId: string;

  @Column()
  deviceId: string;

  @Column({ unique: true })
  sessionToken: string;

  @Column({ unique: true })
  refreshToken: string;

  @Column()
  ipAddress: string;

  @Column({ type: 'text' })
  userAgent: string;

  @Column()
  deviceFingerprint: string;

  @Column({ default: false })
  isActive: boolean;

  @Column({ type: 'timestamp' })
  lastActivityAt: Date;

  @Column({ type: 'timestamp' })
  expiresAt: Date;

  @Column({ type: 'json', nullable: true })
  deviceInfo: DeviceInfo;

  @Column({ type: 'json', nullable: true })
  locationInfo: LocationInfo;

  @Column({ default: 'NORMAL' })
  securityLevel: 'NORMAL' | 'HIGH' | 'CRITICAL';

  @Column({ default: 0 })
  warningCount: number;

  @Column({ type: 'timestamp', nullable: true })
  lastWarningAt: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @ManyToOne(() => User, user => user.sessions)
  user: User;

  @ManyToOne(() => Device, device => device.sessions)
  device: Device;
}