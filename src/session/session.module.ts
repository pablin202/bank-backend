import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { UserSession } from './entities/user-session.entity';
import { Device } from '../device/entities/device.entity';
import { RateLimitAttempt } from '../auth/entities/rate-limit-attempt.entity';
import { SessionService } from './session.service';
import { SessionController } from './session.controller';
import { DeviceModule } from '../device/device.module';
import { NotificationModule } from '../notification/notification.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([UserSession, Device, RateLimitAttempt]),
    JwtModule.register({
      secret: process.env.JWT_SECRET || 'your-secret-key',
      signOptions: { expiresIn: '15m' },
    }),
    DeviceModule,
    NotificationModule,
    AuditModule,
  ],
  controllers: [SessionController],
  providers: [SessionService],
  exports: [SessionService],
})
export class SessionModule {}