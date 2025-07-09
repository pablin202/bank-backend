import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { Device } from './entities/device.entity';
import { User } from '../user/user.entity';
import { RateLimitAttempt } from '../auth/entities/rate-limit-attempt.entity';
import { DeviceService } from './device.service';
import { DeviceController } from './device.controller';
import { NotificationModule } from '../notification/notification.module';
import { AuditModule } from '../audit/audit.module';
import { SessionModule } from '../session/session.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Device, User, RateLimitAttempt]),
    NotificationModule,
    AuditModule,
    forwardRef(() => SessionModule),
    JwtModule.register({
      signOptions: { expiresIn: '15m' },
    }),
  ],
  controllers: [DeviceController],
  providers: [DeviceService],
  exports: [DeviceService],
})
export class DeviceModule { }