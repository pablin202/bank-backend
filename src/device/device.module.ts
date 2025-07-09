import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Device } from './entities/device.entity';
import { User } from '../user/user.entity';
import { RateLimitAttempt } from '../auth/entities/rate-limit-attempt.entity';
import { DeviceService } from './device.service';
import { DeviceController } from './device.controller';
import { NotificationModule } from '../notification/notification.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Device, User, RateLimitAttempt]),
    NotificationModule,
    AuditModule,
  ],
  controllers: [DeviceController],
  providers: [DeviceService],
  exports: [DeviceService],
})
export class DeviceModule {}