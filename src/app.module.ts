import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { AccountModule } from './account/account.module';
import { EmailModule } from './email/email.module';
import { SessionModule } from './session/session.module';
import { DeviceModule } from './device/device.module';
import { NotificationModule } from './notification/notification.module';
import { AuditModule } from './audit/audit.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DB_HOST,
      port: +(process.env.DB_PORT || 18152),
      username: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      ssl: { rejectUnauthorized: false }, // needed for Railway
      entities: [__dirname + '/**/*.entity{.ts,.js}'],
      synchronize: true, // ONLY in development
    }),
    UserModule,
    AuthModule,
    AccountModule,
    EmailModule,
    SessionModule,
    DeviceModule,
    NotificationModule,
    AuditModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
