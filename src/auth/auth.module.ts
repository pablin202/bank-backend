import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './jwt.strategy';
import { MfaService } from './mfa/mfa.service';
import { UserModule } from 'src/user/user.module';
import { EmailModule } from 'src/email/email.module';
import { RateLimitAttempt } from './entities/rate-limit-attempt.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([RateLimitAttempt]),
    PassportModule,
    UserModule,
    EmailModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '15m' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy, MfaService],
  exports: [AuthService],
})
export class AuthModule {}
