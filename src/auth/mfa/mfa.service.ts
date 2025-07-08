import { Injectable, BadRequestException, Logger } from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';
import * as crypto from 'crypto';
import { UserService } from 'src/user/user.service';
import { MfaSetupResponse } from '../interfaces/auth.interface';

@Injectable()
export class MfaService {
  private readonly logger = new Logger(MfaService.name);

  constructor(private readonly userService: UserService) {}

  async generateMfaSecret(userId: number, email: string): Promise<MfaSetupResponse> {
    try {
      const user = await this.userService.findById(userId);
      if (!user) {
        throw new BadRequestException('User not found');
      }

      if (user.isMfaEnabled) {
        throw new BadRequestException('MFA is already enabled for this user');
      }

      const secret = speakeasy.generateSecret({
        name: `BankApp (${email})`,
        issuer: 'BankApp',
        length: 32,
      });

      // Generate backup codes
      const backupCodes = this.generateBackupCodes();

      // Save the secret but don't enable MFA yet (user needs to verify first)
      await this.userService.update(userId, {
        mfaSecret: secret.base32,
        // Don't enable MFA until user verifies the setup
      });

      const qrCodeDataURL = await qrcode.toDataURL(secret.otpauth_url);

      this.logger.log(`MFA setup initiated for user: ${userId}`);

      return {
        secret: secret.base32,
        qrCodeDataURL,
        backupCodes
      };
    } catch (error) {
      this.logger.error(`MFA setup failed for user ${userId}:`, error.message);
      throw error;
    }
  }

  async enableMfa(userId: number, verificationCode: string): Promise<void> {
    const user = await this.userService.findById(userId);
    if (!user || !user.mfaSecret) {
      throw new BadRequestException('MFA setup not found. Please setup MFA first.');
    }

    if (user.isMfaEnabled) {
      throw new BadRequestException('MFA is already enabled');
    }

    const isValid = this.validateMfaCode(user.mfaSecret, verificationCode);
    if (!isValid) {
      throw new BadRequestException('Invalid verification code');
    }

    await this.userService.update(userId, {
      isMfaEnabled: true,
    });

    this.logger.log(`MFA enabled for user: ${userId}`);
  }

  async disableMfa(userId: number, verificationCode: string): Promise<void> {
    const user = await this.userService.findById(userId);
    if (!user || !user.isMfaEnabled) {
      throw new BadRequestException('MFA is not enabled for this user');
    }

    const isValid = this.validateMfaCode(user.mfaSecret!, verificationCode);
    if (!isValid) {
      throw new BadRequestException('Invalid verification code');
    }

    await this.userService.update(userId, {
      isMfaEnabled: false,
      mfaSecret: undefined,
    });

    this.logger.log(`MFA disabled for user: ${userId}`);
  }

  validateMfaCode(secret: string, code: string): boolean {
    try {
      return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token: code,
        window: 2, // Allow 2 time steps before/after for clock drift
        step: 30, // 30 second time step
      });
    } catch (error) {
      this.logger.error('MFA code validation error:', error.message);
      return false;
    }
  }

  private generateBackupCodes(): string[] {
    const codes: string[] = [];
    for (let i = 0; i < 10; i++) {
      // Generate 8-character backup codes
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      codes.push(code);
    }
    return codes;
  }

  async validateBackupCode(userId: number, backupCode: string): Promise<boolean> {
    // TODO: Implement backup code validation
    // This would require storing backup codes in the database
    // and marking them as used when validated
    this.logger.warn(`Backup code validation not implemented for user: ${userId}`);
    return false;
  }
}