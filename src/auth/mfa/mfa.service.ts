import { Injectable } from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';
import { UserService } from 'src/user/user.service';


@Injectable()
export class MfaService {
  constructor(private readonly userService: UserService) {}

  async generateMfaSecret(userId: number, email: string) {
    const secret = speakeasy.generateSecret({
      name: `BankApp (${email})`,
    });

    // Guarda el secret temporalmente
    await this.userService.update(userId, {
      mfaSecret: secret.base32,
      isMfaEnabled: true,
    });

    const qrCodeDataURL = await qrcode.toDataURL(secret.otpauth_url);

    return { secret: secret.base32, qrCodeDataURL };
  }

  validateMfaCode(secret: string, code: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token: code,
      window: 1,
    });
  }
}