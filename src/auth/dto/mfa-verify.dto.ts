import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Length } from 'class-validator';

export class MfaVerifyDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'User email address',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: '123456',
    description: '6-digit MFA code from authenticator app',
  })
  @IsString()
  @Length(6, 6, { message: 'MFA code must be exactly 6 digits' })
  code: string;
}