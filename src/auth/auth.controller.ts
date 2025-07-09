import {
  Controller,
  Get,
  Post,
  Body,
  UnauthorizedException,
  UseGuards,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Query
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { MfaService } from './mfa/mfa.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { GetUser } from './get-user.decorator';
import { UserService } from 'src/user/user.service';
import {
  ApiBody,
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery
} from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { MfaVerifyDto } from './dto/mfa-verify.dto';
import { ForgotPasswordDto, ResetPasswordDto } from './dto/password-reset.dto';
import { UserSafeData } from './interfaces/auth.interface';
import { RateLimitGuard, RateLimit } from './guards/rate-limit.guard';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {

  constructor(
    private readonly authService: AuthService,
    private readonly mfaService: MfaService,
    private readonly userService: UserService
  ) { }

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User successfully registered' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 409, description: 'User already exists' })
  @ApiBody({ type: RegisterDto })
  async register(@Body(ValidationPipe) registerDto: RegisterDto) {
    const user = await this.authService.register(registerDto.email, registerDto.password);
    return {
      message: 'User registered successfully. Please check your email to verify your account.',
      userId: user.id
    };
  }

  @Post('login')
  @UseGuards(RateLimitGuard)
  @RateLimit({ windowMs: 15 * 60 * 1000, max: 5 }) // 5 attempts per 15 minutes
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login with email and password' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 429, description: 'Too many login attempts' })
  @ApiBody({ type: LoginDto })
  async login(@Body(ValidationPipe) loginDto: LoginDto) {
    return this.authService.loginWithPassword(loginDto.email, loginDto.password);
  }

  @Get('verify-email')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify email address' })
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  @ApiResponse({ status: 400, description: 'Invalid or expired token' })
  @ApiQuery({ name: 'token', description: 'Email verification token' })
  async verifyEmail(@Query('token') token: string) {
    await this.authService.verifyEmail(token);
    return { message: 'Email verified successfully' };
  }

  @Post('resend-verification')
  @UseGuards(RateLimitGuard)
  @RateLimit({ windowMs: 60 * 60 * 1000, max: 3 }) // 3 attempts per hour
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Resend email verification' })
  @ApiResponse({ status: 200, description: 'Verification email sent' })
  @ApiResponse({ status: 400, description: 'Email already verified or user not found' })
  @ApiResponse({ status: 429, description: 'Too many resend attempts' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          format: 'email',
          example: 'user@example.com'
        }
      },
      required: ['email']
    }
  })
  async resendVerification(@Body('email') email: string) {
    await this.authService.resendVerificationEmail(email);
    return { message: 'If an unverified account with that email exists, a verification email has been sent.' };
  }

  @Post('forgot-password')
  @UseGuards(RateLimitGuard)
  @RateLimit({ windowMs: 60 * 60 * 1000, max: 3 }) // 3 attempts per hour
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Request password reset' })
  @ApiResponse({ status: 200, description: 'Password reset email sent' })
  @ApiResponse({ status: 429, description: 'Too many password reset attempts' })
  @ApiBody({ type: ForgotPasswordDto })
  async forgotPassword(@Body(ValidationPipe) forgotPasswordDto: ForgotPasswordDto) {
    await this.authService.forgotPassword(forgotPasswordDto.email);
    return { message: 'If an account with that email exists, a password reset link has been sent.' };
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reset password with token' })
  @ApiResponse({ status: 200, description: 'Password reset successfully' })
  @ApiResponse({ status: 400, description: 'Invalid or expired token' })
  @ApiBody({ type: ResetPasswordDto })
  async resetPassword(@Body(ValidationPipe) resetPasswordDto: ResetPasswordDto) {
    await this.authService.resetPassword(resetPasswordDto.token, resetPasswordDto.newPassword);
    return { message: 'Password reset successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Post('mfa/setup')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Setup MFA for authenticated user' })
  @ApiResponse({ status: 200, description: 'MFA setup initiated' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async setupMfa(@GetUser() user: UserSafeData) {
    return this.mfaService.generateMfaSecret(user.id, user.email);
  }

  @UseGuards(JwtAuthGuard)
  @Post('mfa/enable')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Enable MFA after setup verification' })
  @ApiResponse({ status: 200, description: 'MFA enabled successfully' })
  @ApiResponse({ status: 400, description: 'Invalid verification code' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async enableMfa(
    @GetUser() user: UserSafeData,
    @Body('code') verificationCode: string
  ) {
    await this.mfaService.enableMfa(user.id, verificationCode);
    return { message: 'MFA enabled successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Post('mfa/disable')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Disable MFA for authenticated user' })
  @ApiResponse({ status: 200, description: 'MFA disabled successfully' })
  @ApiResponse({ status: 400, description: 'Invalid verification code' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async disableMfa(
    @GetUser() user: UserSafeData,
    @Body('code') verificationCode: string
  ) {
    await this.mfaService.disableMfa(user.id, verificationCode);
    return { message: 'MFA disabled successfully' };
  }

  @Post('mfa/verify')
  @UseGuards(RateLimitGuard)
  @RateLimit({ windowMs: 15 * 60 * 1000, max: 10 }) // 10 attempts per 15 minutes
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Verify MFA code during login' })
  @ApiResponse({ status: 200, description: 'MFA verification successful' })
  @ApiResponse({ status: 401, description: 'Invalid MFA code' })
  @ApiResponse({ status: 429, description: 'Too many MFA verification attempts' })
  @ApiBody({ type: MfaVerifyDto })
  async verifyMfa(@Body(ValidationPipe) mfaVerifyDto: MfaVerifyDto) {
    const user = await this.userService.findByEmail(mfaVerifyDto.email);
    if (!user?.mfaSecret || !user.isMfaEnabled) {
      throw new UnauthorizedException('MFA not enabled for this user');
    }

    const isValid = this.mfaService.validateMfaCode(user.mfaSecret, mfaVerifyDto.code);

    if (!isValid) {
      throw new UnauthorizedException('Invalid MFA code');
    }

    const safeUserData = await this.userService.getSafeUserData(user);
    const loginResponse = await this.authService.login(safeUserData);
    return loginResponse;
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({ status: 200, description: 'User profile retrieved successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getProfile(@GetUser() user: UserSafeData) {
    return user;
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout current user' })
  @ApiResponse({ status: 200, description: 'Logout successful' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async logout(@GetUser() user: UserSafeData) {
    // TODO: Implement token blacklisting for better security
    // For now, just return success - client should remove token
    return { message: 'Logout successful' };
  }
}
