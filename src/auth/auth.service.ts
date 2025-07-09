import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import { EmailService } from 'src/email/email.service';
import {
  ConflictException,
  Injectable,
  UnauthorizedException,
  BadRequestException,
  Logger
} from '@nestjs/common';
import { User } from 'src/user/user.entity';
import {
  JwtPayload,
  LoginResponse,
  MfaRequiredResponse,
  UserSafeData
} from './interfaces/auth.interface';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
    private readonly emailService: EmailService,
  ) { }

  async validateUser(email: string, password: string): Promise<UserSafeData | null> {
    try {
      const user = await this.userService.findByEmail(email);
      if (!user) {
        return null;
      }

      // Check if account is locked
      if (user.isLocked) {
        throw new UnauthorizedException('Account is temporarily locked due to too many failed login attempts');
      }

      // Check if account is active
      if (!user.isActive) {
        throw new UnauthorizedException('Account is deactivated');
      }

      // Validate password
      const isPasswordValid = await this.userService.validatePassword(password, user.password);
      
      if (isPasswordValid) {
        // Record successful login
        await this.userService.recordLoginAttempt(user.id, true);
        return this.userService.getSafeUserData(user);
      } else {
        // Record failed login attempt
        await this.userService.recordLoginAttempt(user.id, false);
        return null;
      }
    } catch (error) {
      this.logger.error(`Login validation failed for email ${email}:`, error.message);
      throw error;
    }
  }

  async login(user: UserSafeData): Promise<LoginResponse> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email
    };

    const accessToken = this.jwtService.sign(payload);

    return {
      access_token: accessToken,
      user: {
        id: user.id,
        email: user.email,
        isEmailVerified: user.isEmailVerified,
        isMfaEnabled: user.isMfaEnabled,
      },
    };
  }

  async loginWithPassword(email: string, password: string): Promise<LoginResponse | MfaRequiredResponse> {
    const user = await this.validateUser(email, password);
    
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if email is verified
    if (!user.isEmailVerified) {
      throw new UnauthorizedException('Please verify your email before logging in');
    }

    // Check if MFA is enabled
    if (user.isMfaEnabled) {
      return {
        mfaRequired: true,
        message: 'Please provide your MFA code to complete login'
      };
    }

    return this.login(user);
  }

  async register(email: string, password: string): Promise<User> {
    try {
      // Create user (UserService will check for existing email)
      const user = await this.userService.create(email, password);
      
      this.logger.log(`New user registered: ${email}`);
      
      // Send email verification email
      if (user.emailVerificationToken) {
        try {
          await this.emailService.sendVerificationEmail(user.email, user.emailVerificationToken);
          this.logger.log(`Verification email sent to: ${email}`);
        } catch (error) {
          this.logger.error(`Failed to send verification email to ${email}:`, error.message);
          // Don't throw error here as user is already created
        }
      }
      
      return user;
    } catch (error) {
      this.logger.error(`Registration failed for email ${email}:`, error.message);
      throw error;
    }
  }

  async verifyEmail(token: string): Promise<void> {
    try {
      const user = await this.userService.verifyEmail(token);
      this.logger.log(`Email verified successfully for token: ${token.substring(0, 8)}...`);
      
      // Send welcome email after successful verification
      try {
        await this.emailService.sendWelcomeEmail(user.email);
        this.logger.log(`Welcome email sent to: ${user.email}`);
      } catch (error) {
        this.logger.error(`Failed to send welcome email to ${user.email}:`, error.message);
        // Don't throw error here as verification was successful
      }
    } catch (error) {
      this.logger.error(`Email verification failed:`, error.message);
      throw error;
    }
  }

  async forgotPassword(email: string): Promise<void> {
    try {
      const resetToken = await this.userService.generatePasswordResetToken(email);
      
      // Send password reset email
      try {
        await this.emailService.sendPasswordResetEmail(email, resetToken);
        this.logger.log(`Password reset email sent to: ${email}`);
      } catch (error) {
        this.logger.error(`Failed to send password reset email to ${email}:`, error.message);
        // Don't throw error here for security reasons (don't reveal if email exists)
      }
      
      this.logger.log(`Password reset requested for email: ${email}`);
    } catch (error) {
      // Don't reveal if email exists or not for security
      this.logger.warn(`Password reset attempt for email: ${email}`);
    }
  }

  async resendVerificationEmail(email: string): Promise<void> {
    try {
      const user = await this.userService.findByEmail(email);
      
      // Don't reveal if user exists or not for security
      if (!user || user.isEmailVerified) {
        this.logger.warn(`Resend verification attempt for email: ${email}`);
        return;
      }

      // Generate new verification token if needed
      let verificationToken = user.emailVerificationToken;
      if (!verificationToken) {
        verificationToken = await this.userService.generateEmailVerificationToken(user.id);
      }

      // Send verification email
      if (verificationToken) {
        await this.emailService.sendVerificationEmail(user.email, verificationToken);
      }
      this.logger.log(`Verification email resent to: ${email}`);
    } catch (error) {
      // Don't reveal if email exists or not for security
      this.logger.warn(`Resend verification attempt for email: ${email}`);
    }
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    try {
      await this.userService.resetPassword(token, newPassword);
      this.logger.log(`Password reset successfully for token: ${token.substring(0, 8)}...`);
    } catch (error) {
      this.logger.error(`Password reset failed:`, error.message);
      throw error;
    }
  }

  async validateJwtPayload(payload: JwtPayload): Promise<UserSafeData | null> {
    try {
      const user = await this.userService.findById(payload.sub);
      
      if (!user || !user.isActive) {
        return null;
      }

      return this.userService.getSafeUserData(user);
    } catch (error) {
      this.logger.error(`JWT validation failed for user ${payload.sub}:`, error.message);
      return null;
    }
  }
}