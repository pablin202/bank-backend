import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import * as handlebars from 'handlebars';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;

  constructor(private configService: ConfigService) {
    this.createTransporter();
  }

  private createTransporter() {
    const emailConfig = {
      host: this.configService.get<string>('EMAIL_HOST', 'smtp.gmail.com'),
      port: this.configService.get<number>('EMAIL_PORT', 587),
      secure: this.configService.get<boolean>('EMAIL_SECURE', false),
      auth: {
        user: this.configService.get<string>('EMAIL_USER'),
        pass: this.configService.get<string>('EMAIL_PASSWORD'),
      },
    };

    this.transporter = nodemailer.createTransport(emailConfig);

    // Verify connection configuration
    this.transporter.verify((error, success) => {
      if (error) {
        this.logger.error('Email configuration error:', error);
      } else {
        this.logger.log('Email service is ready to send messages');
      }
    });
  }

  async sendVerificationEmail(email: string, token: string): Promise<void> {
    try {
      const verificationUrl = `${this.configService.get<string>('FRONTEND_URL', 'http://localhost:3000')}/verify-email?token=${token}`;
      
      const template = this.getEmailTemplate('verification');
      const html = template({
        verificationUrl,
        appName: this.configService.get<string>('APP_NAME', 'Bank App'),
      });

      const mailOptions = {
        from: `"${this.configService.get<string>('APP_NAME', 'Bank App')}" <${this.configService.get<string>('EMAIL_FROM') || this.configService.get<string>('EMAIL_USER')}>`,
        to: email,
        subject: 'Verify your email address',
        html,
      };

      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Verification email sent to: ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send verification email to ${email}:`, error);
      throw new Error('Failed to send verification email');
    }
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    try {
      const resetUrl = `${this.configService.get<string>('FRONTEND_URL', 'http://localhost:3000')}/reset-password?token=${token}`;
      
      const template = this.getEmailTemplate('password-reset');
      const html = template({
        resetUrl,
        appName: this.configService.get<string>('APP_NAME', 'Bank App'),
      });

      const mailOptions = {
        from: `"${this.configService.get<string>('APP_NAME', 'Bank App')}" <${this.configService.get<string>('EMAIL_FROM') || this.configService.get<string>('EMAIL_USER')}>`,
        to: email,
        subject: 'Reset your password',
        html,
      };

      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Password reset email sent to: ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send password reset email to ${email}:`, error);
      throw new Error('Failed to send password reset email');
    }
  }

  async sendWelcomeEmail(email: string, name?: string): Promise<void> {
    try {
      const template = this.getEmailTemplate('welcome');
      const html = template({
        name: name || 'User',
        appName: this.configService.get<string>('APP_NAME', 'Bank App'),
        loginUrl: `${this.configService.get<string>('FRONTEND_URL', 'http://localhost:3000')}/login`,
      });

      const mailOptions = {
        from: `"${this.configService.get<string>('APP_NAME', 'Bank App')}" <${this.configService.get<string>('EMAIL_FROM') || this.configService.get<string>('EMAIL_USER')}>`,
        to: email,
        subject: 'Welcome to Bank App!',
        html,
      };

      await this.transporter.sendMail(mailOptions);
      this.logger.log(`Welcome email sent to: ${email}`);
    } catch (error) {
      this.logger.error(`Failed to send welcome email to ${email}:`, error);
      // Don't throw error for welcome email as it's not critical
    }
  }

  private getEmailTemplate(templateName: string): handlebars.TemplateDelegate {
    try {
      const templatePath = path.join(__dirname, '..', 'templates', 'emails', `${templateName}.hbs`);
      const templateSource = fs.readFileSync(templatePath, 'utf8');
      return handlebars.compile(templateSource);
    } catch (error) {
      this.logger.warn(`Template ${templateName} not found, using fallback`);
      return this.getFallbackTemplate(templateName);
    }
  }

  private getFallbackTemplate(templateName: string): handlebars.TemplateDelegate {
    let template = '';
    
    switch (templateName) {
      case 'verification':
        template = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Verify your email address</h2>
            <p>Thank you for registering with {{appName}}!</p>
            <p>Please click the button below to verify your email address:</p>
            <a href="{{verificationUrl}}" style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify Email</a>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p>{{verificationUrl}}</p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't create an account, please ignore this email.</p>
          </div>
        `;
        break;
      case 'password-reset':
        template = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Reset your password</h2>
            <p>You requested to reset your password for {{appName}}.</p>
            <p>Please click the button below to reset your password:</p>
            <a href="{{resetUrl}}" style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p>{{resetUrl}}</p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, please ignore this email.</p>
          </div>
        `;
        break;
      case 'welcome':
        template = `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Welcome to {{appName}}!</h2>
            <p>Hi {{name}},</p>
            <p>Welcome to {{appName}}! Your account has been successfully verified.</p>
            <p>You can now log in and start using our services:</p>
            <a href="{{loginUrl}}" style="background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Login Now</a>
            <p>Thank you for choosing {{appName}}!</p>
          </div>
        `;
        break;
      default:
        template = '<p>{{message}}</p>';
    }
    
    return handlebars.compile(template);
  }
}