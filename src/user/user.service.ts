import { Injectable, NotFoundException, ConflictException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { UserSafeData } from '../auth/interfaces/auth.interface';

@Injectable()
export class UserService {
  private readonly SALT_ROUNDS = 12;
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCK_TIME = 2 * 60 * 60 * 1000; // 2 hours

  constructor(
    @InjectRepository(User)
    private userRepo: Repository<User>,
  ) { }

  async create(email: string, plainPassword: string): Promise<User> {
    // Check if user already exists
    const existingUser = await this.findByEmail(email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword = await this.hashPassword(plainPassword);
    const emailVerificationToken = this.generateToken();
    
    const user = this.userRepo.create({
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      emailVerificationToken,
      isEmailVerified: false,
    });

    return this.userRepo.save(user);
  }

  async findAll(): Promise<UserSafeData[]> {
    const users = await this.userRepo.find({
      select: ['id', 'email', 'isEmailVerified', 'isMfaEnabled', 'isActive', 'lastLoginAt', 'createdAt']
    });
    return users;
  }

  async findById(id: number): Promise<User | null> {
    return this.userRepo.findOne({ where: { id } });
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { email: email.toLowerCase().trim() } });
  }

  async findByEmailVerificationToken(token: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { emailVerificationToken: token } });
  }

  async findByPasswordResetToken(token: string): Promise<User | null> {
    return this.userRepo.findOne({ 
      where: { 
        passwordResetToken: token,
        passwordResetExpires: new Date() // Token should not be expired
      } 
    });
  }

  async update(userId: number, partialUser: Partial<User>): Promise<User> {
    const user = await this.findById(userId);
    if (!user) {
      throw new NotFoundException(`User with id ${userId} not found`);
    }

    await this.userRepo.update(userId, partialUser);
    const updatedUser = await this.findById(userId);
    if (!updatedUser) {
      throw new NotFoundException(`User with id ${userId} not found after update`);
    }
    return updatedUser;
  }

  async updatePassword(userId: number, newPassword: string): Promise<void> {
    const hashedPassword = await this.hashPassword(newPassword);
    await this.userRepo.update(userId, { 
      password: hashedPassword,
      passwordResetToken: undefined,
      passwordResetExpires: undefined,
    });
  }

  async verifyEmail(token: string): Promise<void> {
    const user = await this.findByEmailVerificationToken(token);
    if (!user) {
      throw new BadRequestException('Invalid or expired verification token');
    }

    await this.userRepo.update(user.id, {
      isEmailVerified: true,
      emailVerificationToken: undefined,
    });
  }

  async generatePasswordResetToken(email: string): Promise<string> {
    const user = await this.findByEmail(email);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const resetToken = this.generateToken();
    const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await this.userRepo.update(user.id, {
      passwordResetToken: resetToken,
      passwordResetExpires: resetExpires,
    });

    return resetToken;
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const user = await this.findByPasswordResetToken(token);
    if (!user) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    await this.updatePassword(user.id, newPassword);
  }

  async recordLoginAttempt(userId: number, successful: boolean): Promise<void> {
    const user = await this.findById(userId);
    if (!user) return;

    if (successful) {
      await this.userRepo.update(userId, {
        lastLoginAt: new Date(),
        loginAttempts: 0,
        lockedUntil: undefined,
      });
    } else {
      const attempts = user.loginAttempts + 1;
      const updateData: Partial<User> = { loginAttempts: attempts };

      if (attempts >= this.MAX_LOGIN_ATTEMPTS) {
        updateData.lockedUntil = new Date(Date.now() + this.LOCK_TIME);
      }

      await this.userRepo.update(userId, updateData);
    }
  }

  async isAccountLocked(userId: number): Promise<boolean> {
    const user = await this.findById(userId);
    return user ? user.isLocked : false;
  }

  async validatePassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(plainPassword, hashedPassword);
  }

  private async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.SALT_ROUNDS);
  }

  private generateToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  async getSafeUserData(user: User): Promise<UserSafeData> {
    return {
      id: user.id,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
      isMfaEnabled: user.isMfaEnabled,
      isActive: user.isActive,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
    };
  }
}
