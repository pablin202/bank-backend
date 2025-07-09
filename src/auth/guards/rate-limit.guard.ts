import { Injectable, CanActivate, ExecutionContext, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan, MoreThan, MoreThanOrEqual } from 'typeorm';
import { RateLimitAttempt } from '../entities/rate-limit-attempt.entity';

interface RateLimitConfig {
  windowMs: number;
  maxAttempts: number;
  blockDurationMs: number;
}

@Injectable()
export class RateLimitGuard implements CanActivate {
  private readonly logger = new Logger(RateLimitGuard.name);
  
  private readonly configs: { [key: string]: RateLimitConfig } = {
    'POST /auth/login': { windowMs: 15 * 60 * 1000, maxAttempts: 5, blockDurationMs: 30 * 60 * 1000 },
    'POST /auth/register': { windowMs: 60 * 60 * 1000, maxAttempts: 3, blockDurationMs: 60 * 60 * 1000 },
    'POST /auth/forgot-password': { windowMs: 60 * 60 * 1000, maxAttempts: 3, blockDurationMs: 60 * 60 * 1000 },
    'POST /auth/mfa/verify': { windowMs: 15 * 60 * 1000, maxAttempts: 10, blockDurationMs: 30 * 60 * 1000 },
    'POST /session': { windowMs: 15 * 60 * 1000, maxAttempts: 5, blockDurationMs: 30 * 60 * 1000 },
    'POST /session/validate': { windowMs: 60 * 1000, maxAttempts: 30, blockDurationMs: 5 * 60 * 1000 },
    'POST /session/refresh': { windowMs: 60 * 1000, maxAttempts: 10, blockDurationMs: 5 * 60 * 1000 },
    'POST /device/register': { windowMs: 60 * 60 * 1000, maxAttempts: 5, blockDurationMs: 60 * 60 * 1000 },
    'POST /device/*/approve': { windowMs: 60 * 60 * 1000, maxAttempts: 10, blockDurationMs: 60 * 60 * 1000 },
    'default': { windowMs: 60 * 1000, maxAttempts: 60, blockDurationMs: 60 * 1000 },
  };

  constructor(
    @InjectRepository(RateLimitAttempt)
    private rateLimitRepository: Repository<RateLimitAttempt>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    
    const key = this.getKey(request);
    const identifier = this.getIdentifier(request);
    const config = this.getConfig(key);
    
    try {
      const now = new Date();
      const windowStart = new Date(now.getTime() - config.windowMs);
      
      // Limpiar intentos antiguos
      await this.rateLimitRepository.delete({
        createdAt: LessThan(windowStart),
      });
      
      // Verificar si está bloqueado
      const blockCheck = await this.rateLimitRepository.findOne({
        where: {
          identifier,
          key,
          isBlocked: true,
          blockedUntil: MoreThan(now),
        },
        order: { createdAt: 'DESC' },
      });
      
      if (blockCheck) {
        const resetTime = blockCheck.blockedUntil;
        const remainingTime = Math.ceil((resetTime.getTime() - now.getTime()) / 1000);
        
        response.setHeader('X-RateLimit-Blocked', 'true');
        response.setHeader('X-RateLimit-Reset', resetTime.toISOString());
        response.setHeader('X-RateLimit-Remaining-Time', remainingTime.toString());
        
        throw new HttpException({
          message: 'Rate limit exceeded. Please try again later.',
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          error: 'Too Many Requests',
          retryAfter: remainingTime,
        }, HttpStatus.TOO_MANY_REQUESTS);
      }
      
      // Contar intentos en la ventana actual
      const attempts = await this.rateLimitRepository.count({
        where: {
          identifier,
          key,
          createdAt: MoreThanOrEqual(windowStart),
        },
      });
      
      const remaining = Math.max(0, config.maxAttempts - attempts);
      const resetTime = new Date(now.getTime() + config.windowMs);
      
      // Agregar headers de rate limit
      response.setHeader('X-RateLimit-Limit', config.maxAttempts.toString());
      response.setHeader('X-RateLimit-Remaining', remaining.toString());
      response.setHeader('X-RateLimit-Reset', resetTime.toISOString());
      response.setHeader('X-RateLimit-Window', config.windowMs.toString());
      
      // Verificar si excede el límite
      if (attempts >= config.maxAttempts) {
        // Crear bloqueo
        const blockedUntil = new Date(now.getTime() + config.blockDurationMs);
        
        await this.rateLimitRepository.save({
          identifier,
          key,
          attempts: attempts + 1,
          isBlocked: true,
          blockedUntil,
          userAgent: request.headers['user-agent'],
          ipAddress: request.ip || request.connection.remoteAddress,
          createdAt: now,
        });
        
        this.logger.warn(`Rate limit exceeded for ${identifier} on ${key}. Blocked until ${blockedUntil}`);
        
        const blockDurationSeconds = Math.ceil(config.blockDurationMs / 1000);
        
        response.setHeader('X-RateLimit-Blocked', 'true');
        response.setHeader('X-RateLimit-Reset', blockedUntil.toISOString());
        response.setHeader('X-RateLimit-Remaining-Time', blockDurationSeconds.toString());
        
        throw new HttpException({
          message: 'Rate limit exceeded. Please try again later.',
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          error: 'Too Many Requests',
          retryAfter: blockDurationSeconds,
        }, HttpStatus.TOO_MANY_REQUESTS);
      }
      
      // Registrar intento
      await this.rateLimitRepository.save({
        identifier,
        key,
        attempts: 1,
        isBlocked: false,
        userAgent: request.headers['user-agent'],
        ipAddress: request.ip || request.connection.remoteAddress,
        createdAt: now,
      });
      
      return true;
      
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      
      this.logger.error('Rate limit check failed:', error);
      // En caso de error, permitir la request pero loggear
      return true;
    }
  }
  
  private getKey(request: any): string {
    const method = request.method;
    const path = request.route?.path || request.url;
    const key = `${method} ${path}`;
    
    // Normalizar paths con parámetros
    const normalizedKey = key.replace(/\/:[^\/]+/g, '/*');
    
    return normalizedKey;
  }
  
  private getIdentifier(request: any): string {
    // Usar IP + User Agent como identificador único
    const ip = request.ip || request.connection.remoteAddress;
    const userAgent = request.headers['user-agent'] || '';
    const deviceFingerprint = request.headers['x-device-fingerprint'] || '';
    
    // Si hay usuario autenticado, usar su ID
    if (request.user?.id) {
      return `user:${request.user.id}`;
    }
    
    // Si hay device fingerprint, usarlo
    if (deviceFingerprint) {
      return `device:${deviceFingerprint}`;
    }
    
    // Fallback a IP + User Agent
    return `ip:${ip}:ua:${userAgent.substring(0, 50)}`;
  }
  
  private getConfig(key: string): RateLimitConfig {
    return this.configs[key] || this.configs['default'];
  }
}