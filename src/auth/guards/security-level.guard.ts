import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, SetMetadata } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SessionService } from '../../session/session.service';
import { CRITICAL_OPERATIONS, HIGH_SECURITY_OPERATIONS } from '../../session/entities/session-config.entity';

export const SECURITY_LEVEL_KEY = 'securityLevel';
export const SecurityLevel = (level: 'NORMAL' | 'HIGH' | 'CRITICAL') => 
  SetMetadata(SECURITY_LEVEL_KEY, level);

export const OPERATION_KEY = 'operation';
export const Operation = (operation: string) => 
  SetMetadata(OPERATION_KEY, operation);

@Injectable()
export class SecurityLevelGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private sessionService: SessionService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new UnauthorizedException('User not authenticated');
    }

    // Obtener el nivel de seguridad requerido desde el metadata
    const requiredLevel = this.reflector.getAllAndOverride<string>(SECURITY_LEVEL_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Obtener la operación desde el metadata
    const operation = this.reflector.getAllAndOverride<string>(OPERATION_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    // Determinar nivel de seguridad requerido basado en la operación
    let finalRequiredLevel = requiredLevel;
    
    if (operation) {
      if (CRITICAL_OPERATIONS.includes(operation)) {
        finalRequiredLevel = 'CRITICAL';
      } else if (HIGH_SECURITY_OPERATIONS.includes(operation)) {
        finalRequiredLevel = 'HIGH';
      }
    }

    // Si no se especifica nivel, permitir acceso
    if (!finalRequiredLevel) {
      return true;
    }

    // Verificar nivel de seguridad actual de la sesión
    const currentLevel = user.session?.securityLevel || 'NORMAL';
    
    if (!this.hasRequiredSecurityLevel(currentLevel, finalRequiredLevel)) {
      // Intentar elevar el nivel de seguridad automáticamente
      await this.sessionService.updateSecurityLevel(user.sessionId, finalRequiredLevel as 'NORMAL' | 'HIGH' | 'CRITICAL');
      
      // Si requiere re-autenticación, rechazar
      if (finalRequiredLevel === 'CRITICAL' || finalRequiredLevel === 'HIGH') {
        throw new UnauthorizedException({
          message: 'Higher security level required',
          requiredLevel: finalRequiredLevel,
          currentLevel,
          requiresReauth: true,
        });
      }
    }

    return true;
  }

  private hasRequiredSecurityLevel(current: string, required: string): boolean {
    const levels = { 'NORMAL': 0, 'HIGH': 1, 'CRITICAL': 2 };
    return levels[current] >= levels[required];
  }
}