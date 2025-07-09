import {
  Controller,
  Post,
  Get,
  Put,
  Delete,
  Body,
  Param,
  Query,
  UseGuards,
  Request,
  HttpStatus,
  HttpCode,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { SessionService } from './session.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { SessionGuard } from '../auth/guards/session.guard';
import { RateLimitGuard } from '../auth/guards/rate-limit.guard';
import {
  CreateSessionDto,
  ValidateSessionDto,
  RefreshTokenDto,
  UpdateSessionSecurityDto,
  SessionResponseDto,
  SessionValidationResponseDto,
  ActiveSessionDto,
} from './dto/session.dto';

@ApiTags('Session Management')
@Controller('session')
export class SessionController {
  constructor(private readonly sessionService: SessionService) {}

  @Post()
  @UseGuards(RateLimitGuard)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Create new session' })
  @ApiResponse({ 
    status: 201, 
    description: 'Session created successfully',
    type: SessionResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 401, description: 'Device not approved' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  async createSession(
    @Body() createSessionDto: CreateSessionDto,
    @Request() req
  ): Promise<SessionResponseDto> {
    const userId = req.user?.id || req.userId;
    return await this.sessionService.createSession(userId, createSessionDto);
  }

  @Post('validate')
  @UseGuards(RateLimitGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Validate session' })
  @ApiResponse({ 
    status: 200, 
    description: 'Session validation result',
    type: SessionValidationResponseDto 
  })
  @ApiResponse({ status: 400, description: 'Invalid session data' })
  @ApiResponse({ status: 401, description: 'Session invalid or expired' })
  async validateSession(
    @Body() validateSessionDto: ValidateSessionDto
  ): Promise<SessionValidationResponseDto> {
    return await this.sessionService.validateSession(validateSessionDto);
  }

  @Post('refresh')
  @UseGuards(RateLimitGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ 
    status: 200, 
    description: 'Token refreshed successfully',
    type: SessionResponseDto 
  })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  async refreshToken(
    @Body() refreshTokenDto: RefreshTokenDto
  ): Promise<SessionResponseDto> {
    return await this.sessionService.refreshToken(refreshTokenDto);
  }

  @Get('active')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get all active sessions for current user' })
  @ApiResponse({ 
    status: 200, 
    description: 'List of active sessions',
    type: [ActiveSessionDto] 
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getActiveSessions(@Request() req): Promise<ActiveSessionDto[]> {
    const userId = req.user.id;
    const currentSessionId = req.user.sessionId;
    
    const sessions = await this.sessionService.getActiveSessions(userId);
    
    // Marcar la sesión actual
    return sessions.map(session => ({
      ...session,
      isCurrent: session.id === currentSessionId,
    }));
  }

  @Put(':sessionId/security')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update session security level' })
  @ApiResponse({ status: 200, description: 'Security level updated successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Session not found' })
  async updateSecurityLevel(
    @Param('sessionId') sessionId: string,
    @Body() updateSecurityDto: UpdateSessionSecurityDto,
    @Request() req
  ): Promise<{ message: string }> {
    // Verificar que la sesión pertenece al usuario
    if (req.user.sessionId !== sessionId) {
      const userSessions = await this.sessionService.getActiveSessions(req.user.id);
      const sessionExists = userSessions.some(s => s.id === sessionId);
      
      if (!sessionExists) {
        throw new Error('Session not found or access denied');
      }
    }

    await this.sessionService.updateSecurityLevel(sessionId, updateSecurityDto.securityLevel);
    
    return { message: 'Security level updated successfully' };
  }

  @Delete(':sessionId')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Terminate specific session' })
  @ApiResponse({ status: 204, description: 'Session terminated successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Session not found' })
  async terminateSession(
    @Param('sessionId') sessionId: string,
    @Request() req
  ): Promise<void> {
    // Verificar que la sesión pertenece al usuario
    const userSessions = await this.sessionService.getActiveSessions(req.user.id);
    const sessionExists = userSessions.some(s => s.id === sessionId);
    
    if (!sessionExists) {
      throw new Error('Session not found or access denied');
    }

    await this.sessionService.terminateSession(sessionId, 'USER_REQUESTED');
  }

  @Delete('all')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Terminate all sessions except current' })
  @ApiResponse({ status: 204, description: 'All sessions terminated successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async terminateAllSessions(@Request() req): Promise<void> {
    const userId = req.user.id;
    const currentSessionId = req.user.sessionId;
    
    await this.sessionService.terminateAllUserSessions(userId, currentSessionId);
  }

  @Delete()
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Logout - terminate current session' })
  @ApiResponse({ status: 204, description: 'Logged out successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async logout(@Request() req): Promise<void> {
    const sessionId = req.user.sessionId;
    await this.sessionService.terminateSession(sessionId, 'USER_LOGOUT');
  }

  @Get(':sessionId/status')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get session status and timing information' })
  @ApiResponse({ 
    status: 200, 
    description: 'Session status information',
    type: SessionValidationResponseDto 
  })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Session not found' })
  async getSessionStatus(
    @Param('sessionId') sessionId: string,
    @Request() req
  ): Promise<SessionValidationResponseDto> {
    // Verificar que la sesión pertenece al usuario
    if (req.user.sessionId !== sessionId) {
      const userSessions = await this.sessionService.getActiveSessions(req.user.id);
      const sessionExists = userSessions.some(s => s.id === sessionId);
      
      if (!sessionExists) {
        throw new Error('Session not found or access denied');
      }
    }

    const deviceFingerprint = req.headers['x-device-fingerprint'] as string;
    const ipAddress = req.ip || req.connection.remoteAddress;

    return await this.sessionService.validateSession({
      sessionId,
      deviceFingerprint,
      ipAddress,
    });
  }

  @Post(':sessionId/extend')
  @UseGuards(JwtAuthGuard, SessionGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Extend session timeout' })
  @ApiResponse({ status: 200, description: 'Session extended successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Session not found' })
  async extendSession(
    @Param('sessionId') sessionId: string,
    @Request() req
  ): Promise<{ message: string; newExpiryTime: Date }> {
    // Verificar que la sesión pertenece al usuario
    if (req.user.sessionId !== sessionId) {
      throw new Error('Can only extend your own session');
    }

    const deviceFingerprint = req.headers['x-device-fingerprint'] as string;
    const ipAddress = req.ip || req.connection.remoteAddress;

    // Validar sesión para actualizar actividad
    const validation = await this.sessionService.validateSession({
      sessionId,
      deviceFingerprint,
      ipAddress,
    });

    if (!validation.isValid) {
      throw new Error('Cannot extend invalid session');
    }

    // El acto de validar ya actualiza la actividad
    return { 
      message: 'Session extended successfully',
      newExpiryTime: new Date(Date.now() + (validation.timeUntilExpiry || 0))
    };
  }
}