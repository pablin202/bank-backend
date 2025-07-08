import { Controller, Get, Post, Body, UnauthorizedException, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MfaService } from './mfa/mfa.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { GetUser } from './get-user.decorator';
import { UserService } from 'src/user/user.service';
import { CreateUserDto } from 'src/account/dto/create-user.dto';
import { ApiBody, ApiTags } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {

  constructor(private readonly authService: AuthService,
    private readonly mfaService: MfaService,
    private readonly userService: UserService) { }

  @Post('login')
  @ApiBody({ type: LoginDto })
  async login(@Body() body: LoginDto) {
    const user = await this.authService.validateUser(body.email, body.password);
    if (!user) {
      throw new UnauthorizedException();
    }
    return this.authService.login(user);
  }

  @UseGuards(JwtAuthGuard)
  @Post('mfa/setup')
  async setupMfa(@GetUser() user) {
    return this.mfaService.generateMfaSecret(user.userId, user.email);
  }

  @Post('mfa/verify')
  async verifyMfa(@Body() body: { email: string; code: string }) {
    const user = await this.userService.findByEmail(body.email);
    if (!user?.mfaSecret) {
      throw new UnauthorizedException('MFA not setup');
    }

    const isValid = this.mfaService.validateMfaCode(user.mfaSecret, body.code);

    if (!isValid) {
      throw new UnauthorizedException('Invalid MFA code');
    }

    // Aquí generas el JWT
    const token = await this.authService.login(user);
    return token;
  }

  @Post('signup')
  @ApiBody({ type: CreateUserDto })
  async signup(@Body() createUserDto: CreateUserDto) {
    const user = await this.authService.register(createUserDto.email, createUserDto.password);
    return { message: 'User created successfully', userId: user.id };
  }
}
