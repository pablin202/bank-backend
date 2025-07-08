import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { GetUser } from 'src/auth/get-user.decorator';

@Controller('account')
export class AccountController {
  @UseGuards(JwtAuthGuard)
  @Get('balance')
  getBalance(@GetUser() user) {
    console.log(user); // payload de validate() en JwtStrategy
    return {
      balance: 1234.56, // Mock data
      userId: user.userId,
      email: user.email,
    };
  }
}