import { Controller, Get, Post, Body, UseGuards } from '@nestjs/common';
import { AccountService } from './account.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { GetUser } from '../auth/get-user.decorator';
import { TransferDto } from './dto/transfer.dto';

@UseGuards(JwtAuthGuard)
@Controller('account')
export class AccountController {
  constructor(private readonly accountService: AccountService) {}

  @Get('balance')
  getBalance(@GetUser() user) {
    return this.accountService.getBalance(user.userId);
  }

  @Get('transactions')
  getTransactions(@GetUser() user) {
    return this.accountService.getTransactions(user.userId);
  }

  @Post('transfer')
  transfer(@GetUser() user, @Body() dto: TransferDto) {
    return this.accountService.transfer(user.userId, dto.toAccount, dto.amount);
  }
}