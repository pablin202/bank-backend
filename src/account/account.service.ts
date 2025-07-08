import { Injectable } from '@nestjs/common';

@Injectable()
export class AccountService {
  async getBalance(userId: number) {
    // TODO: Query the DB for the actual balance of this user.
    return {
      userId,
      balance: 1234.56,
      currency: 'USD',
      updatedAt: new Date().toISOString(),
    };
  }

  async getTransactions(userId: number) {
    // TODO: Fetch from DB. Mock data below.
    return [
      {
        id: 1,
        date: '2025-07-08T10:30:00.000Z',
        type: 'credit',
        amount: 1500,
        description: 'Salary deposit',
      },
      {
        id: 2,
        date: '2025-07-07T14:45:00.000Z',
        type: 'debit',
        amount: 120,
        description: 'Grocery store',
      },
      {
        id: 3,
        date: '2025-07-06T09:15:00.000Z',
        type: 'debit',
        amount: 60,
        description: 'Coffee shop',
      },
    ];
  }

  async transfer(userId: number, toAccount: string, amount: number) {
    // TODO: Validate balance >= amount, deduct from user, add to recipient, save in DB.
    return {
      status: 'success',
      fromUser: userId,
      toAccount,
      amount,
      currency: 'USD',
      timestamp: new Date().toISOString(),
      message: `Transferred ${amount} USD to account ${toAccount}`,
    };
  }
}