import { Injectable } from '@nestjs/common';

@Injectable()
export class AccountService {
  async getBalance(userId: number) {
    // 🔷 Aquí podrías consultar DB, de momento mock
    return { balance: 1234.56, currency: 'USD', userId };
  }

  async getTransactions(userId: number) {
    // 🔷 Mock data
    return [
      { id: 1, date: '2025-07-08', type: 'credit', amount: 500, description: 'Salary' },
      { id: 2, date: '2025-07-07', type: 'debit', amount: 100, description: 'Grocery' },
    ];
  }

  async transfer(userId: number, toAccount: string, amount: number) {
    // 🔷 Aquí validas saldo suficiente, etc. (mock)
    return {
      status: 'success',
      fromUser: userId,
      toAccount,
      amount,
      timestamp: new Date(),
    };
  }
}