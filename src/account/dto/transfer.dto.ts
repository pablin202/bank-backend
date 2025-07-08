import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsPositive, IsNumber } from 'class-validator';

export class TransferDto {
  @ApiProperty({ example: '1234567890', description: 'Destination account number' })
  @IsString()
  toAccount: string;

  @ApiProperty({ example: 100, description: 'Amount to transfer' })
  @IsNumber()
  @IsPositive()
  amount: number;
}