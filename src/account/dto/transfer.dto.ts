import { IsNumber, IsPositive, IsString } from 'class-validator';

export class TransferDto {
  @IsString()
  toAccount: string;

  @IsNumber()
  @IsPositive()
  amount: number;
}