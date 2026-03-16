import { Controller, Get, Post, Put, Body, Param } from '@nestjs/common';
import { TransactionsService } from './transactions.service';

@Controller('transactions')
export class TransactionsController {
  constructor(private readonly transactionsService: TransactionsService) {}

  @Get('user/:userId')
  getUserTransactions(@Param('userId') userId: string) {
    return this.transactionsService.getUserTransactions(userId);
  }

  @Get('brand/:brandId')
  getBrandTransactions(@Param('brandId') brandId: string) {
    return this.transactionsService.getBrandTransactions(brandId);
  }

  @Get('hash/:txHash')
  getTransactionByHash(@Param('txHash') txHash: string) {
    return this.transactionsService.getTransactionByHash(txHash);
  }

  @Post()
  createTransaction(@Body() body: any) {
    return this.transactionsService.createTransaction(body);
  }

  @Put(':id/status')
  updateStatus(
    @Param('id') id: string,
    @Body() body: { status: string; txHash?: string }
  ) {
    return this.transactionsService.updateTransactionStatus(
      id, body.status, body.txHash
    );
  }
}
