import { Controller, Get, Post, Param, Body } from '@nestjs/common';
import { TransactionsService } from './transactions.service';
@Controller('transactions')
export class TransactionsController {
constructor(private readonly transactionsService: TransactionsService) {}
@Get()
getAllTransactions() {
return this.transactionsService.getAllTransactions();
}
@Get('today')
getTodayTransactions() {
return this.transactionsService.getTodayTransactions();
}
@Get('brand/:brandId')
getBrandTransactions(@Param('brandId') brandId: string) {
return this.transactionsService.getBrandTransactions(brandId);
}
@Get('brand/:brandId/total')
getBrandRevenueTotal(@Param('brandId') brandId: string) {
return this.transactionsService.getBrandRevenueTotal(brandId);
}
@Post()
recordTransaction(@Body() dto: any) {
return this.transactionsService.recordTransaction(dto);
}
}
