import { Module } from '@nestjs/common';
import { TransactionsController } from './transactions.controller';
import { TransactionsService } from './transactions.service';
import { SupabaseService } from '../supabase.service';
@Module({
controllers: [TransactionsController],
providers: [TransactionsService, SupabaseService],
exports: [TransactionsService],
})
export class TransactionsModule {}
