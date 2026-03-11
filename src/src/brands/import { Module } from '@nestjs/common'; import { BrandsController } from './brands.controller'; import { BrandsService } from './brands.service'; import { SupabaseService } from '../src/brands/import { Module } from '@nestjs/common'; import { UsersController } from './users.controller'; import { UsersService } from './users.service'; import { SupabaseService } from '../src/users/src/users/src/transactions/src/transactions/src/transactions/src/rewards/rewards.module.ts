import { Module } from '@nestjs/common';
import { RewardsController } from './rewards.controller';
import { RewardsService } from './rewards.service';
import { SupabaseService } from '../supabase.service';
@Module({
controllers: [RewardsController],
providers: [RewardsService, SupabaseService],
exports: [RewardsService],
})
export class RewardsModule {}
