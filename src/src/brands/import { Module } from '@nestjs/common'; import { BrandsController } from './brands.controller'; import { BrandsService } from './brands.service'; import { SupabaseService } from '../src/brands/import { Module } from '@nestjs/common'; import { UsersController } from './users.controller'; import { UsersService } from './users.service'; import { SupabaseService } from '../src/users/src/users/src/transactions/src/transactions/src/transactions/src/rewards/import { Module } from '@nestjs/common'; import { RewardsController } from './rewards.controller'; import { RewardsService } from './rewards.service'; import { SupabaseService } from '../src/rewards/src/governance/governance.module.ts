import { Module } from '@nestjs/common';
import { GovernanceController } from './governance.controller';
import { GovernanceService } from './governance.service';
import { SupabaseService } from '../supabase.service';
@Module({
controllers: [GovernanceController],
providers: [GovernanceService, SupabaseService],
exports: [GovernanceService],
})
export class GovernanceModule {}
