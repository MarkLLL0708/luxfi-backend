import { Module } from '@nestjs/common';
import { MarketplaceController } from './marketplace.controller';
import { MarketplaceService } from './marketplace.service';
import { SupabaseService } from '../supabase.service';
@Module({
controllers: [MarketplaceController],
providers: [MarketplaceService, SupabaseService],
exports: [MarketplaceService],
})
export class MarketplaceModule {}
