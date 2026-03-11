import { Module } from '@nestjs/common';
import { BrandsController } from './brands.controller';
import { BrandsService } from './brands.service';
import { SupabaseService } from '../supabase.service';
@Module({
controllers: [BrandsController],
providers: [BrandsService, SupabaseService],
exports: [BrandsService],
})
export class BrandsModule {}
