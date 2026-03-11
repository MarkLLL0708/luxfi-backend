import { Injectable } from '@nestjs/common';
import { SupabaseService } from '../supabase.service';
@Injectable()
export class TransactionsService {
constructor(private supabase: SupabaseService) {}
async recordTransaction(dto: any) {
const { data, error } = await this.supabase.getClient()
.from('transactions')
.insert(dto)
.select()
.single();
if (error) throw error;
return data;
}
async getBrandTransactions(brandId: string) {
const { data, error } = await this.supabase.getClient()
.from('transactions')
.select('*')
.eq('brand_id', brandId)
.order('recorded_at', { ascending: false });
if (error) throw error;
return data;
}
async getBrandRevenueTotal(brandId: string) {
const { data, error } = await this.supabase.getClient()
.from('transactions')
.select('amount')
.eq('brand_id', brandId);
if (error) throw error;
const total = data.reduce((sum: number, t: any) => sum + Number(t.amount), 0);
return { brandId, total };
}
async getAllTransactions() {
const { data, error } = await this.supabase.getClient()
.from('transactions')
.select('*, brands(name)')
.order('recorded_at', { ascending: false })
.limit(100);
if (error) throw error;
return data;
}
async getTodayTransactions() {
const today = new Date();
today.setHours(0, 0, 0, 0);
const { data, error } = await this.supabase.getClient()
.from('transactions')
.select('*')
.gte('recorded_at', today.toISOString());
if (error) throw error;
return data;
}
}
