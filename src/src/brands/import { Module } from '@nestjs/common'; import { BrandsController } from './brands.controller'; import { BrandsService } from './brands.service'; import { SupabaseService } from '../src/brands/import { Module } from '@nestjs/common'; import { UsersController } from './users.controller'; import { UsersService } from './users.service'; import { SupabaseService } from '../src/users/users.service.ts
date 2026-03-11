import { Injectable } from '@nestjs/common';
import { SupabaseService } from '../supabase.service';
@Injectable()
export class UsersService {
constructor(private supabase: SupabaseService) {}
async getUserByWallet(walletAddress: string) {
const { data, error } = await this.supabase.getClient()
.from('users')
.select('*')
.eq('wallet_address', walletAddress)
.single();
if (error) return null;
return data;
}
async createUser(walletAddress: string, email?: string) {
const { data, error } = await this.supabase.getClient()
.from('users')
.insert({ wallet_address: walletAddress, email })
.select()
.single();
if (error) throw error;
return data;
}
async getOrCreateUser(walletAddress: string) {
const existing = await this.getUserByWallet(walletAddress);
if (existing) return existing;
return this.createUser(walletAddress);
}
async updateKycStatus(id: string, status: string, providerId?: string) {
const { data, error } = await this.supabase.getClient()
.from('users')
.update({ kyc_status: status, kyc_provider_id: providerId })
.eq('id', id)
.select()
.single();
if (error) throw error;
return data;
}
async getUserById(id: string) {
const { data, error } = await this.supabase.getClient()
.from('users')
.select('*')
.eq('id', id)
.single();
if (error) throw error;
return data;
}
async updateTotalInvested(id: string, amount: number) {
const { data, error } = await this.supabase.getClient()
.from('users')
.update({ total_invested: amount })
.eq('id', id)
.select()
.single();
if (error) throw error;
return data;
}
}
