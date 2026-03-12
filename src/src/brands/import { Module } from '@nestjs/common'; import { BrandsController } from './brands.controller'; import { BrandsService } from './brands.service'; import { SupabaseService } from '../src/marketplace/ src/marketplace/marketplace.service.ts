import { Injectable } from '@nestjs/common';
import { SupabaseService } from '../supabase.service';
@Injectable()
export class MarketplaceService {
constructor(private supabase: SupabaseService) {}
async createListing(dto: any) {
const { data, error } = await this.supabase.getClient()
.from('marketplace_listings')
.insert(dto)
.select()
.single();
if (error) throw error;
return data;
}
async getActiveListings() {
const { data, error } = await this.supabase.getClient()
.from('marketplace_listings')
.select('*, brands(name, category), users(wallet_address)')
.eq('active', true)
.order('listed_at', { ascending: false });
if (error) throw error;
return data;
}
async getListingById(id: string) {
const { data, error } = await this.supabase.getClient()
.from('marketplace_listings')
.select('*, brands(name, category), users(wallet_address)')
.eq('id', id)
.single();
if (error) throw error;
return data;
}
async getBrandListings(brandId: string) {
const { data, error } = await this.supabase.getClient()
.from('marketplace_listings')
.select('*, users(wallet_address)')
.eq('brand_id', brandId)
.eq('active', true)
.order('listed_at', { ascending: false });
if (error) throw error;
return data;
}
async getUserListings(userId: string) {
const { data, error } = await this.supabase.getClient()
.from('marketplace_listings')
.select('*, brands(name, category)')
.eq('seller_id', userId)
.order('listed_at', { ascending: false });
if (error) throw error;
return data;
}
async cancelListing(id: string, userId: string) {
const { data, error } = await this.supabase.getClient()
.from('marketplace_listings')
.update({ active: false })
.eq('id', id)
.eq('seller_id', userId)
.select()
.single();
if (error) throw error;
return data;
}
async purchaseListing(id: string, buyerAmount: number) {
const listing = await this.getListingById(id);
if (!listing.active) throw new Error('Listing not active');
const newAmount = listing.token_amount - buyerAmount;
const { data, error } = await this.supabase.getClient()
.from('marketplace_listings')
.update({
token_amount: newAmount,
active: newAmount > 0
})
.eq('id', id)
.select()
.single();
if (error) throw error;
return data;
}
}
