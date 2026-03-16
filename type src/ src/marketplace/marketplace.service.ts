import { Injectable, NotFoundException } from '@nestjs/common';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

@Injectable()
export class MarketplaceService {

  async getListings(filters?: {
    brand_id?: string;
    status?: string;
    min_price?: number;
    max_price?: number;
  }) {
    let query = supabase
      .from('marketplace_listings')
      .select('*, brands(name, category, city, country)')
      .order('created_at', { ascending: false });

    if (filters?.brand_id) query = query.eq('brand_id', filters.brand_id);
    if (filters?.status) query = query.eq('status', filters.status);
    else query = query.eq('status', 'active');
    if (filters?.min_price) query = query.gte('price', filters.min_price);
    if (filters?.max_price) query = query.lte('price', filters.max_price);

    const { data, error } = await query;
    if (error) throw error;
    return data;
  }

  async getListingById(id: string) {
    const { data, error } = await supabase
      .from('marketplace_listings')
      .select('*, brands(name, category, city, country)')
      .eq('id', id)
      .single();

    if (error) throw new NotFoundException('Listing not found');
    return data;
  }

  async createListing(payload: {
    brand_id: string;
    seller_wallet: string;
    price_bnb: number;
    amount: number;
    description?: string;
  }) {
    const { data, error } = await supabase
      .from('marketplace_listings')
      .insert({
        ...payload,
        status: 'active'
      })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async purchaseListing(id: string, payload: {
    buyer_wallet: string;
    tx_hash: string;
  }) {
    const listing = await this.getListingById(id);
    if (listing.status !== 'active') {
      throw new Error('Listing is no longer available');
    }

    const { data, error } = await supabase
      .from('marketplace_listings')
      .update({
        status: 'sold',
        buyer_wallet: payload.buyer_wallet,
        tx_hash: payload.tx_hash,
        sold_at: new Date().toISOString()
      })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async cancelListing(id: string, sellerWallet: string) {
    const { data, error } = await supabase
      .from('marketplace_listings')
      .update({ status: 'cancelled' })
      .eq('id', id)
      .eq('seller_wallet', sellerWallet)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async getSellerListings(sellerWallet: string) {
    const { data, error } = await supabase
      .from('marketplace_listings')
      .select('*, brands(name, category)')
      .eq('seller_wallet', sellerWallet)
      .order('created_at', { ascending: false });

    if (error) throw error;
    return data;
  }
}
