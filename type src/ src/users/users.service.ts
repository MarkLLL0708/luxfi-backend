import { Injectable, NotFoundException } from '@nestjs/common';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

@Injectable()
export class UsersService {

  async getUserByWallet(walletAddress: string) {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('wallet_address', walletAddress)
      .single();

    if (error) throw new NotFoundException('User not found');
    return data;
  }

  async getUserById(id: string) {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', id)
      .single();

    if (error) throw new NotFoundException('User not found');
    return data;
  }

  async createUser(payload: {
    wallet_address: string;
    email?: string;
    username?: string;
    country?: string;
  }) {
    const { data, error } = await supabase
      .from('users')
      .insert(payload)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async updateUser(id: string, payload: any) {
    const { data, error } = await supabase
      .from('users')
      .update(payload)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async getOrCreateUser(walletAddress: string) {
    const { data: existing } = await supabase
      .from('users')
      .select('*')
      .eq('wallet_address', walletAddress)
      .single();

    if (existing) return existing;

    const { data, error } = await supabase
      .from('users')
      .insert({ wallet_address: walletAddress })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async getUserParticipations(userId: string) {
    const { data, error } = await supabase
      .from('participations')
      .select('*, brands(name, category, city)')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;
    return data;
  }

  async updateKycStatus(id: string, status: string) {
    const { data, error } = await supabase
      .from('users')
      .update({ kyc_status: status })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    return data;
  }
}
