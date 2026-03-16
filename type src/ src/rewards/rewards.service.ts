import { Injectable } from '@nestjs/common';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

@Injectable()
export class RewardsService {

  async getUserRewards(userId: string) {
    const { data, error } = await supabase
      .from('reward_claims')
      .select('*, reward_pools(brand_id, amount, period)')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;
    return data;
  }

  async getRewardPools(brandId?: string) {
    let query = supabase
      .from('reward_pools')
      .select('*, brands(name, category)')
      .order('created_at', { ascending: false });

    if (brandId) query = query.eq('brand_id', brandId);

    const { data, error } = await query;
    if (error) throw error;
    return data;
  }

  async createRewardPool(payload: {
    brand_id: string;
    amount: number;
    period: string;
    status?: string;
  }) {
    const { data, error } = await supabase
      .from('reward_pools')
      .insert({
        ...payload,
        status: payload.status || 'active'
      })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async claimReward(payload: {
    user_id: string;
    reward_pool_id: string;
    amount: number;
    tx_hash?: string;
  }) {
    const { data, error } = await supabase
      .from('reward_claims')
      .insert({
        ...payload,
        status: 'pending'
      })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async updateRewardStatus(id: string, status: string, txHash?: string) {
    const { data, error } = await supabase
      .from('reward_claims')
      .update({ status, tx_hash: txHash })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async getTotalRewardsEarned(userId: string) {
    const { data, error } = await supabase
      .from('reward_claims')
      .select('amount')
      .eq('user_id', userId)
      .eq('status', 'approved');

    if (error) throw error;
    const total = data?.reduce((sum, r) => sum + r.amount, 0) || 0;
    return { total };
  }
}
