import { Injectable } from '@nestjs/common';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

@Injectable()
export class TransactionsService {

  async getUserTransactions(userId: string) {
    const { data, error } = await supabase
      .from('transactions')
      .select('*, brands(name, category)')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;
    return data;
  }

  async createTransaction(payload: {
    user_id: string;
    brand_id: string;
    type: string;
    amount: number;
    tx_hash?: string;
    status?: string;
  }) {
    const { data, error } = await supabase
      .from('transactions')
      .insert({
        ...payload,
        status: payload.status || 'pending'
      })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async updateTransactionStatus(id: string, status: string, txHash?: string) {
    const { data, error } = await supabase
      .from('transactions')
      .update({ status, tx_hash: txHash })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async getTransactionByHash(txHash: string) {
    const { data, error } = await supabase
      .from('transactions')
      .select('*')
      .eq('tx_hash', txHash)
      .single();

    if (error) throw error;
    return data;
  }

  async getBrandTransactions(brandId: string) {
    const { data, error } = await supabase
      .from('transactions')
      .select('*, users(wallet_address)')
      .eq('brand_id', brandId)
      .order('created_at', { ascending: false });

    if (error) throw error;
    return data;
  }
}
