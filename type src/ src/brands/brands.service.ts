import { Injectable, NotFoundException } from '@nestjs/common';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

@Injectable()
export class BrandsService {

  async getAllBrands(filters?: {
    category?: string;
    country?: string;
    city?: string;
    status?: string;
  }) {
    let query = supabase
      .from('brands')
      .select('*')
      .order('created_at', { ascending: false });

    if (filters?.category) query = query.eq('category', filters.category);
    if (filters?.country) query = query.eq('country', filters.country);
    if (filters?.city) query = query.eq('city', filters.city);
    if (filters?.status) query = query.eq('status', filters.status);
    else query = query.eq('status', 'active');

    const { data, error } = await query;
    if (error) throw error;
    return data;
  }

  async getBrandById(id: string) {
    const { data, error } = await supabase
      .from('brands')
      .select('*')
      .eq('id', id)
      .single();

    if (error) throw new NotFoundException('Brand not found');
    return data;
  }

  async createBrand(payload: {
    name: string;
    description: string;
    category: string;
    country: string;
    city: string;
    status?: string;
  }) {
    const { data, error } = await supabase
      .from('brands')
      .insert(payload)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async updateBrand(id: string, payload: any) {
    const { data, error } = await supabase
      .from('brands')
      .update(payload)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async deleteBrand(id: string) {
    const { error } = await supabase
      .from('brands')
      .update({ status: 'inactive' })
      .eq('id', id);

    if (error) throw error;
    return { success: true };
  }
}
