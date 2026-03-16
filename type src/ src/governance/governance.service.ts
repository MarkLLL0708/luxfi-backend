import { Injectable, NotFoundException } from '@nestjs/common';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

@Injectable()
export class GovernanceService {

  async getProposals(brandId?: string) {
    let query = supabase
      .from('governance_proposals')
      .select('*, brands(name, category)')
      .order('created_at', { ascending: false });

    if (brandId) query = query.eq('brand_id', brandId);

    const { data, error } = await query;
    if (error) throw error;
    return data;
  }

  async getProposalById(id: string) {
    const { data, error } = await supabase
      .from('governance_proposals')
      .select('*, brands(name, category)')
      .eq('id', id)
      .single();

    if (error) throw new NotFoundException('Proposal not found');
    return data;
  }

  async createProposal(payload: {
    brand_id: string;
    title: string;
    description: string;
    options: string[];
    deadline: string;
    created_by: string;
  }) {
    const { data, error } = await supabase
      .from('governance_proposals')
      .insert({
        ...payload,
        status: 'active'
      })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async castVote(payload: {
    proposal_id: string;
    user_id: string;
    option: string;
    voting_power: number;
  }) {
    // Check if already voted
    const { data: existing } = await supabase
      .from('votes')
      .select('id')
      .eq('proposal_id', payload.proposal_id)
      .eq('user_id', payload.user_id)
      .single();

    if (existing) throw new Error('Already voted on this proposal');

    const { data, error } = await supabase
      .from('votes')
      .insert(payload)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async getProposalVotes(proposalId: string) {
    const { data, error } = await supabase
      .from('votes')
      .select('*')
      .eq('proposal_id', proposalId);

    if (error) throw error;

    // Tally votes
    const tally = data?.reduce((acc, vote) => {
      acc[vote.option] = (acc[vote.option] || 0) + vote.voting_power;
      return acc;
    }, {});

    return { votes: data, tally };
  }

  async closeProposal(id: string) {
    const { data, error } = await supabase
      .from('governance_proposals')
      .update({ status: 'closed' })
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    return data;
  }
}
