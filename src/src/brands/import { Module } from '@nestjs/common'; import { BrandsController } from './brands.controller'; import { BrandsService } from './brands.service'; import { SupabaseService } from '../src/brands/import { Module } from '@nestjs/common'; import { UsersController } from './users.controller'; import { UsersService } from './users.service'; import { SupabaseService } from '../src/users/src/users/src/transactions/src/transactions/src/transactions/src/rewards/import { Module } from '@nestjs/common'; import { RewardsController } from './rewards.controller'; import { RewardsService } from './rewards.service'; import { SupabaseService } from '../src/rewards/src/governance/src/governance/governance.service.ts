import { Injectable } from '@nestjs/common';
import { SupabaseService } from '../supabase.service';
@Injectable()
export class GovernanceService {
constructor(private supabase: SupabaseService) {}
async createProposal(dto: any) {
const { data, error } = await this.supabase.getClient()
.from('governance_proposals')
.insert(dto)
.select()
.single();
if (error) throw error;
return data;
}
async getAllProposals() {
const { data, error } = await this.supabase.getClient()
.from('governance_proposals')
.select('*, brands(name)')
.order('start_time', { ascending: false });
if (error) throw error;
return data;
}
async getProposalById(id: string) {
const { data, error } = await this.supabase.getClient()
.from('governance_proposals')
.select('*, brands(name)')
.eq('id', id)
.single();
if (error) throw error;
return data;
}
async getBrandProposals(brandId: string) {
const { data, error } = await this.supabase.getClient()
.from('governance_proposals')
.select('*')
.eq('brand_id', brandId)
.order('start_time', { ascending: false });
if (error) throw error;
return data;
}
async getActiveProposals() {
const { data, error } = await this.supabase.getClient()
.from('governance_proposals')
.select('*, brands(name)')
.eq('status', 'active')
.gt('end_time', new Date().toISOString())
.order('end_time', { ascending: true });
if (error) throw error;
return data;
}
async castVote(proposalId: string, userId: string, support: boolean, weight: number) {
const { data: existing } = await this.supabase.getClient()
.from('votes')
.select('id')
.eq('proposal_id', proposalId)
.eq('user_id', userId)
.single();
if (existing) throw new Error('Already voted');
const { data, error } = await this.supabase.getClient()
.from('votes')
.insert({ proposal_id: proposalId, user_id: userId, support, weight })
.select()
.single();
if (error) throw error;
const field = support ? 'votes_for' : 'votes_against';
const proposal = await this.getProposalById(proposalId);
await this.supabase.getClient()
.from('governance_proposals')
.update({ [field]: Number(proposal[field]) + weight })
.eq('id', proposalId);
return data;
}
async finalizeProposal(id: string) {
const proposal = await this.getProposalById(id);
const status = proposal.votes_for > proposal.votes_against ? 'passed' : 'rejected';
const { data, error } = await this.supabase.getClient()
.from('governance_proposals')
.update({ status })
.eq('id', id)
.select()
.single();
if (error) throw error;
return data;
}
async getProposalVotes(proposalId: string) {
const { data, error } = await this.supabase.getClient()
.from('votes')
.select('*')
.eq('proposal_id', proposalId);
if (error) throw error;
return data;
}
}

