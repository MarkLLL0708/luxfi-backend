import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

@Injectable()
export class MissionsService {

  async getActiveMissions(filters?: {
    city?: string;
    mission_type?: string;
    difficulty?: string;
  }) {
    let query = supabase
      .from('missions')
      .select('*')
      .eq('status', 'active')
      .gt('deadline', new Date().toISOString())
      .order('is_featured', { ascending: false })
      .order('created_at', { ascending: false });

    if (filters?.city) query = query.eq('city', filters.city);
    if (filters?.mission_type) query = query.eq('mission_type', filters.mission_type);
    if (filters?.difficulty) query = query.eq('difficulty', filters.difficulty);

    const { data, error } = await query;
    if (error) throw error;
    return data;
  }

  async getMissionById(id: string) {
    const { data, error } = await supabase
      .from('missions')
      .select('*')
      .eq('id', id)
      .single();

    if (error) throw new NotFoundException('Mission not found');
    return data;
  }

  async createMission(payload: any) {
    const { data, error } = await supabase
      .from('missions')
      .insert(payload)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async claimMission(missionId: string, agentWallet: string, stakeTxHash: string) {
    const mission = await this.getMissionById(missionId);
    if (mission.status !== 'active') {
      throw new BadRequestException('Mission is no longer available');
    }

    if (new Date(mission.deadline) < new Date()) {
      throw new BadRequestException('Mission deadline has passed');
    }

    const { data: existing } = await supabase
      .from('mission_claims')
      .select('id')
      .eq('mission_id', missionId)
      .eq('agent_wallet', agentWallet)
      .single();

    if (existing) throw new BadRequestException('You already claimed this mission');

    await this.getOrCreateAgent(agentWallet);

    const { data: claim, error } = await supabase
      .from('mission_claims')
      .insert({
        mission_id: missionId,
        agent_wallet: agentWallet,
        stake_tx_hash: stakeTxHash,
        stake_amount_bnb: mission.stake_required_bnb,
      })
      .select()
      .single();

    if (error) throw error;
    return claim;
  }

  async submitMission(claimId: string, agentWallet: string, submission: {
    intel_text: string;
    intel_photos: string[];
    intel_video_url?: string;
    gps_lat?: number;
    gps_lng?: number;
  }) {
    const { data: claim } = await supabase
      .from('mission_claims')
      .select('*')
      .eq('id', claimId)
      .eq('agent_wallet', agentWallet)
      .single();

    if (!claim) throw new NotFoundException('Claim not found');
    if (claim.status !== 'active') throw new BadRequestException('Claim is not active');

    const { data, error } = await supabase
      .from('mission_claims')
      .update({
        status: 'submitted',
        intel_text: submission.intel_text,
        intel_photos: submission.intel_photos,
        intel_video_url: submission.intel_video_url,
        gps_lat: submission.gps_lat,
        gps_lng: submission.gps_lng,
        gps_verified: !!(submission.gps_lat && submission.gps_lng),
        submitted_at: new Date().toISOString(),
      })
      .eq('id', claimId)
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async approveSubmission(claimId: string, payoutTxHash?: string) {
    const { error } = await supabase.rpc('approve_mission', { p_claim_id: claimId });
    if (error) throw error;

    if (payoutTxHash) {
      await supabase
        .from('mission_claims')
        .update({ payout_tx_hash: payoutTxHash })
        .eq('id', claimId);
    }

    return { success: true };
  }

  async rejectSubmission(claimId: string, reason: string) {
    const { data: claim } = await supabase
      .from('mission_claims')
      .select('*, missions(*)')
      .eq('id', claimId)
      .single();

    await supabase
      .from('mission_claims')
      .update({
        status: 'rejected',
        rejection_reason: reason,
        reviewed_at: new Date().toISOString(),
      })
      .eq('id', claimId);

    await supabase
      .from('missions')
      .update({ status: 'active' })
      .eq('id', claim.mission_id);

    return { success: true };
  }

  async getOrCreateAgent(walletAddress: string) {
    const { data: existing } = await supabase
      .from('agent_profiles')
      .select('*')
      .eq('wallet_address', walletAddress)
      .single();

    if (existing) return existing;

    const { data: codename } = await supabase
      .rpc('generate_codename', { wallet: walletAddress });

    const { data, error } = await supabase
      .from('agent_profiles')
      .insert({ wallet_address: walletAddress, codename })
      .select()
      .single();

    if (error) throw error;
    return data;
  }

  async getAgentStats(walletAddress: string) {
    const [profileRes, claimsRes] = await Promise.all([
      supabase
        .from('agent_profiles')
        .select('*')
        .eq('wallet_address', walletAddress)
        .single(),
      supabase
        .from('mission_claims')
        .select('*, missions(codename, mission_type, city, reward_bnb, difficulty)')
        .eq('agent_wallet', walletAddress)
        .order('claimed_at', { ascending: false })
        .limit(20),
    ]);

    return {
      profile: profileRes.data,
      missions: claimsRes.data,
    };
  }

  async getLeaderboard() {
    const { data, error } = await supabase
      .from('leaderboard_weekly')
      .select('*')
      .limit(20);

    if (error) throw error;
    return data;
  }

  async getPendingSubmissions() {
    const { data, error } = await supabase
      .from('mission_claims')
      .select('*, missions(*)')
      .eq('status', 'submitted')
      .order('submitted_at', { ascending: true });

    if (error) throw error;
    return data;
  }
}
