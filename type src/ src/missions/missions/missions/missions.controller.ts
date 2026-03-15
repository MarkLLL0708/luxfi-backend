import {
  Controller, Get, Post, Body, Param, Query, Headers, UnauthorizedException
} from '@nestjs/common';
import { MissionsService } from './missions.service';

@Controller('missions')
export class MissionsController {
  constructor(private readonly missionsService: MissionsService) {}

  @Get()
  getActiveMissions(
    @Query('city') city?: string,
    @Query('mission_type') mission_type?: string,
    @Query('difficulty') difficulty?: string,
  ) {
    return this.missionsService.getActiveMissions({ city, mission_type, difficulty });
  }

  @Get('leaderboard')
  getLeaderboard() {
    return this.missionsService.getLeaderboard();
  }

  @Get(':id')
  getMission(@Param('id') id: string) {
    return this.missionsService.getMissionById(id);
  }

  @Get('agent/:wallet')
  getAgentStats(@Param('wallet') wallet: string) {
    return this.missionsService.getAgentStats(wallet);
  }

  @Post('agent/register')
  registerAgent(@Body() body: { walletAddress: string }) {
    return this.missionsService.getOrCreateAgent(body.walletAddress);
  }

  @Post(':id/claim')
  claimMission(
    @Param('id') missionId: string,
    @Body() body: { walletAddress: string; stakeTxHash: string }
  ) {
    return this.missionsService.claimMission(
      missionId, body.walletAddress, body.stakeTxHash
    );
  }

  @Post('claims/:claimId/submit')
  submitMission(
    @Param('claimId') claimId: string,
    @Body() body: any
  ) {
    return this.missionsService.submitMission(claimId, body.agentWallet, {
      intel_text: body.intel_text,
      intel_photos: body.intel_photos,
      intel_video_url: body.intel_video_url,
      gps_lat: body.gps_lat,
      gps_lng: body.gps_lng,
    });
  }

  @Post('admin/claims/:claimId/approve')
  approveSubmission(
    @Headers('x-admin-key') adminKey: string,
    @Param('claimId') claimId: string,
    @Body() body: { payoutTxHash?: string }
  ) {
    if (adminKey !== process.env.ADMIN_API_KEY) {
      throw new UnauthorizedException('Invalid admin key');
    }
    return this.missionsService.approveSubmission(claimId, body.payoutTxHash);
  }

  @Post('admin/claims/:claimId/reject')
  rejectSubmission(
    @Headers('x-admin-key') adminKey: string,
    @Param('claimId') claimId: string,
    @Body() body: { reason: string }
  ) {
    if (adminKey !== process.env.ADMIN_API_KEY) {
      throw new UnauthorizedException('Invalid admin key');
    }
    return this.missionsService.rejectSubmission(claimId, body.reason);
  }

  @Get('admin/pending')
  getPendingSubmissions(@Headers('x-admin-key') adminKey: string) {
    if (adminKey !== process.env.ADMIN_API_KEY) {
      throw new UnauthorizedException('Invalid admin key');
    }
    return this.missionsService.getPendingSubmissions();
  }

  @Post('admin/create')
  createMission(
    @Headers('x-admin-key') adminKey: string,
    @Body() body: any
  ) {
    if (adminKey !== process.env.ADMIN_API_KEY) {
      throw new UnauthorizedException('Invalid admin key');
    }
    return this.missionsService.createMission(body);
  }
}
