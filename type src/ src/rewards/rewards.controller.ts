import { Controller, Get, Post, Put, Body, Param } from '@nestjs/common';
import { RewardsService } from './rewards.service';

@Controller('rewards')
export class RewardsController {
  constructor(private readonly rewardsService: RewardsService) {}

  @Get('user/:userId')
  getUserRewards(@Param('userId') userId: string) {
    return this.rewardsService.getUserRewards(userId);
  }

  @Get('user/:userId/total')
  getTotalRewardsEarned(@Param('userId') userId: string) {
    return this.rewardsService.getTotalRewardsEarned(userId);
  }

  @Get('pools')
  getRewardPools() {
    return this.rewardsService.getRewardPools();
  }

  @Get('pools/brand/:brandId')
  getBrandRewardPools(@Param('brandId') brandId: string) {
    return this.rewardsService.getRewardPools(brandId);
  }

  @Post('pools')
  createRewardPool(@Body() body: any) {
    return this.rewardsService.createRewardPool(body);
  }

  @Post('claim')
  claimReward(@Body() body: any) {
    return this.rewardsService.claimReward(body);
  }

  @Put(':id/status')
  updateRewardStatus(
    @Param('id') id: string,
    @Body() body: { status: string; txHash?: string }
  ) {
    return this.rewardsService.updateRewardStatus(id, body.status, body.txHash);
  }
}
