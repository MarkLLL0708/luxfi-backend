import { Controller, Get, Post, Param, Body } from '@nestjs/common';
import { RewardsService } from './rewards.service';
@Controller('rewards')
export class RewardsController {
constructor(private readonly rewardsService: RewardsService) {}
@Get('pools')
getActivePools() {
return this.rewardsService.getActivePools();
}
@Get('pools/:id')
getPoolById(@Param('id') id: string) {
return this.rewardsService.getPoolById(id);
}
@Get('pools/brand/:brandId')
getBrandPools(@Param('brandId') brandId: string) {
return this.rewardsService.getBrandPools(brandId);
}
@Get('user/:userId')
getUserClaims(@Param('userId') userId: string) {
return this.rewardsService.getUserClaims(userId);
}
@Post('pools')
createPool(@Body() dto: any) {
return this.rewardsService.createPool(dto);
}
@Post('allocate')
allocateReward(@Body() dto: any) {
return this.rewardsService.allocateReward(dto.poolId, dto.userId, dto.amount);
}
@Post('claim')
claimReward(@Body() dto: any) {
return this.rewardsService.claimReward(dto.poolId, dto.userId);
}
}
