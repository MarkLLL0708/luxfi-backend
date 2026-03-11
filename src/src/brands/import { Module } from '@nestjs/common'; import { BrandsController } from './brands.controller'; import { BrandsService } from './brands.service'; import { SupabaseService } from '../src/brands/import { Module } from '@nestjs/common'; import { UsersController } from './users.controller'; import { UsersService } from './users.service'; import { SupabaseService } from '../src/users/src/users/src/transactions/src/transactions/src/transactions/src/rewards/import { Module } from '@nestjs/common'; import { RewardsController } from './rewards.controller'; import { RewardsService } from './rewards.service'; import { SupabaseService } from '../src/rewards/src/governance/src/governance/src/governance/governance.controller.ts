import { Controller, Get, Post, Param, Body } from '@nestjs/common';
import { GovernanceService } from './governance.service';
@Controller('governance')
export class GovernanceController {
constructor(private readonly governanceService: GovernanceService) {}
@Get()
getAllProposals() {
return this.governanceService.getAllProposals();
}
@Get('active')
getActiveProposals() {
return this.governanceService.getActiveProposals();
}
@Get(':id')
getProposalById(@Param('id') id: string) {
return this.governanceService.getProposalById(id);
}
@Get(':id/votes')
getProposalVotes(@Param('id') id: string) {
return this.governanceService.getProposalVotes(id);
}
@Get('brand/:brandId')
getBrandProposals(@Param('brandId') brandId: string) {
return this.governanceService.getBrandProposals(brandId);
}
@Post()
createProposal(@Body() dto: any) {
return this.governanceService.createProposal(dto);
}
@Post('vote')
castVote(@Body() dto: any) {
return this.governanceService.castVote(dto.proposalId, dto.userId, dto.support, dto.weight);
}
@Post(':id/finalize')
finalizeProposal(@Param('id') id: string) {
return this.governanceService.finalizeProposal(id);
}
}
