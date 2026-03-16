import { Controller, Get, Post, Put, Body, Param, Query } from '@nestjs/common';
import { GovernanceService } from './governance.service';

@Controller('governance')
export class GovernanceController {
  constructor(private readonly governanceService: GovernanceService) {}

  @Get()
  getProposals(@Query('brandId') brandId?: string) {
    return this.governanceService.getProposals(brandId);
  }

  @Get(':id')
  getProposalById(@Param('id') id: string) {
    return this.governanceService.getProposalById(id);
  }

  @Get(':id/votes')
  getProposalVotes(@Param('id') id: string) {
    return this.governanceService.getProposalVotes(id);
  }

  @Post()
  createProposal(@Body() body: any) {
    return this.governanceService.createProposal(body);
  }

  @Post('vote')
  castVote(@Body() body: any) {
    return this.governanceService.castVote(body);
  }

  @Put(':id/close')
  closeProposal(@Param('id') id: string) {
    return this.governanceService.closeProposal(id);
  }
}
