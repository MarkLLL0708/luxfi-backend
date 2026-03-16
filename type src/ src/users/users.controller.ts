import { Controller, Get, Post, Put, Body, Param } from '@nestjs/common';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get(':id')
  getUserById(@Param('id') id: string) {
    return this.usersService.getUserById(id);
  }

  @Get('wallet/:address')
  getUserByWallet(@Param('address') address: string) {
    return this.usersService.getUserByWallet(address);
  }

  @Post()
  createUser(@Body() body: any) {
    return this.usersService.createUser(body);
  }

  @Post('connect')
  getOrCreateUser(@Body() body: { walletAddress: string }) {
    return this.usersService.getOrCreateUser(body.walletAddress);
  }

  @Put(':id')
  updateUser(@Param('id') id: string, @Body() body: any) {
    return this.usersService.updateUser(id, body);
  }

  @Get(':id/participations')
  getUserParticipations(@Param('id') id: string) {
    return this.usersService.getUserParticipations(id);
  }

  @Put(':id/kyc')
  updateKycStatus(
    @Param('id') id: string,
    @Body() body: { status: string }
  ) {
    return this.usersService.updateKycStatus(id, body.status);
  }
}
