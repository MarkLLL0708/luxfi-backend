import { Controller, Get, Post, Put, Param, Body } from '@nestjs/common';
import { UsersService } from './users.service';
@Controller('users')
export class UsersController {
constructor(private readonly usersService: UsersService) {}
@Get(':wallet')
getUserByWallet(@Param('wallet') wallet: string) {
return this.usersService.getUserByWallet(wallet);
}
@Get('id/:id')
getUserById(@Param('id') id: string) {
return this.usersService.getUserById(id);
}
@Post()
createUser(@Body() dto: any) {
return this.usersService.createUser(dto.walletAddress, dto.email);
}
@Post('connect')
getOrCreateUser(@Body('walletAddress') walletAddress: string) {
return this.usersService.getOrCreateUser(walletAddress);
}
@Put(':id/kyc')
updateKyc(@Param('id') id: string, @Body() dto: any) {
return this.usersService.updateKycStatus(id, dto.status, dto.providerId);
}
@Put(':id/invested')
updateInvested(@Param('id') id: string, @Body('amount') amount: number) {
return this.usersService.updateTotalInvested(id, amount);
}
}
