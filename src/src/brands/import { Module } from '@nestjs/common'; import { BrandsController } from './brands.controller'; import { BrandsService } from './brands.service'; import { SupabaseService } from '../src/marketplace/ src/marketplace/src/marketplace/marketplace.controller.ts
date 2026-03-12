import { Controller, Get, Post, Delete, Param, Body } from '@nestjs/common';
import { MarketplaceService } from './marketplace.service';
@Controller('marketplace')
export class MarketplaceController {
constructor(private readonly marketplaceService: MarketplaceService) {}
@Get()
getActiveListings() {
return this.marketplaceService.getActiveListings();
}
@Get(':id')
getListingById(@Param('id') id: string) {
return this.marketplaceService.getListingById(id);
}
@Get('brand/:brandId')
getBrandListings(@Param('brandId') brandId: string) {
return this.marketplaceService.getBrandListings(brandId);
}
@Get('user/:userId')
getUserListings(@Param('userId') userId: string) {
return this.marketplaceService.getUserListings(userId);
}
@Post()
createListing(@Body() dto: any) {
return this.marketplaceService.createListing(dto);
}
@Post(':id/purchase')
purchaseListing(@Param('id') id: string, @Body('amount') amount: number) {
return this.marketplaceService.purchaseListing(id, amount);
}
@Delete(':id')
cancelListing(@Param('id') id: string, @Body('userId') userId: string) {
return this.marketplaceService.cancelListing(id, userId);
}
}
