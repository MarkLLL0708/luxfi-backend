import { Controller, Get, Post, Put, Body, Param, Query } from '@nestjs/common';
import { MarketplaceService } from './marketplace.service';

@Controller('marketplace')
export class MarketplaceController {
  constructor(private readonly marketplaceService: MarketplaceService) {}

  @Get()
  getListings(
    @Query('brand_id') brand_id?: string,
    @Query('min_price') min_price?: number,
    @Query('max_price') max_price?: number,
  ) {
    return this.marketplaceService.getListings({ brand_id, min_price, max_price });
  }

  @Get('seller/:wallet')
  getSellerListings(@Param('wallet') wallet: string) {
    return this.marketplaceService.getSellerListings(wallet);
  }

  @Get(':id')
  getListingById(@Param('id') id: string) {
    return this.marketplaceService.getListingById(id);
  }

  @Post()
  createListing(@Body() body: any) {
    return this.marketplaceService.createListing(body);
  }

  @Post(':id/purchase')
  purchaseListing(
    @Param('id') id: string,
    @Body() body: { buyer_wallet: string; tx_hash: string }
  ) {
    return this.marketplaceService.purchaseListing(id, body);
  }

  @Put(':id/cancel')
  cancelListing(
    @Param('id') id: string,
    @Body() body: { sellerWallet: string }
  ) {
    return this.marketplaceService.cancelListing(id, body.sellerWallet);
  }
}
