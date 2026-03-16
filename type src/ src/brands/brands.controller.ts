import { Controller, Get, Post, Put, Delete, Body, Param, Query } from '@nestjs/common';
import { BrandsService } from './brands.service';

@Controller('brands')
export class BrandsController {
  constructor(private readonly brandsService: BrandsService) {}

  @Get()
  getAllBrands(
    @Query('category') category?: string,
    @Query('country') country?: string,
    @Query('city') city?: string,
  ) {
    return this.brandsService.getAllBrands({ category, country, city });
  }

  @Get(':id')
  getBrandById(@Param('id') id: string) {
    return this.brandsService.getBrandById(id);
  }

  @Post()
  createBrand(@Body() body: any) {
    return this.brandsService.createBrand(body);
  }

  @Put(':id')
  updateBrand(@Param('id') id: string, @Body() body: any) {
    return this.brandsService.updateBrand(id, body);
  }

  @Delete(':id')
  deleteBrand(@Param('id') id: string) {
    return this.brandsService.deleteBrand(id);
  }
}
