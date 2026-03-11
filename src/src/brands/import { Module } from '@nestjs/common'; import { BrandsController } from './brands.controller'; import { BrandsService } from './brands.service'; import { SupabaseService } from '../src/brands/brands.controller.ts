import { Controller, Get, Post, Put, Param, Body } from '@nestjs/common';
import { BrandsService } from './brands.service';
@Controller('brands')
export class BrandsController {
constructor(private readonly brandsService: BrandsService) {}
@Get()
getAllBrands() {
return this.brandsService.getAllBrands();
}
@Get('active')
getActiveBrands() {
return this.brandsService.getActiveBrands();
}
@Get(':id')
getBrandById(@Param('id') id: string) {
return this.brandsService.getBrandById(id);
}
@Post()
createBrand(@Body() dto: any) {
return this.brandsService.createBrand(dto);
}
@Put(':id')
updateBrand(@Param('id') id: string, @Body() dto: any) {
return this.brandsService.updateBrand(id, dto);
}
@Put(':id/revenue')
updateRevenue(@Param('id') id: string, @Body('revenue') revenue: number) {
return this.brandsService.updateRevenue(id, revenue);
}
}
