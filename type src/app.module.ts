import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { BrandsModule } from './brands/brands.module';
import { UsersModule } from './users/users.module';
import { TransactionsModule } from './transactions/transactions.module';
import { RewardsModule } from './rewards/rewards.module';
import { GovernanceModule } from './governance/governance.module';
import { MarketplaceModule } from './marketplace/marketplace.module';
@Module({
imports: [
ConfigModule.forRoot({ isGlobal: true }),
BrandsModule,
UsersModule,
TransactionsModule,
RewardsModule,
GovernanceModule,
MarketplaceModule,
],
})
export class AppModule {}

