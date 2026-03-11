import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
async function bootstrap() {
const app = await NestFactory.create(AppModule);
app.use(helmet());
app.enableCors({
origin: [
'https://luxfivault.netlify.app',
'http://localhost:3000',
'http://localhost:5173'
],
credentials: true
});
app.use(rateLimit({
windowMs: 15 * 60 * 1000,
max: 100,
message: 'Too many requests'
}));
app.setGlobalPrefix('api');
const port = process.env.PORT || 3001;
await app.listen(port);
console.log(LUXFI Backend running on port ${port});
}
bootstrap();
