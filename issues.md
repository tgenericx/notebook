so I tried to plug:
➜  auth git:(lib) ✗ cat src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { UserRepository } from './services/user.service';
import { EmailModule } from './email/email.module';
import { APP_GUARD } from '@nestjs/core';
import { AuthController } from './controllers/auth.controller';
import { AuthModule, JwtAuthGuard } from '@nahnah/nestjs-auth-module';
import { EmailService } from './email/email.service';
import { DatabaseModule } from './database/database.module';
import { PrismaService } from './database/prisma.service';
import { GoogleOAuthModule } from '@nahnah/nestjs-auth-module/google-auth.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    DatabaseModule,
    EmailModule,
    AuthModule.forRootAsync({
      imports: [ConfigModule, DatabaseModule, EmailModule],
      useFactory: () => ({
        jwt: {
          accessTokenSignOptions: {
            secret: 'access',
            expiresIn: '15m',
            audience: 'api',
          },
          refreshTokenSignOptions: {
            secret: 'refresh',
            expiresIn: '7d',
            audience: 'refresh',
          },
        },
        password: {
          minLength: 8,
          requireSpecialChar: true,
          requireNumber: true,
          requireUppercase: true,
        },
      }),
      inject: [ConfigService, PrismaService, EmailService],
      userRepository: UserRepository,
      emailService: EmailService
    }),
    GoogleOAuthModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        clientId: config.getOrThrow('GOOGLE_CLIENT_ID'),
        clientSecret: config.getOrThrow('GOOGLE_CLIENT_SECRET'),
        callbackURL: config.getOrThrow('GOOGLE_REDIRECT_URL'),
      }),
    })
  ],
  providers: [
    UserRepository,
    { provide: APP_GUARD, useClass: JwtAuthGuard },
  ],
  controllers: [AuthController],
})
export class AppModule { }
➜  auth git:(lib) ✗

