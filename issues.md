

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

[7:43:20 AM] File change detected. Starting incremental compilation...
                                                                                                     [7:43:22 AM] Found 0 errors. Watching for file changes.                                              
[Nest] 21694  - 12/13/2025, 7:43:51 AM     LOG [NestFactory] Starting Nest application...            [Nest] 21694  - 12/13/2025, 7:43:51 AM     LOG [InstanceLoader] DatabaseModule dependencies initialized +114ms
[Nest] 21694  - 12/13/2025, 7:43:51 AM     LOG [InstanceLoader] PassportModule dependencies initialized +0ms                                                                                              [Nest] 21694  - 12/13/2025, 7:43:51 AM   ERROR [ExceptionHandler] UnknownDependenciesException [Error]: Nest can't resolve dependencies of the GoogleOAuthService (GOOGLE_OAUTH_CONFIG, ?, TokenService). Please make sure that the argument "USER_REPOSITORY" at index [1] is available in the GoogleOAuthModule context.                                                                                          
Potential solutions:                                                                                 - Is GoogleOAuthModule a valid NestJS module?                                                        - If "USER_REPOSITORY" is a provider, is it part of the current GoogleOAuthModule?
- If "USER_REPOSITORY" is exported from a separate @Module, is that module imported within GoogleOAuthModule?                                                                                               @Module({
    imports: [ /* the Module containing "USER_REPOSITORY" */ ]
  })                                                                                                                                                                                                      For more common dependency resolution issues, see: https://docs.nestjs.com/faq/common-errors
    at Injector.lookupComponentInParentModules (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/injector.js:286:19)
    at async resolveParam (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/injector.js:140:38)
    at async Promise.all (index 1)
    at async Injector.resolveConstructorParams (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/injector.js:169:27)
    at async Injector.loadInstance (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/injector.js:75:13)
    at async Injector.loadProvider (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/injector.js:103:9)
    at async /root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/instance-loader.js:56:13
    at async Promise.all (index 6)
    at async InstanceLoader.createInstancesOfProviders (/root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/instance-loader.js:55:9)
    at async /root/auth/node_modules/.pnpm/@nestjs+core@11.1.9_@nestjs+common@11.1.9_class-transformer@0.5.1_class-validator@0.14._35aa21069415c61cc2ff03470cea104c/node_modules/@nestjs/core/injector/instance-loader.js:40:13 {
  type: 'GoogleOAuthService',
  context: {
    index: 1,
    dependencies: [
      'GOOGLE_OAUTH_CONFIG',
      'USER_REPOSITORY',
      [class TokenService]
    ],
    name: 'USER_REPOSITORY'
  },
  metadata: {
    id: '52743e9a2481573916c4f'
  },
  moduleRef: {
    id: '5dbf57e804c560fc2a5d1'
  }
}