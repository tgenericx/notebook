➜  auth git:(main) ✗ tree src
src
├── auth.constants.ts
├── auth.module.ts
├── decorators
│   ├── current-user.decorator.ts
│   ├── public.decorator.ts
│   └── roles.decorator.ts
├── dto
│   ├── jwt-payload.dto.ts
│   ├── login.dto.ts
│   ├── refresh-token.dto.ts
│   ├── register.dto.ts
│   └── token-response.dto.ts
├── google-auth.constants.ts
├── google-auth.module.ts
├── guards
│   ├── google-auth.guard.ts
│   ├── jwt-auth.guard.ts
│   └── roles.guard.ts
├── index.ts
├── interfaces
│   ├── auth-config.interface.ts
│   ├── auth-user.interface.ts
│   ├── email-service.interface.ts
│   └── user-repository.interface.ts
├── services
│   ├── auth.service.ts
│   ├── google-auth.service.ts
│   ├── password.service.ts
│   └── token.service.ts
├── strategies
│   ├── google.strategy.ts
│   └── jwt.strategy.ts
└── utils
    └── token-validation.utils.ts

8 directories, 27 files
➜  auth git:(main) ✗ cat src/*.ts
export const AUTH_MODULE_CONFIG = 'AUTH_MODULE_CONFIG';
export const USER_REPOSITORY = 'USER_REPOSITORY';
export const EMAIL_SERVICE = 'EMAIL_SERVICE';
import { DynamicModule, Module, Provider, Type } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './services/auth.service';
import { TokenService } from './services/token.service';
import { PasswordService } from './services/password.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { IAuthModuleConfig, IJwtConfig, IPasswordConfig } from './interfaces/auth-config.interface';
import { IUserRepository } from './interfaces/user-repository.interface';
import { IEmailService } from './interfaces/email-service.interface';
import { AUTH_MODULE_CONFIG, USER_REPOSITORY, EMAIL_SERVICE } from './auth.constants';
import { validateJwtConfig } from './utils/token-validation.utils';

/**
 * Options for registering the Auth module synchronously
 */
export interface AuthModuleOptions {
  /** JWT and authentication configuration */
  config: IAuthModuleConfig;

  /**
   * Service class that implements IUserRepository interface
   * This service must be decorated with @Injectable()
   */
  userRepository: Type<IUserRepository>;

  /**
   * Optional service class that implements IEmailService interface
   * This service must be decorated with @Injectable()
   */
  emailService?: Type<IEmailService>;
}

/**
 * Options for registering the Auth module asynchronously
 */
export interface AuthModuleAsyncOptions {
  /** Modules to import that are required by the factory */
  imports?: any[];

  /**
   * Factory function that returns auth configuration
   * Can be async if configuration requires async operations
   */
  useFactory: (...args: any[]) => Promise<IAuthModuleConfig> | IAuthModuleConfig;

  /** Dependencies to inject into the factory function */
  inject?: any[];

  /**
   * Service class that implements IUserRepository interface
   * This service must be decorated with @Injectable()
   */
  userRepository: Type<IUserRepository>;

  /**
   * Optional service class that implements IEmailService interface
   * This service must be decorated with @Injectable()
   */
  emailService?: Type<IEmailService>;
}

@Module({})
export class AuthModule {
  /**
   * Register the Auth module with synchronous configuration
   *
   * Note: This module no longer includes Google OAuth.
   * To enable Google OAuth, import GoogleOAuthModule separately.
   *
   * @example
   * ```typescript
   * @Module({
   *   imports: [
   *     AuthModule.forRoot({
   *       config: {
   *         jwt: {
   *           accessTokenSignOptions: { secret: 'secret', expiresIn: '15m' },
   *           refreshTokenSignOptions: { secret: 'refresh-secret', expiresIn: '7d' }
   *         }
   *       },
   *       userRepository: UserService
   *     }),
   *     // Optional: Enable Google OAuth
   *     GoogleOAuthModule.forRoot({
   *       google: {
   *         clientId: 'your-client-id',
   *         clientSecret: 'your-client-secret',
   *         callbackURL: 'http://localhost:3000/auth/google/callback'
   *       }
   *     })
   *   ]
   * })
   * ```
   */
  static forRoot(options: AuthModuleOptions): DynamicModule {
    this.validateOptions(options);

    const providers: Provider[] = [
      {
        provide: AUTH_MODULE_CONFIG,
        useValue: options.config,
      },
      {
        provide: USER_REPOSITORY,
        useClass: options.userRepository,
      },
      ...(options.emailService
        ? [{
          provide: EMAIL_SERVICE,
          useClass: options.emailService,
        }]
        : [{
          provide: EMAIL_SERVICE,
          useValue: null,
        }]),
      AuthService,
      TokenService,
      PasswordService,
      JwtStrategy,
      JwtAuthGuard,
      RolesGuard,
    ];

    return {
      module: AuthModule,
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.register({
          signOptions: { ...options.config.jwt.accessTokenSignOptions },
        }),
      ],
      providers,
      exports: [
        AuthService,
        TokenService,
        PasswordService,
        JwtAuthGuard,
        RolesGuard,
        JwtModule,
        USER_REPOSITORY,
      ],
    };
  }

  /**
   * Register the Auth module with asynchronous configuration
   *
   * @example
   * ```typescript
   * @Module({
   *   imports: [
   *     AuthModule.forRootAsync({
   *       imports: [ConfigModule],
   *       useFactory: (config: ConfigService) => ({
   *         jwt: {
   *           accessTokenSignOptions: {
   *             secret: config.get('JWT_SECRET'),
   *             expiresIn: '15m'
   *           },
   *           refreshTokenSignOptions: {
   *             secret: config.get('REFRESH_SECRET'),
   *             expiresIn: '7d'
   *           }
   *         }
   *       }),
   *       inject: [ConfigService],
   *       userRepository: UserService
   *     }),
   *     // Optional: Enable Google OAuth
   *     GoogleOAuthModule.forRootAsync({
   *       imports: [ConfigModule],
   *       inject: [ConfigService],
   *       useFactory: (config: ConfigService) => ({
   *         clientId: config.get('GOOGLE_CLIENT_ID'),
   *         clientSecret: config.get('GOOGLE_CLIENT_SECRET'),
   *         callbackURL: config.get('GOOGLE_REDIRECT_URL')
   *       })
   *     })
   *   ]
   * })
   * ```
   */
  static forRootAsync(options: AuthModuleAsyncOptions): DynamicModule {
    this.validateAsyncOptions(options);

    const providers: Provider[] = [
      {
        provide: AUTH_MODULE_CONFIG,
        useFactory: async (...args: any[]) => {
          const config = await options.useFactory(...args);
          validateJwtConfig(config.jwt);
          return config;
        },
        inject: options.inject || [],
      },
      {
        provide: USER_REPOSITORY,
        useClass: options.userRepository,
      },
      ...(options.emailService
        ? [{
          provide: EMAIL_SERVICE,
          useClass: options.emailService,
        }]
        : [{
          provide: EMAIL_SERVICE,
          useValue: null,
        }]),
      AuthService,
      TokenService,
      PasswordService,
      JwtStrategy,
      JwtAuthGuard,
      RolesGuard,
    ];

    const jwtModule = JwtModule.registerAsync({
      imports: options.imports || [],
      useFactory: async (...args: any[]) => {
        const config = await options.useFactory(...args);
        return {
          signOptions: { ...config.jwt.accessTokenSignOptions },
        };
      },
      inject: options.inject || [],
    });

    return {
      module: AuthModule,
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        jwtModule,
        ...(options.imports || []),
      ],
      providers,
      exports: [
        AuthService,
        TokenService,
        PasswordService,
        JwtAuthGuard,
        RolesGuard,
        JwtModule,
        USER_REPOSITORY,
      ],
    };
  }

  private static validateOptions(options: AuthModuleOptions): void {
    if (!options.config) {
      throw new Error('AuthModule: "config" is required');
    }
    if (!options.config.jwt) {
      throw new Error('AuthModule: "config.jwt" is required');
    }
    if (!options.config.jwt.refreshTokenSignOptions) {
      throw new Error('AuthModule: "config.jwt.refreshTokenSignOptions" is required');
    }
    if (!options.config.jwt.accessTokenSignOptions) {
      throw new Error('AuthModule: "config.jwt.accessTokenSignOptions" is required');
    }
    if (!options.userRepository) {
      throw new Error('AuthModule: "userRepository" is required');
    }

    validateJwtConfig(options.config.jwt);
  }

  private static validateAsyncOptions(options: AuthModuleAsyncOptions): void {
    if (!options.useFactory) {
      throw new Error('AuthModule: "useFactory" is required for async configuration');
    }
    if (!options.userRepository) {
      throw new Error('AuthModule: "userRepository" is required');
    }
  }
}
export const GOOGLE_OAUTH_CONFIG = 'GOOGLE_OAUTH_CONFIG';
import { DynamicModule, Module, Provider, Type } from '@nestjs/common';
import { GoogleStrategy } from './strategies/google.strategy';
import { GoogleAuthGuard } from './guards/google-auth.guard';
import { StrategyOptionsWithRequest } from 'passport-google-oauth20';
import { GOOGLE_OAUTH_CONFIG } from './google-auth.constants';
import { GoogleOAuthService } from './services/google-auth.service';

/**
 * Options for registering the Google OAuth module synchronously
 */
export interface GoogleOAuthModuleOptions {
  /** Google OAuth configuration */
  google: StrategyOptionsWithRequest;
}

/**
 * Options for registering the Google OAuth module asynchronously
 */
export interface GoogleOAuthModuleAsyncOptions {
  /** Modules to import that are required by the factory */
  imports?: any[];

  /**
   * Factory function that returns Google OAuth configuration
   * Can be async if configuration requires async operations
   */
  useFactory: (...args: any[]) => Promise<StrategyOptionsWithRequest> | StrategyOptionsWithRequest;

  /** Dependencies to inject into the factory function */
  inject?: any[];
}

@Module({})
export class GoogleOAuthModule {
  /**
   * Register the Google OAuth module with synchronous configuration
   *
   * @example
   * ```typescript
   * GoogleOAuthModule.forRoot({
   *   google: {
   *     clientId: 'your-client-id',
   *     clientSecret: 'your-client-secret',
   *     callbackURL: 'http://localhost:3000/auth/google/callback',
   *   }
   * })
   * ```
   */
  static forRoot(options: GoogleOAuthModuleOptions): DynamicModule {
    this.validateOptions(options);

    const providers: Provider[] = [
      {
        provide: GOOGLE_OAUTH_CONFIG,
        useValue: options.google,
      },
      GoogleStrategy,
      GoogleAuthGuard,
      GoogleOAuthService,
    ];

    return {
      module: GoogleOAuthModule,
      providers,
      exports: [GoogleAuthGuard, GoogleOAuthService, GoogleStrategy],
    };
  }

  /**
   * Register the Google OAuth module with asynchronous configuration
   * Use this when your configuration depends on other modules (like ConfigModule)
   *
   * @example
   * ```typescript
   * GoogleOAuthModule.forRootAsync({
   *   imports: [ConfigModule],
   *   inject: [ConfigService],
   *   useFactory: (config: ConfigService) => ({
   *     clientId: config.get('GOOGLE_CLIENT_ID'),
   *     clientSecret: config.get('GOOGLE_CLIENT_SECRET'),
   *     callbackURL: config.get('GOOGLE_REDIRECT_URL'),
   *   }),
   * })
   * ```
   */
  static forRootAsync(options: GoogleOAuthModuleAsyncOptions): DynamicModule {
    this.validateAsyncOptions(options);

    const providers: Provider[] = [
      {
        provide: GOOGLE_OAUTH_CONFIG,
        useFactory: async (...args: any[]) => {
          const config = await options.useFactory(...args);
          this.validateConfig(config);
          return config;
        },
        inject: options.inject || [],
      },
      GoogleStrategy,
      GoogleAuthGuard,
      GoogleOAuthService,
    ];

    return {
      module: GoogleOAuthModule,
      imports: options.imports || [],
      providers,
      exports: [GoogleAuthGuard, GoogleOAuthService, GoogleStrategy],
    };
  }

  /**
   * Validate synchronous configuration options
   */
  private static validateOptions(options: GoogleOAuthModuleOptions): void {
    if (!options.google) {
      throw new Error('GoogleOAuthModule: "google" configuration is required');
    }
    this.validateConfig(options.google);
  }

  /**
   * Validate asynchronous configuration options
   */
  private static validateAsyncOptions(options: GoogleOAuthModuleAsyncOptions): void {
    if (!options.useFactory) {
      throw new Error('GoogleOAuthModule: "useFactory" is required for async configuration');
    }
  }

  /**
   * Validate Google OAuth configuration
   */
  private static validateConfig(config: StrategyOptionsWithRequest): void {
    if (!config.clientID) {
      throw new Error('GoogleOAuthModule: "clientId" is required');
    }
    if (!config.clientSecret) {
      throw new Error('GoogleOAuthModule: "clientSecret" is required');
    }
    if (!config.callbackURL) {
      throw new Error('GoogleOAuthModule: "callbackURL" is required');
    }

    // Validate callback URL format
    try {
      new URL(config.callbackURL);
    } catch (error) {
      throw new Error('GoogleOAuthModule: "callbackURL" must be a valid URL');
    }
  }
}
export * from './auth.module';
export * from './google-auth.module';
export * from './services/auth.service';
export * from './services/token.service';
export * from './services/password.service';
export * from './guards/jwt-auth.guard';
export * from './guards/google-auth.guard';
export * from './guards/roles.guard';
export * from './decorators/current-user.decorator';
export * from './decorators/public.decorator';
export * from './decorators/roles.decorator';
export * from './dto/login.dto';
export * from './dto/register.dto';
export * from './dto/refresh-token.dto';
export * from './dto/token-response.dto';
export * from './dto/jwt-payload.dto';
export * from './interfaces/auth-user.interface';
export * from './interfaces/user-repository.interface';
export * from './interfaces/email-service.interface';
export * from './interfaces/auth-config.interface';
➜  auth git:(main) ✗ cat src/*/*
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
export class JwtPayloadDto {
  sub: string; // user id
  email: string;
  roles?: string[];
  iat?: number;
  exp?: number;
}
import { IsEmail, IsString, MinLength } from 'class-validator';

export class LoginDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;
}
import { IsString } from 'class-validator';

export class RefreshTokenDto {
  @IsString()
  refreshToken: string;
}
import { IsEmail, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;
}
export class TokenResponseDto {
  accessToken: string;
  refreshToken: string;
}
import { Injectable, ExecutionContext, ServiceUnavailableException, Inject } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { StrategyOptionsWithRequest } from 'passport-google-oauth20';
import { GOOGLE_OAUTH_CONFIG } from '../google-auth.constants';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
  constructor(
    @Inject(GOOGLE_OAUTH_CONFIG) private readonly config: StrategyOptionsWithRequest,
  ) {
    super();
  }

  canActivate(context: ExecutionContext) {
    // Check if Google OAuth is configured
    if (!this.config) {
      throw new ServiceUnavailableException(
        'Google OAuth authentication is not configured. Please enable Google OAuth in the auth module configuration.'
      );
    }

    return super.canActivate(context);
  }
}
import { Injectable, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    return super.canActivate(context);
  }
}
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) { }

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();

    if (!user?.roles) {
      return false;
    }

    return requiredRoles.some((role) => user.roles?.includes(role));
  }
}
import { JwtSignOptions } from "@nestjs/jwt";

export interface IJwtConfig {
  /**
   * Sign options for access tokens
   * Recommended: expiresIn between 5m-30m (e.g., '15m')
   * Should always be shorter than refresh token expiry
   */
  accessTokenSignOptions: JwtSignOptions;

  /**
   * Sign options for refresh tokens
   * Recommended: expiresIn between 7d-30d (e.g., '7d')
   * Must be longer than access token expiry
   */
  refreshTokenSignOptions: JwtSignOptions;
}

export interface IPasswordConfig {
  minLength?: number;
  requireSpecialChar?: boolean;
  requireNumber?: boolean;
  requireUppercase?: boolean;
}

export interface IGoogleOAuthConfig {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
}

/**
 * Core auth module configuration (without Google OAuth)
 */
export interface IAuthModuleConfig {
  jwt: IJwtConfig;
  password?: IPasswordConfig;
}
export interface IAuthUser {
  id: string;
  email: string;
  passwordHash?: string;
  hashedRefreshToken?: string | null;
  roles?: string[];
  isActive?: boolean;
}
export interface IEmailService {
  sendPasswordResetEmail(email: string, token: string): Promise<void>;
  sendVerificationEmail(email: string, token: string): Promise<void>;
}
import { IAuthUser } from "./auth-user.interface";

export interface IUserRepository {
  findByEmail(email: string): Promise<IAuthUser | null>;
  findById(id: string): Promise<IAuthUser | null>;
  findByGoogleId(googleId: string): Promise<IAuthUser | null>;
  create(email: string, passwordHash: string): Promise<IAuthUser>;
  createFromGoogle(email: string, googleId: string, profile: any): Promise<IAuthUser>;
  updatePassword(userId: string, passwordHash: string): Promise<void>;
  updateRefreshToken(userId: string, refreshToken: string | null): Promise<void>;
}
import { Injectable, Inject, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { TokenResponseDto } from '../dto/token-response.dto';
import type { IUserRepository } from '../interfaces/user-repository.interface';
import { IEmailService } from '../interfaces/email-service.interface';
import { PasswordService } from './password.service';
import { TokenService } from './token.service';
import { AUTH_MODULE_CONFIG, USER_REPOSITORY, EMAIL_SERVICE } from '../auth.constants';
import type { IAuthModuleConfig } from '../interfaces/auth-config.interface';

@Injectable()
export class AuthService {
  constructor(
    @Inject(USER_REPOSITORY) private readonly userRepository: IUserRepository,
    @Inject(EMAIL_SERVICE) private readonly emailService: IEmailService | null,
    @Inject(AUTH_MODULE_CONFIG) private readonly config: IAuthModuleConfig,
    private readonly passwordService: PasswordService,
    private readonly tokenService: TokenService,
  ) { }

  async register(dto: RegisterDto): Promise<TokenResponseDto> {
    // Validate password
    const validation = this.passwordService.validate(dto.password, this.config.password);
    if (!validation.valid) {
      throw new BadRequestException(validation.errors);
    }

    // Check if user exists
    const existingUser = await this.userRepository.findByEmail(dto.email);
    if (existingUser) {
      throw new BadRequestException('User with this email already exists');
    }

    // Hash password and create user
    const passwordHash = await this.passwordService.hash(dto.password);
    const user = await this.userRepository.create(dto.email, passwordHash);

    // Generate tokens
    const accessToken = this.tokenService.generateAccessToken(user);
    const refreshToken = this.tokenService.generateRefreshToken(user);

    // Store hashed refresh token
    const hashedRefreshToken = await this.tokenService.hashToken(refreshToken);
    await this.userRepository.updateRefreshToken(user.id, hashedRefreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  async login(dto: LoginDto): Promise<TokenResponseDto> {
    // Find user
    const user = await this.userRepository.findByEmail(dto.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verify password
    if (!user.passwordHash) {
      throw new UnauthorizedException('Please log in using Google');
    }

    const isPasswordValid = await this.passwordService.compare(
      dto.password,
      user.passwordHash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if user is active
    if (user.isActive === false) {
      throw new UnauthorizedException('Account is inactive');
    }

    // Generate tokens
    const accessToken = this.tokenService.generateAccessToken(user);
    const refreshToken = this.tokenService.generateRefreshToken(user);

    // Store hashed refresh token
    const hashedRefreshToken = await this.tokenService.hashToken(refreshToken);
    await this.userRepository.updateRefreshToken(user.id, hashedRefreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  async refresh(refreshToken: string): Promise<TokenResponseDto> {
    // Verify token
    const payload = await this.tokenService.verifyToken(refreshToken);

    // Find user
    const user = await this.userRepository.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('Invalid token');
    }

    // Validate refresh token against stored hash
    if (!user.hashedRefreshToken) {
      throw new UnauthorizedException('Invalid token');
    }

    const isRefreshTokenValid = await this.tokenService.compareToken(
      refreshToken,
      user.hashedRefreshToken,
    );

    if (!isRefreshTokenValid) {
      throw new UnauthorizedException('Invalid token');
    }

    // Generate new tokens
    const newAccessToken = this.tokenService.generateAccessToken(user);
    const newRefreshToken = this.tokenService.generateRefreshToken(user);

    // Update stored refresh token
    const hashedRefreshToken = await this.tokenService.hashToken(newRefreshToken);
    await this.userRepository.updateRefreshToken(user.id, hashedRefreshToken);

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }

  async logout(userId: string): Promise<void> {
    await this.userRepository.updateRefreshToken(userId, null);
  }

  async requestPasswordReset(email: string): Promise<void> {
    const user = await this.userRepository.findByEmail(email);
    if (!user) {
      // Don't reveal if user exists
      return;
    }

    const resetToken = this.passwordService.generateResetToken();

    if (this.emailService) {
      await this.emailService.sendPasswordResetEmail(email, resetToken);
    }

    // Note: You'll need to store the reset token with expiry
    // This is left to the consuming app to implement
  }

  async googleLogin(googleProfile: any): Promise<TokenResponseDto> {
    // Check if user exists by Google ID
    let user = await this.userRepository.findByGoogleId(googleProfile.googleId);

    if (!user) {
      // Check if user exists by email
      user = await this.userRepository.findByEmail(googleProfile.email);

      if (user) {
        // User exists with this email but no Google ID
        // This means they registered with email/password
        // You might want to link the accounts or throw an error
        throw new BadRequestException('An account with this email already exists. Please log in with your password.');
      }

      // Create new user from Google profile
      user = await this.userRepository.createFromGoogle(
        googleProfile.email,
        googleProfile.googleId,
        googleProfile,
      );
    }

    // Generate tokens
    const accessToken = this.tokenService.generateAccessToken(user);
    const refreshToken = this.tokenService.generateRefreshToken(user);

    // Store hashed refresh token
    const hashedRefreshToken = await this.tokenService.hashToken(refreshToken);
    await this.userRepository.updateRefreshToken(user.id, hashedRefreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }
}
import { Injectable, Inject, BadRequestException } from '@nestjs/common';
import { USER_REPOSITORY } from '../auth.constants';
import type { IUserRepository } from '../interfaces/user-repository.interface';
import { TokenService } from './token.service';
import { TokenResponseDto } from '../dto/token-response.dto';
import type { StrategyOptionsWithRequest } from 'passport-google-oauth20';
import { GOOGLE_OAUTH_CONFIG } from '../google-auth.constants';

export interface GoogleProfile {
  googleId: string;
  email: string;
  displayName?: string;
  firstName?: string;
  lastName?: string;
  photo?: string;
  accessToken?: string;
}

@Injectable()
export class GoogleOAuthService {
  constructor(
    @Inject(GOOGLE_OAUTH_CONFIG) private readonly config: StrategyOptionsWithRequest,
    @Inject(USER_REPOSITORY) private readonly userRepository: IUserRepository,
    private readonly tokenService: TokenService,
  ) { }

  /**
   * Handle Google OAuth login/signup
   */
  async handleGoogleLogin(profile: GoogleProfile): Promise<TokenResponseDto> {
    // Check if user exists by Google ID
    let user = await this.userRepository.findByGoogleId(profile.googleId);

    if (!user) {
      // Check if user exists by email
      user = await this.userRepository.findByEmail(profile.email);

      if (user) {
        // User exists with this email but no Google ID
        // This means they registered with email/password
        throw new BadRequestException(
          'An account with this email already exists. Please log in with your password.'
        );
      }

      // Create new user from Google profile
      user = await this.userRepository.createFromGoogle(
        profile.email,
        profile.googleId,
        profile,
      );
    }

    // Check if user is active
    if (user.isActive === false) {
      throw new BadRequestException('Account is inactive');
    }

    // Generate tokens
    const accessToken = this.tokenService.generateAccessToken(user);
    const refreshToken = this.tokenService.generateRefreshToken(user);

    // Store hashed refresh token
    const hashedRefreshToken = await this.tokenService.hashToken(refreshToken);
    await this.userRepository.updateRefreshToken(user.id, hashedRefreshToken);

    return {
      accessToken,
      refreshToken,
    };
  }

  /**
   * Get Google OAuth configuration (useful for debugging)
   */
  getConfig(): Omit<StrategyOptionsWithRequest, 'clientSecret'> {
    return {
      ...this.config
    };
  }
}
import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';
import { IPasswordConfig } from '../interfaces/auth-config.interface';

@Injectable()
export class PasswordService {
  async hash(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id, // Most secure variant
      memoryCost: 2 ** 16, // 64 MB
      timeCost: 3,
      parallelism: 1,
    });
  }

  async compare(password: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      return false;
    }
  }

  generateResetToken(): string {
    return randomBytes(32).toString('hex');
  }

  validate(password: string, config?: IPasswordConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (config?.minLength && password.length < config.minLength) {
      errors.push(`Password must be at least ${config.minLength} characters`);
    }

    if (config?.requireSpecialChar && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }

    if (config?.requireNumber && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (config?.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    return { valid: errors.length === 0, errors };
  }
}
import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { JwtService, JwtVerifyOptions } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { JwtPayloadDto } from '../dto/jwt-payload.dto';
import { IAuthUser } from '../interfaces/auth-user.interface';
import { AUTH_MODULE_CONFIG } from '../auth.constants';
import type { IAuthModuleConfig } from '../interfaces/auth-config.interface';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(AUTH_MODULE_CONFIG) private readonly config: IAuthModuleConfig,
  ) { }

  generateAccessToken(user: IAuthUser): string {
    const payload: JwtPayloadDto = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
    };

    return this.jwtService.sign(payload, {
      ...this.config.jwt.accessTokenSignOptions
    });
  }

  generateRefreshToken(user: IAuthUser): string {
    const payload: JwtPayloadDto = {
      sub: user.id,
      email: user.email,
    };

    return this.jwtService.sign(payload, {
      ...this.config.jwt.refreshTokenSignOptions
    });
  }

  async verifyToken(token: string, isRefreshToken: boolean = false): Promise<JwtPayloadDto> {
    try {
      const signOptions = isRefreshToken
        ? this.config.jwt.refreshTokenSignOptions
        : this.config.jwt.accessTokenSignOptions;

      const verifyOptions: JwtVerifyOptions = {
        secret: signOptions.secret,
        algorithms: signOptions.algorithm ? [signOptions.algorithm] : undefined,
        audience: signOptions.audience as any,
        issuer: signOptions.issuer,
        ignoreExpiration: false,
      };

      return this.jwtService.verify(token, verifyOptions);
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async hashToken(token: string): Promise<string> {
    return argon2.hash(token);
  }

  async compareToken(token: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, token);
    } catch (error) {
      return false;
    }
  }
}
import { Injectable, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, type StrategyOptionsWithRequest, VerifyCallback } from 'passport-google-oauth20';
import { GOOGLE_OAUTH_CONFIG } from '../google-auth.constants';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(@Inject(GOOGLE_OAUTH_CONFIG) config: StrategyOptionsWithRequest) {
    super({
      ...config,
      scope: config.scope || ['email', 'profile'],
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, emails, name, displayName, photos } = profile;

    const user = {
      googleId: id,
      email: emails[0].value,
      displayName: displayName || `${name?.givenName || ''} ${name?.familyName || ''}`.trim(),
      firstName: name?.givenName,
      lastName: name?.familyName,
      photo: photos?.[0]?.value,
      accessToken,
    };

    done(null, user);
  }
}
import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayloadDto } from '../dto/jwt-payload.dto';
import type { IUserRepository } from '../interfaces/user-repository.interface';
import { AUTH_MODULE_CONFIG, USER_REPOSITORY } from '../auth.constants';
import type { IAuthModuleConfig } from '../interfaces/auth-config.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject(AUTH_MODULE_CONFIG) config: IAuthModuleConfig,
    @Inject(USER_REPOSITORY) private readonly userRepository: IUserRepository,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.jwt.accessTokenSignOptions.secret,
    });
  }

  async validate(payload: JwtPayloadDto) {
    const user = await this.userRepository.findById(payload.sub);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.isActive === false) {
      throw new UnauthorizedException('Account is inactive');
    }

    return {
      id: user.id,
      email: user.email,
      roles: user.roles,
    };
  }
}
import { IJwtConfig } from '../interfaces/auth-config.interface';

/**
 * Converts JWT expiry string to milliseconds
 * Supports: '15m', '7d', '24h', '60s', etc.
 */
export function parseExpiryToMs(expiry: string | number | undefined): number | null {
  if (!expiry) return null;
  if (typeof expiry === 'number') return expiry * 1000;

  const matches = expiry.match(/^(\d+)([smhd])$/);
  if (!matches) return null;

  const value = parseInt(matches[1], 10);
  const unit = matches[2];

  const multipliers: Record<string, number> = {
    s: 1000,
    m: 60 * 1000,
    h: 60 * 60 * 1000,
    d: 24 * 60 * 60 * 1000,
  };

  return value * multipliers[unit];
}

/**
 * Validates JWT configuration to ensure proper token separation
 * Throws errors for critical misconfigurations
 */
export function validateJwtConfig(config: IJwtConfig): void {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate that both expiresIn are set
  const accessExpiry = config.accessTokenSignOptions?.expiresIn;
  const refreshExpiry = config.refreshTokenSignOptions?.expiresIn;

  if (!accessExpiry) {
    errors.push('Access token expiresIn must be specified');
  }

  if (!refreshExpiry) {
    errors.push('Refresh token expiresIn must be specified');
  }

  if (accessExpiry && refreshExpiry) {
    const accessMs = parseExpiryToMs(accessExpiry);
    const refreshMs = parseExpiryToMs(refreshExpiry);

    if (accessMs === null) {
      errors.push(`Invalid access token expiresIn format: "${accessExpiry}". Use formats like "15m", "1h", "7d"`);
    }

    if (refreshMs === null) {
      errors.push(`Invalid refresh token expiresIn format: "${refreshExpiry}". Use formats like "15m", "1h", "7d"`);
    }

    if (accessMs !== null && refreshMs !== null) {
      // Critical: Refresh must be longer than access
      if (refreshMs <= accessMs) {
        errors.push(
          `Refresh token expiry (${refreshExpiry}) must be longer than access token expiry (${accessExpiry}). ` +
          `This is a critical security requirement.`
        );
      }

      // Warning: Access token too long
      const thirtyMinutes = 30 * 60 * 1000;
      if (accessMs > thirtyMinutes) {
        warnings.push(
          `Access token expiry (${accessExpiry}) is longer than 30 minutes. ` +
          `Consider using shorter-lived access tokens (5-15 minutes) for better security.`
        );
      }

      // Warning: Refresh token too short
      const sevenDays = 7 * 24 * 60 * 60 * 1000;
      if (refreshMs < sevenDays) {
        warnings.push(
          `Refresh token expiry (${refreshExpiry}) is shorter than 7 days. ` +
          `Consider using longer-lived refresh tokens (7-30 days) for better user experience.`
        );
      }

      // Warning: Tokens are too similar (within 10% difference)
      const difference = refreshMs - accessMs;
      const percentDifference = (difference / accessMs) * 100;
      if (percentDifference < 10) {
        warnings.push(
          `Access and refresh token expiry times are very similar (${accessExpiry} vs ${refreshExpiry}). ` +
          `Refresh tokens should typically be much longer-lived than access tokens.`
        );
      }
    }
  }

  // Check for audience separation (recommended but not required)
  const accessAud = config.accessTokenSignOptions?.audience;
  const refreshAud = config.refreshTokenSignOptions?.audience;

  if (accessAud && refreshAud && accessAud === refreshAud) {
    warnings.push(
      `Access and refresh tokens have the same audience ("${accessAud}"). ` +
      `Consider using different audiences (e.g., "api" vs "refresh") for enhanced security.`
    );
  }

  // Throw if there are errors
  if (errors.length > 0) {
    throw new Error(
      `JWT Configuration Validation Failed:\n${errors.map(e => `  - ${e}`).join('\n')}`
    );
  }

  // Log warnings in development
  if (warnings.length > 0 && process.env.NODE_ENV !== 'production') {
    console.warn('\n⚠️  JWT Configuration Warnings:');
    warnings.forEach(w => console.warn(`  - ${w}`));
    console.warn('');
  }
}

/**
 * Provides recommended default configurations
 */
export const RECOMMENDED_JWT_CONFIG = {
  development: {
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
  },
  production: {
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '30d',
  },
} as const;
➜  auth git:(main) ✗

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