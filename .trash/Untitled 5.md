➜  auth git:(main) tree src
src
├── auth-jwt
│   ├── auth-jwt.module.ts
│   ├── decorators
│   │   ├── current-user.decorator.ts
│   │   ├── index.ts
│   │   ├── public.decorator.ts
│   │   └── roles.decorator.ts
│   ├── jwt-auth.guard.ts
│   ├── jwt.strategy.ts
│   ├── roles.guard.ts
│   └── token.service.ts
├── auth.module.ts
├── constants
│   ├── index.ts
│   └── tokens.ts
├── credentials-auth
│   ├── credentials-auth.module.ts
│   ├── credentials-auth.service.ts
│   └── password.service.ts
├── google-oauth
│   ├── google-auth.guard.ts
│   ├── google-oauth.module.ts
│   ├── google.service.ts
│   └── google.strategy.ts
├── index.ts
└── interfaces
    ├── authentication
    │   ├── auth-response.interface.ts
    │   ├── auth-user-data.interface.ts
    │   ├── index.ts
    │   ├── jwt-payload.interface.ts
    │   └── token-pair.interface.ts
    ├── configuration
    │   ├── auth-module-async-options.interface.ts
    │   ├── auth-module-config.interface.ts
    │   ├── credentials-auth-config.interface.ts
    │   ├── google-oauth-config.interface.ts
    │   ├── index.ts
    │   └── jwt-config.interface.ts
    ├── index.ts
    ├── operation-contracts
    │   ├── index.ts
    │   ├── login.interface.ts
    │   ├── oauth-callback.interface.ts
    │   ├── password-change.interface.ts
    │   ├── registration.interface.ts
    │   └── token-refresh.interface.ts
    └── user-model
        ├── authenticated-request.interface.ts
        ├── index.ts
        ├── request-user.interface.ts
        ├── user.interface.ts
        └── user-repository.interface.ts

11 directories, 43 files
➜  auth git:(main) cat src/*.ts
import { DynamicModule, Module, Provider, Global } from '@nestjs/common';
import {
  AuthModuleAsyncOptions,
  AuthModuleConfig,
  AuthUser,
} from './interfaces';
import { AUTH_CONFIG, AUTH_CAPABILITIES, PROVIDERS } from './constants';
import { AuthJwtModule } from './auth-jwt/auth-jwt.module';
import { GoogleOAuthModule } from './google-oauth/google-oauth.module';
import { CredentialsAuthModule } from './credentials-auth/credentials-auth.module';

@Global()
@Module({})
export class AuthModule {
  static forRootAsync<User extends Partial<AuthUser> = any>(
    options: AuthModuleAsyncOptions<User>,
  ): DynamicModule {
    const configProvider: Provider = {
      provide: AUTH_CONFIG,
      useFactory: options.useFactory,
      inject: options.inject || [],
    };

    const userRepositoryProvider: Provider = {
      provide: PROVIDERS.USER_REPOSITORY,
      useClass: options.userRepository,
    };

    const jwtConfigProvider: Provider = {
      provide: AUTH_CAPABILITIES.JWT,
      useFactory: (config: AuthModuleConfig) => config.jwt,
      inject: [AUTH_CONFIG],
    };

    const credentialsConfigProvider: Provider = {
      provide: AUTH_CAPABILITIES.CREDENTIALS,
      useFactory: (config: AuthModuleConfig) =>
        options.enabledCapabilities.includes('credentials')
          ? config.credentials
          : undefined,
      inject: [AUTH_CONFIG],
    };

    const googleConfigProvider: Provider = {
      provide: AUTH_CAPABILITIES.GOOGLE,
      useFactory: (config: AuthModuleConfig) =>
        options.enabledCapabilities.includes('google')
          ? config.google
          : undefined,
      inject: [AUTH_CONFIG],
    };

    const imports = [...(options.imports || []), AuthJwtModule.forRoot()];

    const exports = [
      AUTH_CONFIG,
      AUTH_CAPABILITIES.JWT,
      PROVIDERS.USER_REPOSITORY,
      AuthJwtModule,
    ];

    if (options.enabledCapabilities.includes('credentials')) {
      imports.push(CredentialsAuthModule.forRoot());
      exports.push(AUTH_CAPABILITIES.CREDENTIALS, CredentialsAuthModule);
    } else {
      exports.push(AUTH_CAPABILITIES.CREDENTIALS);
    }

    if (options.enabledCapabilities.includes('google')) {
      imports.push(GoogleOAuthModule.forRoot());
      exports.push(AUTH_CAPABILITIES.GOOGLE, GoogleOAuthModule);
    } else {
      exports.push(AUTH_CAPABILITIES.GOOGLE);
    }

    return {
      module: AuthModule,
      global: true,
      imports,
      providers: [
        configProvider,
        userRepositoryProvider,
        jwtConfigProvider,
        credentialsConfigProvider,
        googleConfigProvider,
      ],
      exports,
    };
  }
}
export * from './interfaces';
export * from './auth.module';

export * from './auth-jwt/decorators/public.decorator';
export * from './auth-jwt/decorators/roles.decorator';
export * from './auth-jwt/decorators/current-user.decorator';
export * from './auth-jwt/jwt-auth.guard';
export * from './auth-jwt/roles.guard';

export * from './credentials-auth/credentials-auth.service';

export * from './google-oauth/google.service';
export * from './google-oauth/google-auth.guard';
➜  auth git:(main) cat src/*/*.ts
import { DynamicModule, Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AUTH_CAPABILITIES } from '../constants';
import { TokenService } from './token.service';
import { JwtStrategy } from './jwt.strategy';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RolesGuard } from './roles.guard';
import { JwtConfig } from '../interfaces';

@Module({})
export class AuthJwtModule {
  static forRoot(): DynamicModule {
    return {
      module: AuthJwtModule,
      imports: [
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
          useFactory: (jwtConfig: JwtConfig) => ({
            ...jwtConfig.accessTokenSignOptions,
          }),
          inject: [AUTH_CAPABILITIES.JWT],
        }),
      ],
      providers: [TokenService, JwtStrategy, JwtAuthGuard, RolesGuard],
      exports: [TokenService, JwtAuthGuard, RolesGuard],
    };
  }
}
import { Injectable, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from './decorators';

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
import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, SecretOrKeyProvider, Strategy } from 'passport-jwt';
import type { JwtConfig, JwtPayload, RequestUser } from '../interfaces';
import { AUTH_CAPABILITIES } from '../constants';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly config: JwtConfig,
  ) {
    const secretOrKeyProvider: SecretOrKeyProvider = (
      request,
      rawJwtToken,
      done,
    ) => {
      const secretOrKey =
        config.accessTokenSignOptions.secret ??
        config.accessTokenSignOptions.privateKey;

      done(secretOrKey);
    };
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider,
    });
  }

  async validate(payload: JwtPayload): Promise<RequestUser> {
    if (!payload.sub || !payload.roles) {
      throw new UnauthorizedException('Invalid token payload');
    }
    return {
      userId: payload.sub,
      roles: payload.roles,
    };
  }
}
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from './decorators';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

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
import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { JwtService, JwtVerifyOptions } from '@nestjs/jwt';
import { AUTH_CAPABILITIES } from '../constants';
import type {
  AuthUser,
  BaseUser,
  JwtConfig,
  JwtPayload,
  TokenPair,
} from '../interfaces';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly config: JwtConfig,
  ) {}

  generateAccessToken(user: BaseUser): string {
    const payload: JwtPayload = {
      sub: user.id,
      roles: user.roles,
    };

    return this.jwtService.sign(payload, {
      ...this.config.accessTokenSignOptions,
    });
  }

  generateRefreshToken(user: { id: string }): string {
    const payload = { sub: user.id };

    return this.jwtService.sign(payload, {
      ...this.config.refreshTokenSignOptions,
    });
  }

  generateTokens(user: AuthUser): TokenPair {
    return {
      accessToken: this.generateAccessToken(user),
      refreshToken: this.generateRefreshToken({ id: user.id }),
    };
  }

  async verifyAccessToken(token: string): Promise<JwtPayload> {
    try {
      return await this.jwtService.verifyAsync<JwtPayload>(
        token,
        this.config.accessTokenSignOptions as JwtVerifyOptions,
      );
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Access token has expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid access token');
      }
      throw new UnauthorizedException('Token verification failed');
    }
  }

  async verifyRefreshToken(token: string): Promise<{ sub: string }> {
    try {
      return await this.jwtService.verifyAsync<{ sub: string }>(
        token,
        this.config.refreshTokenSignOptions as JwtVerifyOptions,
      );
    } catch (error: any) {
      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Refresh token has expired');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid refresh token');
      }
      throw new UnauthorizedException('Token verification failed');
    }
  }

  decodeToken(token: string): JwtPayload | null {
    try {
      return this.jwtService.decode(token) as JwtPayload;
    } catch {
      return null;
    }
  }
}
export * from './tokens';
export const AUTH_CONFIG = Symbol('AUTH_CONFIG');

export const AUTH_CAPABILITIES = Object.freeze({
  JWT: Symbol('JWT_CONFIG'),
  CREDENTIALS: Symbol('CREDENTIALS_CONFIG'),
  GOOGLE: Symbol('GOOGLE_CONFIG'),
});

export const PROVIDERS = Object.freeze({
  USER_REPOSITORY: Symbol('USER_REPOSITORY'),
});
import { DynamicModule, Module } from '@nestjs/common';
import { PasswordService } from './password.service';
import { CredentialsAuthService } from './credentials-auth.service';

@Module({})
export class CredentialsAuthModule {
  static forRoot(): DynamicModule {
    return {
      module: CredentialsAuthModule,
      providers: [PasswordService, CredentialsAuthService],
      exports: [CredentialsAuthService, PasswordService],
    };
  }
}
import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { PROVIDERS } from '../constants/tokens';
import type {
  AuthResponse,
  AuthUser,
  LoginInput,
  LoginResponse,
  PasswordChangeInput,
  PasswordSetInput,
  RegistrationInput,
  UserRepository,
} from '../interfaces';
import { PasswordService } from './password.service';
import { TokenService } from '../auth-jwt/token.service';

@Injectable()
export class CredentialsAuthService<User extends Partial<AuthUser>> {
  constructor(
    @Inject(PROVIDERS.USER_REPOSITORY)
    private readonly userRepository: UserRepository<User>,
    private readonly passwordService: PasswordService,
    private readonly tokenService: TokenService,
  ) {}

  /**
   * Register a new user with email and password.
   * accepts any DTO that implements CredentialsCreateInput
   */
  async register<UserData extends RegistrationInput = RegistrationInput>(
    userData: UserData,
  ): Promise<AuthResponse> {
    const existingUser = await this.userRepository.findByEmail(userData.email);
    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const hashedPassword = await this.passwordService.hash(userData.password);

    // Create user with all properties from dto (including extra fields)
    const user = await this.userRepository.create({
      ...userData,
      password: hashedPassword,
    } as unknown as Partial<User>);

    const tokens = this.tokenService.generateTokens(user as AuthUser);

    return {
      user: {
        id: user.id!,
        email: user.email!,
        roles: user.roles!,
        isEmailVerified: user.isEmailVerified!,
      },
      tokens,
    };
  }

  /**
   * Login with email and password.
   * Accepts any DTO that has email and password
   */
  async login<UserData extends LoginInput = LoginInput>(
    credentials: UserData,
  ): Promise<LoginResponse> {
    const user = await this.userRepository.findByEmail(credentials.email);
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check if user has a password (might be OAuth-only user)
    if (!user.password) {
      throw new UnauthorizedException(
        'This account uses social login. Please login with Google.',
      );
    }

    // Verify password
    const isPasswordValid = await this.passwordService.verify(
      credentials.password,
      user.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate tokens
    const tokens = this.tokenService.generateTokens(user as AuthUser);

    return {
      user: {
        id: user.id!,
        email: user.email!,
        roles: user.roles!,
        isEmailVerified: user.isEmailVerified!,
      },
      tokens,
    };
  }

  /**
   * Change user password (requires current password).
   */
  async changePassword(
    input: PasswordChangeInput,
  ): Promise<{ message: string }> {
    const user = await this.userRepository.findById(input.userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if user has a password
    if (!user.password) {
      throw new BadRequestException(
        'Cannot change password for OAuth-only accounts',
      );
    }

    // Verify current password
    const isCurrentPasswordValid = await this.passwordService.verify(
      input.currentPassword,
      user.password,
    );

    if (!isCurrentPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    const isSamePassword = await this.passwordService.verify(
      input.newPassword,
      user.password,
    );
    if (isSamePassword) {
      throw new BadRequestException(
        'New password must be different from current password',
      );
    }

    // Hash new password
    const hashedPassword = await this.passwordService.hash(input.newPassword);

    await this.userRepository.update(input.userId, {
      password: hashedPassword,
    } as Partial<User>);

    return { message: 'Password changed successfully' };
  }

  /**
   * Set or reset password (admin operation or forgot password flow).
   * Does NOT require current password.
   */
  async setPassword(input: PasswordSetInput): Promise<{ message: string }> {
    // Find user
    const user = await this.userRepository.findById(input.userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const hashedPassword = await this.passwordService.hash(input.newPassword);

    // Update user
    await this.userRepository.update(input.userId, {
      password: hashedPassword,
    } as Partial<User>);

    return { message: 'Password set successfully' };
  }

  /**
   * Verify user's email (call this after email verification token is validated).
   */
  async verifyEmail(userId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.isEmailVerified) {
      return { message: 'Email already verified' };
    }

    await this.userRepository.update(userId, {
      isEmailVerified: true,
    } as Partial<User>);

    return { message: 'Email verified successfully' };
  }

  /**
   * Validate user exists and is active (useful for token refresh).
   */
  async validateUser(userId: string): Promise<User> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return user;
  }

  // TODO: Implement request password reset.
}
import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';
import { randomBytes } from 'crypto';

@Injectable()
export class PasswordService {
  async hash(password: string): Promise<string> {
    return argon2.hash(password);
  }

  async verify(password: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      return false;
    }
  }

  generateResetToken(): string {
    return randomBytes(32).toString('hex');
  }
}
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {}
import { DynamicModule, Module } from '@nestjs/common';
import { GoogleStrategy } from './google.strategy';
import { GoogleAuthService } from './google.service';
import { GoogleAuthGuard } from './google-auth.guard';

@Module({})
export class GoogleOAuthModule {
  static forRoot(): DynamicModule {
    return {
      module: GoogleOAuthModule,
      providers: [GoogleStrategy, GoogleAuthGuard, GoogleAuthService],
      exports: [GoogleAuthService, GoogleAuthGuard],
    };
  }
}
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import type {
  AuthUser,
  RequestUser,
  TokenPair,
  UserRepository,
} from '../interfaces';
import { PROVIDERS } from '../constants';
import { TokenService } from '../auth-jwt/token.service';

export interface GoogleAuthResponse {
  user: {
    id: string;
    email: string;
    roles: string[];
    isEmailVerified: boolean;
  };
  tokens: TokenPair;
}

@Injectable()
export class GoogleAuthService<User extends Partial<AuthUser>> {
  constructor(
    @Inject(PROVIDERS.USER_REPOSITORY)
    private readonly userRepository: UserRepository<User>,
    private readonly tokenService: TokenService,
  ) {}

  /**
   * Complete the Google OAuth flow by generating JWT tokens.
   * Call this in your callback controller after Passport attaches user to request.
   */
  async handleOAuthCallback(
    requestUser: RequestUser,
  ): Promise<GoogleAuthResponse> {
    // Fetch full user data
    const user = await this.userRepository.findById(requestUser.userId);
    if (!user) {
      throw new UnauthorizedException('User not found after OAuth');
    }

    // Generate JWT tokens
    const tokens = this.tokenService.generateTokens(user as AuthUser);

    return {
      user: {
        id: user.id!,
        email: user.email!,
        roles: user.roles!,
        isEmailVerified: user.isEmailVerified!,
      },
      tokens,
    };
  }

  /**
   * Unlink Google account from user.
   * Useful if user wants to remove Google login but keep password login.
   */
  async unlinkGoogleAccount(userId: string): Promise<{ message: string }> {
    const user = await this.userRepository.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Check if user has another way to login
    if (!user.password && user.googleId) {
      throw new UnauthorizedException(
        'Cannot unlink Google account. Please set a password first.',
      );
    }

    // Unlink Google
    await this.userRepository.update(userId, {
      googleId: null,
    } as Partial<User>);

    return { message: 'Google account unlinked successfully' };
  }

  /**
   * Check if a user has Google OAuth linked.
   */
  async isGoogleLinked(userId: string): Promise<boolean> {
    const user = await this.userRepository.findById(userId);
    return !!user?.googleId;
  }
}
import { Injectable, Inject } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import type {
  AuthUser,
  GoogleOAuthConfig,
  GoogleUserRepository,
  RequestUser,
} from '../interfaces';
import { AUTH_CAPABILITIES, PROVIDERS } from '../constants/tokens';

@Injectable()
export class GoogleStrategy<User extends AuthUser> extends PassportStrategy(
  Strategy,
  'google',
) {
  constructor(
    @Inject(AUTH_CAPABILITIES.GOOGLE)
    private readonly config: GoogleOAuthConfig | undefined,
    @Inject(PROVIDERS.USER_REPOSITORY)
    private readonly user: GoogleUserRepository<User>,
  ) {
    if (!config) {
      throw new Error(
        'GoogleOAuthModule is imported but Google config is not provided. ' +
          'Either remove the module or provide google config in AuthModule.forRootAsync()',
      );
    }
    super({
      ...config,
      scope: config.scope || ['email', 'profile'],
      passReqToCallback: config.passReqToCallback || false,
    });
  }

  async validate(
    _accessToken: string,
    _refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<any> {
    const { id, emails } = profile;
    const email = emails?.[0]?.value;

    if (!email) {
      return done(new Error('No email found in Google profile'));
    }

    let user: Pick<User, 'id' | 'roles'> | null =
      await this.user.findByGoogleId(id);

    if (!user) {
      user = await this.user.findByEmail(email);
      if (user) {
        user = await this.user.update(user.id, {
          googleId: id,
        } as Partial<User>);
      } else {
        user = await this.user.create({
          email,
          googleId: id,
          isEmailVerified: true,
        } as Partial<User>);
      }
    }
    const requestUser: RequestUser = {
      userId: user.id,
      roles: user.roles,
    };

    done(null, requestUser);
  }
}
export * from './configuration';
export * from './user-model';
export * from './authentication';
export * from './operation-contracts';
➜  auth git:(main) cat src/*/*/*.ts
import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { RequestUser } from '../../interfaces';

export const CurrentUser = createParamDecorator(
  (
    data: keyof RequestUser | undefined,
    ctx: ExecutionContext,
  ): RequestUser | string | string[] => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user as RequestUser;

    return data ? user?.[data] : user;
  },
);
export * from './current-user.decorator';
export * from './public.decorator';
export * from './roles.decorator';
export { IS_PUBLIC_KEY } from './public.decorator';
export { ROLES_KEY } from './roles.decorator';
import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
import { BaseUser } from '../user-model';
import { TokenPair } from './token-pair.interface';

/**
 * Standard response format for authentication operations
 */
export interface AuthResponse {
  user: BaseUser;
  tokens: TokenPair;
}
import { BaseUser } from '../user-model';

/**
 * Safe user data exposed in authentication responses
 * Excludes sensitive fields like password
 */
export type AuthUserData = Omit<BaseUser, 'password' | 'googleId'>;
export * from './jwt-payload.interface';
export * from './token-pair.interface';
export * from './auth-response.interface';
export * from './auth-user-data.interface';
/**
 * Structure of JWT token payload
 */
export interface JwtPayload {
  sub: string; // Subject (user ID)
  roles: string[]; // User roles
}
/**
 * Pair of access and refresh tokens returned after successful authentication
 */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}
import { ModuleMetadata, FactoryProvider } from '@nestjs/common';
import { Type } from '@nestjs/common';
import { AuthModuleConfig } from './auth-module-config.interface';
import { AuthUser, UserRepository } from '../user-model';

/**
 * Asynchronous configuration options for the AuthModule
 * Allows consumers to provide configuration via factories
 */
export interface AuthModuleAsyncOptions<
  User extends Partial<AuthUser> = Partial<AuthUser>,
>
  extends
    Pick<ModuleMetadata, 'imports'>,
    Pick<FactoryProvider<AuthModuleConfig>, 'useFactory' | 'inject'> {
  userRepository: Type<UserRepository<User>>;
  enabledCapabilities: ('credentials' | 'google')[];
}
import { JwtConfig } from './jwt-config.interface';
import { CredentialsAuthConfig } from './credentials-auth-config.interface';
import { GoogleOAuthConfig } from './google-oauth-config.interface';

/**
 * Main configuration for the authentication module
 * Optional properties determine which authentication strategies are enabled
 */
export interface AuthModuleConfig {
  jwt: JwtConfig;
  credentials?: CredentialsAuthConfig;
  google?: GoogleOAuthConfig;
}
/**
 * Configuration specific to email/password authentication
 */
export interface CredentialsAuthConfig {
  // For future use: password reset token expiry, password policies, etc.
  // passwordResetTokenExpiry?: number;
  // passwordPolicy?: PasswordPolicy;
}
import { StrategyOptionsWithRequest } from 'passport-google-oauth20';

/**
 * Configuration for Google OAuth authentication
 * Uses passport-google-oauth20 strategy options
 */
export type GoogleOAuthConfig = StrategyOptionsWithRequest;
export * from './auth-module-config.interface';
export * from './auth-module-async-options.interface';
export * from './jwt-config.interface';
export * from './credentials-auth-config.interface';
export * from './google-oauth-config.interface';
import { JwtSignOptions } from '@nestjs/jwt';

/**
 * Configuration for JWT token generation and validation
 */
export interface JwtConfig {
  accessTokenSignOptions: JwtSignOptions;
  refreshTokenSignOptions: JwtSignOptions;
}
export * from './login.interface';
export * from './registration.interface';
export * from './password-change.interface';
export * from './token-refresh.interface';
export * from './oauth-callback.interface';
import { BaseUser } from '../user-model/user.interface';

/**
 * Input data required for login operation
 */
export interface LoginInput {
  email: string;
  password: string;
}

/**
 * Response data returned from login operation
 */
export interface LoginResponse {
  user: BaseUser;
  tokens: {
    accessToken: string;
    refreshToken: string;
  };
}
import { AuthResponse } from '../authentication';
import { RequestUser } from '../user-model';

/**
 * Response from Google OAuth callback operation
 */
export interface GoogleOAuthCallbackResponse extends AuthResponse {}

/**
 * Input for Google OAuth callback (user data from Passport)
 */
export interface GoogleOAuthCallbackInput {
  requestUser: RequestUser;
}
/**
 * Input data for changing user password (requires current password)
 */
export interface PasswordChangeInput {
  userId: string;
  currentPassword: string;
  newPassword: string;
}

/**
 * Input data for setting/resetting password (admin or forgot password flow)
 */
export interface PasswordSetInput {
  userId: string;
  newPassword: string;
}
/**
 * Input data required for user registration
 */
export interface RegistrationInput {
  email: string;
  password: string;
  // Can be extended with additional fields
}
/**
 * Input data for refreshing access token
 */
export interface TokenRefreshInput {
  refreshToken: string;
}
import { Request } from 'express';
import { RequestUser } from './request-user.interface';

/**
 * Extended Express Request with authenticated user data
 */
export interface AuthenticatedRequest extends Request {
  user: RequestUser;
}
export * from './user.interface';
export * from './request-user.interface';
export * from './authenticated-request.interface';
export * from './user-repository.interface';
/**
 * Minimal, safe user data stored in the request object after authentication
 * This is what gets attached to HTTP requests and passed to controllers
 */
export interface RequestUser {
  userId: string;
  roles: string[];
}
/**
 * Base mandatory fields for any user in the authentication system
 */
export interface BaseUser {
  id: string;
  email: string;
  isEmailVerified: boolean;
  roles: string[];
}

/**
 * Fields specific to password-based authentication
 */
export interface CredentialsUser {
  password?: string | null;
}

/**
 * Fields specific to Google OAuth authentication
 */
export interface GoogleUser {
  googleId?: string | null;
}

/**
 * The complete user entity type combining all possible authentication methods
 * Consumers implement concrete types that intersect with only the features they need
 */
export type AuthUser = BaseUser & CredentialsUser & GoogleUser;
import { AuthUser } from './user.interface';

/**
 * Contract for consumer's User Repository implementation
 * Must be implemented by consumers to provide data persistence
 */
export interface UserRepository<User extends Partial<AuthUser>> {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  create(data: Partial<User>): Promise<User>;
  update(id: string, data: Partial<User>): Promise<User>;
}

/**
 * Extended repository interface for Google OAuth
 * Adds method to find users by their Google ID
 */
export type GoogleUserRepository<User extends Partial<AuthUser>> =
  UserRepository<User> & {
    findByGoogleId(googleId: string): Promise<User | null>;
  };
➜  auth git:(main)


We want to analyse and illustrate with markdown mermaid:
Architecture 
Hierarchy control 
Structural partitioning 
Modularity 
...