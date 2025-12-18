

Credentials Auth module, has a service that requires token service for issuing tokens (access and refresh) and other token operations. Credentials Auth module also has password service. Credentials Auth module will need user service for user operations. It exports its service for consumer.

Google 0auth module has service, strategy and guard. It needs user service for user operations. It needs token service for issuing tokens and other token operations. It exports its guard and service for consumer.

To make token service sharing easy between credentials Auth and Google 0auth, we can have a dedicated `AuthJwtModule`, this module should also house the JWT strategy and guard, that means it'll export token service and JWT Auth guard 

Should have a generic internal user type/interface, the generic interface must contain some expected fields that will be used internally.

User service must have a predefined interface/type that will be implemented by the consumer. It should be generic.


```ts
import { JwtSignOptions } from "@nestjs/jwt";
import { StrategyOptionsWithRequest as GoogleStrategyConfig } from "passport-google-oauth20";

export interface CredentialsAuthConfig {
  requireEmailVerification?: boolean;
  passwordResetTokenExpiry?: number;
}

export interface JwtConfig {
  accessTokenSignOptions: JwtSignOptions;
  refreshTokenSignOptions: JwtSignOptions;
}

/**
 * The main configuration object for the entire authentication module.
 * Optional properties determine which sub-modules are enabled.
 */
export interface AuthModuleConfig {
  jwt: JwtConfig;
  credentials?: CredentialsAuthConfig;
  google?: GoogleStrategyConfig;
}
import { Request } from "express";

/**
 * Base mandatory fields for any user in the system.
 */
export interface BaseUser {
  id: string;
  email: string;
  isEmailVerified: boolean;
  roles: string[];
}

export interface CredentialsUser {
  password?: string | null;
}

export interface GoogleUser {
  googleId?: string | null;
}

/**
 * The full potential user entity type, combining all possible features.
 * Consumers implement a concrete type that intersects with only the features they need.
 */
export type AuthUser = BaseUser & CredentialsUser & GoogleUser;

/**
 * The minimal, safe user data stored in the Request object after authentication/JWT verification.
 */
export interface RequestUser {
  id: string;
  roles: string[];
}

export interface AuthenticatedRequest extends Request {
  user: RequestUser
}
import { AuthUser } from "./user.interface";

/**
 * Input required specifically for the credentials (email/password) creation flow.
 */
export interface CredentialsCreateInput {
  email: string;
  password: string;
}

/**
 * The generic contract for the consumer's User Repository/Service implementation.
 * @template User Must extend the base AuthUser type.
 */
export interface UserRepository<User extends AuthUser> {
  findByEmail(email: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  findByGoogleId(googleId: string): Promise<User | null>;
  create(data: CredentialsCreateInput | Partial<User>): Promise<User>;
  updatePassword(userId: string, hashedPassword: string): Promise<void>;
  update(userId: string, data: Partial<User>): Promise<User>;
}
```


