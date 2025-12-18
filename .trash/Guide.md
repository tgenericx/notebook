# 🔐 NestJS Auth Package

## 1️⃣ Single Entry Point (Consumer Contract)

**The consumer application interacts with ONE module only:**

```ts
AuthModule.forRoot / forRootAsync(config)
```
We'll implement forRootAsync(config) first
The consumer:

- **Does NOT import child modules**
    
- **Does NOT know child modules exist**
    
- **Does NOT configure children directly**
    
- **Only declares intent via config**
    

The consumer owns:

- User persistence (implements `UserRepository<User>`)
    

---

## 2️⃣ AuthModule (Mother / Orchestrator)

**Role:** Configuration + Dependency Assembly ONLY

### Responsibilities

- Receives `AuthModuleConfig`
    
- Validates and normalizes config
    
- Decides which auth capabilities are enabled
    
- Registers shared providers (user repository, configs)
    
- Conditionally imports child modules
    
- Re-exports child module providers
    

### Explicitly Does NOT

- Implement auth logic
    
- Create strategies or guards
    
- Talk to Passport
    
- Handle HTTP
    
- Issue or verify tokens
    

---

## 3️⃣ AuthJwtModule (Shared Child — Token Kernel)

**Role:** Owns ALL JWT & token concerns

### Responsibilities

- Issue access & refresh tokens
    
- Verify and decode tokens
    
- Define JWT payload shape (`RequestUser`)
    
- Attach authenticated user to request
    

### Contains

- `TokenService`
    
- `JwtStrategy`
    
- `JwtAuthGuard`
    

### Exports

- `TokenService`
    
- `JwtAuthGuard`
    

### Explicitly Does NOT

- Authenticate users
    
- Know about credentials or Google
    
- Access user persistence
    

---

## 4️⃣ CredentialsAuthModule (Feature Child)

**Role:** Email/Password Authentication

### Depends On

- `TokenService` (from `AuthJwtModule`)
    
- `UserRepository<User>`
    
- `PasswordService` (local)
    

### Contains

- `CredentialsAuthService`
    
- `PasswordService`
    

### Exports

- `CredentialsAuthService`
    

### Explicitly Does NOT

- Own JWT logic or guards
    
- Know about Google OAuth
    
- Read global configuration
    

---

## 5️⃣ GoogleOAuthModule (Feature Child)

**Role:** Google OAuth Authentication

### Depends On

- `TokenService` (from `AuthJwtModule`)
    
- `UserRepository<User>`
    
- `GOOGLE_CONFIG`
    

### Contains

- `GoogleAuthService`
    
- `GoogleStrategy`
    
- `GoogleAuthGuard`
    

### Exports

- `GoogleAuthService`
    
- `GoogleAuthGuard`
    

### Explicitly Does NOT

- Handle passwords
    
- Own JWT validation logic
    
- Know about credentials auth
    

---

## 6️⃣ User Abstractions (Internal Contract)

### Canonical Internal User Type

```ts
AuthUser = BaseUser & CredentialsUser & GoogleUser
```

- Internal guarantee for required fields
    
- Consumers implement only what they use
    
- No unions, no runtime guessing
    

### Request User (JWT Payload)

```ts
RequestUser = { id, roles }
```

Minimal, safe, stable.

---

## 7️⃣ User Repository (Consumer Responsibility)

The consumer **must implement**:

```ts
UserRepository<User extends AuthUser>
```

The auth package:

- Never owns user persistence
    
- Never knows the concrete user type
    
- Depends only on the contract
    

---

## 8️⃣ Dependency Rules (Strict)

- Child modules **never depend on each other**
    
- Credentials & Google **depend on AuthJwtModule**
    
- AuthJwtModule depends on **nothing**
    
- AuthModule depends on **all**, but owns **nothing**
    

---

## 9️⃣ Configuration Flow (One Direction)

```
Consumer App
   ↓
AuthModule (mother)
   ↓
Selective config distribution
   ↓
Child modules
```

No reverse flow. No shortcuts.

---

## 🏁 Final Principle (Non-Negotiable)

> **AuthModule is the only public surface.  
> Children are private capabilities.  
> JWT is centralized.  
> Users are consumer-owned.**

This is the guide.  
Anything that violates this is a bug — not a preference.

```ts
import { JwtSignOptions } from "@nestjs/jwt";
import { StrategyOptionsWithRequest as GoogleStrategyConfig } from "passport-google-oauth20";

export interface CredentialsAuthConfig {
  // No option for now to start simple
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
```