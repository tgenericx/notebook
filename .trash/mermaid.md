```
graph TB
    subgraph "Core Module Layer"
        AuthModule[AuthModule<br/>@Global]
    end
    
    subgraph "Feature Modules"
        AuthJwtModule[AuthJwtModule<br/>JWT Authentication]
        CredentialsModule[CredentialsAuthModule<br/>Email/Password Auth]
        GoogleModule[GoogleOAuthModule<br/>Google OAuth]
    end
    
    subgraph "Services Layer"
        TokenService[TokenService<br/>JWT Operations]
        PasswordService[PasswordService<br/>Password Hashing]
        CredentialsService[CredentialsAuthService<br/>Login/Register]
        GoogleService[GoogleAuthService<br/>OAuth Handling]
    end
    
    subgraph "Guards & Strategies"
        JwtGuard[JwtAuthGuard<br/>Route Protection]
        RolesGuard[RolesGuard<br/>Role-based Access]
        JwtStrategy[JwtStrategy<br/>Passport JWT]
        GoogleGuard[GoogleAuthGuard<br/>OAuth Guard]
        GoogleStrategy[GoogleStrategy<br/>Passport Google]
    end
    
    subgraph "External Dependencies"
        NestJWT[NestJS JWT]
        Passport[Passport]
        Argon2[Argon2]
    end
    
    subgraph "Consumer Implementation"
        UserRepo[UserRepository<br/>Consumer Implements]
        UserEntity[User Entity<br/>Consumer Defines]
    end
    
    AuthModule -->|Dynamic Import| AuthJwtModule
    AuthModule -->|Conditional Import| CredentialsModule
    AuthModule -->|Conditional Import| GoogleModule
    
    AuthJwtModule --> TokenService
    AuthJwtModule --> JwtStrategy
    AuthJwtModule --> JwtGuard
    AuthJwtModule --> RolesGuard
    
    CredentialsModule --> PasswordService
    CredentialsModule --> CredentialsService
    
    GoogleModule --> GoogleStrategy
    GoogleModule --> GoogleService
    GoogleModule --> GoogleGuard
    
    TokenService --> NestJWT
    JwtStrategy --> Passport
    GoogleStrategy --> Passport
    PasswordService --> Argon2
    
    CredentialsService --> UserRepo
    CredentialsService --> PasswordService
    CredentialsService --> TokenService
    
    GoogleService --> UserRepo
    GoogleService --> TokenService
    
    JwtStrategy --> UserRepo
    GoogleStrategy --> UserRepo
    
    UserRepo -.->|Implements| UserEntity
    
    style AuthModule fill:#e1f5ff
    style AuthJwtModule fill:#fff4e1
    style CredentialsModule fill:#ffe1e1
    style GoogleModule fill:#e1ffe1
    style UserRepo fill:#f0e1ff
    style UserEntity fill:#f0e1ff
```

```
graph TD
    subgraph "Root Configuration"
        forRootAsync[AuthModule.forRootAsync]
        Config[AuthModuleConfig]
        EnabledCaps[enabledCapabilities Array]
    end
    
    subgraph "Provider Registration"
        ConfigProvider[AUTH_CONFIG Provider]
        UserRepoProvider[USER_REPOSITORY Provider]
        JwtConfigProvider[JWT Config Provider]
        CredsConfigProvider[CREDENTIALS Config Provider]
        GoogleConfigProvider[GOOGLE Config Provider]
    end
    
    subgraph "Dynamic Module Imports"
        AlwaysImport[Always: AuthJwtModule]
        ConditionalCreds{credentials enabled?}
        ConditionalGoogle{google enabled?}
        ImportCreds[Import CredentialsAuthModule]
        ImportGoogle[Import GoogleOAuthModule]
    end
    
    forRootAsync --> Config
    forRootAsync --> EnabledCaps
    forRootAsync --> ConfigProvider
    forRootAsync --> UserRepoProvider
    forRootAsync --> JwtConfigProvider
    forRootAsync --> CredsConfigProvider
    forRootAsync --> GoogleConfigProvider
    
    forRootAsync --> AlwaysImport
    EnabledCaps --> ConditionalCreds
    EnabledCaps --> ConditionalGoogle
    
    ConditionalCreds -->|Yes| ImportCreds
    ConditionalGoogle -->|Yes| ImportGoogle
    
    style forRootAsync fill:#4a90e2
    style Config fill:#e8f4f8
    style AlwaysImport fill:#90ee90
    style ConditionalCreds fill:#ffd700
    style ConditionalGoogle fill:#ffd700
```


```
sequenceDiagram
    participant Client
    participant Controller
    participant CredentialsService
    participant PasswordService
    participant UserRepository
    participant TokenService
    
    Client->>Controller: POST /auth/login {email, password}
    Controller->>CredentialsService: login(credentials)
    CredentialsService->>UserRepository: findByEmail(email)
    UserRepository-->>CredentialsService: user
    
    alt User not found
        CredentialsService-->>Controller: UnauthorizedException
    end
    
    alt No password (OAuth-only)
        CredentialsService-->>Controller: UnauthorizedException<br/>"Use social login"
    end
    
    CredentialsService->>PasswordService: verify(password, hash)
    PasswordService-->>CredentialsService: isValid
    
    alt Invalid password
        CredentialsService-->>Controller: UnauthorizedException
    end
    
    CredentialsService->>TokenService: generateTokens(user)
    TokenService-->>CredentialsService: {accessToken, refreshToken}
    CredentialsService-->>Controller: LoginResponse
    Controller-->>Client: {user, tokens}
```

```
sequenceDiagram
    participant Client
    participant Controller
    participant GoogleGuard
    participant GoogleStrategy
    participant UserRepository
    participant GoogleService
    participant TokenService
    
    Client->>Controller: GET /auth/google
    Controller->>GoogleGuard: Activate
    GoogleGuard->>GoogleStrategy: Redirect to Google
    GoogleStrategy-->>Client: Redirect to Google OAuth
    
    Client->>GoogleStrategy: Callback with auth code
    GoogleStrategy->>GoogleStrategy: Exchange code for profile
    GoogleStrategy->>UserRepository: findByGoogleId(googleId)
    
    alt User exists
        UserRepository-->>GoogleStrategy: user
    else User not found by Google ID
        GoogleStrategy->>UserRepository: findByEmail(email)
        alt Email exists
            UserRepository-->>GoogleStrategy: user
            GoogleStrategy->>UserRepository: update(userId, {googleId})
        else New user
            GoogleStrategy->>UserRepository: create({email, googleId, verified})
        end
    end
    
    GoogleStrategy-->>Controller: RequestUser attached
    Controller->>GoogleService: handleOAuthCallback(requestUser)
    GoogleService->>UserRepository: findById(userId)
    GoogleService->>TokenService: generateTokens(user)
    TokenService-->>GoogleService: {accessToken, refreshToken}
    GoogleService-->>Controller: GoogleAuthResponse
    Controller-->>Client: {user, tokens}
```

```
sequenceDiagram
    participant Client
    participant Controller
    participant JwtGuard
    participant JwtStrategy
    participant TokenService
    participant RolesGuard
    
    Client->>Controller: Request with Authorization header
    Controller->>JwtGuard: canActivate()
    
    alt Route is @Public
        JwtGuard-->>Controller: Allow (skip auth)
    end
    
    JwtGuard->>JwtStrategy: validate JWT
    JwtStrategy->>JwtStrategy: Extract & verify token
    
    alt Invalid/Expired token
        JwtStrategy-->>JwtGuard: UnauthorizedException
        JwtGuard-->>Client: 401 Unauthorized
    end
    
    JwtStrategy->>JwtStrategy: Decode payload {sub, roles}
    JwtStrategy-->>JwtGuard: RequestUser {userId, roles}
    JwtGuard->>Controller: Attach user to request
    
    Controller->>RolesGuard: canActivate()
    
    alt Route has @Roles
        RolesGuard->>RolesGuard: Check user.roles
        alt Missing required role
            RolesGuard-->>Client: 403 Forbidden
        end
    end
    
    RolesGuard-->>Controller: Allow
    Controller-->>Client: Protected resource
```

```
classDiagram
    class BaseUser {
        +string id
        +string email
        +boolean isEmailVerified
        +string[] roles
    }
    
    class CredentialsUser {
        +string? password
    }
    
    class GoogleUser {
        +string? googleId
    }
    
    class AuthUser {
        <<interface>>
    }
    
    class RequestUser {
        +string userId
        +string[] roles
    }
    
    class JwtPayload {
        +string sub
        +string[] roles
    }
    
    class TokenPair {
        +string accessToken
        +string refreshToken
    }
    
    class AuthResponse {
        +BaseUser user
        +TokenPair tokens
    }
    
    BaseUser <|-- AuthUser
    CredentialsUser <|-- AuthUser
    GoogleUser <|-- AuthUser
    
    AuthResponse --> BaseUser
    AuthResponse --> TokenPair
    
    RequestUser ..> JwtPayload : derived from
    
    class UserRepository~User~ {
        <<interface>>
        +findById(id: string) User | null
        +findByEmail(email: string) User | null
        +create(data: Partial~User~) User
        +update(id: string, data: Partial~User~) User
    }
    
    class GoogleUserRepository~User~ {
        <<interface>>
        +findByGoogleId(googleId: string) User | null
    }
    
    UserRepository <|-- GoogleUserRepository
```

```
graph LR
    subgraph "Interfaces Layer"
        direction TB
        Config[configuration/]
        UserModel[user-model/]
        Auth[authentication/]
        Contracts[operation-contracts/]
    end
    
    subgraph "Core Infrastructure"
        direction TB
        Constants[constants/]
        Decorators[decorators/]
    end
    
    subgraph "Feature Modules"
        direction TB
        JWT[auth-jwt/]
        Creds[credentials-auth/]
        Google[google-oauth/]
    end
    
    subgraph "Public API"
        Index[index.ts<br/>Exports]
    end
    
    Interfaces --> Core
    Core --> Features
    Features --> Public
    
    Config -.-> Features
    UserModel -.-> Features
    Auth -.-> Features
    Contracts -.-> Features
    
    style Interfaces fill:#e3f2fd
    style Core fill:#fff3e0
    style Features fill:#f3e5f5
    style Public fill:#e8f5e9
```


```
graph TB
    subgraph "Configuration Tokens"
        AUTH_CONFIG[AUTH_CONFIG<br/>Symbol]
        JWT_TOKEN[AUTH_CAPABILITIES.JWT<br/>Symbol]
        CREDS_TOKEN[AUTH_CAPABILITIES.CREDENTIALS<br/>Symbol]
        GOOGLE_TOKEN[AUTH_CAPABILITIES.GOOGLE<br/>Symbol]
    end
    
    subgraph "Provider Tokens"
        USER_REPO[PROVIDERS.USER_REPOSITORY<br/>Symbol]
    end
    
    subgraph "Injected Into"
        TokenSvc[TokenService]
        JwtStrat[JwtStrategy]
        CredsSvc[CredentialsAuthService]
        GoogleStrat[GoogleStrategy]
        GoogleSvc[GoogleAuthService]
    end
    
    AUTH_CONFIG --> JWT_TOKEN
    AUTH_CONFIG --> CREDS_TOKEN
    AUTH_CONFIG --> GOOGLE_TOKEN
    
    JWT_TOKEN --> TokenSvc
    JWT_TOKEN --> JwtStrat
    CREDS_TOKEN --> CredsSvc
    GOOGLE_TOKEN --> GoogleStrat
    USER_REPO --> CredsSvc
    USER_REPO --> GoogleStrat
    USER_REPO --> GoogleSvc
    
    style AUTH_CONFIG fill:#ffeb3b
    style USER_REPO fill:#ff9800
```


