```mermaid
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


