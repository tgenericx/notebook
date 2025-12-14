```mermaid
flowchart LR
    Config["forRootAsync()<br/>{<br/>  credentials?: {...},<br/>  google?: {...},<br/>  providers: {...}<br/>}"]
    
    Config --> AuthMod["AuthModule"]
    
    AuthMod -->|"Always provides"| JWT["JWT Infrastructure<br/>• JwtStrategy<br/>• JwtAuthGuard<br/>• RolesGuard<br/>• TokenService"]
    
    AuthMod -->|"If credentials<br/>config exists"| Cred["CredentialAuthModule<br/>• CredentialAuthService<br/>• Uses TokenService<br/>• Uses PasswordService"]
    
    AuthMod -->|"If google<br/>config exists"| Google["GoogleOAuthModule<br/>• GoogleStrategy<br/>• GoogleAuthGuard<br/>• Uses TokenService"]
    
    style Config fill:#f0f0f0
    style JWT fill:#c8e6c9
    style Cred fill:#fff9c4
    style Google fill:#f8bbd0
    ```