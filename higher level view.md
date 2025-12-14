```mermaid
flowchart TD
    A["AuthModule<br/>(Parent/Orchestrator)"]
    B["CredentialAuthModule<br/>(Optional Child)"]
    C["GoogleOAuthModule<br/>(Optional Child)"]
    
    A -->|"imports if<br/>credentials config exists"| B
    A -->|"imports if<br/>google config exists"| C
    
    subgraph Core["Always Provided by AuthModule"]
        D["TokenService"]
        E["PasswordService"]
        F["JwtStrategy"]
        G["JwtAuthGuard"]
        H["RolesGuard"]
    end
    
    A -.->|provides| Core
    B -.->|uses| D
    B -.->|uses| E
    C -.->|uses| D
    
    style A fill:#e1f5ff
    style B fill:#fff4e1
    style C fill:#ffe1f5
    style Core fill:#e8f5e9
  ```


