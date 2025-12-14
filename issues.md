```mermaid
flowchart TD
  A[AuthModule<br/>register(options)] --> B[CredentialAuthModule]
  A --> C[GoogleOAuthModule]

  subgraph Parent
    A
  end

  subgraph Children
    B
    C
  end
  ```
  
  ```mermaid
  flowchart LR
  Config[AuthModule options<br/>{ strategyConfigs, providers, redirectUrls, ... }]
    --> B[CredentialAuthModule<br/>(uses: userRepo, passwordHasher, jwtConfig)]
  Config
    --> C[GoogleOAuthModule<br/>(uses: clientId, clientSecret, callbackUrl, scopes)]
    
    ```