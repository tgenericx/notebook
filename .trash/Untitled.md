```mermaid
graph TD
    subgraph Core
        J[JWT Module]
        T(Token Service)
    end

    subgraph Authentication Module (Root)
        direction LR
        CA[Credentials Auth Module]
        GA(Google OAuth Module)
    end

    U[User Service (Consumer Implemented)]
    IntUser(Generic Internal User Type)
    ConsumerApp(Consumer Application)

    % Core Dependencies
    T -.-> J: requires
    AuthModule -.-> Core: contains

    % Auth Providers Dependencies
    CA --> T: uses (issue/refresh tokens)
    CA --> U: uses (user operations)
    CA --> P[Password Service]

    GA --> T: uses (issue tokens)
    GA --> U: uses (user operations)
    GA --> Strat(Google Strategy & Guard)

    % Data/Type Dependencies (dotted line for "depends on structure of")
    U .-> IntUser: implements/uses
    T .-> IntUser: works with

    % Exported Services
    ConsumerApp -.-> CA: uses exported service
    ConsumerApp -.-> GA: uses exported guard/service

```