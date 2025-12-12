# `Improve error handling when Google OAuth is not configured`

**Problem**  
When `AuthModule.forRootAsync` is configured without the `google` section, the module still exposes `/auth/google` and `/auth/google/callback` routes protected by `AuthGuard('google')`.[1]
Calling these routes results in a generic `Error: Unknown authentication strategy "google"` from Passport, which looks like a misconfiguration or bug instead of a deliberate choice to disable Google OAuth.[3][2]

**Current behavior**  

- Config:

  ```ts
  AuthModule.forRootAsync({
    useFactory: (config: ConfigService) => ({
      jwt: { /* ... */ },
      password: { /* ... */ },
      // google: { ... }  // intentionally commented out / omitted
    }),
    // ...
  })
  ```

- Routes `/auth/google` and `/auth/google/callback` are still mapped.  
- Hitting `/auth/google` logs `Error: Unknown authentication strategy "google"` and returns a 500 error.[3][1]

**Expected behavior**  

One of these (you can propose which you prefer):

- If Google config is missing, either:  
  - Do not register the Google routes at all, or  
  - Guard them with a custom check that returns a 404 or 503 with a clear JSON message like “Google OAuth is disabled in configuration”, instead of letting Passport throw “Unknown authentication strategy”.[4][1]

**Proposed solution ideas**

- During module initialization, check if `options.google` is present:  
  - If not, skip registering the Google strategy and related routes.  
  - Or wrap the Google guard so that when the strategy is not configured, it throws a controlled `BadRequestException`/`ServiceUnavailableException` with a helpful message.[5][6][7]
- Optionally expose an explicit `enableGoogle: boolean` flag so behavior is obvious in config.

**Acceptance criteria**

- When Google config is omitted, calling `/auth/google` and `/auth/google/callback` no longer produces `Unknown authentication strategy "google"` from Passport.[2][1]
- The behavior is either “route not registered” (404) or a clear, documented error response stating that Google OAuth is disabled by configuration.[5][4]
- This behavior is covered by at least one test (e2e or unit) in the auth module repository.
