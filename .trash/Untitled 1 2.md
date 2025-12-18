Generate a conventional commit message in a markdown following this exact structure:

1. **First line format:** `type(optional scope): imperative subject`
   - Use lowercase, present tense, no period
   - Example: `feat(auth): add password reset functionality`

2. **Blank line** after the first line

3. **Body:** Unordered list of bullet points explaining the "what" and "why"
   - Start each bullet with `- `
   - Focus on changes in behavior, not just file modifications

4. **Blank line** after body (if footers are needed)

5. **Footers:** For breaking changes, references, etc.
   - Format: `BREAKING CHANGE: description` or `Closes #123`

Based on these git staged changes: 
diff --git a/src/interfaces/authentication/auth-response.interface.ts b/src/interfaces/authentication/auth-response.interface.ts
new file mode 100644
index 0000000..0e425a4
--- /dev/null
+++ b/src/interfaces/authentication/auth-response.interface.ts
@@ -0,0 +1,10 @@
+import { BaseUser } from '../user/user.interface';
+import { TokenPair } from './token-pair.interface';
+
+/**
+ * Standard response format for authentication operations
+ */
+export interface AuthResponse {
+  user: BaseUser;
+  tokens: TokenPair;
+}
diff --git a/src/interfaces/authentication/auth-user-data.interface.ts b/src/interfaces/authentication/auth-user-data.interface.ts
new file mode 100644
index 0000000..4b68b0d
--- /dev/null
+++ b/src/interfaces/authentication/auth-user-data.interface.ts
@@ -0,0 +1,7 @@
+import { BaseUser } from '../user/user.interface';
+
+/**
+ * Safe user data exposed in authentication responses
+ * Excludes sensitive fields like password
+ */
+export type AuthUserData = Omit<BaseUser, 'password' | 'googleId'>;
diff --git a/src/interfaces/authentication/index.ts b/src/interfaces/authentication/index.ts
new file mode 100644
index 0000000..2b768b7
--- /dev/null
+++ b/src/interfaces/authentication/index.ts
@@ -0,0 +1,4 @@
+export * from './jwt-payload.interface';
+export * from './token-pair.interface';
+export * from './auth-response.interface';
+export * from './auth-user-data.interface';
diff --git a/src/interfaces/authentication/jwt-payload.interface.ts b/src/interfaces/authentication/jwt-payload.interface.ts
new file mode 100644
index 0000000..7e061ea
--- /dev/null
+++ b/src/interfaces/authentication/jwt-payload.interface.ts
@@ -0,0 +1,7 @@
+/**
+ * Structure of JWT token payload
+ */
+export interface JwtPayload {
+  sub: string;      // Subject (user ID)
+  roles: string[];  // User roles
+}
diff --git a/src/interfaces/authentication/token-pair.interface.ts b/src/interfaces/authentication/token-pair.interface.ts
new file mode 100644
index 0000000..60299e2
--- /dev/null
+++ b/src/interfaces/authentication/token-pair.interface.ts
@@ -0,0 +1,7 @@
+/**
+ * Pair of access and refresh tokens returned after successful authentication
+ */
+export interface TokenPair {
+  accessToken: string;
+  refreshToken: string;
+}
diff --git a/src/interfaces/configuration/auth-module-async-options.interface.ts b/src/interfaces/configuration/auth-module-async-options.interface.ts
new file mode 100644
index 0000000..1ac9a81
--- /dev/null
+++ b/src/interfaces/configuration/auth-module-async-options.interface.ts
@@ -0,0 +1,14 @@
+import { ModuleMetadata, FactoryProvider } from '@nestjs/common';
+import { Type } from '@nestjs/common';
+import { UserRepository } from '../user/user-repository.interface';
+import { AuthUser } from '../user/user.interface';
+
+/**
+ * Asynchronous configuration options for the AuthModule
+ * Allows consumers to provide configuration via factories
+ */
+export interface AuthModuleAsyncOptions<User extends Partial<AuthUser> = any>
+  extends Pick<ModuleMetadata, 'imports'>,
+  Pick<FactoryProvider<AuthModuleConfig>, 'useFactory' | 'inject'> {
+  userRepository: Type<UserRepository<User>>;
+}
diff --git a/src/interfaces/configuration/auth-module-config.interface.ts b/src/interfaces/configuration/auth-module-config.interface.ts
new file mode 100644
index 0000000..f7cf121
--- /dev/null
+++ b/src/interfaces/configuration/auth-module-config.interface.ts
@@ -0,0 +1,13 @@
+import { JwtConfig } from './jwt-config.interface';
+import { CredentialsAuthConfig } from './credentials-auth-config.interface';
+import { GoogleOAuthConfig } from './google-oauth-config.interface';
+
+/**
+ * Main configuration for the authentication module
+ * Optional properties determine which authentication strategies are enabled
+ */
+export interface AuthModuleConfig {
+  jwt: JwtConfig;
+  credentials?: CredentialsAuthConfig;
+  google?: GoogleOAuthConfig;
+}
diff --git a/src/interfaces/configuration/credentials-auth-config.interface.ts b/src/interfaces/configuration/credentials-auth-config.interface.ts
new file mode 100644
index 0000000..45bf812
--- /dev/null
+++ b/src/interfaces/configuration/credentials-auth-config.interface.ts
@@ -0,0 +1,8 @@
+/**
+ * Configuration specific to email/password authentication
+ */
+export interface CredentialsAuthConfig {
+  // For future use: password reset token expiry, password policies, etc.
+  // passwordResetTokenExpiry?: number;
+  // passwordPolicy?: PasswordPolicy;
+}
diff --git a/src/interfaces/configuration/google-oauth-config.interface.ts b/src/interfaces/configuration/google-oauth-config.interface.ts
new file mode 100644
index 0000000..d9cc182
--- /dev/null
+++ b/src/interfaces/configuration/google-oauth-config.interface.ts
@@ -0,0 +1,7 @@
+import { StrategyOptionsWithRequest } from 'passport-google-oauth20';
+
+/**
+ * Configuration for Google OAuth authentication
+ * Uses passport-google-oauth20 strategy options
+ */
+export type GoogleOAuthConfig = StrategyOptionsWithRequest;
diff --git a/src/interfaces/configuration/index.ts b/src/interfaces/configuration/index.ts
new file mode 100644
index 0000000..5480ce5
--- /dev/null
+++ b/src/interfaces/configuration/index.ts
@@ -0,0 +1,5 @@
+export * from './auth-module-config.interface';
+export * from './auth-module-async-options.interface';
+export * from './jwt-config.interface';
+export * from './credentials-auth-config.interface';
+export * from './google-oauth-config.interface';
diff --git a/src/interfaces/configuration/jwt-config.interface.ts b/src/interfaces/configuration/jwt-config.interface.ts
new file mode 100644
index 0000000..63390ef
--- /dev/null
+++ b/src/interfaces/configuration/jwt-config.interface.ts
@@ -0,0 +1,9 @@
+import { JwtSignOptions } from '@nestjs/jwt';
+
+/**
+ * Configuration for JWT token generation and validation
+ */
+export interface JwtConfig {
+  accessTokenSignOptions: JwtSignOptions;
+  refreshTokenSignOptions: JwtSignOptions;
+}
diff --git a/src/interfaces/index.ts b/src/interfaces/index.ts
new file mode 100644
index 0000000..fe14cc3
--- /dev/null
+++ b/src/interfaces/index.ts
@@ -0,0 +1,4 @@
+export * from './configuration';
+export * from './user-model';
+export * from './authentication';
+export * from './operation-contracts';
diff --git a/src/interfaces/operation-contracts/index.ts b/src/interfaces/operation-contracts/index.ts
new file mode 100644
index 0000000..8dd4dad
--- /dev/null
+++ b/src/interfaces/operation-contracts/index.ts
@@ -0,0 +1,5 @@
+export * from './login.interface';
+export * from './registration.interface';
+export * from './password-change.interface';
+export * from './token-refresh.interface';
+export * from './oauth-callback.interface';
diff --git a/src/interfaces/operation-contracts/login.interface.ts b/src/interfaces/operation-contracts/login.interface.ts
new file mode 100644
index 0000000..1dce5be
--- /dev/null
+++ b/src/interfaces/operation-contracts/login.interface.ts
@@ -0,0 +1,20 @@
+import { BaseUser } from "../user-model/user.interface";
+
+/**
+ * Input data required for login operation
+ */
+export interface LoginInput {
+  email: string;
+  password: string;
+}
+
+/**
+ * Response data returned from login operation
+ */
+export interface LoginResponse {
+  user: BaseUser;
+  tokens: {
+    accessToken: string;
+    refreshToken: string;
+  };
+}
diff --git a/src/interfaces/operation-contracts/oauth-callback.interface.ts b/src/interfaces/operation-contracts/oauth-callback.interface.ts
new file mode 100644
index 0000000..816b957
--- /dev/null
+++ b/src/interfaces/operation-contracts/oauth-callback.interface.ts
@@ -0,0 +1,14 @@
+import { RequestUser } from '../user/request-user.interface';
+import { AuthResponse } from '../auth/auth-response.interface';
+
+/**
+ * Response from Google OAuth callback operation
+ */
+export interface GoogleOAuthCallbackResponse extends AuthResponse { }
+
+/**
+ * Input for Google OAuth callback (user data from Passport)
+ */
+export interface GoogleOAuthCallbackInput {
+  requestUser: RequestUser;
+}
diff --git a/src/interfaces/operation-contracts/password-change.interface.ts b/src/interfaces/operation-contracts/password-change.interface.ts
new file mode 100644
index 0000000..3ad6757
--- /dev/null
+++ b/src/interfaces/operation-contracts/password-change.interface.ts
@@ -0,0 +1,16 @@
+/**
+ * Input data for changing user password (requires current password)
+ */
+export interface PasswordChangeInput {
+  userId: string;
+  currentPassword: string;
+  newPassword: string;
+}
+
+/**
+ * Input data for setting/resetting password (admin or forgot password flow)
+ */
+export interface PasswordSetInput {
+  userId: string;
+  newPassword: string;
+}
diff --git a/src/interfaces/operation-contracts/registration.interface.ts b/src/interfaces/operation-contracts/registration.interface.ts
new file mode 100644
index 0000000..5361702
--- /dev/null
+++ b/src/interfaces/operation-contracts/registration.interface.ts
@@ -0,0 +1,8 @@
+/**
+ * Input data required for user registration
+ */
+export interface RegistrationInput {
+  email: string;
+  password: string;
+  // Can be extended with additional fields
+}
diff --git a/src/interfaces/operation-contracts/token-refresh.interface.ts b/src/interfaces/operation-contracts/token-refresh.interface.ts
new file mode 100644
index 0000000..e9b581d
--- /dev/null
+++ b/src/interfaces/operation-contracts/token-refresh.interface.ts
@@ -0,0 +1,6 @@
+/**
+ * Input data for refreshing access token
+ */
+export interface TokenRefreshInput {
+  refreshToken: string;
+}
diff --git a/src/interfaces/user-model/authenticated-request.interface.ts b/src/interfaces/user-model/authenticated-request.interface.ts
new file mode 100644
index 0000000..6eedbf5
--- /dev/null
+++ b/src/interfaces/user-model/authenticated-request.interface.ts
@@ -0,0 +1,9 @@
+import { Request } from 'express';
+import { RequestUser } from './request-user.interface';
+
+/**
+ * Extended Express Request with authenticated user data
+ */
+export interface AuthenticatedRequest extends Request {
+  user: RequestUser;
+}
diff --git a/src/interfaces/user-model/index.ts b/src/interfaces/user-model/index.ts
new file mode 100644
index 0000000..6c217dd
--- /dev/null
+++ b/src/interfaces/user-model/index.ts
@@ -0,0 +1,4 @@
+export * from './user.interface';
+export * from './request-user.interface';
+export * from './authenticated-request.interface';
+export * from './user-repository.interface';
diff --git a/src/interfaces/user-model/request-user.interface.ts b/src/interfaces/user-model/request-user.interface.ts
new file mode 100644
index 0000000..3b0805b
--- /dev/null
+++ b/src/interfaces/user-model/request-user.interface.ts
@@ -0,0 +1,8 @@
+/**
+ * Minimal, safe user data stored in the request object after authentication
+ * This is what gets attached to HTTP requests and passed to controllers
+ */
+export interface RequestUser {
+  userId: string;
+  roles: string[];
+}
diff --git a/src/interfaces/user-model/user-repository.interface.ts b/src/interfaces/user-model/user-repository.interface.ts
new file mode 100644
index 0000000..6f43cae
--- /dev/null
+++ b/src/interfaces/user-model/user-repository.interface.ts
@@ -0,0 +1,13 @@
+import { AuthUser } from './user.interface';
+
+/**
+ * Contract for consumer's User Repository implementation
+ * Must be implemented by consumers to provide data persistence
+ */
+export interface UserRepository<User extends Partial<AuthUser>> {
+  findById(id: string): Promise<User | null>;
+  findByEmail(email: string): Promise<User | null>;
+  findByGoogleId(googleId: string): Promise<User | null>;
+  create(data: Partial<User>): Promise<User>;
+  update(id: string, data: Partial<User>): Promise<User>;
+}
diff --git a/src/interfaces/user-model/user.interface.ts b/src/interfaces/user-model/user.interface.ts
new file mode 100644
index 0000000..ff68cdb
--- /dev/null
+++ b/src/interfaces/user-model/user.interface.ts
@@ -0,0 +1,29 @@
+/**
+ * Base mandatory fields for any user in the authentication system
+ */
+export interface BaseUser {
+  id: string;
+  email: string;
+  isEmailVerified: boolean;
+  roles: string[];
+}
+
+/**
+ * Fields specific to password-based authentication
+ */
+export interface CredentialsUser {
+  password?: string | null;
+}
+
+/**
+ * Fields specific to Google OAuth authentication
+ */
+export interface GoogleUser {
+  googleId?: string | null;
+}
+
+/**
+ * The complete user entity type combining all possible authentication methods
+ * Consumers implement concrete types that intersect with only the features they need
+ */
+export type AuthUser = BaseUser & CredentialsUser & GoogleUser;