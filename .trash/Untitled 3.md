Below is a **clean, professional, production-grade rewrite** of your README. I kept your intent, features, and API intact, but tightened the language, improved structure, removed redundancy, and aligned it with what top NestJS OSS libraries look like on npm/GitHub.

You’re building something solid here — this now _reads_ like it belongs in serious production repos.

---

# `@nahnah/nestjs-auth-module`

[![NestJS Logo](https://nestjs.com/img/logo-small.svg)](https://nestjs.com/)

**A production-ready authentication module for NestJS**  
JWT, Passport strategies, role-based authorization, and clean extensibility.

 [![NPM Version](https://img.shields.io/npm/v/@nahnah/nestjs-auth-module.svg)](https://www.npmjs.com/package/@nahnah/nestjs-auth-module)[![License](https://img.shields.io/npm/l/@nahnah/nestjs-auth-module.svg) ](LICENSE)[![Downloads](https://img.shields.io/npm/dt/@nahnah/nestjs-auth-module.svg) ](https://www.npmjs.com/package/@nahnah/nestjs-auth-module)[![Stars](https://img.shields.io/github/stars/tgenericx/nestjs-auth-module.svg) ](https://github.com/tgenericx/nestjs-auth-module/stargazers)[![Forks](https://img.shields.io/github/forks/tgenericx/nestjs-auth-module.svg)](https://github.com/tgenericx/nestjs-auth-module/network/members)

---

## 📖 Overview

`@nahnah/nestjs-auth-module` is a **plug-and-play authentication solution for NestJS** designed for real-world production use.

It provides JWT-based authentication with access and refresh tokens, secure password hashing via **Argon2**, optional **Google OAuth**, role-based authorization, and a clean **interface-driven architecture** that lets you bring your own database and email implementation.

If you want **speed without sacrificing structure**, this module is for you.

---

## ✨ Features

- 🔐 **JWT Authentication** — Access & refresh tokens with configurable lifetimes
- 🔑 **Secure Passwords** — Argon2 hashing out of the box
- 🌐 **Google OAuth 2.0** — Optional social authentication
- 👥 **Role-Based Access Control** — `@Roles()` decorator + guard
- 🎯 **Clean DX** — `@Public()`, `@CurrentUser()` decorators
- 🔌 **Database-Agnostic** — Bring your own repository
- 📦 **Capability-Driven** — Enable only what you need
- 🛡️ **Fully Type-Safe** — Strict TypeScript support
- ⚡ **Sensible Defaults** — Zero-config to get started fast

---

## 📦 Installation

```bash
npm install @nahnah/nestjs-auth-module
# or
yarn add @nahnah/nestjs-auth-module
# or
pnpm add @nahnah/nestjs-auth-module
```

### Required Peer Dependencies

```bash
npm install @nestjs/common @nestjs/core @nestjs/jwt @nestjs/passport \
passport passport-jwt argon2 class-validator class-transformer
```

### Optional (Google OAuth)

```bash
npm install passport-google-oauth20 @types/passport-google-oauth20
```

---

## 🚀 Quick Start

### 1️⃣ Implement a User Repository

The module is **database-agnostic**. You must implement the `UserRepository` interface.

```ts
import { Injectable } from '@nestjs/common';
import { UserRepository, AuthUser } from '@nahnah/nestjs-auth-module';

export interface User extends AuthUser {
  firstName?: string;
  lastName?: string;
  createdAt?: Date;
}

@Injectable()
export class UserRepositoryService implements UserRepository<User> {
  private users = new Map<string, User>();

  async findById(id: string) {
    return this.users.get(id) ?? null;
  }

  async findByEmail(email: string) {
    return [...this.users.values()].find(u => u.email === email) ?? null;
  }

  async findByGoogleId(googleId: string) {
    return [...this.users.values()].find(u => u.googleId === googleId) ?? null;
  }

  async create(data: Partial<User>) {
    const user: User = {
      id: crypto.randomUUID(),
      email: data.email!,
      password: data.password ?? null,
      googleId: data.googleId ?? null,
      isEmailVerified: data.isEmailVerified ?? false,
      roles: data.roles ?? ['user'],
      createdAt: new Date(),
    };

    this.users.set(user.id, user);
    return user;
  }

  async update(id: string, data: Partial<User>) {
    const user = await this.findById(id);
    if (!user) throw new Error('User not found');

    Object.assign(user, data);
    return user;
  }
}
```

---

### 2️⃣ Configure the Auth Module

```ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthModule } from '@nahnah/nestjs-auth-module';
import { UserRepositoryService } from './users/user-repository.service';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),

    AuthModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        jwt: {
          accessTokenSignOptions: {
            secret: config.get('JWT_SECRET')!,
            expiresIn: '15m',
          },
          refreshTokenSignOptions: {
            secret: config.get('JWT_REFRESH_SECRET')!,
            expiresIn: '7d',
          },
        },
        credentials: {},
        google: {
          clientID: config.get('GOOGLE_CLIENT_ID')!,
          clientSecret: config.get('GOOGLE_CLIENT_SECRET')!,
          callbackURL: config.get('GOOGLE_CALLBACK_URL')!,
        },
      }),
      userRepository: UserRepositoryService,
      enabledCapabilities: ['credentials', 'google'],
    }),
  ],
  providers: [UserRepositoryService],
})
export class AppModule {}
```

---

## 🎯 Core Concepts

### Capabilities

Enable only what you need:

```ts
enabledCapabilities: ['credentials'];
// or
enabledCapabilities: ['google'];
// or
enabledCapabilities: ['credentials', 'google'];
```

---

### User Repository Contract

```ts
interface UserRepository<User extends Partial<AuthUser>> {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  create(data: Partial<User>): Promise<User>;
  update(id: string, data: Partial<User>): Promise<User>;
}
```

---

## 🎨 Decorators

### `@Public()`

Skip authentication for a route.

### `@CurrentUser()`

Access the authenticated user or a specific field.

### `@Roles()`

Restrict access by role (use with `RolesGuard`).

---

## 🔐 Security Best Practices

- Always use **environment variables** for secrets
- Enforce **HTTPS** in production
- Implement **refresh token rotation** (roadmap)
- Add **rate limiting** to auth endpoints
- Enforce **strong password policies**

---

## 🗺️ Roadmap

- Refresh token rotation & blacklisting
- Magic link authentication
- Password reset helpers
- Email verification helpers
- Account lockout protection
- Additional OAuth providers (GitHub, Microsoft)

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo
2. Create a feature branch
3. Commit your changes
4. Push and open a PR

---

## 📄 License

MIT © Nahnah

---

## ⭐ Support

If this module helped you:

- ⭐ Star the repository
- 🐛 Report issues
- 💡 Suggest features

---

If you want, I can also:

- **Tighten it further for npm SEO**
- **Add architecture diagrams**
- **Split docs into `/docs`**
- **Rewrite it to match NestJS core style exactly**

Just tell me what direction you want to push it.