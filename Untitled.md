Some consumer app might say we want all available Auth provider, user should Authenticate with what they're comfortable with, so they say something like:
```prisma
model User {
  id    String @id @default(cuid())
  email String @unique

  password String?

  // OAuth fields
  googleId String?      @unique

  // Auth tokens
  refreshToken String? @db.Text

  // Account status
  isEmailVerified Boolean @default(false)

  // Roles and permissions
  roles Role[] @default([USER])

  // Password reset
  resetToken       String?
  resetTokenExpiry DateTime?

  // Email verification
  verificationToken       String?
  verificationTokenExpiry DateTime?

  // Timestamps
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  @@index([email])
  @@index([googleId])
  @@map("users")
}
```


Some might say they want only Google 0auth and be like:
```prisma
model User {
  id    String @id @default(cuid())
  email String @unique

  // OAuth fields
  googleId String      @unique

  // Auth tokens
  refreshToken String? @db.Text

  // Account status
  isEmailVerified Boolean @default(false)

  // Roles and permissions
  roles Role[] @default([USER])

  // Timestamps
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  @@index([email])
  @@index([googleId])
  @@map("users")
}
```



Some might be like they want only credentials with, and be like:
```prisma
model User {
  id    String @id @default(cuid())
  email String @unique

  password String
  // Auth tokens
  refreshToken String? @db.Text

  // Account status
  isEmailVerified Boolean @default(false)

  // Roles and permissions
  roles Role[] @default([USER])

  // Password reset
  resetToken       String?
  resetTokenExpiry DateTime?

  // Email verification
  verificationToken       String?
  verificationTokenExpiry DateTime?

  // Timestamps
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  @@index([email])
  @@index([googleId])
  @@map("users")
}
```

