# Next.js Authentication (TypeScript)

A lightweight and reusable authentication library for **Next.js App Router** projects.

This package provides everything needed to build a secure authentication system, including:

- JWT Authentication
- Password Hashing (Argon2)
- AES Encryption/Decryption
- Route Protection Middleware
- Cookie Authentication
- Session Management
- User Authentication Utilities

---

## Features

- 🔐 JWT Token Generation & Verification
- 🔑 RSA Public/Private Key Support
- 🔒 Argon2 Password Hashing
- 🛡 AES-256-CBC Encryption
- 🍪 Cookie-based Authentication
- 🚀 Next.js Middleware Support
- 📦 Session Management
- 👤 User Authentication Helper
- 💯 Written in TypeScript

---

# Requirements

- Node.js 18+
- Next.js 15+
- TypeScript

---

# Environment Variables

Create a `.env` file.

```env
JWT_ENCODE_ALGORITHM=RS256

JWT_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----

JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----

JWT_TOKEN_VALIDATION_TIME=3600

JWT_COOKIE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----

JWT_COOKIE_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----

JWT_COOKIE_TOKEN_VALIDATION_TIME=3600

AES_CRYPTOGRAPHY_PASSWORD=your-secret-password
```

---

# Package Structure

```
src/

├── authentication.ts
├── authentication_middleware.ts
├── jwt_token_handler.ts
├── cryptography.ts
├── aes_cryptography.ts
├── session_manager.ts
└── user_manager.ts
```

---

# Password Hashing

Uses **Argon2id** for password hashing.

```ts
import UserManager from "next_js_authentication";

const user = new UserManager();

const hash = await user.create(password, repeatPassword);

const valid = await user.singIn(password, hash);
```

---

# JWT Token

Generate JWT token.

```ts
const token = await user.getToken({
    id: 1,
    email: "user@example.com"
});
```

Verify token.

```ts
const auth = new AuthenticationManager(request);

const payload = await auth.authentication();
```

---

# AES Encryption

Encrypt

```ts
const crypto = new Cryptography();

const encrypted = crypto.aseEncrypt("Hello World");
```

Decrypt

```ts
const decrypted = crypto.aseDecrypt(encrypted);
```

AES uses:

- AES-256-CBC
- Random IV
- SHA-256 Key Derivation

---

# Authentication Manager

Supports authentication using:

- Authorization Header
- Cookies

Example

```ts
const auth = new AuthenticationManager(request);

const payload = await auth.authentication();
```

Cookie Authentication

```ts
const payload = await auth.authenticationByCookies();
```

---

# Middleware

Protect application routes.

```ts
import { AuthenticationMiddleware } from "next_js_authentication";

export async function middleware(request: NextRequest) {

    return await new AuthenticationMiddleware(
        request,
        [
            "/dashboard/:path*",
            "/admin/:path*"
        ],
        "/login"
    ).authenticationByCookies();

}
```

---

# Session Manager

Automatically

- Reads access token
- Checks expiration
- Refreshes expired token
- Redirects unauthorized users

```ts
const session = new SessionManager(router);

const token = await session.getToken();
```

---

# Security

This library includes several security features:

- Argon2id Password Hashing
- RSA JWT Signature
- AES-256 Encryption
- Expiration Validation
- Cookie Authentication
- Authorization Header Validation

---

# Dependencies

- jose
- argon2
- crypto
- next
- path-to-regexp

---

# Designed For

This package is ideal for:

- Next.js App Router
- REST APIs
- Admin Dashboards
- ERP Systems
- CRM Applications
- SaaS Platforms

---

# License

MIT License

---

# Author

**M N Tushar**

GitHub:
https://github.com/<your-username>

---

# Contributing

Contributions, issues, and feature requests are welcome.

Feel free to open an issue or submit a pull request.

---

# Future Improvements

- Two Factor Authentication
- Email Verification
- Rate Limiting
- Session Revocation
