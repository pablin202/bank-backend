# 🏦 Bank App Backend

This is a secure, modular backend for a **mock banking application**, built with [NestJS](https://nestjs.com/) and [PostgreSQL](https://www.postgresql.org/), designed to demonstrate best practices in authentication, security, and clean architecture.

---

## 🎯 Objective

This project aims to showcase how a banking app backend **should be structured and secured**, following real-world practices such as:

✅ JWT-based authentication  
✅ MFA (TOTP with Google Authenticator / Authy)  
✅ Modular NestJS architecture  
✅ Protected endpoints with roles and authorization  
✅ PostgreSQL with encrypted data  
✅ Ready for cloud deployment

---

## 🚀 Features

- User registration & login (with bcrypt password hashing)
- JWT authentication
- Optional MFA using TOTP (QR code for setup)
- Protected endpoints: account balance, transactions, transfer
- Modular architecture (User, Auth, Account modules)
- Mock data for demo purposes
- OpenAPI-ready

---

## 📦 Modules & Dependencies

Our application follows NestJS's modular and decoupled architecture.  
Each module has a single responsibility and exports only what is required.

### 🔷 Diagram
```mermaid
graph TD

  UserModule -->|exports UserService| AuthModule
  AuthModule -->|uses AuthService & JwtAuthGuard| AccountModule

  UserModule[UserModule]
  AuthModule[AuthModule]
  AccountModule[AccountModule]


