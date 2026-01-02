# Authentication System

A robust and secure authentication system built with Node.js, Express, and MongoDB. This system implements modern security practices, including OTP-based email verification, JWT authentication, and brute-force protection.

## 🚀 Features

### 🔐 Multi-Step Authentication
- **Secure Registration:** Registers users with hashed passwords using `bcrypt`.
- **Email Verification (OTP):** Automatically generates and sends a 6-digit OTP via Gmail upon registration.
- **Brute-Force Protection:** Limits OTP verification attempts (max 5) to prevent automated attacks.
- **OTP Expiry:** Tokens are valid for only 10 minutes for enhanced security.

### 🛡️ Security Measures
- **Password Hashing:** Uses `bcrypt` for one-way password encryption.
- **Secure Storage:** OTPs are hashed using `SHA-256` before being stored in the database.
- **JWT Protection:** State-of-the-art authentication using JSON Web Tokens (JWT).
- **Session Integrity:** Automatically invalidates active JWTs if a user changes their password.
- **Route Protection:** Middleware to ensure only authorized users can access specific resources.

### 🔄 Password & Account Management
- **Forget Password:** Secure OTP-based identity verification for password recovery.
- **Reset Password:** Allows users to set a new password after successful verification.
- **Soft Deactivation:** Users can "delete" their accounts, which simply deactivates them (`active: false`) without immediate data loss.
- **Profile Updates:** Users can securely update their name and email.

## 🛠️ Technology Stack
- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB with Mongoose ODM
- **Security:** JWT (JSON Web Tokens), Bcrypt, Crypto
- **Communication:** Nodemailer (Gmail service)

## 📍 API Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/signUp` | `POST` | Register a new user and send verification OTP |
| `/signIn` | `POST` | Authenticate user and return JWT |
| `/verifyUser` | `POST` | Verify email using OTP |
| `/requestNewOTP` | `POST` | Resend a new verification OTP |
| `/forgetPassword` | `POST` | Initiate password recovery via OTP |
| `/verifyResetPassword`| `POST` | Verify OTP for password reset |
| `/resetPassword` | `POST` | Update password after recovery verification |

## 📦 User Model Attributes
- `name`: User's full name.
- `email`: Unique email address.
- `password`: Securely hashed password (hidden by default).
- `isVerified`: Boolean flag for email verification status.
- `otp`: Hashed one-time password.
- `otpExpiry`: Timestamp for OTP expiration.
- `active`: Boolean flag for account status (Soft Delete).
- `passwordChangeAt`: Tracks last password modification for session management.
