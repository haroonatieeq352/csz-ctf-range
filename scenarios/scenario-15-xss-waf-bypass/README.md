# Scenario 15: Advanced WAF & Filter Bypass XSS

- **Port:** `8015`
- **Vulnerability:** Web Application Firewall & Filter Evasion XSS
- **Flag:** `CTF{w4f_byp4ss_h5_v3ct0r}`

## Exploitation Walkthrough
1. Access `http://<host>:8015/preview?rule=test`.
2. Test common payloads (`<script>`, `onerror=`, `onload=`, `"`) and observe WAF error signatures.
3. Identify that HTML5 events (e.g. `<svg><animate onbegin=...>`, `<details open ontoggle=...>`, `<body onpageshow=...>`) are not in the blocklist.
4. Notice that double quotes `"` are blocked by the WAF, but single quotes `'` or template strings are permitted.
5. Craft an evasion vector without double quotes using allowed HTML5 tags & event triggers:
   ```html
   <svg><animate onbegin=alert('cszone') attributeName=x>
   ```
   Or:
   ```html
   <details open ontoggle=alert('cszone')>
   ```
6. Submit the payload via the Rule Input form or URL query to bypass the WAF filter, execute `alert("cszone")`, and reveal the captured flag.
