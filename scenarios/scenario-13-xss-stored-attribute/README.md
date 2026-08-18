# Scenario 13: Stored XSS in Attribute Context & Event Breakout

- **Port:** `8013`
- **Vulnerability:** Stored Cross-Site Scripting (HTML Attribute Breakout)
- **Flag:** `CTF{st0r3d_4ttr1but3_br34k0ut}`

## Exploitation Walkthrough
1. Access `http://<host>:8013/feedback`.
2. Notice submitting `<script>` tags gets stripped by server-side filter.
3. Inspect the DOM to observe author name rendered inside an `<input value="...">` attribute.
4. Submit an attribute breakout payload using Burp Suite or the form:
   - **Author:** `" onfocus="document.getElementById('reward-panel').innerText=document.getElementById('secret-vault-key').value" autofocus="`
   - **Comment:** `Triggering attribute payload`
5. On page reload, the `autofocus` attribute forces focus onto the input, executing `onfocus` handler and revealing the flag.
