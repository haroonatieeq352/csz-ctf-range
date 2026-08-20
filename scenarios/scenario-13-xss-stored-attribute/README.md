# Scenario 13: Stored XSS in Attribute Context & Event Breakout

- **Port:** `8013`
- **Vulnerability:** Stored Cross-Site Scripting (HTML Attribute Breakout)
- **Flag:** `CTF{st0r3d_4ttr1but3_br34k0ut}`

## Exploitation Walkthrough
1. Access `http://<host>:8013/feedback`.
2. Notice submitting `<script>` tags gets stripped by server-side filter.
3. Inspect the DOM to observe author name rendered inside an `<input value="...">` attribute.
4. Submit an attribute breakout payload in the Developer Handle / Name field:
   - **Author:** `" onfocus="alert(1)" autofocus="`  *(or `"><img src=x onerror=alert(1)>`)*
   - **Comment:** `Triggering attribute payload`
5. On submission and page reload, the `autofocus` attribute forces browser focus onto the input, executing the `onfocus` JavaScript event handler and revealing the captured flag.
