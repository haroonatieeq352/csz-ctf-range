# Scenario 12: Reflected XSS into HTML Context (Tag Breakout)

- **Port:** `8012`
- **Vulnerability:** Reflected Cross-Site Scripting (HTML Tag Breakout)
- **Flag:** `CTF{r3fl3ct3d_xss_b4s1cs}`
- **Tooling:** Browser URL / Search Input (No Burp Suite required)

## Exploitation Walkthrough
1. **Reflection Discovery:** Enter a search query (e.g. `test`) and observe that it is reflected on the page.
2. **Initial Attempt Trapped:** Submit `<script>alert(1)</script>` in the search box.
   - The alert does NOT pop up because the input is trapped inside a `<textarea>` tag.
3. **Source Code Inspection:** Right click and inspect the DOM (`Ctrl + U` / `Ctrl + Shift + I`).
   - Notice: `<textarea class="query-echo-box" readonly rows="2"><script>alert(1)</script></textarea>`.
4. **Tag Breakout Execution:** Close the `<textarea>` tag first:
   ```html
   </textarea><script>alert(1)</script>
   ```
5. **Flag Reveal:** The script executes, the alert pops up, and the page automatically displays the CTF flag!
