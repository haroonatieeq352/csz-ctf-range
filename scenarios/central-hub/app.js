// CSZone Central Operations Hub — Scenario Dynamic Registry & Dispatcher
const SCENARIOS = [
  {
    id: 1,
    title: "Scenario 01: Recon & HTTP Debug Headers",
    category: "recon",
    categoryLabel: "Reconnaissance / HTTP",
    difficulty: "easy",
    difficultyLabel: "Easy",
    port: 8001,
    description: "Investigate developer comments in frontend DOM structure and unearth hidden HTTP response debugging headers.",
    tags: ["HTML Comments", "HTTP Headers", "Recon"]
  },
  {
    id: 2,
    title: "Scenario 02: Robots.txt & Ops Archive Recon",
    category: "recon",
    categoryLabel: "Reconnaissance / Traversal",
    difficulty: "easy",
    difficultyLabel: "Easy",
    port: 8002,
    description: "Discover disallowed internal pathways in robots.txt and inspect server operations archive dumps for leaked tokens.",
    tags: ["robots.txt", "Sensitive Logs", "Directory Traversal"]
  },
  {
    id: 3,
    title: "Scenario 03: JavaScript & XOR Cryptography",
    category: "crypto",
    categoryLabel: "Cryptography / JS Deobfuscation",
    difficulty: "medium",
    difficultyLabel: "Medium",
    port: 8003,
    description: "Extract hidden global window properties in script bundles and decrypt single-byte XOR protected secrets.",
    tags: ["JS Obfuscation", "XOR Crypto", "Config Analysis"]
  },
  {
    id: 4,
    title: "Scenario 04: Admin Relocation Leak",
    category: "access",
    categoryLabel: "Broken Access Control",
    difficulty: "easy",
    difficultyLabel: "Easy",
    port: 8004,
    description: "Identify administrative path migrations through client-side console logging and access unprotected admin consoles.",
    tags: ["Console Leak", "Broken Access", "Admin Portal"]
  },
  {
    id: 5,
    title: "Scenario 05: Frontend IDOR Invoices",
    category: "access",
    categoryLabel: "Insecure Direct Object Reference",
    difficulty: "easy",
    difficultyLabel: "Easy",
    port: 8005,
    description: "Manipulate sequential client query parameters to view sensitive internal vendor invoices and audit notes.",
    tags: ["IDOR", "Parameter Tampering", "Invoices"]
  },
  {
    id: 6,
    title: "Scenario 06: Partner Promo & Cookie Guard",
    category: "crypto",
    categoryLabel: "Crypto & Cookie Bypass",
    difficulty: "medium",
    difficultyLabel: "Medium",
    port: 8006,
    description: "Decode promotional vouchers and forge elevated cookie privilege headers to pass administrative gate checks.",
    tags: ["Base64", "Cookie Forgery", "Auth Bypass"]
  },
  {
    id: 7,
    title: "Scenario 07: Backup Service Authentication",
    category: "access",
    categoryLabel: "Auth / Brute-Force",
    difficulty: "medium",
    difficultyLabel: "Medium",
    port: 8007,
    description: "Examine salt schema exports, crack SHA-256 password digests, and launch credential brute-force attacks.",
    tags: ["Hash Cracking", "Burp Intruder", "Authentication"]
  },
  {
    id: 8,
    title: "Scenario 08: Central Vault Finale",
    category: "crypto",
    categoryLabel: "Multi-Byte XOR Crypto",
    difficulty: "hard",
    difficultyLabel: "Hard",
    port: 8008,
    description: "Combine dual-authentication credentials with multi-byte repeating XOR key cryptanalysis to unlock the master vault.",
    tags: ["Multi-Byte XOR", "Dual-Auth", "Crypto Finale"]
  },
  {
    id: 9,
    title: "Scenario 09: Products SQL Injection",
    category: "sqli",
    categoryLabel: "SQLi / E-Commerce Filter",
    difficulty: "medium",
    difficultyLabel: "Medium",
    port: 8009,
    description: "Exploit Boolean logic bypasses in product queries and perform UNION-based database extraction from hidden tables.",
    tags: ["Boolean SQLi", "UNION SQLi", "Database"]
  },
  {
    id: 10,
    title: "Scenario 10: Personnel Directory UNION SQLi",
    category: "sqli",
    categoryLabel: "SQLi / 3-Column UNION",
    difficulty: "medium",
    difficultyLabel: "Medium",
    port: 8010,
    description: "Determine column counts, map data types, and extract confidential employee clearance records via UNION SELECT.",
    tags: ["UNION SELECT", "Schema Discovery", "SQLi"]
  },
  {
    id: 11,
    title: "Scenario 11: Enterprise Asset Inventory (Schema SQLi)",
    category: "sqli",
    categoryLabel: "SQLi / 4-Column Schema Enum",
    difficulty: "hard",
    difficultyLabel: "Hard",
    port: 8011,
    description: "Break out of double quotes, use '#' comments, map 4 strict datatypes, and enumerate hidden tables via sqlite_master.",
    tags: ["Double Quotes", "4-Column UNION", "Schema Enumeration", "SQLi"]
  },
  {
    id: 12,
    title: "Scenario 12: Reflected XSS (HTML Context)",
    category: "xss",
    categoryLabel: "Cross-Site Scripting / Reflected",
    difficulty: "easy",
    difficultyLabel: "Easy",
    port: 8012,
    description: "Identify unsanitized parameter reflection in search results and execute client-side scripts to extract hidden session tokens.",
    tags: ["Reflected XSS", "DOM Token", "HTML Context"]
  },
  {
    id: 13,
    title: "Scenario 13: Stored XSS (Attribute & Event Breakout)",
    category: "xss",
    categoryLabel: "Cross-Site Scripting / Stored",
    difficulty: "medium",
    difficultyLabel: "Medium",
    port: 8013,
    description: "Bypass naive tag filters by breaking out of input attributes and leveraging autofocus event handlers to trigger stored payloads.",
    tags: ["Stored XSS", "Attribute Breakout", "Event Handlers"]
  },
  {
    id: 14,
    title: "Scenario 14: DOM-based XSS (Source to Sink)",
    category: "xss",
    categoryLabel: "Cross-Site Scripting / DOM-based",
    difficulty: "hard",
    difficultyLabel: "Hard",
    port: 8014,
    description: "Trace client JavaScript execution from URL parameter sources to innerHTML sinks and dump internal window telemetry secrets.",
    tags: ["DOM XSS", "Source to Sink", "Client-Side SPA"]
  },
  {
    id: 15,
    title: "Scenario 15: Advanced WAF & Filter Bypass XSS",
    category: "xss",
    categoryLabel: "Cross-Site Scripting / WAF Bypass",
    difficulty: "hard",
    difficultyLabel: "Expert",
    port: 8015,
    description: "Evade aggressive WAF regex rules blocking script tags and common handlers using HTML5 SVG animation and toggle vectors.",
    tags: ["WAF Evasion", "HTML5 Vectors", "SVG Animation"]
  },
  {
    id: 16,
    title: "Scenario 16: INSERT SQLi to Second-Order Stored XSS",
    category: "web",
    categoryLabel: "Chained / INSERT SQLi + Stored XSS",
    difficulty: "hard",
    difficultyLabel: "Expert",
    port: 8016,
    description: "Exploit an INSERT-based SQL injection to elevate ticket triage priority and plant a Second-Order Stored XSS payload rendered in the Admin Compliance Queue.",
    tags: ["INSERT SQLi", "Second-Order XSS", "Privilege Escalation", "Chained"]
  },
  {
    id: 17,
    title: "Scenario 17: Mass Assignment & Profile Overwrite IDOR",
    category: "access",
    categoryLabel: "BOPLA / Mass Assignment IDOR",
    difficulty: "medium",
    difficultyLabel: "Practitioner",
    port: 8017,
    description: "Intercept background profile updates to exploit Mass Assignment parameter binding and elevate account role to administrator.",
    tags: ["Mass Assignment", "BOPLA", "Profile IDOR", "Privilege Escalation"]
  },
  {
    id: 18,
    title: "Scenario 18: Obfuscated & UUID Leakage IDOR",
    category: "access",
    categoryLabel: "UUID Discovery / Vault IDOR",
    difficulty: "medium",
    difficultyLabel: "Intermediate",
    port: 8018,
    description: "Discover unguessable executive document UUIDs leaked in public audit feeds and bypass ownership checks on private download routes.",
    tags: ["UUID Discovery", "Vault IDOR", "Information Leakage"]
  },
  {
    id: 19,
    title: "Scenario 19: RESTful HTTP Verb Tampering & Multi-Tenant IDOR",
    category: "access",
    categoryLabel: "Verb Tampering / Multi-Tenant BOLA",
    difficulty: "hard",
    difficultyLabel: "Advanced",
    port: 8019,
    description: "Bypass 403 Forbidden gateway filters on sovereign tenant endpoints by switching HTTP verbs to PUT/PATCH and extracting master keys.",
    tags: ["Verb Tampering", "BOLA", "Multi-Tenant", "API Security"]
  },
  {
    id: 20,
    title: "Scenario 20: BOLA Multi-Step Password Reset ATO",
    category: "access",
    categoryLabel: "BOLA / Account Takeover",
    difficulty: "hard",
    difficultyLabel: "Expert",
    port: 8020,
    description: "Exploit Broken Object Level Authorization during multi-step OTP verification to issue an admin password reset token and achieve full ATO.",
    tags: ["BOLA", "Password Reset", "Account Takeover", "API1:2023"]
  },
  {
    id: 21,
    title: "Scenario 21: Web Cache Deception & Poisoning",
    category: "web",
    categoryLabel: "Web Cache Attacks",
    difficulty: "hard",
    difficultyLabel: "In Development",
    isComingSoon: true,
    port: 8021,
    description: "Trick proxy caching layers using static delimiter extensions (.css, .js) and poison multi-tier shared edge caches via unkeyed request headers.",
    tags: ["Cache Deception", "Cache Poisoning", "Edge Caching"]
  },
  {
    id: 22,
    title: "Scenario 22: Cross-Site Request Forgery (CSRF)",
    category: "web",
    categoryLabel: "CSRF / State Change",
    difficulty: "medium",
    difficultyLabel: "In Development",
    isComingSoon: true,
    port: 8022,
    description: "Craft cross-site state-changing POST requests against vulnerable account profile endpoints without anti-CSRF tokens and bypass SameSite cookie protections.",
    tags: ["CSRF", "State Change", "Web Security"]
  },
  {
    id: 23,
    title: "Scenario 23: Unrestricted File Upload & Stored Execution",
    category: "web",
    categoryLabel: "File Upload / Stored XSS",
    difficulty: "medium",
    difficultyLabel: "In Development",
    isComingSoon: true,
    port: 8023,
    description: "Bypass server extension blocklists, MIME type validators, and magic byte filters to upload arbitrary HTML files and execute client-side scripts in user context.",
    tags: ["File Upload", "MIME Bypass", "Polyglot Files"]
  },
  {
    id: 24,
    title: "Scenario 24: Server-Side Request Forgery (SSRF)",
    category: "web",
    categoryLabel: "SSRF / Metadata Retrieval",
    difficulty: "medium",
    difficultyLabel: "In Development",
    isComingSoon: true,
    port: 8024,
    description: "Force the remote web backend to fetch loopback internal cloud metadata APIs (169.254.169.254) and bypass IP address access whitelists via DNS rebinding.",
    tags: ["SSRF", "Internal Metadata", "Cloud Security"]
  }
];

// Determine host dynamically so it works seamlessly on localhost, 127.0.0.1, LAN, VPS IP, or custom domain!
let currentHost = window.location.hostname || "localhost";
if (currentHost === "0.0.0.0" || currentHost === "") {
  currentHost = "localhost";
}
const currentProtocol = window.location.protocol || "http:";

const scenariosGrid = document.getElementById("scenariosGrid");
const searchInput = document.getElementById("searchInput");
const filterPills = document.getElementById("filterPills");
const visibleCounter = document.getElementById("visibleCounter");

let activeFilter = "all";
let searchQuery = "";

function buildScenarioUrl(s) {
  let hostname = window.location.hostname || "localhost";
  const protocol = window.location.protocol || "http:";
  
  if (hostname === "0.0.0.0" || hostname === "") {
    hostname = "localhost";
  }

  const padId = String(s.id).padStart(2, "0"); // 1 -> "01", 20 -> "20"

  // 1. Subdomain routing (e.g. hub.offensivegrid.com, hub.offensgrid.com, or any hub.<domain>)
  if (hostname.startsWith("hub.")) {
    const rootDomain = hostname.substring(4); // e.g. offensivegrid.com
    return `${protocol}//s${padId}.${rootDomain}`;
  }

  // 2. Direct domain check
  if (hostname.includes("offensivegrid.com") || hostname.includes("offensgrid.com")) {
    const baseDomain = hostname.includes("offensivegrid.com") ? "offensivegrid.com" : "offensgrid.com";
    return `${protocol}//s${padId}.${baseDomain}`;
  }

  // 3. Localhost / Local IP development fallback
  return `${protocol}//${hostname}:${s.port}`;
}

function renderCards() {
  const filtered = SCENARIOS.filter(s => {
    const matchesFilter = activeFilter === "all" || s.category === activeFilter;
    const query = searchQuery.toLowerCase().trim();
    const matchesSearch = !query || 
      s.title.toLowerCase().includes(query) ||
      s.categoryLabel.toLowerCase().includes(query) ||
      s.description.toLowerCase().includes(query) ||
      s.port.toString().includes(query) ||
      s.tags.some(t => t.toLowerCase().includes(query));
    return matchesFilter && matchesSearch;
  });

  if (visibleCounter) {
    visibleCounter.textContent = `Showing ${filtered.length} of ${SCENARIOS.length} targets`;
  }

  if (filtered.length === 0) {
    scenariosGrid.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 60px 20px; color: var(--text-muted);">
        <p style="font-size: 1.2rem; margin-bottom: 8px;">No scenarios matched your query.</p>
        <p style="font-size: 0.88rem;">Try searching for another vulnerability or reset your filter.</p>
      </div>
    `;
    return;
  }

  scenariosGrid.innerHTML = filtered.map(s => {
    const targetUrl = buildScenarioUrl(s);
    if (s.isComingSoon) {
      return `
        <div class="scenario-card card-coming-soon" data-category="${s.category}" style="border: 1px dashed rgba(245, 158, 11, 0.4); background: rgba(22, 18, 28, 0.75);">
          <div class="card-top">
            <span class="port-tag" style="opacity: 0.7;">PORT ${s.port}</span>
            <span class="difficulty-badge" style="background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); font-weight: 700;">🚧 COMING SOON</span>
          </div>
          <h4 class="card-title" style="color: #e2e8f0;">${s.title}</h4>
          <div class="card-cat" style="color: #f59e0b;">${s.categoryLabel}</div>
          <p class="card-desc" style="color: #94a3b8;">${s.description}</p>
          <div class="card-action">
            <button type="button" onclick="openComingSoonModal(${s.id})" class="launch-btn" style="background: #191422; color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); cursor: pointer; width: 100%;">
              <span>🚧 Work in Progress</span>
            </button>
          </div>
        </div>
      `;
    }
    return `
      <div class="scenario-card" data-category="${s.category}">
        <div class="card-top">
          <span class="port-tag">PORT ${s.port}</span>
          <span class="difficulty-badge diff-${s.difficulty}">${s.difficultyLabel}</span>
        </div>
        <h4 class="card-title">${s.title}</h4>
        <div class="card-cat">${s.categoryLabel}</div>
        <p class="card-desc">${s.description}</p>
        <div class="card-action">
          <a href="${targetUrl}" target="_blank" class="launch-btn">
            <span>Launch Target</span>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
              <polyline points="15 3 21 3 21 9"></polyline>
              <line x1="10" y1="14" x2="21" y2="3"></line>
            </svg>
          </a>
        </div>
      </div>
    `;
  }).join("");
}

function openComingSoonModal(scenarioId) {
  const s = SCENARIOS.find(item => item.id === scenarioId);
  if (!s) return;
  document.getElementById("modalTitle").textContent = s.title;
  document.getElementById("modalPort").textContent = `PORT ${s.port}`;
  document.getElementById("modalCategory").textContent = s.categoryLabel;
  document.getElementById("modalDesc").textContent = s.description;
  const modal = document.getElementById("comingSoonModal");
  if (modal) modal.style.display = "flex";
}

function closeComingSoonModal() {
  const modal = document.getElementById("comingSoonModal");
  if (modal) modal.style.display = "none";
}

function handleBackdropClick(e) {
  if (e.target && e.target.id === "comingSoonModal") {
    closeComingSoonModal();
  }
}

// Event Listeners
if (searchInput) {
  searchInput.addEventListener("input", (e) => {
    searchQuery = e.target.value;
    renderCards();
  });
}

if (filterPills) {
  filterPills.addEventListener("click", (e) => {
    const btn = e.target.closest(".pill");
    if (!btn) return;
    filterPills.querySelectorAll(".pill").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    activeFilter = btn.dataset.category;
    renderCards();
  });
}

// Initial Render
document.addEventListener("DOMContentLoaded", () => {
  renderCards();
});
