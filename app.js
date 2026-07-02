const state = {
  target: null,
  headers: new Map(),
  rawHeaders: "",
  html: "",
  findings: [],
  tech: [],
  ssl: [],
  fetchStatus: "Not checked",
  generatedAt: null
};

const severityWeight = {
  critical: 22,
  high: 16,
  medium: 9,
  low: 4,
  info: 0
};

const owasp = [
  ["A01", "Broken Access Control", "Review authorization on object IDs, admin routes, CORS trust, and unauthenticated endpoints."],
  ["A02", "Cryptographic Failures", "Confirm HTTPS everywhere, modern TLS, HSTS, secure cookies, and no sensitive data in cacheable responses."],
  ["A03", "Injection", "Test SQL/NoSQL/LDAP/OS command injection with safe payloads in authorized environments."],
  ["A04", "Insecure Design", "Threat model abuse cases, rate limits, business logic, recovery flows, and tenant boundaries."],
  ["A05", "Security Misconfiguration", "Check headers, default files, directory listing, verbose errors, and cloud storage exposure."],
  ["A06", "Vulnerable and Outdated Components", "Inventory frameworks, libraries, server banners, and map versions to NVD or vendor advisories."],
  ["A07", "Identification and Authentication Failures", "Check MFA, lockout, password reset, session rotation, and cookie attributes."],
  ["A08", "Software and Data Integrity Failures", "Check SRI, CI/CD trust, dependency pinning, signed updates, and deserialization surfaces."],
  ["A09", "Security Logging and Monitoring Failures", "Confirm audit trails, alerting, retention, and incident response evidence."],
  ["A10", "Server-Side Request Forgery", "Test URL fetchers, webhooks, importers, metadata IP blocks, and DNS rebinding defenses."]
];

const headerRules = [
  {
    header: "strict-transport-security",
    missing: ["high", "Missing HSTS", "Browsers are not instructed to force HTTPS for future visits.", "Add Strict-Transport-Security with a long max-age after confirming HTTPS is stable."],
    check: value => /max-age=(\d+)/i.test(value) && Number(value.match(/max-age=(\d+)/i)[1]) >= 15552000
      ? null
      : ["medium", "Weak HSTS max-age", "HSTS exists but the max-age is shorter than common production baselines.", "Use max-age=31536000 or longer, includeSubDomains when safe, and consider preload."]
  },
  {
    header: "content-security-policy",
    missing: ["high", "Missing Content Security Policy", "No CSP was found, so XSS impact and content injection risk are harder to contain.", "Add a restrictive CSP; avoid unsafe-inline and wildcard script sources."],
    check: value => /unsafe-inline|unsafe-eval|\*/i.test(value)
      ? ["medium", "CSP allows risky sources", "The CSP contains unsafe-inline, unsafe-eval, or wildcards.", "Tighten script-src, object-src, base-uri, frame-ancestors, and use nonces or hashes."]
      : null
  },
  {
    header: "x-frame-options",
    alt: "content-security-policy",
    missing: ["medium", "No clickjacking protection found", "Neither X-Frame-Options nor an obvious CSP frame-ancestors directive was found.", "Use CSP frame-ancestors and keep X-Frame-Options for older browsers."],
    check: value => /deny|sameorigin/i.test(value) ? null : ["low", "Weak X-Frame-Options", "X-Frame-Options is present but not DENY or SAMEORIGIN.", "Set DENY or SAMEORIGIN, or enforce CSP frame-ancestors."]
  },
  {
    header: "x-content-type-options",
    missing: ["medium", "Missing X-Content-Type-Options", "Browsers may MIME-sniff responses in risky ways.", "Set X-Content-Type-Options: nosniff on all responses."],
    check: value => /nosniff/i.test(value) ? null : ["low", "Weak X-Content-Type-Options", "Header is present but does not include nosniff.", "Set X-Content-Type-Options: nosniff."]
  },
  {
    header: "referrer-policy",
    missing: ["low", "Missing Referrer-Policy", "URLs and paths may leak through the Referer header.", "Set strict-origin-when-cross-origin or a stricter policy."],
    check: () => null
  },
  {
    header: "permissions-policy",
    missing: ["low", "Missing Permissions-Policy", "Powerful browser features are not explicitly restricted.", "Add a Permissions-Policy that disables unused camera, microphone, geolocation, payment, and sensor APIs."],
    check: () => null
  }
];

const techPatterns = [
  ["WordPress", /wp-content|wp-includes|generator["'][^>]*wordpress\s*([\d.]+)?/i],
  ["Drupal", /drupal(?:\s|_)?([\d.]+)?/i],
  ["Joomla", /joomla!?\s*([\d.]+)?/i],
  ["jQuery", /jquery[-.]([\d.]+)(?:\.min)?\.js|jquery\s*v?([\d.]+)/i],
  ["Bootstrap", /bootstrap[-.]([\d.]+)(?:\.min)?\.(?:css|js)|bootstrap\s*v?([\d.]+)/i],
  ["React", /react(?:\.production)?(?:\.min)?\.js|data-reactroot|react\s*v?([\d.]+)/i],
  ["Vue", /vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js|vue\s*v?([\d.]+)/i],
  ["Angular", /angular(?:\.min)?\.js|ng-version=["']([\d.]+)/i],
  ["Next.js", /_next\/static|next\.js\s*v?([\d.]+)/i],
  ["Laravel", /laravel_session|laravel\s*v?([\d.]+)/i],
  ["Django", /csrftoken|django\s*v?([\d.]+)/i]
];

const $ = selector => document.querySelector(selector);

document.addEventListener("DOMContentLoaded", () => {
  render();
  $("#scan-form").addEventListener("submit", event => {
    event.preventDefault();
    scanTarget();
  });
  $("#analyze-evidence").addEventListener("click", analyzeEvidence);
  $("#load-demo").addEventListener("click", loadDemo);
  $("#clear-all").addEventListener("click", clearAll);
  $("#copy-report").addEventListener("click", copyReport);
  $("#download-json").addEventListener("click", downloadJson);
  document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", switchTab));
});

async function scanTarget() {
  resetAnalysis();
  const parsed = parseTarget($("#target-url").value);
  if (!parsed) {
    addFinding("high", "Invalid target URL", "The scanner could not parse the supplied target.", "Use a full URL such as https://example.com.");
    render();
    return;
  }

  state.target = parsed;
  state.generatedAt = new Date();
  addUrlFindings(parsed);

  if ($("#attempt-fetch").checked) {
    await browserFetch(parsed.href);
  }

  mergeManualEvidence();
  analyzeHeaders();
  analyzeCookies();
  analyzeHtml();
  detectTechnologies();
  if ($("#deep-links").checked) buildDeepLinks(parsed);

  if ($("#attempt-ssl").checked && parsed.protocol === "https:") {
    await requestSslLabs(parsed.hostname);
  }

  render();
}

function analyzeEvidence() {
  resetAnalysis();
  state.target = parseTarget($("#target-url").value);
  state.generatedAt = new Date();
  if (state.target) addUrlFindings(state.target);
  mergeManualEvidence();
  analyzeHeaders();
  analyzeCookies();
  analyzeHtml();
  detectTechnologies();
  if (state.target && $("#deep-links").checked) buildDeepLinks(state.target);
  render();
}

function resetAnalysis() {
  state.headers = new Map();
  state.rawHeaders = "";
  state.html = "";
  state.findings = [];
  state.tech = [];
  state.ssl = [];
  state.fetchStatus = "Not checked";
}

function parseTarget(value) {
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value.trim()) ? value.trim() : `https://${value.trim()}`;
    const url = new URL(withScheme);
    if (!/^https?:$/.test(url.protocol)) return null;
    return url;
  } catch {
    return null;
  }
}

async function browserFetch(url) {
  try {
    const response = await fetch(url, { method: "GET", mode: "cors", credentials: "omit", cache: "no-store" });
    state.fetchStatus = `${response.status} ${response.statusText || ""}`.trim();
    response.headers.forEach((value, key) => state.headers.set(key.toLowerCase(), value));
    state.html = await response.text();
  } catch (error) {
    state.fetchStatus = "Blocked by browser CORS or network policy";
    addFinding("info", "Browser fetch could not read the target", "Static scanners are limited by browser CORS. Paste response headers or HTML to analyze evidence directly.", "Use curl -I, browser DevTools, or a server-side scanner for complete coverage.");
  }
}

function mergeManualEvidence() {
  const rawHeaders = $("#headers-input").value.trim();
  const html = $("#html-input").value.trim();
  if (rawHeaders) {
    state.rawHeaders = rawHeaders;
    parseHeaders(rawHeaders).forEach((value, key) => state.headers.set(key, value));
  }
  if (html) {
    state.html = `${state.html}\n${html}`;
  }
}

function parseHeaders(raw) {
  const headers = new Map();
  raw.split(/\r?\n/).forEach(line => {
    const match = line.match(/^([a-z0-9!#$%&'*+.^_`|~-]+)\s*:\s*(.*)$/i);
    if (!match) return;
    const key = match[1].toLowerCase();
    const previous = headers.get(key);
    headers.set(key, previous ? `${previous}, ${match[2].trim()}` : match[2].trim());
  });
  return headers;
}

function addUrlFindings(url) {
  if (url.protocol !== "https:") {
    addFinding("critical", "Target is not using HTTPS", "Plain HTTP exposes traffic to interception and downgrade attacks.", "Redirect all HTTP traffic to HTTPS and enable HSTS.");
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(url.hostname)) {
    addFinding("medium", "Target uses an IP address", "IP-based origins often miss proper certificates, host isolation, and cookie scoping.", "Use a DNS hostname with a valid certificate and clear ownership.");
  }
  if (url.hostname.startsWith("xn--") || url.hostname.includes(".xn--")) {
    addFinding("low", "Internationalized domain detected", "Punycode domains can be legitimate, but they deserve phishing and lookalike review.", "Verify the displayed domain, certificate subject, and brand ownership.");
  }
}

function analyzeHeaders() {
  const has = name => state.headers.has(name);
  const get = name => state.headers.get(name) || "";

  headerRules.forEach(rule => {
    const value = get(rule.header);
    const coveredByAlt = rule.header === "x-frame-options" && /frame-ancestors/i.test(get("content-security-policy"));
    if (!value && !coveredByAlt) {
      addFinding(...rule.missing);
      return;
    }
    if (value && rule.check) {
      const finding = rule.check(value);
      if (finding) addFinding(...finding);
    }
  });

  if (has("server")) {
    addFinding("low", "Server banner exposed", `Server header discloses: ${get("server")}.`, "Reduce detailed product/version disclosure where possible.");
    addTechFromBanner("Server", get("server"));
  }
  if (has("x-powered-by")) {
    addFinding("medium", "X-Powered-By exposes platform", `X-Powered-By discloses: ${get("x-powered-by")}.`, "Remove framework and runtime banners from production responses.");
    addTechFromBanner("X-Powered-By", get("x-powered-by"));
  }
  if (/\*/.test(get("access-control-allow-origin"))) {
    addFinding("medium", "CORS allows any origin", "Access-Control-Allow-Origin is set to wildcard.", "Use explicit trusted origins and avoid credentials with broad CORS.");
  }
  if (has("x-xss-protection")) {
    addFinding("info", "Legacy X-XSS-Protection present", "This obsolete header is not a substitute for CSP and can be harmful in old browser edge cases.", "Prefer a strong CSP and set X-XSS-Protection: 0 if legacy behavior causes risk.");
  }
  if (/private|no-store|no-cache/i.test(get("cache-control")) === false && state.headers.size) {
    addFinding("low", "Cache policy not restrictive", "Cache-Control does not clearly prevent sensitive response caching.", "Use no-store for authenticated or sensitive pages.");
  }
}

function analyzeCookies() {
  const cookies = state.headers.get("set-cookie");
  if (!cookies) {
    if (state.headers.size) addFinding("info", "No Set-Cookie observed", "No cookies were visible in the supplied evidence.", "If the app uses sessions, inspect authenticated responses too.");
    return;
  }
  splitCookies(cookies).forEach(cookie => {
    const name = cookie.split("=")[0] || "cookie";
    if (!/;\s*secure/i.test(cookie)) addFinding("high", `Cookie ${name} missing Secure`, "The cookie may be sent over plaintext HTTP.", "Add the Secure attribute to session and sensitive cookies.");
    if (!/;\s*httponly/i.test(cookie)) addFinding("medium", `Cookie ${name} missing HttpOnly`, "Client-side scripts may read this cookie if XSS occurs.", "Add HttpOnly to session cookies.");
    if (!/;\s*samesite=(strict|lax|none)/i.test(cookie)) addFinding("medium", `Cookie ${name} missing SameSite`, "Cross-site request behavior is not explicitly constrained.", "Set SameSite=Lax or Strict; use None only with Secure when required.");
  });
}

function splitCookies(value) {
  return value.split(/,(?=\s*[^;,=\s]+=[^;]+)/).map(cookie => cookie.trim()).filter(Boolean);
}

function analyzeHtml() {
  if (!state.html) return;
  if (/http:\/\//i.test(state.html)) {
    addFinding("medium", "Possible mixed-content references", "HTML contains http:// references that may load insecure resources.", "Serve scripts, images, forms, and APIs over HTTPS only.");
  }
  if (/<form[^>]+action=["']http:\/\//i.test(state.html)) {
    addFinding("high", "Insecure form action", "A form appears to submit to an HTTP endpoint.", "Submit credentials and sensitive data only over HTTPS.");
  }
  if (/<script[^>]+src=["'][^"']+["'][^>]*>/i.test(state.html) && !/<script[^>]+integrity=/i.test(state.html)) {
    addFinding("low", "External scripts without visible SRI", "Script tags were found without Subresource Integrity in the supplied source.", "Use integrity and crossorigin for third-party static assets where feasible.");
  }
  if (/<!--[\s\S]*?(todo|password|secret|key|token|debug)[\s\S]*?-->/i.test(state.html)) {
    addFinding("medium", "Sensitive comment keywords", "HTML comments contain words commonly associated with secrets or debug notes.", "Remove sensitive comments and verify no credentials are embedded.");
  }
  if (/stack trace|exception|traceback|syntax error|fatal error/i.test(state.html)) {
    addFinding("high", "Verbose error details detected", "The supplied content resembles a stack trace or framework error page.", "Disable debug mode and return generic production errors.");
  }
}

function detectTechnologies() {
  const combined = `${state.rawHeaders}\n${state.html}`;
  techPatterns.forEach(([name, pattern]) => {
    const match = combined.match(pattern);
    if (!match) return;
    addTech(name, match[1] || match[2] || "");
  });

  for (const [key, value] of state.headers.entries()) {
    if (key === "server" || key === "x-powered-by") {
      value.split(/\s+/).forEach(part => {
        const match = part.match(/^([a-z][a-z0-9_.-]+)\/?([\d.]+)?/i);
        if (match) addTech(match[1], match[2] || "");
      });
    }
  }

  if (state.tech.length) {
    addFinding("info", "Technology inventory created", "Detected technology names and versions were converted into CVE lookup leads.", "Confirm exact versions from build manifests or server inventory before treating any CVE as applicable.");
  }
}

function addTechFromBanner(source, value) {
  const match = value.match(/([a-z][a-z0-9_.-]+)\/?([\d.]+)?/i);
  if (match) addTech(match[1], match[2] || "", source);
}

function addTech(name, version = "", source = "evidence") {
  const normalized = name.trim().replace(/^x-?powered-?by$/i, "");
  if (!normalized) return;
  const key = `${normalized.toLowerCase()}@${version}`;
  if (state.tech.some(item => item.key === key)) return;
  state.tech.push({ key, name: normalized, version, source });
}

function buildDeepLinks(url) {
  if (!url) return;
  const host = url.hostname;
  state.ssl.push({
    label: "SSL Labs deep grade",
    detail: "Authoritative TLS grading requires server-side network tests. Open this for protocol, cipher, certificate chain, HSTS, and known TLS issue checks.",
    href: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(host)}&latest`
  });
  state.ssl.push({
    label: "Hardenize report",
    detail: "Independent HTTPS, DNSSEC, email, and web hardening review.",
    href: `https://www.hardenize.com/report/${encodeURIComponent(host)}`
  });
  state.ssl.push({
    label: "Mozilla TLS configuration",
    detail: "Use Mozilla's current TLS profiles to tune servers after reviewing the grade.",
    href: "https://ssl-config.mozilla.org/"
  });
  state.ssl.push({
    label: "Mozilla Observatory web scan",
    detail: "Independent security header and web platform checks.",
    href: `https://developer.mozilla.org/en-US/observatory/analyze?host=${encodeURIComponent(host)}`
  });
  state.ssl.push({
    label: "security.txt location",
    detail: "Check whether the site publishes vulnerability disclosure contact details.",
    href: `${url.origin}/.well-known/security.txt`
  });
}

async function requestSslLabs(host) {
  try {
    const endpoint = `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(host)}&publish=off&fromCache=on&all=done`;
    const response = await fetch(endpoint, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    const grades = (data.endpoints || []).map(endpointData => endpointData.grade).filter(Boolean);
    if (grades.length) {
      const worst = grades.sort(compareSslGrades)[0];
      state.ssl.unshift({
        label: `Observed SSL Labs cache grade: ${grades.join(", ")}`,
        detail: `Status: ${data.status}. Worst listed grade: ${worst}. Re-run SSL Labs for fresh results before reporting final compliance.`,
        href: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(host)}&latest`
      });
      if (/^(A\+|A|A-)$/i.test(worst) === false) {
        addFinding("high", "TLS grade needs review", `SSL Labs reported grade ${worst} from cached endpoint data.`, "Review certificate chain, supported protocols, ciphers, HSTS, and known TLS vulnerabilities.");
      }
    }
  } catch {
    state.ssl.unshift({
      label: "SSL Labs API unavailable from this browser",
      detail: "The static app could not read SSL Labs API results. Use the linked SSL Labs report for the grade.",
      href: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(host)}&latest`
    });
  }
}

function compareSslGrades(a, b) {
  const rank = {
    "T": 0,
    "F": 1,
    "E": 2,
    "D": 3,
    "C": 4,
    "B": 5,
    "A-": 6,
    "A": 7,
    "A+": 8
  };
  return (rank[a] ?? -1) - (rank[b] ?? -1);
}

function addFinding(severity, title, detail, fix) {
  if (state.findings.some(item => item.title === title && item.detail === detail)) return;
  state.findings.push({ severity, title, detail, fix });
}

function score() {
  const penalty = state.findings.reduce((total, finding) => total + severityWeight[finding.severity], 0);
  const unknownPenalty = state.headers.size || state.html ? 0 : 8;
  return Math.max(0, Math.min(100, 100 - penalty - unknownPenalty));
}

function render() {
  const targetText = state.target ? state.target.href : "No target scanned yet";
  $("#target-title").textContent = targetText;
  const currentScore = state.findings.length || state.headers.size || state.html || state.target ? score() : "--";
  $("#score-value").textContent = currentScore;
  $("#score-label").textContent = currentScore === "--" ? "waiting" : scoreLabel(currentScore);
  renderSummary();
  renderFindings();
  renderSsl();
  renderTech();
  renderOwasp();
  $("#report-output").value = buildMarkdownReport();
}

function scoreLabel(value) {
  if (value >= 90) return "strong";
  if (value >= 75) return "fair";
  if (value >= 55) return "weak";
  return "urgent";
}

function renderSummary() {
  const counts = countSeverity();
  const items = [
    [counts.critical + counts.high, "critical/high"],
    [counts.medium, "medium"],
    [state.tech.length, "CVE leads"],
    [state.fetchStatus, "browser fetch"]
  ];
  $("#summary-grid").innerHTML = items.map(([value, label]) => `<div class="summary-item"><strong>${escapeHtml(String(value))}</strong><span>${escapeHtml(label)}</span></div>`).join("");
}

function countSeverity() {
  return state.findings.reduce((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    return counts;
  }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
}

function renderFindings() {
  const list = $("#findings-list");
  $("#finding-count").textContent = `${state.findings.length} finding${state.findings.length === 1 ? "" : "s"}`;
  if (!state.findings.length) {
    list.className = "finding-list empty-state";
    list.textContent = state.target || state.headers.size || state.html ? "No findings from supplied evidence." : "Enter a target or paste evidence to start.";
    return;
  }
  list.className = "finding-list";
  const ordered = [...state.findings].sort((a, b) => severityWeight[b.severity] - severityWeight[a.severity]);
  list.innerHTML = ordered.map(finding => `
    <article class="finding ${escapeHtml(finding.severity)}">
      <div class="severity-dot" aria-hidden="true"></div>
      <div>
        <div class="finding-head">
          <h4>${escapeHtml(finding.title)}</h4>
          <span class="severity">${escapeHtml(finding.severity)}</span>
        </div>
        <p class="finding-detail">${escapeHtml(finding.detail)}</p>
        <p class="finding-fix">${escapeHtml(finding.fix)}</p>
      </div>
    </article>
  `).join("");
}

function renderSsl() {
  $("#ssl-state").textContent = state.target ? "Ready" : "Needs target";
  $("#ssl-output").innerHTML = state.ssl.length ? state.ssl.map(item => `
    <div class="data-item">
      <strong><a href="${item.href}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.label)}</a></strong>
      <span>${escapeHtml(item.detail)}</span>
    </div>
  `).join("") : "<div class=\"empty-state\">Scan a HTTPS target to generate SSL grade checks.</div>";
}

function renderTech() {
  $("#tech-count").textContent = `${state.tech.length} technolog${state.tech.length === 1 ? "y" : "ies"}`;
  $("#tech-list").innerHTML = state.tech.length ? state.tech.map(item => {
    const query = `${item.name} ${item.version || ""}`.trim();
    const nvd = `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=${encodeURIComponent(query)}&search_type=all`;
    const cve = `https://www.cve.org/CVERecord/SearchResults?query=${encodeURIComponent(query)}`;
    const exploitDb = `https://www.exploit-db.com/search?text=${encodeURIComponent(query)}`;
    return `
      <article class="tech-item">
        <strong>${escapeHtml(item.name)} ${escapeHtml(item.version)}</strong>
        <span class="tech-meta">Source: ${escapeHtml(item.source)}. Treat matches as leads until versions are confirmed.</span>
        <div class="tech-links">
          <a href="${nvd}" target="_blank" rel="noopener noreferrer">NVD</a>
          <a href="${cve}" target="_blank" rel="noopener noreferrer">CVE.org</a>
          <a href="${exploitDb}" target="_blank" rel="noopener noreferrer">Exploit-DB</a>
        </div>
      </article>
    `;
  }).join("") : "<div class=\"empty-state\">No technology evidence yet. Paste headers, HTML, or dependency snippets.</div>";
}

function renderOwasp() {
  const findingText = state.findings.map(finding => `${finding.title} ${finding.detail}`).join(" ").toLowerCase();
  $("#owasp-list").innerHTML = owasp.map(([id, name, guidance]) => {
    const status = inferOwaspStatus(id, findingText);
    return `
      <article class="owasp-item">
        <strong>${id}: ${escapeHtml(name)} - ${status}</strong>
        <span>${escapeHtml(guidance)}</span>
      </article>
    `;
  }).join("");
}

function inferOwaspStatus(id, text) {
  const map = {
    A02: /https|hsts|tls|cookie|cache|mixed-content/,
    A05: /header|cors|banner|misconfiguration|clickjacking|permissions-policy|content-security-policy/,
    A06: /technology|powered-by|server banner|cve/,
    A07: /cookie|session|samesite|httponly/,
    A08: /sri|integrity|third-party/,
    A10: /ssrf/
  };
  return map[id] && map[id].test(text) ? "evidence found" : "manual review needed";
}

function buildMarkdownReport() {
  const target = state.target ? state.target.href : "Evidence-only assessment";
  const lines = [
    `# Web Application Security Triage`,
    ``,
    `Target: ${target}`,
    `Generated: ${state.generatedAt ? state.generatedAt.toISOString() : "Not generated"}`,
    `Score: ${state.findings.length || state.headers.size || state.html || state.target ? score() : "Not scored"}`,
    `Browser fetch: ${state.fetchStatus}`,
    ``,
    `## Findings`
  ];
  if (!state.findings.length) lines.push(`No findings from supplied evidence.`);
  [...state.findings].sort((a, b) => severityWeight[b.severity] - severityWeight[a.severity]).forEach(finding => {
    lines.push(`- [${finding.severity.toUpperCase()}] ${finding.title}: ${finding.detail} Remediation: ${finding.fix}`);
  });
  lines.push(``, `## Technologies and CVE Leads`);
  if (!state.tech.length) lines.push(`No technology evidence detected.`);
  state.tech.forEach(item => lines.push(`- ${item.name} ${item.version || ""} (${item.source})`));
  lines.push(``, `## SSL Checks`);
  if (!state.ssl.length) lines.push(`No SSL checks generated.`);
  state.ssl.forEach(item => lines.push(`- ${item.label}: ${item.href}`));
  lines.push(``, `## Notes`, `This static scanner cannot replace authenticated testing, server-side TLS probing, source review, dependency SCA, DAST, or manual authorization testing.`);
  return lines.join("\n");
}

function copyReport() {
  navigator.clipboard.writeText($("#report-output").value);
}

function downloadJson() {
  const payload = JSON.stringify({
    target: state.target ? state.target.href : null,
    generatedAt: state.generatedAt ? state.generatedAt.toISOString() : null,
    score: score(),
    fetchStatus: state.fetchStatus,
    findings: state.findings,
    technologies: state.tech,
    ssl: state.ssl
  }, null, 2);
  const blob = new Blob([payload], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "web-app-security-report.json";
  link.click();
  URL.revokeObjectURL(url);
}

function switchTab(event) {
  document.querySelectorAll(".tab").forEach(tab => tab.classList.remove("is-active"));
  document.querySelectorAll(".tab-panel").forEach(panel => panel.classList.remove("is-active"));
  event.currentTarget.classList.add("is-active");
  $(`#tab-${event.currentTarget.dataset.tab}`).classList.add("is-active");
}

function loadDemo() {
  $("#target-url").value = "https://demo.example";
  $("#headers-input").value = [
    "HTTP/2 200",
    "server: nginx/1.18.0",
    "x-powered-by: PHP/7.4.33",
    "access-control-allow-origin: *",
    "set-cookie: sid=abc123; Path=/",
    "cache-control: public, max-age=3600"
  ].join("\n");
  $("#html-input").value = [
    "<meta name=\"generator\" content=\"WordPress 5.8\">",
    "<script src=\"https://cdn.example/jquery-1.12.4.min.js\"></script>",
    "<!-- TODO remove debug token before launch -->",
    "<form action=\"http://demo.example/login\"></form>"
  ].join("\n");
  analyzeEvidence();
}

function clearAll() {
  $("#target-url").value = "";
  $("#headers-input").value = "";
  $("#html-input").value = "";
  resetAnalysis();
  state.target = null;
  state.generatedAt = null;
  render();
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#039;"
  }[char]));
}
