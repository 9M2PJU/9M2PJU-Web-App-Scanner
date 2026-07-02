# 9M2PJU Web App Scanner

A static, GitHub Pages compatible web application security scanner. It performs browser-safe checks, analyzes pasted response headers or HTML evidence, creates SSL/TLS deep-scan links, and turns detected technology/version evidence into CVE research leads.

## What it checks

- HTTPS usage, HSTS, CSP, clickjacking, MIME sniffing, referrer, permissions policy, CORS, cache policy, and server banners
- Cookie flags including `Secure`, `HttpOnly`, and `SameSite`
- HTML evidence for mixed content, insecure forms, missing SRI, sensitive comments, and verbose error pages
- Technology fingerprints from headers and HTML snippets
- CVE research links for NVD, CVE.org, and Exploit-DB
- SSL Labs and Hardenize links, with optional SSL Labs cached API lookup when the browser allows it
- OWASP Top 10 coverage prompts
- Markdown and JSON report export

## GitHub Pages

This app has no build step.

1. Commit `index.html`, `styles.css`, and `app.js`.
2. In GitHub, open repository Settings.
3. Go to Pages.
4. Select the branch and root folder.
5. Save and open the published URL.

## Important limitation

GitHub Pages is static hosting. A browser-only app cannot perform raw socket TLS tests, bypass CORS, crawl authenticated areas, run exploit payloads, or prove CVE exploitability. This scanner marks uncertain areas clearly and provides links or evidence inputs for deeper validation.
