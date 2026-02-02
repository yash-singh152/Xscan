import requests

def basic_scan(url, on_progress=None):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        
    findings = []
    
    if on_progress: on_progress(10) # Initialized

    try:
        if on_progress: on_progress(30) # Starting request
        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent": "Mozilla/5.0 VulnScanner"
            }
        )
        
        if on_progress: on_progress(60) # Analyzing headers
        headers = response.headers

        if "Strict-Transport-Security" not in headers:
            findings.append({
                "title": "Missing HSTS Header",
                "severity": "High",
                "description": "HSTS header is missing. This may allow SSL stripping attacks.",
                "mitigation": "Enable Strict-Transport-Security header."
            })

        if "Content-Security-Policy" not in headers:
            findings.append({
                "title": "Missing Content Security Policy",
                "severity": "Medium",
                "description": "CSP header is missing, increasing XSS attack risk.",
                "mitigation": "Define a strong Content-Security-Policy header."
            })

        if "X-Frame-Options" not in headers:
            findings.append({
                "title": "Missing X-Frame-Options",
                "severity": "Low",
                "description": "X-Frame-Options header is missing. Clickjacking possible.",
                "mitigation": "Add X-Frame-Options SAMEORIGIN or DENY."
            })

        if on_progress: on_progress(90) # Finishing up

        # If no issues found
        if not findings:
            findings.append({
                "title": "No Critical Issues Found",
                "severity": "Low",
                "description": "Basic security headers are present.",
                "mitigation": "Maintain current security configuration."
            })

    except requests.exceptions.ReadTimeout:
        findings.append({
            "title": "Connection Timeout",
            "severity": "Medium",
            "description": "Target website did not respond within the time limit.",
            "mitigation": "Try scanning again later or use a smaller website."
        })

    except requests.exceptions.ConnectionError:
        findings.append({
            "title": "Connection Failed",
            "severity": "High",
            "description": "Unable to establish connection to the target website.",
            "mitigation": "Ensure the website is reachable and online."
        })

    except Exception as e:
        findings.append({
            "title": "Unexpected Scan Error",
            "severity": "Critical",
            "description": str(e),
            "mitigation": "Check server logs or contact support."
        })

    if on_progress: on_progress(100) # Completed
    return findings


def deep_scan(url, on_progress=None):
    if on_progress: on_progress(5)
    
    # 1. Run basic scan (re-allocated as 40% of deep scan)
    def basic_cb(p):
        if on_progress: on_progress(int(5 + (p * 0.4)))
        
    findings = basic_scan(url, on_progress=basic_cb)

    # 2. Robots.txt (45% - 55%)
    try:
        if on_progress: on_progress(45)
        robots_url = url.rstrip("/") + "/robots.txt"
        resp = requests.get(robots_url, timeout=5, headers={"User-Agent": "VulnScanner"})
        if resp.status_code == 200:
            findings.append({
                "title": "Robots.txt Found",
                "severity": "Low",
                "description": f"Robots.txt file found at {robots_url}. Check for sensitive paths.",
                "mitigation": "Ensure no sensitive administrative paths are disclosed."
            })
    except:
        pass

    # 3. Sitemap (55% - 65%)
    try:
        if on_progress: on_progress(55)
        sitemap_url = url.rstrip("/") + "/sitemap.xml"
        resp = requests.get(sitemap_url, timeout=5, headers={"User-Agent": "VulnScanner"})
        if resp.status_code == 200:
            findings.append({
                "title": "Sitemap Found",
                "severity": "Low",
                "description": f"Sitemap found at {sitemap_url}.",
                "mitigation": "Review sitemap to ensure no private URLs are listed."
            })
    except:
        pass

    # 4. Information Disclosure (65% - 75%)
    try:
        if on_progress: on_progress(65)
        resp = requests.get(url, timeout=5, headers={"User-Agent": "VulnScanner"})
        server_header = resp.headers.get("Server")
        if server_header:
            findings.append({
                "title": "Server Header Disclosure",
                "severity": "Low",
                "description": f"Server header reveals: {server_header}",
                "mitigation": "Configure server to suppress detailed version information."
            })
        
        if "X-Content-Type-Options" not in resp.headers:
             findings.append({
                "title": "Missing X-Content-Type-Options",
                "severity": "Low",
                "description": "X-Content-Type-Options header is missing (nosniff).",
                "mitigation": "Set X-Content-Type-Options to 'nosniff'."
            })

    except:
        pass
    
    # 5. Sensitive Files (75% - 90%)
    try:
        if on_progress: on_progress(80)
        env_url = url.rstrip("/") + "/.env"
        resp = requests.get(env_url, timeout=5, headers={"User-Agent": "VulnScanner"})
        if resp.status_code == 200 and "DB_PASSWORD" in resp.text:
             findings.append({
                "title": "Critical: .env File Exposed",
                "severity": "Critical",
                "description": "Environment file (.env) is publicly accessible!",
                "mitigation": "Immediately remove .env file from public access and rotate secrets."
            })
            
        if on_progress: on_progress(85)
        git_url = url.rstrip("/") + "/.git/HEAD"
        resp = requests.get(git_url, timeout=5, headers={"User-Agent": "VulnScanner"})
        if resp.status_code == 200 and "ref: refs/" in resp.text:
             findings.append({
                "title": "Critical: .git Directory Exposed",
                "severity": "Critical",
                "description": "Git repository (.git) is publicly accessible.",
                "mitigation": "Deny access to .git directory in server configuration."
            })
    except:
        pass

    if on_progress: on_progress(100)
    return findings
