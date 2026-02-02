
import os

# Content with corrected syntax
content = """{% extends 'base.html' %}

{% block title %}New Scan | VulnScanner{% endblock %}

{% block content %}
<div style="max-width: 600px; margin: 4rem auto;">
    <div class="card">
        <h2 style="font-family: 'Outfit'; margin-bottom: 1rem;">🔐 Start Security Scan</h2>
        <p style="color: var(--text-secondary); margin-bottom: 2rem;">Enter a website URL to identify potential
            vulnerabilities.</p>

        <form method="POST">
            {% csrf_token %}
            <div class="form-group">
                <label for="target_url">Target URL</label>
                <input type="url" id="target_url" name="target_url" placeholder="https://example.com" required>
            </div>

            <div class="form-group" style="margin-top: 1rem;">
                <label>Scan Type</label>
                <div style="display: flex; gap: 1rem; margin-top: 0.5rem;">
                    <label style="cursor: pointer; display: flex; align-items: center; gap: 0.5rem;">
                        <input type="radio" name="scan_type" value="Quick" {% if initial_scan_type == 'Quick' %}checked{% endif %}>
                        <span>⚡ Quick Scan</span>
                    </label>
                    <label style="cursor: pointer; display: flex; align-items: center; gap: 0.5rem;">
                        <input type="radio" name="scan_type" value="Deep" {% if initial_scan_type == 'Deep' %}checked{% endif %}>
                        <span>🔍 Deep Scan (Login Required)</span>
                    </label>
                </div>
            </div>
            <button type="submit" class="btn btn-primary" style="width: 100%; padding: 1rem;">🚀 Analyze Now</button>
        </form>

        <div
            style="margin-top: 2rem; padding: 1.5rem; border-top: 1px solid var(--border); font-size: 0.875rem; color: var(--text-secondary); text-align: left;">
            <p style="margin-bottom: 0.5rem; font-weight: 600; color: var(--text-primary);">What we check:</p>
            <ul style="list-style: '✔ '; padding-left: 1.25rem;">
                <li>Cross-Site Scripting (XSS)</li>
                <li>SQL Injection (SQLi)</li>
                <li>Insecure Security Headers</li>
                <li>SSL/TLS Configuration</li>
            </ul>
        </div>
    </div>
</div>
{% endblock %}
"""

# Path to the target file
path = r"c:\Users\Yash\OneDrive\Desktop\vulnscanner\vulnscanner\scanner\templates\scanner\scan_form.html"

try:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Successfully overwrote {path}")
except Exception as e:
    print(f"Failed to overwrite: {e}")
