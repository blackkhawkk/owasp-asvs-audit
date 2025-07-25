import csv
import os
import argparse
from pathlib import Path
import datetime
from collections import OrderedDict

CSV_FILE = "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv"

def load_asvs_requirements(csv_path):
    requirements = []
    with open(csv_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            requirements.append(row)
    return requirements

def analyze_source_code(source_path, requirements):
    findings = []
    source_dir = Path(source_path)
    import re
    def search_code(patterns, exts, context_files=None):
        matches = set()
        for ext in exts:
            for file in source_dir.rglob(ext):
                if context_files and not any(cf in str(file).lower() for cf in context_files):
                    continue
                try:
                    content = file.read_text(encoding="utf-8", errors="ignore")
                    for pat in patterns:
                        if re.search(pat, content, re.IGNORECASE):
                            matches.add(str(file))
                except Exception:
                    continue
        return matches

    for req in requirements:
        status = "Manual Check Required"
        notes = "Automated check not implemented."
        recommendation = None
        desc = req["req_description"].lower()
        # Expanded automation for more requirements
        # V1: Encoding, Injection, Sanitization
        if any(x in desc for x in ["encode", "escape", "sanitize", "injection", "parameterized", "orm", "sql", "ldap", "xpath", "os command", "csv", "regex", "eval", "template", "xxe", "deserialization"]):
            found = search_code([
                r'encode|escape|sanitize|validator|joi|yup|parameterized|sequelize|mongoose|orm|query\.escape|html-escape|sanitize-html|xss-clean|express-validator|safe-eval|sqlalchemy|preparedstatement|inputfilter|filter_var|htmlspecialchars|htmlentities|strip_tags|addslashes|pg_escape|mysql_escape|sqlite_escape'
            ], ["*.js", "*.ts", "*.py", "*.php", "*.java", "*.cs"])
            dangerous = search_code([
                r'eval\s*\(|exec\s*\(|Function\s*\(|child_process|shell\.exec|os\.system|subprocess|rawQuery|dangerouslySetInnerHTML|system\(|popen\(|passthru\(|proc_open\(|spawn\(|runtime\.exec|ProcessBuilder|eval_rpn|template_eval'
            ], ["*.js", "*.ts", "*.py", "*.php", "*.java", "*.cs"])
            if found and not dangerous:
                status = "Pass"
                notes = f"Encoding/sanitization/parameterized query patterns found in: {', '.join(found)}"
            elif dangerous:
                status = "Fail"
                notes = f"Potentially dangerous function(s) found in: {', '.join(dangerous)}. Manual review required."
                recommendation = "Search for use of eval, exec, or raw queries. Replace with safe alternatives."
            else:
                status = "Fail"
                notes = "No clear encoding/sanitization/parameterized query pattern found."
                recommendation = "Review input/output handling, query construction, and use of dangerous functions."
        # V2: Validation, Business Logic (expanded)
        elif "input validation" in desc or "business logic" in desc or "validate" in desc:
            found = search_code([
                r'validate|validator|joi|yup|schema|sanitize|express-validator|inputfilter|filter_var|checkSchema|zod|cerberus|marshmallow|pydantic|class-validator|validateSync|validateOrReject'
            ], ["*.js", "*.ts", "*.py", "*.php", "*.java", "*.cs"], context_files=["register", "signup", "user", "logic", "validate"])
            if found:
                status = "Pass"
                notes = f"Input validation/business logic validation found in: {', '.join(found)}"
            else:
                status = "Fail"
                notes = "No input/business logic validation found."
                recommendation = "Review input validation and business logic enforcement in backend."
        # V3: Web Frontend Security (CSP, cookies, headers, expanded)
        elif any(x in desc for x in ["cookie", "csp", "content-security-policy", "hsts", "cors", "x-content-type-options", "referrer policy", "frame-ancestors", "jsonp", "postmessage", "subresource integrity", "redirect", "header", "set-cookie"]):
            found = search_code([
                r'csp|content-security-policy|hsts|samesite|secure|httponly|x-content-type-options|referrer-policy|frame-ancestors|sri|jsonp|postmessage|redirect|setHeader|set-cookie|helmet|cookie-parser|cookie-session|csrf|x-frame-options|x-xss-protection'
            ], ["*.js", "*.ts", "*.py", "*.json", "*.yml", "*.php", "*.java", "*.cs"], context_files=["header", "cookie", "security", "config", "policy"])
            if found:
                status = "Pass"
                notes = f"Frontend security headers/cookie settings found in: {', '.join(found)}"
            else:
                status = "Fail"
                notes = "No clear evidence of frontend security headers/cookie settings."
                recommendation = "Review HTTP headers, cookie settings, and frontend security controls."
        # V4: API/Web Service (Content-Type, CORS, HTTP methods, expanded)
        elif any(x in desc for x in ["content-type", "cors", "http method", "websocket", "graphql", "api", "rest", "endpoint", "openapi", "swagger"]):
            found = search_code([
                r'content-type|cors|options|websocket|graphql|api|allow-origin|openapi|swagger|restify|fastapi|express.Router|route|endpoint|@api|@rest|@route'
            ], ["*.js", "*.ts", "*.py", "*.json", "*.yml", "*.php", "*.java", "*.cs"])
            if found:
                status = "Pass"
                notes = f"API/web service security patterns found in: {', '.join(found)}"
            else:
                status = "Fail"
                notes = "No clear API/web service security pattern found."
                recommendation = "Review API/web service security controls, allowed HTTP methods, and CORS settings."
        # ...existing code...
        # V2: Validation, Business Logic
        elif "input validation" in desc or "business logic" in desc:
            found = search_code([r'validate|validator|joi|yup|schema|sanitize'], ["*.js", "*.ts", "*.py"], context_files=["register", "signup", "user", "logic"])
            if found:
                status = "Pass"
                notes = f"Input validation/business logic validation found in: {', '.join(found)}"
            else:
                status = "Fail"
                notes = "No input/business logic validation found."
                recommendation = "Review input validation and business logic enforcement in backend."
        # V3: Web Frontend Security (CSP, cookies, headers)
        elif any(x in desc for x in ["cookie", "csp", "content-security-policy", "hsts", "cors", "x-content-type-options", "referrer policy", "frame-ancestors", "jsonp", "postmessage", "subresource integrity", "redirect"]):
            found = search_code([r'csp|content-security-policy|hsts|samesite|secure|httponly|x-content-type-options|referrer-policy|frame-ancestors|sri|jsonp|postmessage|redirect'], ["*.js", "*.ts", "*.py", "*.json", "*.yml"], context_files=["header", "cookie", "security", "config"])
            if found:
                status = "Pass"
                notes = f"Frontend security headers/cookie settings found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear evidence of frontend security headers/cookie settings."
                recommendation = "Review HTTP headers, cookie settings, and frontend security controls."
        # V4: API/Web Service (Content-Type, CORS, HTTP methods)
        elif any(x in desc for x in ["content-type", "cors", "http method", "websocket", "graphql", "api"]):
            found = search_code([r'content-type|cors|options|websocket|graphql|api|allow-origin'], ["*.js", "*.ts", "*.py"])
            if found:
                status = "Pass"
                notes = f"API/web service security patterns found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear API/web service security pattern found."
                recommendation = "Review API/web service security controls, allowed HTTP methods, and CORS settings."
        # V5: File Handling (upload, download, storage)
        elif any(x in desc for x in ["file upload", "file download", "file storage", "file type", "file extension", "magic bytes", "antivirus", "symlink", "compressed file", "archive"]):
            found = search_code([r'upload|download|filetype|mimetype|magic bytes|antivirus|scan|symlink|archive|unzip|extract'], ["*.js", "*.ts", "*.py"], context_files=["file", "upload", "download"])
            if found:
                status = "Pass"
                notes = f"File handling/upload/download logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear file handling/upload/download logic found."
                recommendation = "Review file upload/download/storage logic and ensure proper validation and scanning."
        # V6: Authentication (passwords, MFA, reset)
        elif any(x in desc for x in ["password", "authentication", "mfa", "multi-factor", "reset", "login", "logout", "account lockout", "credential", "otp", "token", "session"]):
            found = search_code([r'password|bcrypt|argon2|pbkdf2|login|logout|mfa|otp|token|session|reset|lockout|jwt|jsonwebtoken'], ["*.js", "*.ts", "*.py"], context_files=["auth", "user", "login", "session", "password"])
            if found:
                status = "Pass"
                notes = f"Authentication/password/session logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear authentication/password/session logic found."
                recommendation = "Review authentication, password, and session management logic."
        # V7: Session Management (token, timeout, invalidation)
        elif any(x in desc for x in ["session", "token", "timeout", "invalidation", "logout", "reauthentication"]):
            found = search_code([r'session|token|timeout|invalidate|logout|reauthenticate'], ["*.js", "*.ts", "*.py"], context_files=["session", "token", "auth"])
            if found:
                status = "Pass"
                notes = f"Session management logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear session management logic found."
                recommendation = "Review session management, token handling, and timeout/invalidation logic."
        # V8: Authorization (access control, permissions)
        elif any(x in desc for x in ["authorization", "access control", "permission", "role", "rbac", "abac", "object reference", "idor", "bopla", "multi-tenant", "admin"]):
            found = search_code([r'authorize|accesscontrol|permission|role|rbac|abac|isadmin|isuser|idor|bopla|tenant'], ["*.js", "*.ts", "*.py"], context_files=["auth", "user", "role", "access", "permission"])
            if found:
                status = "Pass"
                notes = f"Authorization/access control logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear authorization/access control logic found."
                recommendation = "Review access control, permissions, and authorization logic."
        # V9: Self-contained Tokens (JWT, MAC, claims)
        elif any(x in desc for x in ["jwt", "token", "mac", "claims", "audience", "issuer", "signature", "jws", "jwk"]):
            found = search_code([r'jwt|jsonwebtoken|jws|jwk|aud|iss|signature|mac'], ["*.js", "*.ts", "*.py"], context_files=["token", "jwt", "auth"])
            if found:
                status = "Pass"
                notes = f"JWT/token/claims logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear JWT/token/claims logic found."
                recommendation = "Review JWT/token handling, claims validation, and signature verification."
        # V10: OAuth/OIDC
        elif any(x in desc for x in ["oauth", "oidc", "openid", "authorization server", "resource server", "access token", "refresh token", "client secret", "scope", "pkce"]):
            found = search_code([r'oauth|oidc|openid|access token|refresh token|client secret|scope|pkce'], ["*.js", "*.ts", "*.py"], context_files=["oauth", "oidc", "openid", "auth"])
            if found:
                status = "Pass"
                notes = f"OAuth/OIDC logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear OAuth/OIDC logic found."
                recommendation = "Review OAuth/OIDC implementation, token handling, and PKCE usage."
        # V11: Cryptography (encryption, hashing, key management)
        elif any(x in desc for x in ["crypto", "encryption", "hash", "key", "certificate", "tls", "ssl", "random", "nonce", "mac", "ecc", "rsa", "aes", "pbkdf2", "argon2", "bcrypt"]):
            found = search_code([r'crypto|encrypt|decrypt|hash|pbkdf2|argon2|bcrypt|aes|rsa|ecc|tls|ssl|certificate|random|nonce|mac'], ["*.js", "*.ts", "*.py"], context_files=["crypto", "key", "cert", "tls", "ssl"])
            if found:
                status = "Pass"
                notes = f"Cryptography/crypto/key/cert logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear cryptography/crypto/key/cert logic found."
                recommendation = "Review cryptography, key management, and encryption/hashing logic."
        # V12: Secure Communication (TLS, HTTPS, mTLS)
        elif any(x in desc for x in ["tls", "https", "ssl", "certificate", "mtls", "encrypted protocol", "ocsp", "ech"]):
            found = search_code([r'tls|https|ssl|certificate|mtls|ocsp|ech'], ["*.js", "*.ts", "*.py", "*.json", "*.yml"], context_files=["tls", "ssl", "cert", "config"])
            if found:
                status = "Pass"
                notes = f"TLS/HTTPS/SSL/certificate/mTLS logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear TLS/HTTPS/SSL/certificate/mTLS logic found."
                recommendation = "Review secure communication, TLS/SSL, and certificate handling."
        # V13: Configuration (secrets, debug, allowlist, resource limits)
        elif any(x in desc for x in ["config", "secret", "debug", "allowlist", "resource", "timeout", "retry", "pool", "concurrent", "expose", "directory listing", "trace method", "version info"]):
            found = search_code([r'config|secret|vault|debug|allowlist|timeout|retry|pool|concurrent|directory listing|trace method|version info'], ["*.js", "*.ts", "*.py", "*.json", "*.yml"], context_files=["config", "secret", "debug", "resource", "pool"])
            if found:
                status = "Pass"
                notes = f"Configuration/secrets/resource/limits logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear configuration/secrets/resource/limits logic found."
                recommendation = "Review configuration, secrets management, and resource limits."
        # V14: Data Protection (sensitive data, retention, masking)
        elif any(x in desc for x in ["sensitive data", "data protection", "mask", "retention", "cache", "privacy", "minimization", "client storage"]):
            found = search_code([r'mask|retention|cache|privacy|minimize|clear-site-data|localstorage|sessionstorage|indexeddb'], ["*.js", "*.ts", "*.py"], context_files=["data", "privacy", "storage"])
            if found:
                status = "Pass"
                notes = f"Sensitive data protection/masking/retention logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear sensitive data protection/masking/retention logic found."
                recommendation = "Review sensitive data handling, retention, masking, and privacy controls."
        # V15: Secure Coding and Architecture (SBOM, dependencies, risky components)
        elif any(x in desc for x in ["sbom", "dependency", "third-party", "library", "component", "dangerous functionality", "mass assignment", "thread", "race condition", "lock", "starvation"]):
            found = search_code([r'sbom|dependency|require|import|dangerous|mass assignment|thread|lock|starvation'], ["*.js", "*.ts", "*.py", "*.json"], context_files=["sbom", "dependency", "lib", "component", "thread"])
            if found:
                status = "Pass"
                notes = f"SBOM/dependency/risky component logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear SBOM/dependency/risky component logic found."
                recommendation = "Review SBOM, dependencies, and risky component usage."
        # V16: Logging and Error Handling
        elif any(x in desc for x in ["log", "logging", "error", "exception", "fail", "handler", "audit", "event", "correlate", "mask", "broadcast"]):
            found = search_code([r'log|logger|logging|error|exception|fail|handler|audit|event|mask|broadcast'], ["*.js", "*.ts", "*.py"], context_files=["log", "error", "audit", "event"])
            if found:
                status = "Pass"
                notes = f"Logging/error handling/audit logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear logging/error handling/audit logic found."
                recommendation = "Review logging, error handling, and audit event logic."
        # V17: WebRTC (TURN, DTLS, SRTP, signaling)
        elif any(x in desc for x in ["webrtc", "turn", "dtls", "srtp", "media server", "signaling"]):
            found = search_code([r'webrtc|turn|dtls|srtp|media server|signaling'], ["*.js", "*.ts", "*.py"], context_files=["webrtc", "media", "signal"])
            if found:
                status = "Pass"
                notes = f"WebRTC/media/signaling logic found in: {', '.join(found)}"
            else:
                status = "Manual Check Required"
                notes = "No clear WebRTC/media/signaling logic found."
                recommendation = "Review WebRTC, TURN, DTLS, SRTP, and signaling server logic."
        else:
            recommendation = f"Manual review: {req['req_description']}\n- Inspect relevant code, configuration, and documentation.\n- Interview developers if needed.\n- Test the application for this control."
        findings.append({
            "chapter_id": req["chapter_id"],
            "chapter_name": req["chapter_name"],
            "section_id": req["section_id"],
            "section_name": req["section_name"],
            "req_id": req["req_id"],
            "req_description": req["req_description"],
            "status": status,
            "notes": notes,
            "recommendation": recommendation
        })
    return findings

def generate_html_report(findings, output_file):
    total_pass = sum(1 for f in findings if f["status"] == "Pass")
    total_fail = sum(1 for f in findings if f["status"] == "Fail")
    total_manual = sum(1 for f in findings if f["status"] == "Manual Check Required")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    chapters = OrderedDict()
    for f in findings:
        if f["chapter_id"] not in chapters:
            chapters[f["chapter_id"]] = f["chapter_name"]
    # Risk Matrix Calculation (simple: Fail=High, Manual=Medium, Pass=Low)
    risk_matrix = {"High": total_fail, "Medium": total_manual, "Low": total_pass}
    # CERT-In style: add executive summary, objective, scope, methodology, technical summary
    html = [
        "<html><head><meta charset='utf-8'><title>OWASP ASVS 5.0 Security Report</title>",
        "<style>body{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6fa;margin:0;}h1,h2,h3{color:#1a237e;}h1{margin-top:0;}#cover{background:#1a237e;color:#fff;padding:48px 0 32px 0;text-align:center;}#cover h1{font-size:2.8em;}#cover .meta{margin:18px 0 0 0;font-size:1.1em;}#summary{background:#fff;padding:32px 40px;max-width:900px;margin:32px auto 0 auto;border-radius:12px;box-shadow:0 2px 12px #0002;}#summary h2{color:#0d47a1;}#summary .section{margin-bottom:24px;}#chart-container{display:flex;justify-content:center;margin:32px 0;}#risk-matrix{margin:32px auto;max-width:600px;}#toc{background:#fff;padding:24px 32px 24px 32px;margin:32px auto 32px auto;max-width:900px;border-radius:12px;box-shadow:0 2px 8px #0001;}#toc h2{margin-top:0;}#toc ul{list-style:none;padding:0;}#toc li{margin:8px 0;}#toc a{text-decoration:none;color:#1976d2;font-weight:500;}#toc a:hover{text-decoration:underline;}table{border-collapse:collapse;width:100%;margin:24px 0 32px 0;}th,td{border:1px solid #bdbdbd;padding:10px 12px;}th{background:#e3eafc;position:sticky;top:0;z-index:2;}tr:nth-child(even){background:#f9f9fb;}tr:hover{background:#e3f2fd;} .pass{background:#e8f5e9;} .fail{background:#ffebee;} .manual{background:#fffde7;} .section{background:#e3eafc;font-weight:bold;padding:8px 0;} .status-icon{font-size:1.2em;} .footer{margin:48px 0 0 0;text-align:center;color:#888;font-size:0.95em;}@media print{body{margin:0;}#cover,#toc,.footer{page-break-after:always;}}.risk-high{color:#b71c1c;font-weight:bold;}.risk-medium{color:#fbc02d;font-weight:bold;}.risk-low{color:#388e3c;font-weight:bold;}</style>",
        "<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>",
        "<script>function scrollToId(id){document.getElementById(id).scrollIntoView({behavior:'smooth'});}</script>",
        "</head><body>",
        "<div id='cover'><h1>OWASP ASVS 5.0 Security Assessment Report</h1>",
        f"<div class='meta'><b>Project:</b> Juice Shop &nbsp; <b>Date:</b> {now}</div>",
        f"<div class='meta'><b>Total Pass:</b> {total_pass} &nbsp; <b>Total Fail:</b> {total_fail} &nbsp; <b>Manual Review:</b> {total_manual}</div>",
        "</div>",
        "<div id='summary'>",
        "<h2>Executive Summary</h2>",
        "<div class='section'>This report provides a comprehensive security assessment of the Juice Shop application, benchmarked against the OWASP Application Security Verification Standard (ASVS) 5.0. The assessment identifies strengths, weaknesses, and actionable recommendations to improve the application's security posture.</div>",
        "<h2>Objective</h2>",
        "<div class='section'>To evaluate the security controls of the Juice Shop application and ensure alignment with industry best practices as defined by OWASP ASVS 5.0.</div>",
        "<h2>Scope</h2>",
        "<div class='section'>The assessment covers the entire source code of the Juice Shop application, including backend, frontend, configuration, and supporting scripts.</div>",
        "<h2>Approach & Methodology</h2>",
        "<div class='section'>The assessment was performed using automated static code analysis, pattern matching, and configuration review, mapped to ASVS 5.0 controls. Where automation was not possible, recommendations for manual review are provided.</div>",
        "<h2>Technical Summary</h2>",
        f"<div class='section'>Total Requirements: {len(findings)}<br>Pass: <span class='risk-low'>{total_pass}</span> &nbsp; Fail: <span class='risk-high'>{total_fail}</span> &nbsp; Manual: <span class='risk-medium'>{total_manual}</span></div>",
        "<div id='chart-container'><canvas id='summaryChart' width='320' height='180'></canvas></div>",
        "<div id='risk-matrix'><h3>Risk Matrix</h3>",
        "<table><tr><th>Risk Level</th><th>Count</th></tr>",
        f"<tr><td class='risk-high'>High (Fail)</td><td>{risk_matrix['High']}</td></tr>",
        f"<tr><td class='risk-medium'>Medium (Manual)</td><td>{risk_matrix['Medium']}</td></tr>",
        f"<tr><td class='risk-low'>Low (Pass)</td><td>{risk_matrix['Low']}</td></tr>",
        "</table></div>",
        "</div>",
        "<div id='toc'><h2>Table of Contents</h2><ul>"
    ]
    for chap_id, chap_name in chapters.items():
        html.append(f"<li><a href='#ch{chap_id}' onclick=\"scrollToId('ch{chap_id}')\">{chap_id}: {chap_name}</a></li>")
    html.append("</ul></div>")
    last_chapter = last_section = None
    for f in findings:
        if f["chapter_id"] != last_chapter:
            html.append(f"<h2 id='ch{f['chapter_id']}'>{f['chapter_id']}: {f['chapter_name']}</h2>")
            last_chapter = f["chapter_id"]
            last_section = None
        if f["section_id"] != last_section:
            html.append(f"<div class='section'>{f['section_id']}: {f['section_name']}</div>")
            html.append("<table><tr><th>ID</th><th>Description</th><th>Status</th><th>Notes</th><th>Recommendation</th></tr>")
            last_section = f["section_id"]
        status_class = "pass" if f["status"]=="Pass" else ("fail" if f["status"]=="Fail" else "manual")
        status_icon = "✅" if f["status"]=="Pass" else ("❌" if f["status"]=="Fail" else "🕵️")
        html.append(f"<tr class='{status_class}'><td>{f['req_id']}</td><td>{f['req_description']}</td><td class='status-icon'>{status_icon} {f['status']}</td><td>{f['notes']}</td><td>{f['recommendation'] or ''}</td></tr>")
        next_idx = findings.index(f)+1
        if next_idx==len(findings) or (findings[next_idx]["section_id"] != f["section_id"]):
            html.append("</table>")
    html.append(f"<div class='footer'>Report generated on {now} by ASVS Assessment Tool &mdash; <a href='https://owasp.org/www-project-application-security-verification-standard/'>OWASP ASVS 5.0</a></div>")
    html.append("<script>const ctx=document.getElementById('summaryChart').getContext('2d');new Chart(ctx,{type:'pie',data:{labels:['Pass','Fail','Manual'],datasets:[{data:[" + str(total_pass) + "," + str(total_fail) + "," + str(total_manual) + "],backgroundColor:['#43a047','#e53935','#fbc02d']}]},options:{plugins:{legend:{display:true,position:'bottom'}}}});</script>")
    html.append("</body></html>")
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        print(f"[+] Report successfully generated: {os.path.abspath(output_file)}")
    except Exception as e:
        print(f"[!] Failed to write report: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(description="OWASP ASVS 5.0 Assessment Tool (CSV-driven)")
    parser.add_argument("source_path", help="The path to the source code directory to analyze.")
    parser.add_argument("--output", default="asvs_full_report.html", help="The name of the output HTML report file.")
    parser.add_argument("--csv", default=CSV_FILE, help="Path to the ASVS CSV file.")
    args = parser.parse_args()
    print(f"[*] Loading ASVS requirements from: {args.csv}")
    requirements = load_asvs_requirements(args.csv)
    print(f"[*] Loaded {len(requirements)} requirements. Starting analysis...")
    findings = analyze_source_code(args.source_path, requirements)
    print(f"[*] Analysis complete. {len(findings)} findings generated. Generating report...")
    generate_html_report(findings, args.output)
    print(f"[*] Report generation step complete.")

if __name__ == '__main__':
    main()
