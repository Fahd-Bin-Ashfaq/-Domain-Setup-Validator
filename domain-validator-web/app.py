from flask import Flask, render_template, request
import socket, ssl, datetime, re
import requests
import dns.resolver

app = Flask(__name__)

def dns_checks(domain, expected_ip="", expected_cname=""):
    result = {"ok": True, "a_records": [], "cname": None, "errors": [], "notes": []}
    try:
        # A records
        try:
            answers = dns.resolver.resolve(domain, "A")
            result["a_records"] = [rdata.to_text() for rdata in answers]
        except Exception:
            result["a_records"] = []

        # CNAME
        try:
            answers = dns.resolver.resolve(domain, "CNAME")
            # usually one; take first
            result["cname"] = answers[0].target.to_text().rstrip(".")
        except Exception:
            result["cname"] = None

        if not result["a_records"] and not result["cname"]:
            result["errors"].append(f"No A or CNAME records found for {domain}")
            result["ok"] = False

        # expected IP
        if expected_ip:
            if expected_ip in result["a_records"]:
                result["notes"].append(f"Expected IP {expected_ip} present in A records.")
            else:
                result["errors"].append(f"Expected IP {expected_ip} NOT found in A records.")
                result["ok"] = False

        # expected CNAME
        if expected_cname:
            norm_cname = (result["cname"] or "").rstrip(".")
            norm_expected = expected_cname.rstrip(".")
            if norm_cname == norm_expected:
                result["notes"].append(f"CNAME matches expected ({expected_cname}).")
            else:
                found = result["cname"] if result["cname"] else "none"
                result["errors"].append(f"CNAME does not match expected. Found: '{found}'")
                result["ok"] = False

    except Exception as e:
        result["errors"].append(f"DNS check failed: {e}")
        result["ok"] = False

    return result

def https_check(domain):
    result = {"ok": True, "status": None, "errors": []}
    try:
        r = requests.head(f"https://{domain}", timeout=10, allow_redirects=True)
        result["status"] = r.status_code
        if r.status_code >= 400:
            result["ok"] = False
            result["errors"].append(f"HTTPS endpoint returned HTTP {r.status_code}")
    except requests.RequestException as e:
        result["ok"] = False
        result["errors"].append(f"curl/requests failed to connect: {e}")
    return result

def cert_check(domain):
    result = {
        "ok": True,
        "not_after": None,
        "days_left": None,
        "sans": [],
        "covers_domain": False,
        "errors": [],
        "warnings": [],
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # Expiry
        if "notAfter" in cert:
            # format e.g. 'Aug 13 15:04:05 2025 GMT'
            not_after_str = cert["notAfter"]
            result["not_after"] = not_after_str
            dt = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (dt - datetime.datetime.utcnow()).days
            result["days_left"] = days_left
            if days_left < 0:
                result["ok"] = False
                result["errors"].append("Certificate has expired.")
        else:
            result["ok"] = False
            result["errors"].append("No certificate end date present.")

        # SAN / CN
        sans = []
        if "subjectAltName" in cert:
            sans = [v for (k, v) in cert["subjectAltName"] if k == "DNS"]
        # fallback CN
        if not sans and "subject" in cert:
            for tup in cert["subject"]:
                for k, v in tup:
                    if k == "commonName":
                        sans = [v]
                        break
        result["sans"] = sans or []

        # cover check (exact or wildcard)
        def covers(d, san):
            if san == d:
                return True
            if san.startswith("*."):
                # wildcard: *.example.com covers a.example.com (not example.com)
                suf = san[1:]  # '.example.com'
                return d.endswith(suf) and d.count(".") > suf.count(".")
            return False

        result["covers_domain"] = any(covers(domain, s) for s in result["sans"])
        if not result["covers_domain"]:
            result["ok"] = False
            result["errors"].append(f"Certificate does NOT cover domain {domain}.")

    except Exception as e:
        result["ok"] = False
        result["errors"].append(f"openssl/SSL failed: {e}")

    return result

@app.route("/", methods=["GET", "POST"])
def index():
    data = None
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        expected_ip = request.form.get("expected_ip", "").strip()
        expected_cname = request.form.get("expected_cname", "").strip()
        if not domain:
            data = {"error": "Please enter a domain."}
        else:
            dns_res = dns_checks(domain, expected_ip, expected_cname)
            https_res = https_check(domain)
            cert_res = cert_check(domain)
            ok_all = dns_res["ok"] and https_res["ok"] and cert_res["ok"]
            data = {
                "domain": domain,
                "expected_ip": expected_ip,
                "expected_cname": expected_cname,
                "dns": dns_res,
                "https": https_res,
                "cert": cert_res,
                "ok_all": ok_all,
            }
    return render_template("index.html", data=data)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
