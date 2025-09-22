import argparse, random, string, socket, sys, json, ipaddress, os, html as htmlmod, webbrowser, re, atexit, ctypes
from typing import Optional, List, Tuple
from urllib.parse import urlparse, urlunparse
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# ======== Version/Owner ========
VERSION = "2.8"
OWNER   = "Dang3rXgh0st"

# ======== UI Globals ========
USE_COLOR = True   # always green unless --no-color
NO_LOGO = False

# ======== Windows ANSI Enable ========
def _enable_windows_ansi() -> bool:
    try:
        if os.name != "nt":
            return True
        kernel32 = ctypes.windll.kernel32
        hOut = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(hOut, ctypes.byref(mode)) == 0:
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if kernel32.SetConsoleMode(hOut, new_mode) == 0:
            return False
        return True
    except Exception:
        return False

def c(_code):  # color helper (baseline is already green)
    return ""

def banner():
    if NO_LOGO:
        return
    text = [
        r" __        __    _    ______      ____       _           _           ",
        r" \ \      / /   | |  |  ____|    |  _ \     | |         | |          ",
        r"  \ \ /\ / /__ _| | _| |__   _ __| |_) | ___| |__   ___ | |_ _   _   ",
        r"   \ V  V / _` | |/ /  __| | '__|  _ < / _ \ '_ \ / _ \| __| | | |  ",
        r"    \_/\_/\__,_|___/|_|    |_|  |_| \_\___/_.__/ \___/ \__|_| |_|  ",
        r"                                                                    ",
        f"          W A F   D e t e c t o r   v{VERSION}  —  {OWNER}          ",
    ]
    for line in text:
        print(line)
    print("Use legally with permission.\n")

# ======== Signatures ========
SIGNATURES = [
    {"name":"Cloudflare",
     "high":[("header_prefix","cf-"),
             ("header_exact",("server","cloudflare"))],
     "medium":[("header_exact",("cf-ray",None)),
               ("header_exact",("cf-cache-status",None)),
               ("cookie","__cf_bm"),
               ("cookie","cf_clearance")]},
    {"name":"Sucuri",
     "high":[("header_exact",("x-sucuri-id",None)),
             ("header_exact",("x-sucuri-cache",None)),
             ("header_exact",("x-sucuri-block",None))],
     "medium":[]},
    {"name":"Imperva / Incapsula",
     "high":[("header_exact",("x-iinfo",None)),
             ("header_value_contains",("x-cdn","incapsula")),
             ("cookie_prefix","visid_incap"),
             ("cookie_prefix","incap_ses")],
     "medium":[]},
    {"name":"Akamai",
     "high":[("header_value_contains",("server","akamai")),
             ("header_prefix","x-akamai-")],
     "medium":[("header_value_contains",("via","akamai"))]},
    {"name":"F5 BIG-IP ASM",
     "high":[("cookie_prefix","BIGipServer"),
             ("cookie_prefix","TS")],
     "medium":[("header_prefix","x-asm")]},
    {"name":"ModSecurity (OWASP CRS)",
     "high":[("header_prefix","x-mod-"),
             ("header_value_contains",("x-powered-by","modsecurity"))],
     "medium":[]},
    {"name":"DDoS-Guard",
     "high":[("header_value_contains",("server","ddos-guard"))],
     "medium":[]},
    {"name":"StackPath / Fireblade",
     "high":[("header_value_contains",("x-cdn","stackpath"))],
     "medium":[]},
    {"name":"AWS CloudFront (possible AWS WAF)",
     "high":[("header_exact",("x-amz-cf-id",None)),
             ("header_value_contains",("via","cloudfront"))],
     "medium":[]},
    {"name":"Wordfence (WP)",
     "high":[("header_prefix","x-wf-")],
     "medium":[]},
]

# ======== Core utils ========
def is_ip_host(host: str) -> bool:
    if not host: return False
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def normalize_url(target: str, force_scheme: Optional[str] = None, port: Optional[int] = None) -> str:
    t = target.strip()
    if not t.startswith(("http://","https://")):
        host = t.split("/")[0]
        if force_scheme:
            t = f"{force_scheme}://{t}"
        else:
            t = ("http://" if is_ip_host(host) else "https://") + t
    p = urlparse(t)
    netloc = p.netloc
    if port:
        host_only = p.hostname or ""
        if ":" in netloc:
            netloc = f"{host_only}:{port}"
        else:
            netloc = f"{netloc}:{port}"
    path = p.path or "/"
    return urlunparse((p.scheme, netloc, path, "", "", ""))

def rand_path():
    return "/waf-test-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

def safe_lower(s):
    return s.lower() if isinstance(s, str) else s

def match_rule(kind, rule, headers, cookies):
    if kind == "header_prefix":
        prefix = rule
        return any(k.startswith(prefix) for k in headers.keys())
    if kind == "header_exact":
        key, val = rule
        if key not in headers: return False
        if val is None: return True
        return safe_lower(val) in safe_lower(headers.get(key,""))
    if kind == "header_value_contains":
        key, substr = rule
        if key not in headers: return False
        return substr.lower() in str(headers.get(key,"")).lower()
    if kind == "cookie":
        return rule in cookies
    if kind == "cookie_prefix":
        return any(k.startswith(rule) for k in cookies.keys())
    return False

def pretty_hits(hits):
    nice = []
    for kind, rule in hits:
        if kind in ("header_exact","header_value_contains"):
            nice.append(f"{kind}:{rule[0]}")
        else:
            nice.append(f"{kind}:{rule}")
    return sorted(set(nice))

def evaluate_signatures(headers: dict, cookies: dict):
    found = []
    h = {k.lower(): v for k, v in headers.items()}
    ck = {k: v for k, v in cookies.items()}
    for sig in SIGNATURES:
        score, hits = 0, []
        for kind, rule in sig["high"]:
            if match_rule(kind, rule, h, ck):
                score += 2; hits.append((kind, rule))
        for kind, rule in sig["medium"]:
            if match_rule(kind, rule, h, ck):
                score += 1; hits.append((kind, rule))
        if score > 0:
            level = "High" if score >= 2 else "Medium"
            found.append({"vendor": sig["name"], "confidence": level, "evidence": pretty_hits(hits)})
    return found

# ======== Networking ========
def run_checks(base_url, args, out):
    sess = requests.Session()
    sess.headers.update({"User-Agent": args.user_agent, "Accept": "*/*"})
    if args.host_override:
        sess.headers.update({"Host": args.host_override})

    def do_req(method, url):
        try:
            resp = sess.request(method, url, allow_redirects=True, timeout=args.timeout, verify=not args.insecure)
            rec = {"method": method, "url": url, "final_url": resp.url, "status": resp.status_code,
                   "headers": dict(resp.headers),
                   "cookies": requests.utils.dict_from_cookiejar(resp.cookies)}
            out["requests"].append(rec)
            return rec
        except requests.RequestException as e:
            out["requests"].append({"method": method, "url": url, "error": str(e)})
            out["notes"].append(f"{method} request failed: {e}")
            return None

    p = urlparse(base_url)
    target_is_ip = is_ip_host((p.hostname or "").strip("[]"))

    urls_to_try = [base_url]
    if target_is_ip and p.scheme == "https":  # try http fallback for https+IP
        urls_to_try.append(urlunparse(("http", p.netloc, p.path or "/", "", "", "")))
    seen = set(); urls_to_try = [u for u in urls_to_try if not (u in seen or seen.add(u))]

    headers_all, cookies_all = {}, {}
    for u in urls_to_try:
        for method in ("HEAD","GET"):
            r = do_req(method, u)
            if r and "headers" in r: headers_all.update(r["headers"])
            if r and "cookies" in r: cookies_all.update(r["cookies"])

    if args.aggressive:
        probe_urls = [urlunparse((p.scheme, p.netloc, rand_path(), "", "", ""))]
        if target_is_ip and p.scheme == "https":
            probe_urls.append(urlunparse(("http", p.netloc, rand_path(), "", "", "")))
        for pu in probe_urls:
            r3 = do_req("GET", pu)
            if r3 and r3.get("status") in (401,403,406):
                out["notes"].append(f"Aggressive probe {pu} returned {r3['status']} (possible active filtering).")
                headers_all.update(r3.get("headers", {}))
                cookies_all.update(r3.get("cookies", {}))

    detections = evaluate_signatures(headers_all, cookies_all)
    if not detections and any(k.lower() in headers_all for k in ["cf-ray","x-amz-cf-id","x-served-by"]):
        out["detections"] = [{"vendor":"Generic CDN detected","confidence":"Low","evidence":["cdn-headers"]}]
    else:
        out["detections"] = detections

# ======== Report helpers ========
def read_targets_file(path: Path) -> List[str]:
    targets = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        targets.append(s)
    return targets

def build_html_report(results: List[dict], title: str) -> str:
    esc = htmlmod.escape
    def det_summary(dets):
        if not dets: return "<em>None</em>"
        return ", ".join(f"{esc(d['vendor'])} ({esc(d['confidence'])})" for d in dets)

    def req_summary(reqs):
        if not reqs: return "-"
        for r in reqs:
            if "status" in r: return str(r["status"])
        return esc(reqs[0].get("error","-"))

    rows = []
    for r in results:
        ip = r.get("dns",{}).get("ip","-")
        rev = r.get("dns",{}).get("reverse","")
        iptxt = esc(ip + (f" ({rev})" if rev else ""))
        rows.append(f"""
<tr>
  <td>{esc(str(r.get('input','')))}</td>
  <td>{iptxt}</td>
  <td>{esc(str(r.get('normalized_url','')))}</td>
  <td>{req_summary(r.get('requests',[]))}</td>
  <td>{det_summary(r.get('detections',[]))}</td>
</tr>""")

    details_blocks = []
    for r in results:
        dets_html = "<ul>" + "".join(
            f"<li><strong>{esc(d['vendor'])}</strong> — {esc(d['confidence'])}"
            + (": <code>" + ", ".join(esc(e) for e in d.get("evidence",[])) + "</code>" if d.get("evidence") else "")
            + "</li>"
            for d in r.get("detections",[])
        ) + "</ul>" if r.get("detections") else "<em>No detections</em>"

        reqs_html = "<ul>" + "".join(
            f"<li><code>{esc(req.get('method',''))}</code> {esc(req.get('url',''))} → "
            + (str(req.get('status')) if 'status' in req else f"ERROR: {esc(req.get('error',''))}") + "</li>"
            for req in r.get("requests",[])
        ) + "</ul>" if r.get("requests") else "<em>No requests</em>"

        notes_html = "<ul>" + "".join(f"<li>{esc(n)}</li>" for n in r.get("notes",[])) + "</ul>" if r.get("notes") else "-"

        details_blocks.append(f"""
<details>
  <summary><strong>Details:</strong> {esc(str(r.get('input','')))}</summary>
  <div class="box">
    <div><b>Normalized URL:</b> <code>{esc(str(r.get('normalized_url','')))}</code></div>
    <div><b>DNS:</b> <code>{esc(json.dumps(r.get('dns',{}), ensure_ascii=False))}</code></div>
    <div><b>Detections:</b> {dets_html}</div>
    <div><b>Requests:</b> {reqs_html}</div>
    <div><b>Notes:</b> {notes_html}</div>
  </div>
</details>""")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{esc(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Arial; margin:24px;}}
h1{{margin:0 0 8px 0}}
small{{color:#666}}
table{{border-collapse:collapse;width:100%;margin-top:16px}}
th,td{{border:1px solid #ddd;padding:8px;vertical-align:top}}
th{{background:#fafafa;text-align:left}}
tr:nth-child(even){{background:#fcfcfc}}
code{{background:#f6f8fa;padding:2px 4px;border-radius:4px}}
.box{{border:1px solid #eee;padding:8px;border-radius:6px;background:#fff}}
details{{margin:12px 0}}
.footer{{margin-top:18px;color:#666}}
.badge{{display:inline-block;padding:2px 8px;border-radius:999px;background:#efefef;border:1px solid #ddd}}
</style>
</head>
<body>
<h1>WAF Detector Report</h1>
<small><span class="badge">v{esc(VERSION)}</span> <span class="badge">{esc(OWNER)}</span> • Generated at {esc(now)}</small>

<table>
  <thead>
    <tr>
      <th>Target</th>
      <th>Resolved IP (rDNS)</th>
      <th>Final URL</th>
      <th>First Status</th>
      <th>Detections</th>
    </tr>
  </thead>
  <tbody>
    {''.join(rows)}
  </tbody>
</table>

{''.join(details_blocks)}

<div class="footer">Tool: WAF Detector v{esc(VERSION)} — {esc(OWNER)} • Use legally with permission.</div>
</body>
</html>
"""
    return html

def build_xml_report(results: List[dict]) -> bytes:
    root = ET.Element("wafscan", attrib={"tool":"WAF Detector", "version":VERSION, "owner":OWNER})
    for r in results:
        t = ET.SubElement(root, "target")
        ET.SubElement(t, "input").text = str(r.get("input",""))
        ET.SubElement(t, "normalized_url").text = str(r.get("normalized_url",""))
        dns = ET.SubElement(t, "dns")
        d = r.get("dns",{})
        if d.get("host") is not None:
            ET.SubElement(dns, "host").text = str(d.get("host",""))
        if d.get("ip") is not None:
            ET.SubElement(dns, "ip").text = str(d.get("ip",""))
        if d.get("reverse"):
            ET.SubElement(dns, "reverse").text = str(d.get("reverse"))
        reqs = ET.SubElement(t, "requests")
        for q in r.get("requests",[]):
            rq = ET.SubElement(reqs, "request")
            ET.SubElement(rq, "method").text = str(q.get("method",""))
            ET.SubElement(rq, "url").text = str(q.get("url",""))
            if "status" in q:
                ET.SubElement(rq, "status").text = str(q.get("status"))
            if "error" in q:
                ET.SubElement(rq, "error").text = str(q.get("error"))
        dets = ET.SubElement(t, "detections")
        for dct in r.get("detections",[]):
            dt = ET.SubElement(dets, "detection", attrib={"confidence": str(dct.get("confidence",""))})
            ET.SubElement(dt, "vendor").text = str(dct.get("vendor",""))
            ev = ET.SubElement(dt, "evidence")
            for e in dct.get("evidence",[]):
                ET.SubElement(ev, "item").text = str(e)
        notes = ET.SubElement(t, "notes")
        for n in r.get("notes",[]):
            ET.SubElement(notes, "note").text = str(n)
    xml_bytes = ET.tostring(root, encoding="utf-8")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + xml_bytes

def _paths_from_output_base(out_dir: Path, output: Optional[str], prefix: str) -> Tuple[Path, Path, str]:
    if output:
        base = Path(output)
        if base.suffix.lower() in (".html", ".xml"):
            base = base.with_suffix("")
        if base.parent == Path("."):
            out_dir.mkdir(parents=True, exist_ok=True)
            html_path = out_dir / (base.name + ".html")
            xml_path  = out_dir / (base.name + ".xml")
        else:
            base.parent.mkdir(parents=True, exist_ok=True)
            html_path = base.with_suffix(".html")
            xml_path  = base.with_suffix(".xml")
        title_token = base.name
        return html_path, xml_path, title_token
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / f"{prefix}_{ts}.html"
    xml_path  = out_dir / f"{prefix}_{ts}.xml"
    return html_path, xml_path, f"{prefix} — {ts}"

def write_reports_auto(results: List[dict], out_dir: Path, prefix: str, output_base: Optional[str]) -> Tuple[Path, Path]:
    html_path, xml_path, title_token = _paths_from_output_base(out_dir, output_base, prefix)
    title = f"WAF Detector v{VERSION} — {OWNER} — {title_token}"
    html_str = build_html_report(results, title)
    with html_path.open("w", encoding="utf-8") as f:
        f.write(html_str)
    xml_bytes = build_xml_report(results)
    with xml_path.open("wb") as f:
        f.write(xml_bytes)
    return html_path, xml_path

def print_report_links(html_path: Path, xml_path: Path, links_only: bool = False, open_reports: bool = False):
    uri_html = Path(html_path).resolve().as_uri()
    uri_xml  = Path(xml_path).resolve().as_uri()
    print("\nCopy these links into your browser:")
    print(uri_html)
    print(uri_xml)
    if open_reports:
        try:
            webbrowser.open(uri_html)
            webbrowser.open(uri_xml)
        except Exception:
            pass

# ======== Scan Units ========
def scan_one_target(base_url: str, args, original_input: Optional[str] = None) -> dict:
    parsed = urlparse(base_url)
    hostname = (parsed.hostname or "").strip("[]")
    target_is_ip = is_ip_host(hostname)
    out = {"input": original_input if original_input else base_url,
           "normalized_url": base_url,
           "dns": {}, "requests": [], "detections": [], "notes": [],
           "meta": {"version": VERSION, "owner": OWNER}}
    try:
        if target_is_ip:
            out["dns"] = {"host": hostname, "ip": hostname}
            try:
                rdns = socket.gethostbyaddr(hostname)[0]
                out["dns"]["reverse"] = rdns
            except Exception:
                pass
        else:
            ip = socket.gethostbyname(hostname)
            out["dns"] = {"host": hostname, "ip": ip}
    except Exception as e:
        out["notes"].append(f"DNS/Reverse lookup issue: {e}")

    run_checks(base_url, args, out)
    return out

def scan_file_batch(file_path: Path, args):
    if not file_path.exists():
        print(f"[ERR] File not found: {file_path}")
        return
    targets = read_targets_file(file_path)
    if not targets:
        print("[ERR] No targets found in file (empty or only comments).")
        return

    print(f"Loaded {len(targets)} targets from {file_path}. Starting scans with {args.threads} threads...\n")
    results: List[dict] = []

    def prep_url(t):
        return normalize_url(t, force_scheme=args.force_scheme, port=args.port)

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        fut_map = { pool.submit(scan_one_target, prep_url(t), args, t): t for t in targets }
        for fut in as_completed(fut_map):
            t = fut_map[fut]
            try:
                res = fut.result()
                results.append(res)
                dets = ", ".join(d["vendor"] for d in res.get("detections",[])) or "None"
                print(f"[OK] {t} -> detections: {dets}")
            except Exception as e:
                print(f"[ERR] {t}: {e}")

    if args.export:
        html_path, xml_path = write_reports_auto(results, Path(args.out_dir), args.prefix, args.output)
        print_report_links(html_path, xml_path, links_only=args.links_only, open_reports=args.open_reports)
    else:
        print("\n--- Batch scan complete (no reports saved; use -x to export). ---\n")

# ======== Menu ========
def print_menu_box():
    rows = [
        "[00] File  : scan list from file (txt)",
        "[01] HTTP  : e.g., http://example.com",
        "[02] HTTPS : e.g., https://example.com",
        "[03] IP    : e.g., 203.0.113.10 (HTTP)",
        "[04] Exit  : quit menu loop",
    ]
    extra = "Paste a URL/domain/IP at the first prompt if you like."
    header = f"MODE SELECTION — v{VERSION} — {OWNER}"
    width = max(len(header), *(len(r) for r in rows), len(extra)) + 2
    top = "┌" + "─"*width + "┐"
    mid = "├" + "─"*width + "┤"
    bot = "└" + "─"*width + "┘"
    print(top)
    print("│ " + header.center(width-2) + " │")
    print(mid)
    for r in rows:
        print("│ " + r.ljust(width-2) + " │")
    print("│ " + extra.ljust(width-2) + " │")
    print(bot)
    print()

def normalize_mode_choice(val: str) -> str:
    v = val.strip()
    if v in ("00","0"): return "0"
    if v in ("01","1"): return "1"
    if v in ("02","2"): return "2"
    if v in ("03","3"): return "3"
    if v in ("04","4"): return "4"
    return v

def is_like_target(s: str) -> bool:
    if not s:
        return False
    s = s.strip()
    if s.startswith(("http://", "https://")):
        return True
    host = s.split("/")[0].strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", host):
        return True
    return False

def interactive_loop(args):
    while True:
        print_menu_box()
        prompt = "Select option [00/01/02/03/04] OR paste a URL/domain/IP: "
        first = input(prompt).strip()
        choice = normalize_mode_choice(first)

        # [04] Exit
        if choice == "4":
            print("Bye! Exiting interactive mode.")
            return

        # [00] File batch
        if choice == "0":
            fp = input("Enter path to file (one domain/IP/URL per line): ").strip().strip('"').strip("'")
            if not fp:
                print("[ERR] No file path entered.\n")
                continue
            scan_file_batch(Path(fp), args)
            print("\n--- Batch done. Back to menu. ---\n")
            continue

        # If user pasted a full/partial target directly
        if choice not in ("1","2","3") and is_like_target(first):
            target_raw = first
            if target_raw.startswith(("http://", "https://")):
                base_url = normalize_url(target_raw, port=args.port)
            else:
                host_only = target_raw.split("/")[0]
                scheme = "http" if is_ip_host(host_only) else "https"
                base_url = normalize_url(target_raw, force_scheme=scheme, port=args.port)
        else:
            # Normal menu flow with modes 1/2/3
            if choice not in ("1","2","3"):
                print("Invalid choice. Use 00, 01, 02, 03, or 04 to exit.\n")
                continue

            if choice in ("1","2"):
                target = input("Enter domain (e.g., example.com or example.com/path): ").strip()
                port = input("Optional port (press Enter to skip): ").strip()
                port_val = int(port) if port else None
                scheme = "http" if choice == "1" else "https"
                base_url = normalize_url(target, force_scheme=scheme, port=port_val)
            else:  # choice == "3"
                target = input("Enter IP (e.g., 203.0.113.10 or 203.0.113.10/path): ").strip()
                port = input("Optional port (press Enter to skip): ").strip()
                port_val = int(port) if port else None
                base_url = normalize_url(target, force_scheme="http", port=port_val)

        # Optional Host override for IP targets
        host_override = None
        if is_ip_host((urlparse(base_url).hostname or "").strip("[]")):
            h = input("Host header override (optional, e.g., example.com): ").strip()
            host_override = h or None

        # Apply host override just for this scan
        prev_host_override = args.host_override
        if host_override and not args.host_override:
            args.host_override = host_override

        # Run the scan
        try:
            result = scan_one_target(base_url, args, base_url)
            print(json.dumps(result, indent=2, ensure_ascii=False))
            if args.export:
                html_path, xml_path = write_reports_auto([result], Path(args.out_dir), args.prefix, args.output)
                print_report_links(html_path, xml_path, links_only=args.links_only, open_reports=args.open_reports)
        except Exception as e:
            print(f"[ERR] scan failed: {e}")

        # Restore args for next iteration
        args.host_override = prev_host_override
        print("\n--- Scan complete. Do another, choose [00] for file, or [04] Exit. ---\n")

# ======== Main ========
def main():
    description = (
        "A simple, cross-platform WAF detector (Windows PowerShell & Linux). "
        "Scan a single domain/IP/URL or a batch from file."
    )
    epilog = """\
EXAMPLES
  py %(prog)s -i
  py %(prog)s example.com
  py %(prog)s -F subs.txt
"""

    parser = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name,
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", nargs="?", help="Target domain/IP/URL (scheme inferred or forced via --force-scheme)")

    # Interactive/menu
    parser.add_argument("-i", "--menu", action="store_true", help="Interactive menu (loops until [04] Exit; supports [00] file)")
    parser.add_argument("-m", "--mode", choices=["1","2","3","01","02","03"], help="Mode: 1/01=HTTP, 2/02=HTTPS, 3/03=IP(HTTP)")
    parser.add_argument("-O", "--show-options", action="store_true", help="Show options cheat sheet")

    # Batch/reporting
    parser.add_argument("-F", "--input-file", help="Text file with one domain/IP/URL per line")
    parser.add_argument("-t", "--threads", type=int, default=8, help="Parallel workers (default 8)")
    parser.add_argument("-d", "--out-dir", default="reports", help="Directory to save reports (default ./reports)")
    parser.add_argument("-p", "--prefix", default="wafscan", help="Report filename prefix (default wafscan)")
    parser.add_argument("-o", "--output", help="Output filename base or path; writes <name>.html and <name>.xml; overrides prefix/timestamp")
    parser.add_argument("-x", "--export", action="store_true", help="For scans, also write HTML/XML reports")
    parser.add_argument("-l", "--links-only", action="store_true", help="Print ONLY two file:// links (HTML & XML)")
    parser.add_argument("-r", "--open-reports", action="store_true", help="Open generated reports in default browser")

    # Scan behavior
    parser.add_argument("-a", "--aggressive", action="store_true", help="Do extra probes to help trigger filtering")
    parser.add_argument("-T", "--timeout", type=float, default=8.0, help="Per-request timeout in seconds (default 8.0)")
    parser.add_argument("-u", "--user-agent", default=f"Mozilla/5.0 (WAF-Detector/{VERSION})", help="Custom User-Agent")
    parser.add_argument("-H", "--host", dest="host_override", help="Override Host header (useful for IP + vhost, HTTP only)")
    parser.add_argument("-f", "--force-scheme", choices=["http","https"], help="Force scheme when target lacks one")
    parser.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification (for https://IP or cert mismatch)")
    parser.add_argument("-P", "--port", type=int, help="Override port (defaults 80/443 by scheme)")
    parser.add_argument("-L", "--no-logo", action="store_true", help="Hide ASCII banner")
    parser.add_argument("-C", "--no-color", action="store_true", help="Disable ANSI color (override always-green)")

    args = parser.parse_args()

    # Runtime UI prefs
    global USE_COLOR, NO_LOGO
    USE_COLOR = not args.no_color
    NO_LOGO = args.no_logo

    # Enable ANSI & set baseline green across platforms
    if USE_COLOR:
        ok = True
        if os.name == "nt":
            ok = _enable_windows_ansi()
        if ok:
            sys.stdout.write("\033[92m")  # baseline green
            atexit.register(lambda: sys.stdout.write("\033[0m"))

    if args.show_options:
        print("""
============= Options Cheat Sheet =============
Interactive:
  -i/--menu         : Menu loop with [00]=file, [01]=HTTP, [02]=HTTPS, [03]=IP, [04]=Exit
Batch:
  -F/--input-file   : Batch scan from file (same as menu [00])
Reports:
  -x/--export       : Save HTML/XML report (single or batch)
  -r/--open-reports : Open reports in browser
Other:
  -C/--no-color     : Disable ANSI color
================================================
""")
        sys.exit(0)

    banner()

    # Batch mode via CLI flag
    if args.input_file:
        scan_file_batch(Path(args.input_file), args)
        sys.exit(0)

    # Single target / Interactive menu
    if args.menu:
        interactive_loop(args)  # loops until [04] Exit
        sys.exit(0)
    else:
        if not args.target:
            print("No target provided. Use --menu, --input-file, or pass a target (domain/IP/URL).")
            sys.exit(2)
        base_url = normalize_url(args.target, force_scheme=args.force_scheme, port=args.port)

        result = scan_one_target(base_url, args, args.target if args.target else base_url)
        print(json.dumps(result, indent=2, ensure_ascii=False))

        if args.export:
            html_path, xml_path = write_reports_auto([result], Path(args.out_dir), args.prefix, args.output)
            print_report_links(html_path, xml_path, links_only=args.links_only, open_reports=args.open_reports)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
