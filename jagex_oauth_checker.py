"""
FP OSRS Jagex Account Checker v1.0
Automates the Jagex OAuth2 login flow via Playwright browser automation.
For each account: email -> password -> TOTP -> auth code -> access token -> game session.

Author: FruityPebbles
"""

import asyncio
import hmac
import hashlib
import struct
import time
import base64
import json
import os
import secrets
import shutil
import sys
import subprocess
import random
import urllib.request
import urllib.error
from urllib.parse import urlencode, urlparse, parse_qs
from datetime import datetime

# OAuth2 config
LAUNCHER_CLIENT_ID = "com_jagex_auth_desktop_launcher"
CONSENT_CLIENT_ID = "1fddee4e-b100-4f4e-b2b0-097f9088f9d2"
AUTH_URL = "https://account.jagex.com/oauth2/auth"
TOKEN_URL = "https://account.jagex.com/oauth2/token"
REDIRECT_URI = "https://secure.runescape.com/m=weblogin/launcher-redirect"
GAME_SESSION_URL = "https://auth.jagex.com/game-session/v1/sessions"
GAME_ACCOUNTS_URL = "https://auth.jagex.com/game-session/v1/accounts"

RESULTS_FILE = None


def find_chrome() -> str:
    """Auto-detect Chrome installation path."""
    candidates = [
        os.path.join(os.environ.get("PROGRAMFILES", ""), "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Google", "Chrome", "Application", "chrome.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "Application", "chrome.exe"),
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return None


def generate_totp(secret: str) -> str:
    """Generate a 6-digit TOTP code from a base32-encoded secret."""
    key = base64.b32decode(secret.upper())
    counter = int(time.time()) // 30
    msg = struct.pack('>Q', counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack('>I', h[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1000000:06d}"


def load_accounts(path: str) -> list:
    """Load accounts from file. Format: email:password:totp_secret per line."""
    accounts = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":", 2)
            if len(parts) == 3 and parts[2].strip():
                accounts.append({
                    "email": parts[0].strip(),
                    "password": parts[1].strip(),
                    "totp_secret": parts[2].strip()
                })
    return accounts


def record_result(results_file: str, account: dict, status: str, detail: str):
    """Append result to results file."""
    line = f"{account['email']} | {status} | {detail}"
    with open(results_file, "a") as f:
        f.write(line + "\n")
    print(f"  [{status}] {account['email']} - {detail}")


async def handle_turnstile(page, timeout=60):
    """Wait for and attempt to solve Cloudflare turnstile if present."""
    for attempt in range(timeout // 2):
        try:
            title = await page.title()
            if "moment" not in title.lower() and "just a" not in title.lower() and "robot" not in title.lower():
                return True
            if attempt == 1:
                print("  Turnstile detected - attempting to solve...")
            for frame in page.frames:
                if "challenges.cloudflare.com" in (frame.url or ""):
                    try:
                        checkbox = frame.locator('[type="checkbox"], .cb-lb, input')
                        if await checkbox.count() > 0:
                            await checkbox.first.click()
                            print("  Clicked turnstile checkbox")
                            await asyncio.sleep(3)
                            break
                        body = frame.locator("body")
                        if await body.count() > 0:
                            await body.click()
                            await asyncio.sleep(3)
                            break
                    except Exception:
                        pass
        except Exception:
            pass
        await asyncio.sleep(2)
    return False


def exchange_auth_code(auth_code: str) -> dict:
    """Exchange authorization code for tokens."""
    token_data = urlencode({
        "grant_type": "authorization_code",
        "client_id": LAUNCHER_CLIENT_ID,
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
    }).encode()
    req = urllib.request.Request(TOKEN_URL, data=token_data)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    resp = urllib.request.urlopen(req, timeout=15)
    return json.loads(resp.read())


def decode_id_token(jwt: str) -> dict:
    """Decode JWT id_token claims."""
    try:
        b64 = jwt.split(".")[1]
        b64 += "=" * (4 - len(b64) % 4)
        return json.loads(base64.urlsafe_b64decode(b64))
    except Exception:
        return {}


async def check_account(page, results_file, account, num, total):
    """Run the full OAuth flow for one account. Returns (status, detail)."""
    email = account["email"]
    password = account["password"]
    totp_secret = account["totp_secret"]

    print(f"\n[{num}/{total}] Testing: {email}")

    try:
        # Step 1: Navigate to Jagex OAuth2
        state = secrets.token_urlsafe(24)
        auth_params = urlencode({
            "client_id": LAUNCHER_CLIENT_ID, "response_type": "code",
            "scope": "openid offline gamesso.token.create user.profile.read",
            "redirect_uri": REDIRECT_URI, "state": state,
        })
        try:
            await page.goto(f"{AUTH_URL}?{auth_params}", wait_until="commit", timeout=60000)
        except Exception:
            pass

        await handle_turnstile(page)

        # Wait for login page or cached redirect
        already_authed = False
        print("  Waiting for login page...")
        for attempt in range(30):
            try:
                url = page.url
                title = await page.title()

                if "launcher-redirect" in url and "code=" in url:
                    already_authed = True
                    break
                if ("assisted-login" in url or "login_challenge" in url) and \
                   ("log in" in title.lower() or "jagex" in title.lower() or "choose" in title.lower()):
                    break
                if "launcher" in title.lower() or "logging in" in title.lower():
                    if "code" in parse_qs(urlparse(url).query):
                        already_authed = True
                        break
                if "error" in url and "login_challenge" not in url:
                    p = parse_qs(urlparse(url).query)
                    if "code" in p:
                        already_authed = True
                        break
                    return ("ERROR", f"OAuth error: {url[:200]}")
                if "moment" in title.lower() or "just a" in title.lower() or "robot" in title.lower():
                    await handle_turnstile(page)
            except Exception:
                pass
            await asyncio.sleep(2)
        else:
            return ("BLOCKED", "Login page never loaded")

        # Cached session path
        if already_authed:
            url = page.url
            params = parse_qs(urlparse(url).query)
            if "code" not in params:
                return ("ERROR", "Authed but no code in URL")
            try:
                tokens = exchange_auth_code(params["code"][0])
            except Exception as e:
                return ("ERROR", f"Token exchange failed: {e}")
            claims = decode_id_token(tokens.get("id_token", ""))
            nickname = claims.get("nickname", "unknown")
            access_token = tokens.get("access_token", "")
            print(f"  Auth code obtained (cached)")
            print(f"  Launcher auth OK (cached) - nickname: {nickname}")

        # Full login path
        if not already_authed:
            # Cookie banner
            try:
                btn = page.get_by_role("button", name="Use necessary cookies")
                if await btn.is_visible(timeout=3000):
                    await btn.click()
                    await asyncio.sleep(1)
            except Exception:
                pass

            # Email
            field = page.get_by_role("textbox", name="Email")
            try:
                await field.wait_for(state="visible", timeout=10000)
            except Exception:
                return ("ERROR", "Email field not found")
            await field.fill(email)
            await asyncio.sleep(0.5)
            await page.get_by_test_id("continue-with-assisted-via-email-flow").click()
            await asyncio.sleep(2)
            await handle_turnstile(page)

            # Password
            title = await page.title()
            if "error" in title.lower():
                return ("INVALID_EMAIL", f"Account not found: {email}")
            field = page.get_by_role("textbox", name="Password")
            try:
                await field.wait_for(state="visible", timeout=10000)
            except Exception:
                text = await page.inner_text("body")
                if "not found" in text.lower() or "doesn't exist" in text.lower():
                    return ("INVALID_EMAIL", "Account not found")
                return ("ERROR", f"No password field. Title: {title}")
            await field.fill(password)
            await asyncio.sleep(0.5)
            await page.get_by_test_id("continue-with-jagex-flow").click()
            await asyncio.sleep(2)
            await handle_turnstile(page)

            # Check errors
            url = page.url
            if "error" in url or "assisted-login" in url:
                text = await page.inner_text("body")
                tl = text.lower()
                if "incorrect" in tl or "wrong" in tl or "invalid" in tl:
                    return ("BAD_PASSWORD", "Invalid password")
                if "locked" in tl:
                    return ("LOCKED", "Account locked")
                if "banned" in tl or "disabled" in tl:
                    return ("BANNED", "Account banned/disabled")

            # TOTP
            if "totp-verify" in url:
                code = generate_totp(totp_secret)
                print(f"  TOTP code: {code}")
                field = page.get_by_role("textbox", name="Verification code")
                try:
                    await field.wait_for(state="visible", timeout=5000)
                except Exception:
                    return ("ERROR", "TOTP field not found")
                await field.fill(code)
                await asyncio.sleep(0.5)
                await page.get_by_test_id("totp-verify-form--button-continue").click()
                await asyncio.sleep(3)
                await handle_turnstile(page)

            # Wait for auth code redirect
            for _ in range(15):
                url = page.url
                if "launcher-redirect" in url and "code=" in url:
                    break
                if "login_verifier" in url:
                    await asyncio.sleep(2)
                    continue
                await asyncio.sleep(1)

            url = page.url
            params = parse_qs(urlparse(url).query)
            if "code" not in params:
                if "error" in params:
                    desc = params.get("error_description", ["Unknown"])[0]
                    if "locked" in desc.lower(): return ("LOCKED", desc)
                    if "banned" in desc.lower() or "disabled" in desc.lower(): return ("BANNED", desc)
                    return ("AUTH_FAILED", desc)
                return ("ERROR", f"No auth code. URL: {url[:200]}")

            print(f"  Auth code obtained")
            try:
                tokens = exchange_auth_code(params["code"][0])
            except Exception as e:
                return ("ERROR", f"Token exchange failed: {e}")
            access_token = tokens.get("access_token", "")
            claims = decode_id_token(tokens.get("id_token", ""))
            nickname = claims.get("nickname", "unknown")
            print(f"  Launcher auth OK - nickname: {nickname}")

        # Consent flow for game session
        consent_params = urlencode({
            "client_id": CONSENT_CLIENT_ID, "response_type": "id_token code",
            "scope": "openid offline", "redirect_uri": "http://localhost",
            "state": secrets.token_urlsafe(24), "nonce": secrets.token_urlsafe(36),
        })

        async def intercept_localhost(route):
            await route.fulfill(status=200, content_type="text/html",
                body='<html><script>document.title="REDIRECT:"+window.location.hash;</script></html>')

        await page.route("http://localhost**", intercept_localhost)
        try:
            await page.goto(f"{AUTH_URL}?{consent_params}", wait_until="commit", timeout=60000)
        except Exception:
            pass

        await handle_turnstile(page)
        print("  Waiting for consent redirect...")
        for _ in range(30):
            try:
                url = page.url
                title = await page.title()
                if "localhost" in url or title.startswith("REDIRECT:"): break
                if "launcher" in title.lower() or "logging in" in title.lower(): break
                if "moment" in title.lower() or "just a" in title.lower():
                    await handle_turnstile(page)
            except Exception:
                pass
            await asyncio.sleep(2)
        await asyncio.sleep(2)

        # Extract consent id_token
        consent_id_token = None
        for method in range(3):
            if consent_id_token: break
            try:
                if method == 0:
                    t = await page.title()
                    if t.startswith("REDIRECT:#") and "id_token=" in t:
                        consent_id_token = parse_qs(t[len("REDIRECT:#"):]).get("id_token", [None])[0]
                elif method == 1:
                    h = await page.evaluate("window.location.hash")
                    if h and "id_token=" in h:
                        consent_id_token = parse_qs(h.lstrip("#")).get("id_token", [None])[0]
                elif method == 2:
                    u = await page.evaluate("window.location.href")
                    if "#" in u and "id_token=" in u:
                        consent_id_token = parse_qs(u.split("#", 1)[1]).get("id_token", [None])[0]
            except Exception:
                pass

        try:
            await page.unroute("http://localhost**")
        except Exception:
            pass

        if not consent_id_token:
            return ("OK_NO_SESSION", f"nickname:{nickname} | launcher_auth:OK | consent:INCOMPLETE")

        print(f"  Consent token obtained")

        # Game session
        data = json.dumps({"idToken": consent_id_token}).encode()
        req = urllib.request.Request(GAME_SESSION_URL, data=data)
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0")
        req.add_header("Accept", "application/json")
        try:
            resp = urllib.request.urlopen(req, timeout=15)
            session_id = json.loads(resp.read()).get("sessionId", "")
            print(f"  Game session: {session_id[:20]}...")
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            return ("OK_NO_SESSION", f"nickname:{nickname} | session_error:{body[:100]}")

        # Characters
        req = urllib.request.Request(GAME_ACCOUNTS_URL)
        req.add_header("Authorization", f"Bearer {session_id}")
        req.add_header("User-Agent", "Mozilla/5.0")
        req.add_header("Accept", "application/json")
        try:
            resp = urllib.request.urlopen(req, timeout=15)
            chars = [c.get("displayName", "?") for c in json.loads(resp.read())]
        except Exception:
            chars = []
        if chars:
            print(f"  Characters: {chars}")

        detail = (f"nickname:{nickname} | characters:{','.join(chars)} "
                  f"| session_id:{session_id[:30]}... | access_token:{access_token[:30]}...")
        return ("OK", detail)

    except Exception as e:
        err = str(e)
        if "timeout" in err.lower():
            return ("BLOCKED", f"Timeout: {err[:100]}")
        return ("ERROR", err[:200])


def show_gui() -> dict:
    """Show a GUI when launched with no arguments. Returns config dict or None."""
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext

    # FP Brand colours
    BG = "#0D0D12"
    CARD = "#16161E"
    BORDER = "#2A2A35"
    FP_RED = "#E83A30"
    FP_ORANGE = "#F58A2C"
    FP_YELLOW = "#F5D032"
    FP_GREEN = "#5AC45A"
    FP_BLUE = "#3A9BE0"
    FP_PINK = "#E85A9A"
    TEXT = "#ECECF0"
    MUTED = "#6E6E80"

    config = {"file": None, "skip": 0, "limit": 0, "started": False}

    root = tk.Tk()
    root.title("FP Jagex Account Checker v1.0")
    root.geometry("580x520")
    root.resizable(False, False)
    root.configure(bg=BG)

    # Rainbow strip at top
    strip = tk.Frame(root, height=4, bg=BG)
    strip.pack(fill=tk.X)
    strip.pack_propagate(False)
    for color in [FP_RED, FP_ORANGE, FP_YELLOW, FP_GREEN, FP_BLUE, FP_PINK]:
        tk.Frame(strip, bg=color).pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Header
    header = tk.Frame(root, bg=CARD, height=46)
    header.pack(fill=tk.X)
    header.pack_propagate(False)
    tk.Label(header, text="FP Jagex Account Checker", font=("Segoe UI", 15, "bold"),
             fg=TEXT, bg=CARD).pack(side=tk.LEFT, padx=16, pady=10)
    tk.Label(header, text="v1.0", font=("Consolas", 10), fg=MUTED,
             bg=CARD).pack(side=tk.RIGHT, padx=16)

    # Content
    content = tk.Frame(root, bg=BG)
    content.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)

    # File row
    file_frame = tk.Frame(content, bg=BG)
    file_frame.pack(fill=tk.X, pady=(0, 8))

    file_label = tk.Label(file_frame, text="No file selected", font=("Segoe UI", 10),
                          fg=MUTED, bg=BG, anchor="w")

    def browse():
        path = filedialog.askopenfilename(
            title="Select accounts file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            config["file"] = path
            file_label.config(text=os.path.basename(path), fg=FP_GREEN)
            try:
                with open(path) as f:
                    text_area.delete("1.0", tk.END)
                    text_area.insert("1.0", f.read())
                update_count()
            except Exception:
                pass

    browse_btn = tk.Button(file_frame, text="Browse .txt file...", font=("Segoe UI", 10),
                           fg=TEXT, bg=CARD, activebackground=BORDER,
                           activeforeground="white", bd=0, padx=12, pady=4,
                           cursor="hand2", command=browse)
    browse_btn.pack(side=tk.LEFT)
    file_label.pack(side=tk.LEFT, padx=(12, 0), fill=tk.X, expand=True)

    # Paste label
    tk.Label(content, text="Or paste accounts below (email:password:totp per line):",
             font=("Segoe UI", 10), fg=TEXT, bg=BG,
             anchor="w").pack(fill=tk.X, pady=(4, 4))

    # Text area
    text_frame = tk.Frame(content, bg=BORDER, bd=1)
    text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
    text_area = scrolledtext.ScrolledText(text_frame, font=("Consolas", 10),
                                          bg=CARD, fg=TEXT,
                                          insertbackground=FP_ORANGE,
                                          selectbackground=FP_BLUE,
                                          wrap=tk.NONE, bd=0, padx=8, pady=8)
    text_area.pack(fill=tk.BOTH, expand=True)

    # Count label
    count_label = tk.Label(content, text="0 accounts", font=("Segoe UI", 10, "bold"),
                           fg=FP_YELLOW, bg=BG, anchor="w")
    count_label.pack(fill=tk.X)

    def update_count(*_):
        lines = text_area.get("1.0", tk.END).strip().split("\n")
        count = sum(1 for l in lines if l.strip() and not l.strip().startswith("#")
                    and l.count(":") >= 2)
        count_label.config(text=f"{count} account{'s' if count != 1 else ''}")

    text_area.bind("<KeyRelease>", update_count)

    # Options row
    opts = tk.Frame(content, bg=BG)
    opts.pack(fill=tk.X, pady=(8, 0))

    tk.Label(opts, text="Skip:", font=("Segoe UI", 10), fg=MUTED,
             bg=BG).pack(side=tk.LEFT)
    skip_var = tk.StringVar(value="0")
    skip_entry = tk.Entry(opts, textvariable=skip_var, width=5, font=("Consolas", 10),
                          bg=CARD, fg=TEXT, insertbackground=FP_ORANGE, bd=0)
    skip_entry.pack(side=tk.LEFT, padx=(4, 16))

    tk.Label(opts, text="Limit (0=all):", font=("Segoe UI", 10), fg=MUTED,
             bg=BG).pack(side=tk.LEFT)
    limit_var = tk.StringVar(value="0")
    limit_entry = tk.Entry(opts, textvariable=limit_var, width=5, font=("Consolas", 10),
                           bg=CARD, fg=TEXT, insertbackground=FP_ORANGE, bd=0)
    limit_entry.pack(side=tk.LEFT, padx=(4, 0))

    # Buttons
    btn_frame = tk.Frame(content, bg=BG)
    btn_frame.pack(fill=tk.X, pady=(12, 0))

    def on_start():
        # Save text to temp file if no file was browsed
        if not config["file"]:
            text = text_area.get("1.0", tk.END).strip()
            if text:
                tmp = os.path.join(os.environ.get("TEMP", "/tmp"), "fp_checker_input.txt")
                with open(tmp, "w") as f:
                    f.write(text)
                config["file"] = tmp
        config["skip"] = int(skip_var.get() or 0)
        config["limit"] = int(limit_var.get() or 0)
        config["started"] = True
        root.destroy()

    def on_cancel():
        root.destroy()

    cancel_btn = tk.Button(btn_frame, text="Cancel", font=("Segoe UI", 10),
                           fg=MUTED, bg=CARD, activebackground=BORDER,
                           activeforeground="white", bd=0, padx=20, pady=6,
                           cursor="hand2", command=on_cancel)
    cancel_btn.pack(side=tk.RIGHT, padx=(8, 0))

    start_btn = tk.Button(btn_frame, text="Start Checking", font=("Segoe UI", 11, "bold"),
                          fg="white", bg=FP_RED, activebackground=FP_ORANGE,
                          activeforeground="white", bd=0, padx=20, pady=6,
                          cursor="hand2", command=on_start)
    start_btn.pack(side=tk.RIGHT)

    root.mainloop()
    return config if config["started"] else None


async def main():
    print("FP OSRS Jagex Account Checker v1.0")
    print("=" * 40)

    accounts_file = None
    skip = 0
    limit = 0
    chrome_path = None
    global RESULTS_FILE

    args = sys.argv[1:]

    # No args = show GUI
    if not args:
        config = show_gui()
        if not config or not config["file"]:
            print("Cancelled.")
            sys.exit(0)
        accounts_file = config["file"]
        skip = config["skip"]
        limit = config["limit"]
    else:
        i = 0
        while i < len(args):
            if args[i] == "--file" and i + 1 < len(args):
                accounts_file = args[i + 1]; i += 2
            elif args[i] == "--skip" and i + 1 < len(args):
                skip = int(args[i + 1]); i += 2
            elif args[i] == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1]); i += 2
            elif args[i] == "--chrome" and i + 1 < len(args):
                chrome_path = args[i + 1]; i += 2
            elif args[i] == "--output" and i + 1 < len(args):
                RESULTS_FILE = args[i + 1]; i += 2
            elif args[i] == "--help":
                print("""
Usage: jagex_oauth_checker [OPTIONS]

Options:
  --file PATH      Accounts file (email:password:totp per line)
  --skip N         Skip first N accounts
  --limit N        Only check N accounts
  --chrome PATH    Chrome executable path (auto-detected if omitted)
  --output PATH    Results file path (default: results_<timestamp>.txt)
  --help           Show this help
""")
                sys.exit(0)
            else:
                if os.path.isfile(args[i]):
                    accounts_file = args[i]
                i += 1

    if not accounts_file:
        for name in ["accounts.txt", "jagex_accounts.txt", "totp_accounts.txt"]:
            if os.path.isfile(name):
                accounts_file = name
                break

    if not accounts_file or not os.path.isfile(accounts_file):
        print("Error: No accounts file found.")
        print("Usage: jagex_oauth_checker --file accounts.txt")
        print("Format: email:password:totp_secret (one per line)")
        sys.exit(1)

    if not RESULTS_FILE:
        RESULTS_FILE = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    if not chrome_path:
        chrome_path = find_chrome()
    if not chrome_path:
        print("Error: Chrome not found. Specify with --chrome /path/to/chrome")
        sys.exit(1)

    print(f"Chrome: {chrome_path}")

    accounts = load_accounts(accounts_file)
    print(f"Loaded {len(accounts)} accounts from {os.path.basename(accounts_file)}")

    if skip > 0:
        accounts = accounts[skip:]
        print(f"Skipping first {skip}, {len(accounts)} remaining")
    if limit > 0:
        accounts = accounts[:limit]
        print(f"Limiting to {limit} accounts")

    if not accounts:
        print("No accounts to check.")
        sys.exit(0)

    with open(RESULTS_FILE, "a") as f:
        f.write(f"\n# FP Jagex Account Check - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                f" - {len(accounts)} accounts\n")

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("\nPlaywright not installed. Run:")
        print("  pip install playwright && python -m playwright install chromium")
        sys.exit(1)

    results = {"ok": 0, "bad": 0, "banned": 0, "locked": 0, "error": 0}
    debug_port = 9222
    temp_dir = os.environ.get("TEMP", os.environ.get("TMPDIR", "/tmp"))
    profile_dir = os.path.join(temp_dir, f"fp_checker_{os.getpid()}")

    chrome_proc = subprocess.Popen([
        chrome_path, f"--remote-debugging-port={debug_port}",
        f"--user-data-dir={profile_dir}", "--no-first-run",
        "--no-default-browser-check", "--disable-background-networking",
        "--window-size=1280,720", "about:blank",
    ])
    await asyncio.sleep(3)

    async with async_playwright() as p:
        try:
            browser = await p.chromium.connect_over_cdp(f"http://localhost:{debug_port}")
        except Exception as e:
            print(f"Error connecting to Chrome: {e}")
            chrome_proc.kill()
            sys.exit(1)

        ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
        page = ctx.pages[0] if ctx.pages else await ctx.new_page()

        for i, account in enumerate(accounts, 1):
            status, detail = await check_account(page, RESULTS_FILE, account, i + skip, len(accounts) + skip)
            if status == "BLOCKED":
                await asyncio.sleep(5)
                status, detail = await check_account(page, RESULTS_FILE, account, i + skip, len(accounts) + skip)

            record_result(RESULTS_FILE, account, status, detail)

            if "OK" in status: results["ok"] += 1
            elif status == "BAD_PASSWORD": results["bad"] += 1
            elif status == "BANNED": results["banned"] += 1
            elif status == "LOCKED": results["locked"] += 1
            else: results["error"] += 1

            # Keep CF clearance, clear Jagex session
            cookies = await ctx.cookies()
            for c in cookies:
                if ("jagex" in c["domain"] or "runescape" in c["domain"]) and c["name"] != "cf_clearance":
                    await ctx.clear_cookies(domain=c["domain"], name=c["name"])

            if i < len(accounts):
                delay = random.uniform(15, 25)
                print(f"  Waiting {delay:.0f}s before next account...")
                await asyncio.sleep(delay)

        print("\nClosing browser...")
        try:
            cdp = await ctx.new_cdp_session(page)
            await cdp.send("Browser.close")
        except Exception:
            pass
        try:
            await browser.close()
        except Exception:
            pass

    await asyncio.sleep(2)
    try:
        subprocess.run(["taskkill", "/F", "/FI", f"WINDOWTITLE eq *{debug_port}*",
                        "/IM", "chrome.exe"], capture_output=True, timeout=5)
    except Exception:
        pass
    try:
        r = subprocess.run(["wmic", "process", "where",
            f"commandline like '%{os.path.basename(profile_dir)}%'", "get", "processid"],
            capture_output=True, text=True, timeout=10)
        for line in r.stdout.strip().split("\n"):
            if line.strip().isdigit():
                subprocess.run(["taskkill", "/F", "/T", "/PID", line.strip()], capture_output=True, timeout=5)
    except Exception:
        pass
    shutil.rmtree(profile_dir, ignore_errors=True)

    print(f"\n{'=' * 50}")
    print(f"DONE! OK:{results['ok']} Bad:{results['bad']} "
          f"Banned:{results['banned']} Locked:{results['locked']} Error:{results['error']}")
    print(f"Results saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    asyncio.run(main())
