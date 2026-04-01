# FP OSRS Jagex Account Checker

Automated Jagex account credential checker using the OAuth2 authentication flow. Validates accounts with TOTP (authenticator) support via real browser automation.

## Features

- **Full OAuth2 Flow** - Authenticates through Jagex's official OAuth2 endpoints
- **TOTP Auto-Generation** - Generates 6-digit codes from stored TOTP secrets
- **Game Session** - Obtains game session tokens and character lists
- **Real Browser** - Uses your actual Chrome via CDP to bypass bot detection
- **Cloudflare Handling** - Detects and waits for turnstile challenges
- **Bulk Processing** - Process hundreds of accounts with configurable delays

## Requirements

- Python 3.10+
- Google Chrome installed
- Playwright (`pip install playwright`)

## Account Format

```
email@example.com:password:TOTP_SECRET_BASE32
another@email.com:pass456:ABCDEF123456
```

## Usage

```bash
# Check all accounts
python jagex_oauth_checker.py

# Skip first N and limit
python jagex_oauth_checker.py --skip 10 --limit 5

# Use a different file
python jagex_oauth_checker.py --file /path/to/accounts.txt
```

## How It Works

1. Launches Chrome with remote debugging (separate profile)
2. Navigates to Jagex OAuth2 authorization endpoint
3. Fills email, password, generates and submits TOTP code
4. Captures authorization code from redirect
5. Exchanges code for access token + ID token
6. Runs consent flow to obtain game session token
7. Fetches character list from game session API
8. Records results with nickname, characters, tokens

## Results

Results saved to `jagex_oauth_results.txt`:

```
email:pass:totp | OK | nickname:PlayerName#1234 | characters:CharName | session_id:abc... | access_token:xyz...
email2:pass:totp | BAD_PASSWORD | Invalid password
```

## OAuth2 Endpoints

- Auth: `https://account.jagex.com/oauth2/auth`
- Token: `https://account.jagex.com/oauth2/token`
- Game Session: `https://auth.jagex.com/game-session/v1/sessions`
- Characters: `https://auth.jagex.com/game-session/v1/accounts`

## Author

FruityPebbles
