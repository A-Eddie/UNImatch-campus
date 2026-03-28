# Security Policy — UniMatch Campus

## Reporting a Vulnerability

If you discover a security vulnerability in UniMatch Campus, please **do not** open a public GitHub issue. Instead, email the maintainer directly at `security@unimatch.app` (replace with the real contact address) with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested mitigations

We aim to acknowledge reports within **48 hours** and provide a fix timeline within **7 days** for critical issues.

---

## Security Architecture

### Data Storage

This app currently uses `localStorage` for persistence (demo/prototype mode). When migrating to a production Firebase backend:

- All persistent data must be stored in **Cloud Firestore** (never `localStorage` for sensitive data)
- Profile photos must be stored in **Firebase Storage**
- Sensitive PII (email, real name) should live in a private Firestore subcollection that only the owner can read

### Authentication

- Firebase Authentication is used for identity management
- Passwords are **never** stored client-side; Firebase Auth handles credentials
- The hardcoded demo admin account (`admin@unimatch.app`) **must be replaced** with a real Firebase Auth admin user before production deployment
- Enable **Email Enumeration Protection** in Firebase Console → Authentication → Settings to prevent account discovery attacks

### Firestore Security Rules (`firestore.rules`)

The included `firestore.rules` file enforces:

| Rule | Description |
|------|-------------|
| Deny-by-default | All paths not explicitly matched are denied |
| Owner-only writes | Users can only write their own profile document |
| Immutable privilege fields | `isAdmin` and `status` cannot be self-modified |
| Field-length validation | `bio ≤ 500 chars`, `name ≤ 80 chars`, etc. |
| Chat participant enforcement | Messages only readable/writable by conversation participants |
| Report write-only | Users can submit reports but cannot read them |
| Block list privacy | Block lists are private to the owner |
| Server-only matches | Match documents are written by Cloud Functions only |

### Storage Security Rules (`storage.rules`)

The included `storage.rules` file enforces:

| Rule | Description |
|------|-------------|
| Authenticated uploads only | Unauthenticated users cannot upload anything |
| Owner-only path | Files can only be written to `profiles/{uid}/` by that uid |
| File size limit | Maximum 5 MB per file |
| MIME type allowlist | Only `image/jpeg`, `image/png`, `image/webp`, `image/gif` |
| Public read | Profile photos are publicly readable (consistent with public profiles) |

### HTTP Security Headers (`firebase.json`)

All responses from Firebase Hosting include:

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | Restricts script/style/connect sources to trusted origins |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` — enforces HTTPS |
| `X-Frame-Options` | `DENY` — prevents clickjacking |
| `X-Content-Type-Options` | `nosniff` — prevents MIME sniffing |
| `X-XSS-Protection` | `1; mode=block` — legacy XSS filter |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Disables camera, microphone, geolocation, payment APIs |

### XSS Prevention

All user-supplied content rendered via `innerHTML` is escaped through the `escapeHTML()` function before insertion into the DOM. Wherever possible, `textContent` is used instead of `innerHTML`.

### Rate Limiting

Client-side login rate limiting uses exponential backoff:
- After 5 failed attempts the UI locks out the user
- Lockout duration doubles with each further failure, up to 5 minutes
- Lockout state is reset on successful login or logout

Server-side rate limiting must be enforced via Firestore security rules or Firebase Cloud Functions for production.

### Input Validation

All user inputs are validated on both the client (for UX) and server side (via Firestore rules):

| Field | Client max | Firestore rule max |
|-------|-----------|-------------------|
| First/Last name | 50 chars | 80 chars (full name) |
| Email | 200 chars | 200 chars |
| Password | — | Firebase Auth minimum |
| University | 120 chars | 120 chars |
| Department | 120 chars | 120 chars |
| Bio | 500 chars | 500 chars |
| Message text | 2000 chars | 2000 chars |
| Interests | 20 items | 20 items |

---

## Required Manual Steps Before Production Deployment

### 1. Restrict the Firebase API Key (Google Cloud Console)

1. Go to **Google Cloud Console → APIs & Services → Credentials**
2. Find the **Browser key** for the project
3. Under **Application restrictions**, select **HTTP referrers**
4. Add: `unimatch-campus.web.app/*` and `unimatch-campus.firebaseapp.com/*`
5. Under **API restrictions**, limit to:
   - Firebase Installations API
   - Cloud Firestore API
   - Identity Toolkit API
   - Token Service API
   - Cloud Storage for Firebase API
6. Save

### 2. Enable Email Enumeration Protection

1. **Firebase Console → Authentication → Settings**
2. Enable **Email enumeration protection**

### 3. Enable App Check (reCAPTCHA v3)

1. **Firebase Console → App Check → Register** your web app
2. Choose **reCAPTCHA v3** as provider
3. Create a site key at [Google reCAPTCHA Admin](https://www.google.com/recaptcha/admin)
4. Add App Check initialization after `firebase.initializeApp()`:

```javascript
const appCheck = firebase.appCheck();
appCheck.activate('YOUR_RECAPTCHA_V3_SITE_KEY', true);
```

5. Enforce App Check for: **Firestore**, **Storage**, **Authentication**, **Functions**

### 4. Deploy Security Rules

```bash
firebase deploy --only firestore:rules
firebase deploy --only storage
firebase deploy --only hosting
```

### 5. Replace Demo Admin Account

Remove the hardcoded `ADMIN_EMAIL`/`ADMIN_PASS` constants from `index.html` and implement proper admin authentication using a Cloud Function that verifies a custom claim (`isAdmin: true`) set on the Firebase Auth user via the Admin SDK.

### 6. Data Protection (Kenya Data Protection Act 2019)

- Provide users with a clear **Privacy Policy** explaining what data is collected and why
- Implement the **Right to Erasure**: `deleteAccount()` already deletes all local data; extend it to call a Cloud Function that cascades deletion across Firestore and Storage
- Do not store user PII longer than necessary
- Log access to sensitive data for audit purposes

---

## Known Limitations (Demo Mode)

| Limitation | Production Fix |
|-----------|---------------|
| Passwords stored in `localStorage` | Use Firebase Auth — passwords never reach the client |
| localStorage used for all data | Use Firestore + Firebase Storage |
| Client-side match logic (random) | Move to Cloud Functions |
| Demo verification code `123456` | Use real email/SMS OTP via Firebase Auth |
| Sample profiles mixed with real users | Remove or serve from a separate `isSample: true` collection |
| Admin credentials hardcoded | Replace with Firebase custom claims |
