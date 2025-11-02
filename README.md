A small, security-aware FinTech demo application built with Flask that showcases core cybersecurity concepts: authentication, input validation, protected storage, session management, safe error handling, encryption/decryption, activity logs, and file-upload validation.
It includes a repeatable manual testing plan (20 tests) to validate common security controls without automated scanners.

🧱 Tech Stack
Backend: Python 3.x, Flask
Auth/Hashing: bcrypt (via flask-bcrypt or passlib)
Sessions: Flask sessions / secure cookies
Storage: SQLite or Postgres (choose one; default SQLite for demo)
Crypto: cryptography (Fernet) for field-level encryption
Logging: Python logging (security events/audits)

Getting Started
1) Prerequisites
Python 3.10+ recommended
pip, virtualenv

2) Setup
# clone your repo (replace with your GitHub)
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

# (optional) create & activate a venv
python -m venv venv
# Windows: venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# install deps
pip install -r requirements.txt

3) Environment Variables
Create a .env in project root:
FLASK_SECRET_KEY=change_me_in_prod
ENV=development
DATABASE_URL=sqlite:///instance/app.db   # or your Postgres URI
ENCRYPTION_KEY=GENERATE_A_RANDOM_FERNET_KEY   # e.g., from cryptography.fernet.Fernet.generate_key()
SESSION_COOKIE_SECURE=False

4) Initialize DB
# if you use Flask-Migrate, otherwise run a small init script
python -c "from app import init_db; init_db()"

5) Run
# typical
python app.py
# or
flask run --host=127.0.0.1 --port=5000

🔒Security Controls (at a glance)
Password hashing with bcrypt; never store plain passwords.
Password policy: min length, digits, upper/lowercase, symbols.
Input validation/sanitization: server-side checks for length, type, allowed chars.
CSRF protection (if using forms; add Flask-WTF).
Session hardening: HTTPOnly cookies; logout destroys session; session expiry.
Error handling: generic user messages; no stack traces to clients.
Audit logs: login success/fail, profile edits, file uploads.
Field-level encryption for sensitive columns (e.g., notes, tokens).
File upload allow-list: images/pdf only; size limit; MIME sniffing.

🔍 API/Routes (examples)
GET / – Landing / login link
GET /register, POST /register – Create user (hash passwords)
GET /login, POST /login – Authenticate; start session
POST /logout – Destroy session
GET /dashboard – Protected page
GET /profile, POST /profile – Update name/email with validation
POST /upload – File upload (allow-listed types only)
GET /health – Health probe (200 OK when alive)
GET /__test/div0 – Dev-only: triggers controlled divide-by-zero response (HTTP 400)
Note: __test/div0 returns 404 in production (guarded in code) so it’s safe to keep in repo for marking.

No.	Test Case	Action Performed	Expected Outcome	Observed Result	Pass/Fail
1	Input Validation – SQL Injection	Entered 'OR 1=1-- in login form	Input rejected / error handled	Error handled properly	✅
2	Password Strength	Tried weak password 12345	Rejected	Warning shown	✅
3	Special Character Input	Added <script> in username	Sanitized / rejected	Escaped output	✅
4	Unauthorized Access	Opened dashboard without login	Redirected to login	Access blocked	✅
5	Session Expiry	Idle for 5 minutes	Auto logout	Session cleared	✅
6	Logout Functionality	Pressed logout	Session destroyed	Redirect to login	✅
7	Data Confidentiality	Opened stored DB file	Passwords hashed	Secure storage	✅
8	File Upload Validation	Tried uploading .exe	File rejected	Correct behavior	✅
9	Error Message Leakage	Entered invalid query	Generic error	No stack trace	✅
10	Input Length Validation	Entered 5000 chars	Validation triggered	Safe handling	✅
11	Duplicate User Registration	Tried existing username	Error displayed	Correct handling	✅
12	Number Field Validation	Entered letters in amount field	Rejected	Validation successful	✅
13	Password Match Check	Mismatched confirm password	Registration blocked	Correct	✅
14	Data Modification Attempt	Changed transaction ID manually	Access denied	Unauthorized change blocked	✅
15	Email Validation	Entered abc@	Error shown	Validation successful	✅
16	Login Attempt Lockout	5 failed logins	Account locked	Lockout triggered	✅
17	Secure Error Handling	Call GET /__test/div0 then GET /health	Controlled message (400), no stack leak; app still alive (200)	Controlled message; no crash; logs internal only	✅
18	Encrypted Record Check	Viewed stored data file	Data unreadable	Encrypted	✅
19	Input Encoding	Used Unicode emoji input	App handled gracefully	No corruption	✅
20	Empty Field Submission	Left fields blank	Warning displayed	Correct behavior	✅

🧪 How to run the #17 test quickly
# error case (controlled)
curl -i http://127.0.0.1:5000/__test/div0
# healthy request (proves no crash)
curl -i http://127.0.0.1:5000/health

🛡 Configuration Notes
Set a strong FLASK_SECRET_KEY in .env.
For production, set:
SESSION_COOKIE_SECURE=True
ENV=production (so __test/div0 is hidden)
Use HTTPS and secure cookie flags via reverse proxy (Nginx/Caddy).
Rotate ENCRYPTION_KEY carefully; re-encrypt stored data if rotating.

🚀 Deploy (quick pointers)
Gunicorn + Nginx for Linux servers
Set environment via systemd or Docker secrets
Enforce HTTPS, HSTS, secure cookies, proper CORS if applicable

