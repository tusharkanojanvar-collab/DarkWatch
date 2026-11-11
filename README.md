py# DarkWatch – Student Project Starter

DarkWatch is a local Flask web application with:
- Email breach lookup through the Have I Been Pwned API (requires your own API key).
- Basic defensive website checks: HTTP response, HTTPS redirect, TLS certificate verification, and common security headers.
- SQLite scan history and a dashboard.

## Important limitations
- A website URL check cannot prove that a site has been hacked or is completely safe.
- This starter does not access dark-web marketplaces, perform penetration testing, exploit vulnerabilities, or scan private networks.
- The website checker is a basic passive/low-impact check. Only assess websites you own or have permission to assess.
- Email lookups send the email address to the configured breach-intelligence provider. Get the user's consent first.
- Do not enter real passwords. This project does not collect or store passwords.

## 1. Install tools
1. Install Python 3.11 or newer from https://www.python.org/downloads/
2. Install Visual Studio Code from https://code.visualstudio.com/
3. In VS Code, install the official Python extension (Microsoft).
4. Install Git optionally.

## 2. Open the project
1. Extract the ZIP file.
2. Open VS Code.
3. Select File > Open Folder.
4. Select the extracted `DarkWatch` folder.
5. Open Terminal > New Terminal.

## 3. Create and activate a virtual environment

Windows PowerShell:
```powershell
py -m venv .venv
.venv\\Scripts\\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt terminal:
```cmd
.venv\\Scripts\\activate.bat
```

Or keep using PowerShell without activation:
```powershell
.venv\\Scripts\\python.exe -m pip install -r requirements.txt
.venv\\Scripts\\python.exe app.py
```

## 4. Install dependencies
```powershell
python -m pip install -r requirements.txt
```

## 5. Configure breach API (optional for first run)
1. Obtain an API key from Have I Been Pwned using its official API access process: https://haveibeenpwned.com/API/v3
2. Copy `.env.example` to a new file named `.env`.
3. Put your key after `HIBP_API_KEY=`.
4. Never share `.env`, commit it to Git, or put the key in frontend JavaScript.

The website checker and dashboard work without this key. Email breach lookup displays a setup message until a key is configured.

## 6. Run
```powershell
python app.py
```
Open the local address printed in the terminal, normally http://127.0.0.1:5000

Stop the server with Ctrl+C.

## 7. Suggested demo
- Website checker: test a public website you are authorized to assess.
- Email breach monitor: use an email address only with its owner's consent and after configuring the API key.
- Run multiple checks and observe the dashboard history.

## File structure
```text
DarkWatch/
├── app.py
├── requirements.txt
├── README.md
├── .env.example
├── .gitignore
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── app.js
└── darkwatch.db        # created automatically on first run
```

## Next development milestones
1. Add a real URL reputation provider such as Google Safe Browsing or another licensed threat-intelligence service.
2. Add authentication and role-based access before hosting for multiple users.
3. Add email notifications with rate limits and verified recipients.
4. Add unit tests, logging, input validation, HTTPS deployment, and privacy/retention controls.
5. For a project report, document exactly which APIs and checks are implemented; do not claim dark-web access or confirmed hacking detection unless you have evidence from a reliable source.
