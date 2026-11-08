# SecureShield

A lightweight WAF (Web Application Firewall) that sits between the user and a web app, checking incoming requests for SQL Injection, XSS, and brute-force login attempts before letting them through.

Built as my final-year project for Bachelor of Cyber Security.

## What this does

SecureShield runs as a reverse proxy on port 5000. When a request comes in, it checks:

1. Does the request match any SQLi or XSS patterns? (regex rules)
2. Has this IP failed too many logins recently? (brute-force check)
3. Does the ML model flag it as suspicious? (TF-IDF + Logistic Regression)

If any check fires, the request gets blocked and logged. Otherwise it passes through to the real application (DVWA on port 8080) normally.

Everything gets logged to SQLite, and there's a dashboard to view what happened.

## What I'm using

- **Python 3 / Flask** for the proxy and the dashboard
- **Regular expressions** for the SQLi and XSS rules
- **scikit-learn** for the ML classifier (TF-IDF features, Logistic Regression model)
- **SQLite** for logging all security events
- **fpdf2** for generating PDF reports
- **Bootstrap 5** for the dashboard front-end
- **Docker + DVWA** as the test target

## Project layout

```text
secureshield/
├── app/
│   ├── __init__.py        # sets up the Flask app
│   ├── proxy.py           # the main proxy that forwards/blocks requests
│   ├── dashboard.py       # admin dashboard (stats, logs, blocklist)
│   ├── models.py          # database stuff
│   └── templates/         # HTML templates
├── rules/
│   ├── sqli.py            # SQL injection detection patterns
│   ├── xss.py             # XSS detection patterns
│   └── bruteforce.py      # tracks failed logins per IP
├── ml/
│   ├── train.py           # trains the classifier
│   ├── predict.py         # loads the model and classifies requests
│   ├── model/             # where the trained model gets saved
│   └── data/              # training data (labelled payloads)
├── tests/
│   ├── payloads/          # test attack strings
│   ├── test_proxy.py
│   ├── test_rules.py
│   └── test_ml.py
├── reports/               # generated PDF reports go here
├── docs/
│   ├── ethics_statement.md
│   └── architecture.md
├── config.py              # all the settings in one place
├── requirements.txt
├── docker-compose.yml     # starts DVWA
├── run.py                 # entry point
└── .gitignore
```

## Getting it running

You need Python 3.12+, Docker, and pip.

```bash
# set up
git clone <your-repo-url>
cd secureshield
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# start the test target
docker-compose up -d

# first time only: go to http://localhost:8080, login admin/password,
# click "Create / Reset Database", then log in again

# run secureshield
python run.py

# now browse http://localhost:5000 — that goes through the WAF
```

## Settings

Main settings live in `config.py`. The important ones:

- `TARGET_HOST` — where to forward traffic (defaults to `http://localhost:8080`)
- `BRUTE_FORCE_THRESHOLD` — how many failed logins before an IP gets blocked (default 5)
- `BRUTE_FORCE_WINDOW` — time window for counting attempts (default 10 minutes)
- `ML_CONFIDENCE_THRESHOLD` — how confident the ML model needs to be before blocking (default 0.7)

## Testing rules

I only test this against DVWA running locally on my own machine, or whatever my supervisor has approved in writing. No real data, no testing against anything I haven't been given permission for. Full details in `docs/ethics_statement.md`.

## Running the tests

```bash
source venv/bin/activate
docker-compose up -d        # DVWA needs to be running
python run.py &             # start the proxy in background
pytest tests/ -v            # run the test suite
```

## Author

Maria Akter
