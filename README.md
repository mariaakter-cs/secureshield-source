# SecureShield

**SecureShield** is a lightweight hybrid Web Application Firewall (WAF) developed as a Bachelor of Cyber Security final-year project. It filters HTTP requests using **SQL injection (SQLi) and cross-site scripting (XSS) regex rules**, **TF-IDF + Logistic Regression**, and **behaviour-based brute-force monitoring**.

The project was implemented and evaluated in an isolated, three-VM laboratory using DVWA as the authorised test application.

## Features

- Detects and blocks common SQLi and XSS payloads.
- Adds a machine-learning detection layer for requests not blocked by regex rules.
- Monitors confirmed failed logins and temporarily blocks repeat offenders.
- Forwards permitted requests to DVWA and records security events in SQLite.
- Includes Flask dashboard and PDF-reporting modules.

## Architecture

```text
VM1: Kali Linux (192.168.100.10)
                |
                v
VM2: SecureShield WAF (192.168.100.20)
      Nginx :80 -> Gunicorn :5000 -> Flask
                       |
             Regex + ML + brute-force checks
                  /             \
              Block             Allow
              HTTP 403            |
                                  v
VM3: DVWA (192.168.100.30)
      Apache + PHP + MariaDB
```

The VMs use an isolated VirtualBox network. DVWA is hosted on VM3, and its firewall restricts direct HTTP access from Kali. Gunicorn runs locally on VM2 behind Nginx and is managed by `systemd`.

## Technologies

Python 3.12, Flask, Nginx, Gunicorn, scikit-learn, SQLite, Bootstrap, fpdf2, Kali Linux, Ubuntu Server, Apache, MariaDB, DVWA and Oracle VirtualBox.

## Project structure

```text
secureshield/
├── app/                     # Flask proxy, dashboard, logging and reports
│   ├── __init__.py
│   ├── proxy.py
│   ├── dashboard.py
│   ├── models.py
│   ├── reports.py
│   └── templates/
├── rules/                   # SQLi, XSS and brute-force detection
│   ├── sqli.py
│   ├── xss.py
│   └── bruteforce.py
├── ml/                      # Data preparation, training and prediction
│   ├── prepare_data.py
│   ├── train.py
│   ├── evaluate.py
│   ├── predict.py
│   ├── data/
│   └── model/
├── tests/                   # Test modules and sample attacks
├── docs/                    # Architecture, ethics and project documentation
├── reports/                 # Generated evaluation results
├── compare_detection.py     # Regex vs hybrid comparison (final lab addition)
├── config.py
├── requirements.txt
├── run.py
└── docker-compose.yml       # Earlier optional Docker test setup
```

> The original repository includes a Docker configuration, but the **final evaluated deployment uses three VMs**, with DVWA installed on VM3. The evaluation script and generated results must be committed separately if they are not already present in the repository.

## Setup and running

The following commands prepare the **WAF application on Ubuntu VM2** (Python 3.12+). They assume Nginx, Gunicorn, DVWA on VM3, and VM networking are configured separately.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Set `TARGET_HOST` to the DVWA target (for the evaluated lab: `http://192.168.100.30/DVWA`). Nginx accepts traffic on port 80 and proxies it to Gunicorn listening on `127.0.0.1:5000`.

For a manually started application:

```bash
gunicorn --workers 1 --bind 127.0.0.1:5000 'app:create_app()'
```

On the configured lab deployment, Gunicorn is instead managed by `systemd`:

```bash
sudo systemctl status secureshield
sudo journalctl -u secureshield -f
```

The WAF endpoint for other lab VMs is `http://192.168.100.20/`.

## Evaluation results

| Measurement | Regex-only | Regex + ML |
|---|---:|---:|
| Test samples | 36 | 36 |
| Accuracy | 100% | 100% |
| Precision | 100% | 100% |
| Recall | 100% | 100% |
| F1-score | 100% | 100% |
| False-positive rate | 0% | 0% |

- **Additional ML detections:** 0 on this test set.
- **Legitimate request:** HTTP `200`; **SQLi and XSS test requests:** HTTP `403`.
- **Brute-force control:** five confirmed failed attempts within ten minutes triggered a 30-minute temporary IP block.
- **End-to-end HTTP latency:** 4.36 ms average across 30 successful requests (3.19 ms minimum; 23.83 ms maximum).

These are results from a **small, controlled lab evaluation**. Both detectors produced the same predictions, so the experiment does **not** demonstrate an accuracy improvement from ML. The latency measurement covers the full HTTP request path, not ML inference alone.

To reproduce the offline detector comparison on a prepared VM2 environment with the saved test data and trained model:

```bash
source venv/bin/activate
python compare_detection.py
```

## Configuration and limitations

Configuration is in `config.py`, including the target host, ML model paths and detection thresholds. Brute-force tracking is maintained in memory, so a Gunicorn restart resets its counters. The evaluated deployment uses one Gunicorn worker.

This is an academic prototype, **not a production-ready security gateway**. Do not commit credentials, session cookies, SQLite databases containing sensitive data, virtual-machine images or private logs.

## Ethical use

Testing was performed only against an authorised DVWA instance in an isolated lab. See `docs/ethics_statement.md`.

## Author

Maria Akter — Bachelor of Cyber Security
