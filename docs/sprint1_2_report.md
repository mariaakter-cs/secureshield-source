# Sprint 1 & 2 Report — Project Setup and Environment

**Sprint 1 dates:** 27 July – 02 August 2026  
**Sprint 2 dates:** 03 August – 09 August 2026  
**Objectives:**
- Sprint 1: Finalise proposal, complete ethics statement, obtain approval, set up repository.
- Sprint 2: Install Docker, deploy DVWA, install all libraries, verify everything works.

I'm combining these into one report since they're both setup work with no code to show — just infrastructure and admin.

---

## Sprint 1 — What I did

### Project proposal and charter

Wrote and submitted both documents:
- `SecureShield_Project_Proposal.md` — follows the 4Ps/5Ws structure required by the module
- `SecureShield_Project_Charter.md` — sprint schedule with dates, milestones, objectives, roles, risks, budget

Both are in the parent directory outside the code repo since they're submission documents rather than code artefacts.

### Ethics statement

Created `docs/ethics_statement.md` which declares:
- I will only test against DVWA on localhost or a supervisor-approved environment
- No real data, no unauthorised testing, no exploitation beyond detection validation
- The proxy target is hard-coded to prevent accidental out-of-scope testing

This needs to be printed and signed by both me and my supervisor before any testing starts.

### Git repository

Initialised the repo with a proper structure:
- `app/` — Flask application (proxy, dashboard, database)
- `rules/` — detection rule modules (SQLi, XSS, brute-force)
- `ml/` — machine learning training and prediction
- `tests/` — test suite with payload files
- `docs/` — ethics statement, architecture notes, sprint reports
- `reports/` — where generated PDF reports will go

Added a `.gitignore` covering Python bytecode, virtual environment, database files, model files, generated reports, IDE files, and OS junk.

### Remote repository

Set up on GitHub at `git@github.com:mariaakter-cs/secureshield.git` so my supervisor can review progress if needed.

---

## Sprint 2 — What I did

### Docker and DVWA

Installed Docker Desktop (already had it) and created a `docker-compose.yml` that starts DVWA:

```yaml
services:
  dvwa:
    image: vulnerables/web-dvwa
    container_name: secureshield-dvwa
    platform: linux/amd64
    ports:
      - "8080:80"
```

The `platform: linux/amd64` flag is needed because my MacBook is Apple Silicon (ARM64) and the DVWA image is only built for x86. Docker's Rosetta emulation handles it — there's a warning but it works fine.

After starting it, I went to `http://localhost:8080`, logged in with `admin/password`, clicked "Create / Reset Database", and confirmed everything loads correctly.

### Python environment

Created a virtual environment and installed all required libraries:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Verified all imports work:
- Flask 3.0.3
- requests 2.32.3
- scikit-learn 1.5.1
- fpdf2 2.8.1
- SQLite 3.45.1 (built into Python)

### Configuration

Set up `config.py` with all the settings I'll need throughout the project:
- Target host (hard-coded to localhost:8080)
- Flask port (5000)
- Brute-force thresholds (5 attempts, 10-minute window, 30-minute cooldown)
- ML confidence threshold (0.7)
- Database path

Everything is configurable in one place so I can tweak thresholds during testing without hunting through the code.

### Skeleton files

Created placeholder files for every module so the project structure is clear from the start. Each file has a docstring explaining what it will do and which sprint it belongs to. This means I always know what's next without having to look at the charter.

---

## Problems encountered

**DVWA platform warning:** Got a warning that the image is `linux/amd64` but my machine is `linux/arm64/v8`. Adding `platform: linux/amd64` to the compose file explicitly acknowledges this and Docker runs it via emulation. Performance is fine for a test target.

**First DVWA image (cytopia/dvwa):** I initially tried a different DVWA image that needed an external MySQL database. It kept crashing with `MYSQL_HOSTNAME env variable is not set`. Switched to `vulnerables/web-dvwa` which has MySQL built in. Lesson: read the image requirements before choosing one.

---

## Sprint 1 & 2 milestone status

**M1: Project approved; ethics statement completed; authorised scope confirmed.** ✓ Complete (pending supervisor signature on the printed ethics statement).

**M2: Development environment fully operational; DVWA accessible via Docker.** ✓ Complete.
