"""
config.py - All settings for SecureShield in one place.

I've kept everything configurable here so it's easy to tweak
thresholds during testing without hunting through the code.
"""

import os

# Where to forward traffic.
# This is hard-coded to DVWA on localhost — do NOT point this at
# anything that hasn't been explicitly approved for testing.
TARGET_HOST = os.environ.get("TARGET_HOST", "http://192.168.100.30/DVWA")

# Flask
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
SECRET_KEY = os.environ.get("SECRET_KEY", "secureshield-dev-key")

# Database
DATABASE_PATH = os.path.join(os.path.dirname(__file__), "secureshield.db")

# Brute-force settings
BRUTE_FORCE_THRESHOLD = 5      # failed attempts before we block
BRUTE_FORCE_WINDOW = 600       # count attempts within this many seconds (10 min)
BRUTE_FORCE_COOLDOWN = 1800    # how long the block lasts (30 min)

# ML model
ML_MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml", "model", "classifier.pkl")
ML_VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "ml", "model", "vectorizer.pkl")
ML_CONFIDENCE_THRESHOLD = 0.7  # only block if model is this confident

LOG_LEVEL = "INFO"
