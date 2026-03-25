import os
from dotenv import load_dotenv

load_dotenv()

# SIEM Operation Mode
USE_MOCK = True  # Set to False to use real Elasticsearch/Docker

# Elasticsearch settings
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
MODSEC_INDEX = "modsecurity-*"
NORMALIZED_INDEX = "siem-events"

# Telegram settings
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Processing settings
CHECK_INTERVAL = 5  # seconds
BATCH_SIZE = 100

# Severity Levels
class Severity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
