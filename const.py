# Constant definition

# import
import pathlib
from modifier.jlist import JListModifier

# Directory where log files are stored
LOG_DIR = "log"

# Log delimiter If changed on the FortiGate side, follow it Default is half-width space
DELIMITER = " "

# MISP registration settings
# URL of registered MISP
MISP_URL = "https://example.com/"
# set the Authkey of the user you want to register as MISP
MISP_AUTHKEY = "xxx"
# MISP distribution
MISP_DISTRIBUTION = "2"
# MISP threat level
MISP_THREAT_LEVEL_ID = "4"
# MISP analysis
MISP_ANALYSIS = "0"

# email settings
MAIL_FROM = "Fortigate log registration result<{}>".format("info@example.com")
MAIL_TO = None # When to enable "info@example.com"
MAIL_SUBJECT = "Fortigate log registration result notification"
MAIL_SMTP_SERVER = "smtp.example.com"
MAIL_SMTP_USER = "info@example.com"
MAIL_SMTP_PASSWORD = "pass"
ERROR_SUBJECT_PREFIX = "[error]"

# No need to change the following in principle
# store the file name of the last read file
LAST_FILE_NAME = pathlib.Path(__file__).resolve().parent.joinpath("last_file_name")
# Number of retries when an error occurs when importing events
RETRY_MAXIMUM_LIMIT = 5
# Stop processing specified value statements when an error occurs while importing events
COMMAND_INTERVAL_TIME = 10
# A string to supplement the error output that occurs if the event is already registered when importing the event
DUPLICATE_EVENT_CONFIRM_WORD = "Event already exists"

# label with message id
MESSAGE_ID_LABEL = {
    "008192": "AV(Web)",
    "008194": "AV(Mail)",
    "008705": "AV(oversize)",
    "009233": "AV sandbox (analytics)",
    "009238": "AV Sandbox (monitored)",
    "009236": "AV sandbox (blocked)",
    "013056": "Web Filter (Category Block)",
    "020480": "Email Filter (FortiGuard)",
    "016384": "IPS(signature)",
    "018432": "IPS(Anomaly)",
    "016400": "IPS(Botnet IP)",
    "054601": "DNS Filter (Botnet Domain)",
    "054803": "DNS Filter (FortiGuard)"   
}

# modifiers
MODIFIERS = [JListModifier()]

# message id of AV
MESSAGE_ID_AV = ["008192", "008194", "008705", "009233", "009238", "009236", "008212"]

# Below are FortiGate related constants

# Keys to process programmatically without populating attributes
IGNORE_KEYS = ["date", "time", "devname", "devid", "eventtime", "tz", "logid",
               "type", "subtype", "level", "vd", "srcip", "srcport", "dstip", "dstport"]

# Keys entered in event tags instead of attributes
TAG_KEYS = ["devname", "devid", "type", "subtype", "level", "vd", "action"]

# define category and type for each key
KEY_CATEGORY_TYPE = {
    "filehash": ("Payload delivery", "md5"),
    "filename": ("Payload delivery", "filename"),
    "from": ("Network activity", "email-src"),
    "hostname": ("Network activity", "hostname"),
    "mastersrcmac": ("Network activity", "mac-address"),
    "recipient": ("Network activity", "email-dst"),
    "ref": ("External analysis", "url"),
    "referralurl": ("External analysis", "url"),
    "sender": ("Network activity", "email-src"),
    "srcmac": ("Network activity", "mac-address"),
    "to": ("Network activity", "email-dst"),
    "url": ("Network activity", "url"),
    "analyticscksum" : ("Payload delivery", "sha256"),
}

# define category and type for keys without definitions
OTHER_CATEGORY_TYPE = ("Other", "text")

# define categories to be DISABLE_CORRELATION
DISABLE_CORRELATION_CATEGORY = ["External analysis", "Other"]
