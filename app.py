import hashlib
import secrets
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask import render_template
try:
    import pywhatkit as pwk
    PYWHATKIT_AVAILABLE = True
except ImportError:
    PYWHATKIT_AVAILABLE = False
    logging.warning(
        "PyWhatKit is not installed. WhatsApp sending will be simulated. "
        "Install it with: pip install pywhatkit"
    )

app = Flask(__name__)
CORS(app)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

OTP_EXPIRY_SECONDS   = 120   # OTP valid for 2 minutes
MAX_ATTEMPTS         = 5     # Max wrong guesses before lockout
RESEND_COOLDOWN_SEC  = 121   # Must wait 121s before requesting a new OTP
WHATSAPP_SEND_DELAY  = 15    # PyWhatKit schedules messages(seconds)


otp_store: dict[str, dict] = {}



def generate_otp() -> str:

    otp = secrets.randbelow(900_000) + 100_000   # Range: 100000–999999
    return str(otp)


def hash_otp(otp: str) -> str:
   
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def store_otp(phone: str, otp: str) -> None:
 
    otp_store[phone] = {
        "otp_hash":     hash_otp(otp),
        "expires_at":   time.time() + OTP_EXPIRY_SECONDS,
        "attempts":     0,
        "last_sent_at": time.time(),
    }
    logger.info(f"OTP stored for {phone} (expires in {OTP_EXPIRY_SECONDS}s)")


def send_otp_via_whatsapp(phone: str, otp: str) -> bool:
    if not PYWHATKIT_AVAILABLE:
        logger.warning(f"[SIMULATED] OTP {otp} would be sent to +{phone}")
        return True

    message = f"Your OTP is {otp}. It is valid for {OTP_EXPIRY_SECONDS // 60} minutes. Do not share it with anyone."

    try:
        logger.info(f"Sending WhatsApp OTP instantly to +{phone}")

        pwk.sendwhatmsg_instantly(
            phone_no=f"+{phone}",
            message=message,
            wait_time=15,
            tab_close=True,
            close_time=5
        )

        logger.info(f"OTP sent successfully for +{phone}")
        return True

    except Exception as e:
        logger.error(f"Failed to send OTP via WhatsApp to +{phone}: {e}")
        return False

def validate_phone(phone: str) -> bool:
   
    return phone.isdigit() and 7 <= len(phone) <= 15



@app.route("/")
def home():
    return render_template("index.html")
@app.route("/send-otp", methods=["POST"])
def send_otp():

    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).strip()
    if len(phone) == 10:
        phone = "91" + phone


    record = otp_store.get(phone)

    if record and time.time() < record["expires_at"]:
        return jsonify({
            "status": "error",
            "message": "OTP already sent. Please wait."
        }), 400

    # --- Input validation ---
    if not phone:
        return jsonify({"status": "error", "message": "Phone number is required."}), 400
    if not validate_phone(phone):
        return jsonify({"status": "error", "message": "Invalid phone number format. Use international format without '+', digits only."}), 400

    # --- Generate and store OTP ---
    otp = generate_otp()
    store_otp(phone, otp)

    # --- Send via WhatsApp ---
    sent = send_otp_via_whatsapp(phone, otp)
    if not sent:
        # Clean up stored OTP if delivery failed
        otp_store.pop(phone, None)
        return jsonify({
            "status":  "error",
            "message": "Failed to send OTP via WhatsApp. Ensure WhatsApp Web is logged in and try again."
        }), 500

    logger.info(f"OTP send request successful for +{phone}")
    return jsonify({
        "status":  "success",
        "message": f"OTP sent to WhatsApp number +{phone}. Valid for {OTP_EXPIRY_SECONDS // 60} minutes.",
        "note":    "Message is scheduled ~1 minute ahead due to PyWhatKit's design."
    }), 200


@app.route("/verify-otp", methods=["POST"])
def verify_otp():

    data  = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).strip()

    if len(phone) == 10:
        phone = "91" + phone

    otp   = str(data.get("otp",   "")).strip()

    # --- Input validation ---
    if not phone or not otp:
        return jsonify({"status": "error", "message": "Both 'phone' and 'otp' fields are required."}), 400
    if not validate_phone(phone):
        return jsonify({"status": "error", "message": "Invalid phone number format."}), 400
    if not otp.isdigit() or len(otp) != 6:
        return jsonify({"status": "error", "message": "OTP must be exactly 6 digits."}), 400

    # --- Check if OTP exists for this phone ---
    record = otp_store.get(phone)
    print("DEBUG phone:", phone)
    print("DEBUG store:", otp_store)
    if not record:
        return jsonify({"status": "error", "message": "No OTP found for this number. Please request a new OTP."}), 404

    # --- Check attempt limit ---
    if record["attempts"] >= MAX_ATTEMPTS:
        otp_store.pop(phone, None)   # Invalidate after too many attempts
        logger.warning(f"Too many OTP attempts for +{phone}. Record cleared.")
        return jsonify({"status": "error", "message": "Too many incorrect attempts. Please request a new OTP."}), 429

    # --- Check expiry ---
    if time.time() > record["expires_at"]:
        otp_store.pop(phone, None)   # Remove expired OTP
        logger.info(f"OTP expired for +{phone}")
        return jsonify({"status": "error", "message": "OTP has expired. Please request a new OTP."}), 410

    # --- Verify OTP hash ---
    submitted_hash = hash_otp(otp)
    if submitted_hash != record["otp_hash"]:
        record["attempts"] += 1
        remaining = MAX_ATTEMPTS - record["attempts"]
        logger.info(f"Invalid OTP for +{phone}. Attempts remaining: {remaining}")
        return jsonify({
            "status":    "error",
            "message":   "Invalid OTP.",
            "attempts_remaining": remaining
        }), 401

    # --- Success: OTP is correct ---
    otp_store.pop(phone, None)   # Invalidate OTP after successful use
    logger.info(f"OTP verified successfully for +{phone}")
    return jsonify({
        "status":  "success",
        "message": "OTP verified successfully. Phone number authenticated."
    }), 200


@app.route("/resend-otp", methods=["POST"])
def resend_otp():

    data  = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).strip()

    if len(phone) == 10:
        phone = "91" + phone


    # --- Input validation ---
    if not phone:
        return jsonify({"status": "error", "message": "Phone number is required."}), 400
    if not validate_phone(phone):
        return jsonify({"status": "error", "message": "Invalid phone number format."}), 400

    # --- Check resend cooldown ---
    record = otp_store.get(phone)
    if record:
        elapsed = time.time() - record["last_sent_at"]
        if elapsed < RESEND_COOLDOWN_SEC:
            wait = int(RESEND_COOLDOWN_SEC - elapsed)
            logger.info(f"Resend cooldown active for +{phone}. Wait {wait}s.")
            return jsonify({
                "status":  "error",
                "message": f"Please wait {wait} second(s) before requesting a new OTP."
            }), 429

    # --- Generate new OTP (old one is overwritten / invalidated) ---
    otp = generate_otp()
    store_otp(phone, otp)  # Always overwrite the old OTP

    # --- Resend via WhatsApp ---
    print("OTP:", otp)
    sent = send_otp_via_whatsapp(phone, otp)
    if not sent:
        otp_store.pop(phone, None)
        return jsonify({
            "status":  "error",
            "message": "Failed to resend OTP via WhatsApp. Ensure WhatsApp Web is logged in and try again."
        }), 500

    logger.info(f"OTP resent successfully for +{phone}")
    return jsonify({
        "status":  "success",
        "message": f"New OTP sent to WhatsApp number +{phone}. Valid for {OTP_EXPIRY_SECONDS // 60} minutes.",
        "note":    "Old OTP has been invalidated."
    }), 200



@app.route("/health", methods=["GET"])
def health_check():
    """Simple liveness probe to confirm the server is running."""
    return jsonify({
        "status":              "ok",
        "pywhatkit_available": PYWHATKIT_AVAILABLE,
        "active_otp_sessions": len(otp_store),
    }), 200



if __name__ == "__main__":
    print("=" * 65)
    print("  OTP Auth Server — Flask + PyWhatKit")
    print("=" * 65)
    print(f"  OTP Expiry       : {OTP_EXPIRY_SECONDS}s ({OTP_EXPIRY_SECONDS // 60} min)")
    print(f"  Max Attempts     : {MAX_ATTEMPTS}")
    print(f"  Resend Cooldown  : {RESEND_COOLDOWN_SEC}s")
    print(f"  PyWhatKit Ready  : {PYWHATKIT_AVAILABLE}")
    print()
    print("  REMINDER: WhatsApp Web must be logged in on your browser!")
    print("=" * 65)
    print()

    # debug=False for cleaner output; use debug=True during local development
    app.run(host="0.0.0.0", port=5000, debug=False)