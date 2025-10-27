# import all libraries
from flask import Flask, request, jsonify
import threading
from urllib.parse import urlparse
from scipy.stats import entropy
from collections import Counter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import mysql_utils

app = Flask(__name__)

limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])  # applies 5 requests/min per IP

# Mocked domain reputation dictionary
# This can be replaced by MySQL database table in production environment because very likely this list isn't small.
DOMAIN_REPUTATION = {
    "trusted.com": "good",
    "example.com": "medium",
    "fishing.lol123": "bad"
}

# hardcoded api key / can be fetched from mysql db or sqlite db
preassigned_api_key = "mysecretkey@123456"

# Validate/Sanitize the incoming data
def validate_input(data):
    required_data = ['sender', 'subject', 'timestamp', 'links']
    for key in required_data:
        if key not in data:
            return False, f"Missing field: {key}"

    sender = str(data['sender']).strip()
    subject = str(data['subject']).strip()
    timestamp = str(data['timestamp']).strip()
    links = data.get('links') or []

    # checks for '@' symbol and dot(.) in domain name
    if '@' not in sender or '.' not in sender.split('@')[-1]:
        return False, "Invalid sender email format"

    # checks http and https in URLs
    for link in links:
        if link and not (link.startswith("http://") or link.startswith("https://")):
            return False, f"Invalid URL: {link}"

    return True, {"sender": sender, "subject": subject, "timestamp": timestamp, "links": links}

# Calculate Shannon entropy of a string using SciPy
def calc_entropy(link_string):
    if not link_string:
        return 0
    counts = Counter(link_string) # Count recurrence of each character in the URL
    
    # finding probability of each character
    probs = []
    for c in counts.values():
        probs.append(c / len(link_string))
    return entropy(probs, base=2) # calculate entropy and return it

# Process an email after ingestion
def process_email(email_identifier, sender, links):
    email_id_domain = sender.split('@')[-1].lower() # extract the email id domain name
    rep = DOMAIN_REPUTATION.get(email_id_domain, "unknown_rep")
    spoofed = (rep == "bad") or any(email_id_domain not in urlparse(l).netloc for l in links if l)   # Check if any link's domain name does not match the sender's domain name i.e. it will be triggered by any mismatch + if bad reputation, automatically it is False
    entropy_val = max((calc_entropy(l) for l in links if l), default=0)            # Calculate entropy for each link and take the maximum value
    #mysql_utils.insert_signal(email_identifier, rep, entropy_val, spoofed)
    print("SQL SUCCESSFUL") # print line (1) to check sql / delete in prod
    print(f"[+] Processed email {email_identifier} ({sender}) rep={rep}, entropy={entropy_val:.3f}, spoofed={spoofed}") # entropy value is rounded off 3 digits after decimal

# Flask API endpoint for ingesting emails
@app.route('/ingest', methods=['POST'])
@limiter.limit("5 per minute")
def ingest():
    email_identifier = None # early init to avoid bug: cannot access local variable 'email_identifier' where it is not associated with a value
    try:
        # check api key
        key = request.headers.get("X-API-Key")
        if key != preassigned_api_key:
            return jsonify({'error': 'Unauthorized'}), 401

        # check Content-Type
        if request.content_type != "application/json":
            return jsonify({"error": "Content-Type must be application/json"}), 400

        data = request.get_json()
        valid, result = validate_input(data)
        if not valid:
            return jsonify({'error': result}), 400
        #email_identifier = mysql_utils.insert_email_data(result['sender'], result['subject'], result['timestamp'], ','.join(result['links']))
        threading.Thread(target=process_email, args=(email_identifier, result['sender'], result['links'])).start()  #Async flow of task

        # print lines (2) to check sql / delete in prod
        email_identifier = 1
        print("SQL SUCCESSFUL")

        return jsonify({'message': 'Email ingested', 'email_identifier': email_identifier}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

# repo: https://github.com/dasabhijeet/Signal-Transfer-Pipeline
