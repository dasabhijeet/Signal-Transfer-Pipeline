# import libraries
import mysql.connector

# this approach ensures we can add regional databases (if any) and call them in code as needed. Config files can be maintained as well in /home directory.
db_config = {
    'host': 'mysql_db_ip_or_domain_name',
    'user': 'admin',
    'password': 'password',  # change as needed
    'database': 'signalsdb'
}

# insert email data as received, only after proper validation
def insert_email_data(sender, subject, timestamp, links):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO email_data (sender, subject, timestamp, links) VALUES (%s, %s, %s, %s)", (sender, subject, timestamp, links))
    conn.commit()
    email_identifier = cursor.lastrowid # fetch auto-increment id
    cursor.close()
    conn.close()
    return email_identifier

# store processed signals into a separate signals table
def insert_signal(email_identifier, domain_reputation, url_entropy, sender_spoofed_status):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO signals (email_identifier_id, domain_reputation, url_entropy, sender_spoofed_status) VALUES (%s, %s, %s, %s)", (email_identifier, domain_reputation, url_entropy, int(sender_spoofed_status)))
    conn.commit()
    cursor.close()
    conn.close()

# ideas implemented:
# spoofed is taken in as int values i.e. True = 1, False = 0
# each table has its own primary key