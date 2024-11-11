import smtplib
from email.mime.text import MIMEText

sender_email = "vishnutest33@gmail.com"
receiver_email = "vishnu@appinessworld.com"
password = "ijef sioq tihe atvx"

subject = "Test Email"
body = "This is a test email."

msg = MIMEText(body)
msg['Subject'] = subject
msg['From'] = sender_email
msg['To'] = receiver_email

try:
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(sender_email, password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()
    print("Email sent successfully")
except Exception as e:
    print(f"Error: {e}")
