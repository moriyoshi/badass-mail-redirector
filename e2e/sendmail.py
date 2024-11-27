import smtplib
import sys
import time
from email.message import EmailMessage

host = sys.argv[1]
host, _, port_str = host.partition(":")
port = int(port_str) if port_str else 25

def build_message(i: int) -> EmailMessage:
    msg = EmailMessage()
    msg.set_content("hello, world", charset="utf-8", subtype="plain", cte="7bit")
    msg["From"] = "sender@sendmail.example.internal"
    msg["To"] = f"foo+{i}.@badass.example.internal"
    msg["Subject"] = f"test {i}"

    return msg


i = 0
while True:
    print(f"sending email to {host}:{port}")
    with smtplib.SMTP(host, port) as client:
        msg = build_message(i)
        print(msg.as_string(), flush=True)
        client.sendmail(
            msg["From"],
            [msg["To"]],
            msg.as_bytes(), 
        )
    i += 1
    time.sleep(10)