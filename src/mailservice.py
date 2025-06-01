import smtplib, os
from email.mime.text import MIMEText
from dotenv import load_dotenv

def send_email_otp(otp:int, to_email: str):
    '''send email with OTP code using SMTP server'''
    load_dotenv()
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = os.getenv("SMTP_PORT")
    sender_email = os.getenv("SENDER_EMAIL")
    password = os.getenv("SENDER_PASSWORD")
    
    html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding-left: 200px; padding-right: 200px; align-content: center;">
            <div style="background-color: #ffffff; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); text-align: center;">
                <h1 style="color: #333;">Your OTP Code</h1>
                <p style="font-size: 16px;">This is your OTP code for login:</p>
                <p style="font-size: 20px; font-weight: bold; color: #007bff;">{otp}</p>
                <p style="font-size: 14px;">Please do not share this code with anyone. This code is valid for 5 minutes.</p>
                <p style="font-size: 14px;">If you did not request this code, please ignore this email.</p>
                <p style="font-size: 14px;">If you have any questions, please contact support.</p>
                <p style="font-size: 14px;">Thank you for using our service.</p>
                <hr style="border: none; border-top: 1px solid #ccc;">
                <p style="font-size: 12px; color: #777;">This email was sent automatically, please do not reply. This email was sent to </p>
                <div style="text-decoration: underline; font-weight: bold; font-size: 12px;">{to_email}</div>
            </div>
        </body>
        </html>
    """
    
    mail = MIMEText(html, 'html', 'utf-8')
    mail['Subject']='Your OTP Code For Login Online Storage System'
    mail['From']='Online Storage System Bot'
    mail['To']= to_email
    
    smtp = smtplib.SMTP(smtp_server, smtp_port)
    smtp.ehlo()
    smtp.starttls()
    smtp.login(sender_email,password)
    smtp.send_message(mail)
    smtp.quit()

if __name__ == "__main__":
    send_email_otp(123456,"test@gmail.com")