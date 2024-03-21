import sendgrid
from sendgrid.helpers.mail import Mail
import email_config

def send_booking_confirmation(user_email, booking_details):
    sg = sendgrid.SendGridAPIClient(email_config.API_KEY)

    message = Mail(
        from_email='your@example.com',
        to_emails=user_email,
        subject='Booking Confirmation',
        html_content=booking_details
    )

    response = sg.send(message)
