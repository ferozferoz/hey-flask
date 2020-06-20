from . import mail
from flask_mail import Message
from flask import current_app , render_template


def send_email(to, subject, template, **kwargs):
    msg = Message(current_app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,
    sender=current_app.config['FLASKY_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template , **kwargs)
    msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)