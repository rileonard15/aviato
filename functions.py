import logging
import webapp2, jinja2, os
import datetime
import json as simplejson

from google.appengine.api import urlfetch

from settings import SETTINGS
from settings import SECRET_SETTINGS
jinja_environment = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), autoescape=True)


currenturl = str(os.environ['wsgi.url_scheme'])+"://"+str(os.environ['HTTP_HOST'])+"/"

def send_email(receiver_name=False,receiver_email=False,subject=False,content={},email_type=False):
    if not receiver_email or not receiver_name or not subject or not email_type:
        return False
    template = jinja_environment.get_template('frontend/newsletter.html')
    data = {}
    content['date'] = datetime.datetime.utcnow().strftime('%B %d, %Y %H:%M:%S')
    data['current_url'] = currenturl
    data['email_content'] = content
    data['type'] = email_type
    data['receiver_name'] = receiver_name
    data['receiver_email'] = receiver_email
    receiver = [{"email": receiver_email,"name": receiver_name}]
    send_via_mandrill(receiver, subject, html=template.render(data), plain_text = None, email_type = email_type)
    return True

def send_via_mandrill(receiver, subject, html=None, plain_text = None, email_type = None):
    data = {
    "key": SECRET_SETTINGS["mandrill_key"],
    "message": {
        "html": html,
        "subject": subject,
        "from_email": "company@email.com", #company email
        "from_name": "company name", #company name
        "to": receiver,
        "headers": {
            "Reply-To": "company@email.com" #company email that accepts reply
        },
        "tags": [
            "notifications",
            email_type
        ],
        "important": True,
        "track_opens": True,
        "track_clicks": True,
        "auto_text": True
        },
    "async": False
    }

    logging.debug(urlfetch.fetch(url="https://mandrillapp.com/api/1.0/" + "messages/send.json", method=urlfetch.POST, payload=simplejson.dumps(data)).content)

def send_reset_password_email(user, token):
    content = {}
    content['token'] = str(token)

    email = send_email(receiver_name=user.name,receiver_email=user.email,subject="Password Reset",content=content,email_type="reset_password")

    if email:
        return True
    else:
        return False


def normalize_id(this_id):
    try:
        return int(this_id)
    except:
        return this_id




