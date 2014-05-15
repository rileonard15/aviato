import webapp2, jinja2, os
from webapp2_extras import routes
from models import User, PasswordResetToken, Developer, Property
from functions import *
import json as simplejson
import logging
import urllib
import time
import uuid
import datetime
import hashlib
import base64
import facebook
from google.appengine.api import files, images
from google.appengine.ext import blobstore, deferred
from google.appengine.ext.webapp import blobstore_handlers
import json
import re

from google.appengine.api import urlfetch
from google.appengine.ext import ndb
from settings import SETTINGS
from settings import SECRET_SETTINGS
from settings import PROPERTY_AMENITIES

jinja_environment = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), autoescape=True)


def login_required(fn):
    '''So we can decorate any RequestHandler with #@login_required'''
    def wrapper(self, *args):
        if not self.user:
            self.redirect(self.uri_for('www-login', referred=self.request.path))
        else:
            return fn(self, *args)
    return wrapper


def admin_required(fn):
    '''So we can decorate any RequestHandler with @admin_required'''
    def wrapper(self, *args):
        if not self.user:
            self.redirect(self.uri_for('www-login'))
        elif self.user.status == "ADMIN":
            return fn(self, *args)
        else:
            self.redirect(self.uri_for('www-front'))
    return wrapper


def hash_password(email, password):
    i = email + password + SECRET_SETTINGS["password_salt"]
    return base64.b64encode(hashlib.sha1(i).digest())


def cleanup(blob_keys):
    blobstore.delete(blob_keys)


WEBSITE = 'http://blueimp.github.io/jQuery-File-Upload/'
MIN_FILE_SIZE = 1  # bytes
MAX_FILE_SIZE = 5000000  # bytes
IMAGE_TYPES = re.compile('image/(gif|p?jpeg|(x-)?png)')
ACCEPT_FILE_TYPES = IMAGE_TYPES
THUMBNAIL_MODIFICATOR = '=s80'  # max width / height
EXPIRATION_TIME = 300  # seconds




"""Request Handlers Start Here"""



class BaseHandler(webapp2.RequestHandler):
    def __init__(self, request=None, response=None):
        self.now = datetime.datetime.now()
        self.tv = {}
        self.settings = SETTINGS.copy()
        self.initialize(request, response)
        self.has_pass = False
        self.tv["version"] = os.environ['CURRENT_VERSION_ID']
        self.local = False
        if "127.0.0.1" in self.request.uri or "localhost" in self.request.uri:
            self.local = True
        # misc
        self.tv["current_url"] = self.request.uri
        self.tv["fb_login_url"] = facebook.generate_login_url(self.request.path, self.uri_for('www-fblogin'))

        if "?" in self.request.uri:
            self.tv["current_base_url"] = self.request.uri[0:(self.request.uri.find('?'))]
        else:
            self.tv["current_base_url"] = self.request.uri

        try:
            self.tv["safe_current_base_url"] = urllib.quote(self.tv["current_base_url"])
        except:
            logging.exception("safe url error")

        self.tv["request_method"] = self.request.method

        self.session = self.get_session()
        self.user = self.get_current_user()


    def render(self, template_path=None, force=False):
        self.tv["current_timestamp"] = time.mktime(self.now.timetuple())
        self.settings["current_year"] = self.now.year
        self.tv["settings"] = self.settings

        if self.request.get('error'):
            self.tv["error"] = self.request.get("error").strip()
        if self.request.get('success'):
            self.tv["success"] = self.request.get("success").strip()
        if self.request.get('warning'):
            self.tv["warning"] = self.request.get("warning").strip()

        if self.user:
            self.tv["user"] = self.user.to_object()

        if self.request.get('json') or not template_path:
            self.response.out.write(simplejson.dumps(self.tv))
            return

        template = jinja_environment.get_template(template_path)
        self.response.out.write(template.render(self.tv))
        logging.debug(self.tv)


    def get_session(self):
        from gaesessions import get_current_session
        return get_current_session()


    def get_current_user(self):
        if self.session.has_key("user"):
            user = User.get_by_id(self.session["user"])
            return user
        else:
            return None


    def login(self, user):
        self.session["user"] = user.key.id()
        return

    def login_fb(self, fb_content, access_token):
        self.logout()
        user = User.query(User.fb_id == fb_content["id"]).get()
        if not user:
            email = fb_content["email"]
            if email:
                user = User.query(User.email == email).get()

            if user:
                # Merge User

                user.fb_id = fb_content["id"]
                try:
                    user.fb_username = fb_content["username"]
                except:
                    logging.exception("no username?")
                user.first_name = fb_content["first_name"]
                try:
                    user.last_name = fb_content["last_name"]
                except:
                    logging.exception("no last_name?")
                try:
                    user.middle_name = fb_content["middle_name"]
                except:
                    logging.exception('no middle name?')

                user.name = user.first_name
                if user.middle_name:
                    user.name += " " + user.middle_name

                if user.last_name:
                    user.name += " " + user.last_name

                try:
                    user.fb_access_token = access_token
                except:
                    logging.exception('no access token')
            else:
                user = User()
                user.fb_id = fb_content["id"]
                try:
                    user.fb_username = fb_content["username"]
                except:
                    logging.exception("no username?")
                user.email = fb_content["email"]
                user.first_name = fb_content["first_name"]
                try:
                    user.last_name = fb_content["last_name"]
                except:
                    logging.exception("no last_name?")
                try:
                    user.middle_name = fb_content["middle_name"]
                except:
                    logging.exception('no middle name?')

                user.name = user.first_name
                if user.middle_name:
                    user.name += " " + user.middle_name

                if user.last_name:
                    user.name += " " + user.last_name

                try:
                    user.fb_access_token = access_token
                except:
                    logging.exception('no access token')

            user.put()
        self.login(user)
        return


    def logout(self):
        if self.session.is_active():
            self.session.terminate()
            return


    def iptolocation(self):
        country = self.request.headers.get('X-AppEngine-Country')
        logging.info("COUNTRY: " + str(country))
        if country == "GB":
            country = "UK"
        if country == "ZZ":
            country = ""
        if country is None:
            country = ""
        return country



class FrontPage(BaseHandler):
    def get(self):
        if self.user:
            self.redirect(self.uri_for('www-dashboard'))
            return

        self.tv["current_page"] = "FRONT"
        self.render('frontend/frontpage.html')


# class RegisterPage(BaseHandler):
#     def get(self):
#         if self.user:
#             self.redirect(self.uri_for('www-dashboard', referred="register"))
#             return

#         self.tv["current_page"] = "REGISTER"
#         self.render('frontend/register.html')


#     def post(self):
#         if self.user:
#             self.redirect(self.uri_for('www-dashboard'))
#             return

#         if self.request.get('email') and self.request.get('password') and self.request.get('name'):
#             email = self.request.get('email').strip().lower()
#             name = self.request.get('name').strip()
#             password = self.request.get('password')
#             user = User.get_by_id(email)
#             if user:
#                 self.redirect(self.uri_for('www-login', error = "User already exists. Please log in."))
#                 return
#             user = User(id=email)
#             user.password = hash_password(email, password)
#             user.email = email
#             user.name = name
#             user.put()
#             self.login(user)
#             if self.request.get('goto'):
#                 self.redirect(self.request.get('goto'))
#             else:
#                 self.redirect(self.uri_for('www-dashboard'))
#             return
#         else:
#             self.redirect(self.uri_for('www-register', error = "Please enter all the information required."))


class Logout(BaseHandler):
    def get(self):
        if self.user:
            self.logout()
        self.redirect(self.uri_for('www-login', referred="logout"))


class LoginPage(BaseHandler):
    def get(self):
        if self.user:
            self.redirect(self.uri_for('www-dashboard', referred="login"))
            return

        if self.request.get('email'):
            self.tv["email"] = self.request.get("email").strip()

        self.tv["current_page"] = "LOGIN"
        self.render('frontend/login.html')


    def post(self):
        if self.user:
            self.redirect(self.uri_for('www-dashboard'))
            return

        if self.request.get('email') and self.request.get('password'):
            email = self.request.get('email').strip().lower()
            password = self.request.get('password')

            if email == "admin@aviatorealty.com" and password == "aviatoRealty!@#":
                user = User.get_by_id(self.request.get("email"))
                if not user:
                    user = User(id=self.request.get("email"))
                    user.email = email
                    user.password = hash_password(email, password)
                    user.name = "Super Admin"
                    user.first_name = "Super"
                    user.last_name = "Admin"
                    user.status = "ADMIN"

                    user.put()
                    self.login(user)

                    if self.request.get('goto'):
                        self.redirect(self.request.get('goto'))
                    else:
                        self.redirect(self.uri_for('www-dashboard'))

                    return

            user = User.get_by_id(email)
            if not user:
                self.redirect(self.uri_for('www-login', error="User not found. Please try another email or register."))
                return

            if user.password == hash_password(email, password):
                self.login(user)
                if self.request.get('goto'):
                    self.redirect(self.request.get('goto'))
                else:
                    self.redirect(self.uri_for('www-dashboard'))
                return
            else:
                self.redirect(self.uri_for('www-login', error="Wrong password. Please try again.", email=email))
                return
        else:
            self.redirect(self.uri_for('www-login', error="Please enter your email and password."))


class FBLoginPage(BaseHandler):
    def get(self):
        if not self.settings["enable_fb_login"]:
            self.redirect(self.uri_for("www-login"))
            return

        if self.user:
            self.redirect(self.uri_for('www-dashboard', referred="fblogin"))
            return

        if self.request.get('code') and self.request.get('state'):
            state = self.request.get('state')
            code = self.request.get('code')
            access_token = facebook.code_to_access_token(code, self.uri_for('www-fblogin'))
            if not access_token:
                # Assume expiration, just redirect to login page
                self.redirect(self.uri_for('www-login', referred="fblogin", error="We were not able to connect with Facebook. Please try again."))
                return

            url = "https://graph.facebook.com/me?access_token=" + access_token

            result = urlfetch.fetch(url)
            if result.status_code == 200:
                self.login_fb(simplejson.loads(result.content), access_token)
                self.redirect(str(state))
                return

        else:
            self.redirect(facebook.generate_login_url(self.request.get('goto'), self.uri_for('www-fblogin')))


class DashboardPage(BaseHandler):
    @login_required
    def get(self):

        properties = Property.query().fetch()
        self.tv["properties"] = []
        for this_property in properties:
            self.tv["properties"].append(this_property.to_object())

        self.tv["current_page"] = "DASHBOARD"
        self.render('frontend/dashboard.html')


class ForgotPassHandler(BaseHandler):
    def get(self):
        self.tv["current_page"] = "FORGOT PASSWORD"
        self.render('frontend/forgot-pass.html')

    def post(self):
        if self.request.get('email'):
            self.tv["user"] = User.query(User.email == self.request.get("email")).get()
            if self.tv["user"]:
                token = str(uuid.uuid4())
                reset_token = PasswordResetToken(id = token)
                reset_token.email = self.tv["user"].email
                reset_token.token = token
                reset_token.expires = datetime.datetime.now() + datetime.timedelta(hours = 1)
                reset_token.put()

                send_reset_password_email(self.tv["user"], token)
                self.redirect('/forgot-pass?success='+ urllib.quote('Details about how to reset your password have been sent to you by email.'))
            else:
                self.redirect('/forgot-pass?error='+ urllib.quote('Invalid Email.'))
            return


class PasswordReset(BaseHandler):
    def get(self):
        if self.request.get("token"):
            r = PasswordResetToken.get_by_id(self.request.get("token"))

            if r:
                user = User.get_by_id(r.email)
                self.tv["current_user"] = user.to_object()
                self.tv["token"] = self.request.get("token")
                self.render("frontend/reset-password.html")
            else:
                self.redirect('/password/reset?error='+ urllib.quote('Invalid Token.'))
        else:
            self.render("frontend/reset-password.html")

    def post(self):
        if self.request.get("password_original") == self.request.get("password_retype"):
            if self.request.get("email"):
                user = User.get_by_id(self.request.get("email"))
                user.password = hash_password(self.request.get("email"), self.request.get("password_original"))
                user.put()
                self.login(user)

                r = PasswordResetToken.get_by_id(self.request.get("token"))
                r.key.delete()

                self.redirect(self.uri_for('www-dashboard'))
        else:
            self.redirect('/password/reset?error='+ urllib.quote('Password does not match!.'))
            return


class ListsHandler(BaseHandler):
    @admin_required
    def get(self):
        self.tv["current_page"] = "CREATE LIST"

        self.tv["amenities"] = PROPERTY_AMENITIES
        developers = Developer.query().fetch(100)

        self.tv["developers"] = []
        for developer in developers:
            self.tv["developers"].append(developer.to_object())

        self.render("frontend/createlists.html")

    @admin_required
    def post(self):
        newproperty = Property()
        newproperty.title = self.request.get("title").strip()
        newproperty.description = self.request.get("description").strip()
        newproperty.location = self.request.get("location").strip()
        newproperty.sqft = self.request.get("size").strip()
        newproperty.price = self.request.get("price").strip()
        newproperty.kind = self.request.get("type").strip()

        developer_key = ndb.Key("Developer", normalize_id(self.request.get("developer").strip()))
        newproperty.developer = developer_key

        amenities = PROPERTY_AMENITIES.copy()
        new_amenities = PROPERTY_AMENITIES.copy()

        for key, value in amenities.items():
            if self.request.get("amenities_"+key).strip():
                new_val = self.request.get("amenities_"+key).strip()
            else:
                new_val = 0

            new_amenities[key] = new_val

        newproperty.amenities = new_amenities

        newproperty.put()

        self.redirect("/upload/"+ str(newproperty.key.id()))


""" Upload photo's """
class UploadHandler(BaseHandler):

    def initialize(self, request, response):
        super(UploadHandler, self).initialize(request, response)
        self.response.headers['Access-Control-Allow-Origin'] = '*'
        self.response.headers[
            'Access-Control-Allow-Methods'
        ] = 'OPTIONS, HEAD, GET, POST, PUT, DELETE'
        self.response.headers[
            'Access-Control-Allow-Headers'
        ] = 'Content-Type, Content-Range, Content-Disposition'

    def validate(self, file):
        if file['size'] < MIN_FILE_SIZE:
            file['error'] = 'File is too small'
        elif file['size'] > MAX_FILE_SIZE:
            file['error'] = 'File is too big'
        elif not ACCEPT_FILE_TYPES.match(file['type']):
            file['error'] = 'Filetype not allowed'
        else:
            return True
        return False

    def get_file_size(self, file):
        file.seek(0, 2)  # Seek to the end of the file
        size = file.tell()  # Get the position of EOF
        file.seek(0)  # Reset the file position to the beginning
        return size

    def write_blob(self, data, info):
        blob = files.blobstore.create(
            mime_type=info['type'],
            _blobinfo_uploaded_filename=info['name']
        )
        with files.open(blob, 'a') as f:
            f.write(data)
        files.finalize(blob)
        return files.blobstore.get_blob_key(blob)

    def handle_upload(self):
        results = []
        blob_keys = []
        for name, fieldStorage in self.request.POST.items():
            if type(fieldStorage) is unicode:
                continue
            result = {}
            result['name'] = re.sub(
                r'^.*\\',
                '',
                fieldStorage.filename
            )
            result['type'] = fieldStorage.type
            result['size'] = self.get_file_size(fieldStorage.file)
            if self.validate(result):
                blob_key = str(
                    self.write_blob(fieldStorage.value, result)
                )
                blob_keys.append(blob_key)
                result['deleteType'] = 'DELETE'
                result['deleteUrl'] = self.request.host_url +\
                    '/?key=' + urllib.quote(blob_key, '')
                if (IMAGE_TYPES.match(result['type'])):
                    try:
                        result['url'] = images.get_serving_url(
                            blob_key,
                            secure_url=self.request.host_url.startswith(
                                'https'
                            )
                        )
                        result['thumbnailUrl'] = result['url'] +\
                            THUMBNAIL_MODIFICATOR
                    except:  # Could not get an image serving url
                        pass
                if not 'url' in result:
                    result['url'] = self.request.host_url +\
                        '/' + blob_key + '/' + urllib.quote(
                            result['name'].encode('utf-8'), '')
            results.append(result)
        deferred.defer(
            cleanup,
            blob_keys,
            _countdown=EXPIRATION_TIME
        )
        return results

    def options(self):
        pass

    def head(self):
        pass

    @admin_required
    def get(self, this_id=None):
        self.tv["current_page"] = "UPLOAD PHOTOS"
        self.tv["property_id"] = this_id
        self.render('frontend/uploadphotos.html')

    @admin_required
    def post(self, this_id=None):

        this_property = Property.get_by_id(normalize_id(this_id))

        if (self.request.get('_method') == 'DELETE'):
            return self.delete()

        data = self.handle_upload()
        result = {'files': data}
        s = simplejson.dumps(result, separators=(',', ':'))

        if this_property.images:
            this_property.images["files"].append(data[0])
        else:
            this_property.images = result
        this_property.put()

        redirect = self.request.get('redirect')
        if redirect:
            return self.redirect(str(
                redirect.replace('%s', urllib.quote(s, ''), 1)
            ))
        if 'application/json' in self.request.headers.get('Accept'):
            self.response.headers['Content-Type'] = 'application/json'
        self.response.write(s)

    def delete(self):
        key = self.request.get('key') or ''
        blobstore.delete(key)
        s = simplejson.dumps({key: True}, separators=(',', ':'))
        if 'application/json' in self.request.headers.get('Accept'):
            self.response.headers['Content-Type'] = 'application/json'
        self.response.write(s)

class DeveloperHandler(BaseHandler):
    @admin_required
    def get(self, this_id=None):
        self.tv["current_page"] =  "DEVELOPER"
        if this_id:
            developer = Developer.get_by_id(normalize_id(this_id))
            self.tv["developer"] = developer
        else:
            developers = Developer.query().fetch(100)
            self.tv["developers"] = []

            for developer in developers:
                self.tv["developers"].append(developer.to_object())

            self.render('frontend/developer.html')

    @admin_required
    def post(self, this_id=None):
        self.tv["current_page"] =  "DEVELOPER"
        if this_id:
            developer = Developer.get_by_id(normalize_id(this_id))
        else:
            developer = Developer(id=self.request.get("CODE").strip())

        developer.name = self.request.get("developer_name").strip()
        developer.contacts = self.request.get("developer_contact").strip()

        developer.put()

        self.redirect("/developer?success=successfully added!")



class ErrorHandler(BaseHandler):
    def get(self, page):
        self.tv["current_page"] = "ERROR"
        self.render('frontend/dynamic404.html')


site_domain = SETTINGS["site_domain"].replace(".","\.")

app = webapp2.WSGIApplication([
    routes.DomainRoute(r'<:' + site_domain + '|localhost|' + SETTINGS["app_id"] + '\.appspot\.com>', [
        webapp2.Route('/', handler=FrontPage, name="www-front"),

        # pages
        webapp2.Route('/dashboard', handler=DashboardPage, name="www-dashboard"),
        webapp2.Route('/lists', handler=ListsHandler, name="www-lists"),
        webapp2.Route(r'/lists/<:.*>', handler=ListsHandler, name="www-lists"),
        webapp2.Route('/developer', handler=DeveloperHandler, name="www-developer"),
        webapp2.Route(r'/developer/<:.*>', handler=DeveloperHandler, name="www-developer"),

        # upload photos handler
        webapp2.Route(r'/upload/<:.*>', handler=UploadHandler, name="www-upload"),

        webapp2.Route('/logout', handler=Logout, name="www-logout"),
        webapp2.Route('/aviato/login', handler=LoginPage, name="www-login"),

        webapp2.Route('/fblogin', handler=FBLoginPage, name="www-fblogin"),
        webapp2.Route('/forgot-pass', handler=ForgotPassHandler, name="www-forgot-pass"),
        webapp2.Route('/password/reset', handler=PasswordReset, name="www-reset-pass"),
        webapp2.Route(r'/<:.*>', ErrorHandler)
    ])
])