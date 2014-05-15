from google.appengine.ext import ndb
import time
import json

class User(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    email = ndb.StringProperty()
    password = ndb.StringProperty()
    name = ndb.StringProperty()
    first_name = ndb.StringProperty()
    last_name = ndb.StringProperty()
    status = ndb.StringProperty()

    def to_object(self):
        details = {}
        details["created"] = int(time.mktime(self.created.timetuple()))
        details["updated"] = int(time.mktime(self.updated.timetuple()))
        details["email"] = self.email
        details["name"] = self.name
        details["status"] = self.status
        return details


class Developer(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    name = ndb.StringProperty()
    contacts = ndb.StringProperty()

    def to_object(self):
        details = {}
        details["created"] = int(time.mktime(self.created.timetuple()))
        details["updated"] = int(time.mktime(self.updated.timetuple()))
        details["name"] = self.name
        details["id"] = self.key.id()
        details["key"] = self.key.urlsafe()
        details["contacts"] = self.contacts
        return details

class Property(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    title = ndb.StringProperty()
    sqft = ndb.StringProperty()
    kind = ndb.StringProperty() # type
    price = ndb.StringProperty()
    location = ndb.StringProperty()
    description = ndb.TextProperty()
    amenities = ndb.JsonProperty()
    developer = ndb.KeyProperty(kind="Developer")
    status = ndb.StringProperty(default="AVAILABLE")
    images = ndb.JsonProperty()

    def to_object(self):
        details = {}
        details["created"] = int(time.mktime(self.created.timetuple()))
        details["updated"] = int(time.mktime(self.updated.timetuple()))
        details["title"] = self.title
        details["id"] = self.key.id()
        details["location"] = self.location
        details["description"] = self.description
        details["amenities"] = self.amenities
        details["images"] = self.images
        details["developer"] = self.developer.get().to_object()
        details["status"] = self.status

        return details



class PasswordResetToken(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)
    updated = ndb.DateTimeProperty(auto_now=True)
    email = ndb.StringProperty()
    token = ndb.StringProperty()
    expires = ndb.DateTimeProperty()