import os
import jinja2
import hashlib
import hmac
import string
import random
import webapp2
import re
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),"templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))

udpyblog_prefix = ""
        
class UdPyBlogUser(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    lastlog = db.DateTimeProperty(auto_now_add = True)

class UdPyBlogEntry(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class UdPyBlogHandler(webapp2.RequestHandler):
    login = False
    restricted = False
    user = None
    secret = "HmacSecret"
    salt_length = 13
    logout = False
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        if self.user:
            params["username"] = self.user.username
            
        template = jinja_env.get_template(template)
        return template.render(params)

    def render(self, template, **kw):
        self.auth()
        self.write(self.render_str(template, **kw))
        
    def auth(self):
        if self.logout:
            return
            
        if "access" in self.request.cookies:
            if not self.request.cookies.get("access") and not self.restricted:
                return
                
            access = self.request.cookies.get("access").split("|")
            if len(access) == 2:
                user = User.get_by_id(int(access[1]))
                if self.validate_user(user, access):
                    self.user = user
                    return

        self.redirect("/blog/logout")
            
    def make_hash(self, message, salt=None):
        salt = salt or self.make_salt()
        return "%s%s" % (hmac.new(self.secret, message + salt,hashlib.sha256).hexdigest(), salt)
    
    def make_salt(self):
        return "".join( random.choice("abcdef" + string.digits) for x in xrange(self.salt_length) )

    def validate_user(self, user, access):
        hash = access[0][:(self.salt_length * -1)]
        salt = access[0][(self.salt_length * -1):]
        return access[0] == self.make_hash(user.username, salt)

class UdPyBlogBlogPostHandler(UdPyBlogHandler):
    def post(self):
        error = ''
        if self.request.get('subject') == '' or self.request.get('content') == '':
            error = 'Please fill in subject and content'
        else:
            entry = UdPyBlogEntry(
                subject = self.request.get('subject'),
                content = self.request.get('content')
            )
            entry.put()
            self.redirect("/blog/entry/{0}".format(entry.key().id()))

        self.render("blog_form.html",**{'error': error, 'subject': self.request.get('subject'), 'content': self.request.get('content'), 'created': self.request.get('created') })

    def get(self):
        self.render("blog_form.html")

class UdPyBlogEntryHandler(UdPyBlogHandler):
    def get(self,entry_id):
        if entry_id.isdigit():
            try:
                entries = db.GqlQuery("SELECT * FROM UdPyBlogEntry WHERE __key__ = KEY('BlogEntry'," + str(entry_id) + ")")
                self.render("blog_entry.html", entry = entries[0] )
            except:
                self.render("blog_main.html",error = "ID not found (" + str(entry_id) + ")")
        else:
            self.redirect('/blog')

class UdPyBlogBlogHandler(UdPyBlogHandler):
    def get(self):
        entries = db.GqlQuery("SELECT * FROM UdPyBlogEntry ORDER BY created DESC")
        self.render("blog_main.html", entries = entries)

class UdPyBlogSignupSuccessHandler(UdPyBlogHandler):
    restricted = True
    def get(self):
        self.render("signup_db_welcome.html")

class UdPyBlogSignupHandlerLogout(UdPyBlogHandler):
    def get(self):
        self.response.headers.add_header("Set-Cookie", str("%s=%s; path=/" % ( "access","" ) ) )
        self.logout = True
        self.user = None
        self.redirect("/signup")
        
class UdPyBlogSignupHandler(UdPyBlogHandler):
    username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    password_re = re.compile(r"^.{3,20}$")
    fields = [ 'username','password','verify','email' ]

    errors = 0
    args = {}

    def get(self):
        for field in self.fields:
            self.args[field], self.args['error_' + field] = '',''
            
        self.render("signup_db.html", **self.args )

    def post(self):
        for field in self.fields:
            self.args[field],self.args['error_' + field] = '',''
            self.args[field],self.args['error_' + field] = self.validate(field)

        if self.errors > 0:
            self.render("signup.html", **self.args )
            
        else:
            access_hash = self.make_hash(self.args['username'])
            salt = access_hash[(self.salt_length * -1):]
            user = UdPyBlogUser(
                username = self.args['username'],
                password = self.make_hash(self.args['password'],salt),
                salt = salt
            )
            user.put()
            self.response.headers.add_header(
                "Set-Cookie",
                str(
                    "%s=%s|%s; path=/" % ( "access", access_hash, user.key().id() )
                )
            )
            self.redirect("/welcome")
    
    def validate(self,input):
        if input == "username":
            input_username = self.request.get(input)
            if self.username_re.match(input_username):
                if not self.login:
                    users = db.GqlQuery("SELECT * FROM User WHERE username = :1", input_username )
                    if users.count() > 0:
                        self.errors += 1
                        return ('',"That user already exists")
            
                return (input_username,'')
            self.errors += 1
            return ('',"That's not a valid username")

        if input == "password":
            input_password = self.request.get(input)
            if self.password_re.match(input_password):
                return (input_password,'')
            self.errors += 1
            return ('',"That's not a valid password")

        if input == "verify":
            input_verify = self.request.get(input)
            if "password" in self.args and self.args["password"] != "":
                if self.args["password"] != input_verify:
                    self.errors += 1
                    return ('',"Your passwords didn't match")
            return ('','')

        if input == "email":
            input_email = self.request.get(input)
            if input_email == "":
                return ('','')
            elif self.email_re.match(input_email):
                return (input_email,'')
            else:
                self.errors += 1
                return (input_email,"That's not a valid email")

class UdPyBlogSignupHandlerLogin(UdPyBlogSignupHandler):
    fields = [ "username","password" ]
    login = True
    def get(self):
        self.response.headers.add_header("Set-Cookie", str("%s=%s; path=/" % ( "access","" ) ) )
        self.render( "signup_db_login.html" )

    def post(self):
        for field in self.fields:
            self.args[field],self.args['error_' + field] = '',''
            self.args[field],self.args['error_' + field] = self.validate(field)
        
        if self.errors > 0:
            self.render("signup_db_login.html", **self.args )
            return

        else:
            users = db.GqlQuery("SELECT * FROM UdPyBlogUser WHERE username = :1", self.args["username"] )            
            if users.count() == 1:
                if self.make_hash(self.args["password"], users[0].salt ) == users[0].password:
                    self.response.headers.add_header("Set-Cookie", str("%s=%s|%s; path=/" % ( "access", self.make_hash(users[0].username, users[0].salt ), users[0].key().id() ) ) )
                    self.redirect("/welcome")
                    return
            else:
                self.args['error'] = "invalid login"

        self.render("signup_db_login.html", **self.args )
        return

routes = [
    ('/', UdPyBlogBlogHandler),
    ('/signup', UdPyBlogSignupHandler),
    ('/logout', UdPyBlogSignupHandlerLogout),
    ('/login', UdPyBlogSignupHandlerLogin),
    ('/welcome', UdPyBlogSignupSuccessHandler),
    ('/entry/([0-9]+)', UdPyBlogEntryHandler),
    ('/newpost', UdPyBlogBlogPostHandler)
]

def udPygetRoutes(prefix = ""):
    if prefix:
        routes_prefixed = []
        for route in routes:
            route[0] = prefix + route[0]
            routes_prefixed.append(route)
        return routes_prefixed
    else:
        return routes
