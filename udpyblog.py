import os
import jinja2
import hashlib
import hmac
import string
import random
import webapp2
import re
import logging
from webapp2_extras import sessions

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),"templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir))

udpyblog_prefix = "/"
udpyblog_init_pass = "dde"

# Models

class UdPyBlogSession(db.Model):
    session = db.StringProperty(required = True)
    redirect = db.TextProperty(required = True)
    
class UdPyBlogUser(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    lastlog = db.DateTimeProperty(auto_now_add = True)

class UdPyBlogPost(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    categories = db.ListProperty(db.Key)
    user = db.ReferenceProperty(UdPyBlogUser, collection_name='posts')

class UdPyBlogCategory(db.Model):
    category = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    @property
    def posts(self):
        return UdPyBlogPost.gql("WHERE categories = :1", self.key())

class UdPyBlogHandler(webapp2.RequestHandler):
    login = False
    restricted = False
    user = None
    secret = "HmacSecret"
    salt_length = 13
    logout = False
    
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()
        
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def redirect_prefixed(self, fragment):
        self.redirect(udpyblog_prefix + fragment)    
    
    def render_str(self, template, **params):
        params["url_prefix"] = udpyblog_prefix
        if self.user:
            params["username"] = self.user.username
            
        template = jinja_env.get_template(template)
        return template.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        
    def auth(self):
        if self.logout:
            return
            
        if "access" in self.request.cookies:
            if not self.request.cookies.get("access") and not self.restricted:
                return
                
            access = self.request.cookies.get("access").split("|")
            if len(access) == 2:
                user = UdPyBlogUser.get_by_id(int(access[1]))
                if user and self.validate_user(user, access):
                    self.user = user
                    return
                
                if not self.restricted:
                    return

        # store the original url in order to redirect on success!
        self.session['redirect'] = self.request.url
        self.redirect_prefixed("login")
            
    def make_hash(self, message, salt=None):
        salt = salt or self.make_salt()
        return "%s%s" % (hmac.new(self.secret, message + salt,hashlib.sha256).hexdigest(), salt)
    
    def make_salt(self):
        return "".join( random.choice("abcdef" + string.digits) for x in xrange(self.salt_length) )

    def validate_user(self, user, access):
        hash = access[0][:(self.salt_length * -1)]
        salt = access[0][(self.salt_length * -1):]
        return access[0] == self.make_hash(user.username, salt)

class UdPyBlogPostHandler(UdPyBlogHandler):
    url = ""
    restricted = True
    def post(self):
        self.auth()
        error = ''
        if self.request.get('subject') == '' or self.request.get('content') == '':
            error = 'Please fill in subject and content'
        else:

#user muss ermittelt werden! da der post im moment angelegt
# wird ist das self.user!!!
#mary = Contact.gql("name = 'Mary'").get()
#google = Company.gql("name = 'Google'").get()
            post = UdPyBlogPost(
                subject = self.request.get('subject'),
                content = self.request.get('content'),
                user = self.user
            )
            post.put()
            self.redirect_prefixed("post/{0}".format(post.key().id()))
            return

        self.render("blog_form.html",**{'error': error, 'subject': self.request.get('subject'), 'content': self.request.get('content'), 'created': self.request.get('created') })

    def get(self):
        self.auth()
        self.render("blog_form.html")

class UdPyBlogPostViewHandler(UdPyBlogHandler):
    url = "post"
    def get(self,post_id):
        self.auth()
        if post_id.isdigit():
            try:
                post = UdPyBlogPost.get_by_id(int(post_id))
                self.render("blog_post.html", post = post )
            except:
                self.render("blog_main.html",error = "ID not found (" + str(post_id) + ")")
        else:
            self.redirect_prefixed('')

class UdPyBlogSignupSuccessHandler(UdPyBlogHandler):
    restricted = True
    def get(self):
        self.auth()
        self.redirect_prefixed("")

class UdPyBlogSignupHandlerLogout(UdPyBlogHandler):
    def get(self):
        self.auth()
        self.response.headers.add_header("Set-Cookie", str("%s=%s; path=/" % ( "access","" ) ) )
        self.logout = True
        self.user = None
        self.redirect_prefixed("")
        
class UdPyBlogMainHandler(UdPyBlogHandler):
    def get(self):
        self.auth()
        posts = UdPyBlogPost.all()
        self.render("blog_main.html",posts = posts)
        
class UdPyBlogSignupHandler(UdPyBlogHandler):
    username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    password_re = re.compile(r"^.{3,20}$")
    fields = [ 'username','password','verify','email' ]

    errors = 0
    args = {}

    def get(self):
        self.auth()
        for field in self.fields:
            self.args[field], self.args['error_' + field] = '',''
            
        self.render("signup.html", **self.args )

    def post(self):
        self.auth()
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
            self.redirect_prefixed("welcome")
    
    def validate(self,input):
        if input == "username":
            input_username = self.request.get(input)
            if self.username_re.match(input_username):
                if not self.login:
                    users = db.GqlQuery("SELECT * FROM UdPyBlogUser WHERE username = :1", input_username )
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

class UdPyBlogInitHandler(UdPyBlogSignupHandler):
    fields = [ "password" ]
    def get(self):
        self.auth()
        self.render( "init.html" )

    def post(self):
        self.auth()
        for field in self.fields:
            self.args[field],self.args['error_' + field] = '',''
            self.args[field],self.args['error_' + field] = self.validate(field)
        
        if self.errors > 0:
            self.render("init.html", **self.args )
            return

        else:
            if self.args["password"] == udpyblog_init_pass:


                udpyblog_init_blog()
                return
            else:
                self.args['error'] = "invalid login"

        self.render("init.html", **self.args )
        return

class UdPyBlogSignupHandlerLogin(UdPyBlogSignupHandler):
    fields = [ "username","password" ]
    login = True
    def get(self):
        self.auth()
        self.response.headers.add_header("Set-Cookie", str("%s=%s; path=/" % ( "access","" ) ) )
        self.render( "login.html" )

    def post(self):
        self.auth()
        for field in self.fields:
            self.args[field],self.args['error_' + field] = '',''
            self.args[field],self.args['error_' + field] = self.validate(field)
        
        if self.errors > 0:
            self.render("login.html", **self.args )
            return

        else:
            users = db.GqlQuery("SELECT * FROM UdPyBlogUser WHERE username = :1", self.args["username"] )            
            if users.count() == 1:
                if self.make_hash(self.args["password"], users[0].salt ) == users[0].password:
                    self.response.headers.add_header("Set-Cookie", str("%s=%s|%s; path=/" % ( "access", self.make_hash(users[0].username, users[0].salt ), users[0].key().id() ) ) )
                    self.redirect_prefixed("welcome")
                    if self.session['redirect']:
                        redirect_url = str(self.session['redirect'])
                        self.session['redirect'] = None
                        self.redirect(redirect_url)
                        return                        
                    
                    self.redirect_prefixed("")
                    return
            else:
                self.args['error'] = "invalid login"

        self.render("login.html", **self.args )
        return

routes = [
    ('', UdPyBlogMainHandler),
    ('signup', UdPyBlogSignupHandler),
    ('logout', UdPyBlogSignupHandlerLogout),
    ('login', UdPyBlogSignupHandlerLogin),
    ('welcome', UdPyBlogSignupSuccessHandler),
    ('post/([0-9]+)', UdPyBlogPostViewHandler),
    ('init', UdPyBlogInitHandler),
    ('newpost', UdPyBlogPostHandler)
]

def udpyblog_init_blog():
    categories = []
    categories.append(
        UdPyBlogCategory(
            category = "Movies"
        ).put()
    )
    categories.append(
        UdPyBlogCategory(
            category = "Movies"
        ).put()
    )

    return

def udpyblog_get_routes(prefix = ""):
    if prefix:
        routes_prefixed = []
        for route in routes:
            routes_prefixed.append((prefix + route[0],route[1]))
        return routes_prefixed
    else:
        return routes
