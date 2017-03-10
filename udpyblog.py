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

class UdPyBlogPostComment(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    categories = db.ListProperty(db.Key)
    user = db.ReferenceProperty(UdPyBlogUser, collection_name='comments')
    post = db.ReferenceProperty(UdPyBlogPost, collection_name='comments')

class UdPyBlogCategory(db.Model):
    category = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    @property
    def posts(self):
        return UdPyBlogPost.gql("WHERE categories = :1", self.key())

class UdPyBlogPostLikes(db.Model):
    post = db.ReferenceProperty(
        UdPyBlogPost,
        required=True,
        collection_name='users_who_like'
    )
    user = db.ReferenceProperty(
        UdPyBlogUser,
        required=True,
        collection_name='liked_posts'
    )


class UdPyBlogHandler(webapp2.RequestHandler):
    login = False
    restricted = False
    update = False
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

    def redirect_prefixed(self, fragment, code=None):
        self.redirect(UdPyBlog.blog_prefix + fragment, code=code)    
    
    def render_str(self, template_file, **params):
        params["login_page"] = self.login
        params["url_prefix"] = UdPyBlog.blog_prefix
        if self.user:
            params["username"] = self.user.username
        
        return UdPyBlog.render_template(template_file, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        
    def auth(self):
        if self.logout:
            return            
            
        if self.user:
            UdPyBlogUser.get_by_id(int(access[1]))
            
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
        self.session["redirect"] = self.request.url
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

class UdPyBlogPostViewHandler(UdPyBlogHandler):
    url = "post"
    def get(self, post_id):
        self.auth()
        if post_id.isdigit():
            try:
                post = UdPyBlogPost.get_by_id(int(post_id))
                likes_post = False
                if self.user.liked_posts.filter('post = ',post.key()).count() == 1:
                    logging.info("current user likes this post")
                    likes_post = True
                    
                self.render("blog_post.html", **{ "post": post, "user": self.user, "comment": None } )
                return
            except:
                self.render("blog_main.html",error = "ID not found (" + str(post_id) + ")")
                return
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
        if not self.user:
            self.redirect_prefixed("")
            return
          
        self.response.headers.add_header("Set-Cookie", str("%s=%s; path=/" % ( "access","" ) ) )
        self.logout = True
        self.user = None
        self.redirect_prefixed("")
        
class UdPyBlogPostLikeHandler(UdPyBlogHandler):
    """Register or unregister (toggle) likes for a specific post. Only
    logged in users other than the author are allowed to like a post."""
    
    restricted = True
    def post(self, post_id):
        self.session["redirect"] = self.request.referer
        self.auth()
        if not self.user:
            self.redirect_prefixed("")
            return

        post = UdPyBlogPost.get_by_id(int(post_id))
        if not post or post.user.username == self.user.username:
            if self.session["redirect"]:
                redirect_url = self.session["redirect"]
                self.session["redirect"] = ""
                self.redirect(redirect_url)
                return
            
            self.redirect_prefixed("")
            return
            
        posts_user_likes = UdPyBlogPostLikes.all().filter('post =',post.key()).filter('user =',self.user.key())
        logging.info("post has likes: " + str(posts_user_likes.count()))
        if posts_user_likes.count():
            for post_user_likes in posts_user_likes:
                post_user_likes.delete()
        else:
            post_like = UdPyBlogPostLikes(
                post=post,
                user=self.user
            )
            post_like.put()

        if self.session["redirect"]:
            redirect_url = self.session["redirect"]
            self.session["redirect"] = ""
            self.redirect(redirect_url)
            return
            
        self.redirect_prefixed("")
        return
        
class UdPyBlogMainHandler(UdPyBlogHandler):
    def get(self):
        self.auth()
        posts = UdPyBlogPost.all()
        self.render("blog_main.html", **{ "posts": posts, "user": self.user } )
        
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

        if input == "subject":
            input_subject = self.request.get(input)
            if len(input_subject) >= self.subject_min_length:
                return (input_subject,'')

            else:
                self.errors += 1
                return (input_subject,"Subject not valid or too short")

        if input == "content":
            input_content = self.request.get(input)
            if len(input_content) >= self.content_min_length:
                return (input_content,'')

            else:
                self.errors += 1
                return ("","Content not valid or too short")

        if input == "post_id":
            input_post_id = self.request.get(input)
            if input_post_id.isdigit():
                return (input_post_id,"")

            else:
                self.errors += 1
                return ("","Post id missing")

class UdPyBlogPostHandler(UdPyBlogSignupHandler):
    restricted = True
    subject_min_length = 10
    content_min_length = 10
    fields = [ 'subject', 'content' ]
    
    def post(self):
        self.auth()
        if self.update:
            self.fields.append('post_id')
            
        for field in self.fields:
            self.args[field],self.args['error_' + field] = '',''
            self.args[field],self.args['error_' + field] = self.validate(field)

        self.args["update"] = self.update
        if self.errors > 0:
            post = {"subject": "","content": ""}
            self.render("blog_form.html", **self.args )
            return
        else:
            if not self.update:
                post = UdPyBlogPost(
                    subject = self.request.get('subject'),
                    content = self.request.get('content'),
                    user = self.user
                )
            else:
                post = UdPyBlogPost.get_by_id(int(self.args["post_id"]))
                if not post or post.user.username != self.user.username:
                    self.redirect_prefixed("post/{0}".format(self.args["post_id"]))
                    return

                post.content = self.args["content"]
                post.subject = self.args["subject"]

            post.put()
            self.redirect_prefixed("post/{0}".format(post.key().id()))
            return

        self.render(
            "blog_form.html",**{
                "error": error,
                "subject": self.request.get("subject"),
                "content": self.request.get("content"),
                "created": self.request.get("created")
            }
        )

    def get(self):
        self.auth()
        self.render("blog_form.html", **self.args)

class UdPyBlogPostUpdateHandler(UdPyBlogPostHandler):
    update=True
    def get(self):
        self.auth()
        post_id = self.request.get("post_id")
        if post_id.isdigit():
            try:
                post = UdPyBlogPost.get_by_id(int(post_id))
                if post:
                    self.render(
                        "blog_form.html",
                        **{
                            "subject": post.subject,
                            "content": post.content,
                            "post_id": post_id,
                            "update": self.update
                        }
                    )
                    return
            except:
                self.render("blog_main.html",error = "ID not found (" + str(post_id) + ")")
                return
        else:
            self.redirect_prefixed('')


class UdPyBlogPostCommentHandler(UdPyBlogPostHandler):
    """Handling comments posted on a post"""
    
    restricted = True
    def post(self, post_id):
        self.auth()
        if self.update:
            self.fields.append('comment_id')

        post = UdPyBlogPost.get_by_id(int(post_id))
        if not post:
            self.redirect_prefixed('')
            
        for field in self.fields:
            self.args[field],self.args['error_' + field] = '',''
            self.args[field],self.args['error_' + field] = self.validate(field)

        if self.errors > 0:
            self.args["post"] = post
            self.args["user"] = self.user
            self.args["comment"] = None
            self.render("blog_post.html", **self.args )
            return

        else:
            if not self.update:
                comment = UdPyBlogPostComment(
                    subject = self.request.get('subject'),
                    content = self.request.get('content'),
                    post = post,
                    user = self.user
                )
            else:
                comment = UdPyBlogPostComment.get_by_id(int(self.args["comment_id"]))
                if not post or post.user.username != self.user.username:
                    self.redirect_prefixed("post/{0}".format(self.args["post_id"]))
                    return

                comment.content = self.args["content"]
                comment.subject = self.args["subject"]

            comment.put()
            self.redirect_prefixed("post/{0}".format(post.key().id()))
            return

        self.render(
            "blog_post.html",**{
                "error": error,
                "comment": None,
                "post": post,
                "subject": self.request.get("subject"),
                "content": self.request.get("content")
            }
        )

class UdPyBlogPostCommentDeleteHandler(UdPyBlogPostCommentHandler):
    """Handling comment deletions on a post"""
    
    restricted = True
    def get(self, post_id, comment_id):
        self.auth()
        comment = UdPyBlogPostComment.get_by_id(int(comment_id))
        if not comment or comment.user.key() != self.user.key():
            self.redirect_prefixed("")
            return

        comment.delete()
        self.redirect_prefixed("post/{0}".format(post_id))
        return

class UdPyBlogPostCommentEditHandler(UdPyBlogPostCommentHandler):
    """Handling comment edits on a post"""
    
    update = True
    restricted = True
    def get(self, post_id, comment_id):
        self.auth()
        comment = UdPyBlogPostComment.get_by_id(int(comment_id))
        if not comment_id or comment.user.key() != self.user.key():
            self.redirect_prefixed("")
            return
        
        post_id = comment.post.key().id()
        logging.info(comment.post.user.username)
        logging.info(comment.post)
        if not comment.post or comment.user.username != self.user.username:
            self.redirect_prefixed("post/{0}".format(post_id))
            return
            
        self.render(
            "blog_post.html",
            **{
                "post": comment.post,
                "user": self.user,
                "comment": comment,
                "update": self.update
            }
        )

    def post(self, post_id, comment_id):
        self.auth()
        post = UdPyBlogPost.get_by_id(int(post_id))
        if not post:
            self.redirect_prefixed('')
            
        for field in self.fields:
            self.args[field],self.args['error_' + field] = '',''
            self.args[field],self.args['error_' + field] = self.validate(field)

        if self.errors > 0:
            logging.info("Errors gt 0")
            self.render(
                "blog_post.html",
                **{
                    "comment": None,
                    "user": self.user,
                    "post": post,
                    "subject": self.args["subject"],
                    "comment": self.args["comment"],
                    "update": self.update
                }
            )
            return

        else:
            logging.info("All koo")
            if not self.update:
                comment = UdPyBlogPostComment(
                    subject = self.request.get('subject'),
                    content = self.request.get('content'),
                    post = post,
                    user = self.user
                )
            else:
                comment = UdPyBlogPostComment.get_by_id(int(comment_id))
                if not comment or comment.user.username != self.user.username:
                    self.redirect_prefixed("post/{0}".format(post_id))
                    return

                comment.content = self.args["content"]
                comment.subject = self.args["subject"]

            comment.put()
            self.redirect_prefixed("post/{0}".format(post.key().id()))
            return

        self.render(
            "blog_post.html",**{
                "error": error,
                "comment": None,
                "subject": self.request.get("subject"),
                "content": self.request.get("content"),
                "created": self.request.get("created")
            }
        )
   
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

# Base class 
class UdPyBlog():
    """This class serves as a configuration class. It populates all 
    nescessary variables given a dictionary from via the setup method"""

    routes = [
        ('', UdPyBlogMainHandler),
        ('signup', UdPyBlogSignupHandler),
        ('logout', UdPyBlogSignupHandlerLogout),
        ('login', UdPyBlogSignupHandlerLogin),
        ('welcome', UdPyBlogSignupSuccessHandler),
        ('updatepost', UdPyBlogPostUpdateHandler),
        ('post/([0-9]+)', UdPyBlogPostViewHandler),
        ('post/([0-9]+)/comment', UdPyBlogPostCommentHandler),
        ('post/([0-9]+)/comment/([0-9]+)/edit', UdPyBlogPostCommentEditHandler),
        ('post/([0-9]+)/comment/([0-9]+)/delete', UdPyBlogPostCommentDeleteHandler),
        ('init', UdPyBlogInitHandler),
        ('newpost', UdPyBlogPostHandler),
        ('like/([0-9]+)', UdPyBlogPostLikeHandler)
    ]
    
    template_folder = "dist/templates"
    blog_prefix = "/"
    static_path_prefix = ""
    jinja_env = None
    
    @classmethod
    def prepare(cls, config = None):
        if config:
            if "template_folder" in config:
                cls.template_folder = config["template_folder"]

            if "blog_prefix" in config:
                cls.blog_prefix = config["blog_prefix"]

        cls.template_dir = os.path.join(
            os.path.dirname(__file__), 
            cls.template_folder
        )
        cls.jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(cls.template_dir))
        
    @classmethod
    def get_routes(cls):
        if cls.blog_prefix:
            routes_prefixed = []
            for route in cls.routes:
                routes_prefixed.append((cls.blog_prefix + route[0],route[1]))
            return routes_prefixed
        else:
            return cls.routes
 
    @classmethod
    def error_handler(cls, request, response, exception):
        response.out.write(cls.render_template("error.html", exception=exception, response=response))

    @classmethod
    def render_template(cls, template_file, **params):
        template = cls.jinja_env.get_template(template_file)
        return template.render(params)

    @classmethod
    def inject(cls, app):
        app.error_handlers[404] = cls.error_handler
        app.error_handlers[403] = cls.error_handler
        app.error_handlers[500] = cls.error_handler
     
