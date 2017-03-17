import os
import jinja2
import hashlib
import hmac
import string
import random
import webapp2
import re
import logging
import json
import sys

from webapp2_extras import sessions

from google.appengine.ext import db
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.api import app_identity

# Models

class UdPyBlogEmptyModel():
    legit = False
    def __init__(self, properties):
        for property in properties:
            setattr(self, property, properties[property])

    def key(self):
        return ""

class UdPyBlogEntity(db.Model):
    @classmethod
    def empty(cls):
        return UdPyBlogEmptyModel(
            {
            }
        )


class UdPyBlogSession(UdPyBlogEntity):
    legit = True
    session = db.StringProperty(required = True)
    redirect = db.TextProperty(required = True)

class UdPyBlogUser(UdPyBlogEntity):
    legit = True
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    lastlog = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def empty(cls):
        return UdPyBlogEmptyModel(
            {
                "username": "",
                "created": "",
                "lastlog": ""
            }
        )

class UdPyBlogPost(UdPyBlogEntity):
    legit = True
    subject = db.StringProperty(required = True)
    cover_image = db.ReferenceProperty(required = False)
    summary = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    categories = db.ListProperty(db.Key)
    user = db.ReferenceProperty(UdPyBlogUser, collection_name='posts')

class UdPyBlogPostComment(UdPyBlogEntity):
    legit = True
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    categories = db.ListProperty(db.Key)
    user = db.ReferenceProperty(UdPyBlogUser, collection_name='comments')
    post = db.ReferenceProperty(UdPyBlogPost, collection_name='comments')
    @classmethod
    def empty(cls):
        return UdPyBlogEmptyModel(
            {
                "subject": "",
                "content": "",
                "created": "",
                "categories": "",
                "user": None,
                "post": None
            }
        )


#class UdPyBlogCategory(db.Model):
#    category = db.StringProperty(required = True)
#    created = db.DateTimeProperty(auto_now_add = True)
#    @property
#    def posts(self):
#        return UdPyBlogPost.gql("WHERE categories = :1", self.key())

class UdPyBlogPostLikes(db.Model):
    legit = True
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

class UdPyBlogImage(db.Model):
    legit = True
    session = db.StringProperty(required = True)
    user = db.ReferenceProperty(
        UdPyBlogUser,
        required=True,
        collection_name='blobs'
    )
    post = db.ReferenceProperty(required = False)
    blob_key = blobstore.BlobReferenceProperty()
    created = db.DateTimeProperty(auto_now_add = True)

class UdPyBlogHandler(webapp2.RequestHandler):
    signup = False
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

    def url_prefixed(self, fragment):
        return self.request.scheme + "://" + self.request.host + UdPyBlog.blog_prefix + fragment

    def redirect_prefixed(self, fragment, code=None):
        self.redirect(UdPyBlog.blog_prefix + fragment, code=code)

    def render_str(self, template_file, **params):
        params = params or {}
        params["image_url_prefix"] = self.url_prefixed(UdPyBlog.image_view_url_part)
        params["login_page"] = self.login
        params["signup_page"] = self.signup
        params["url_prefix"] = UdPyBlog.blog_prefix
        params["user"] = UdPyBlogUser.empty()
        if self.user:
            params["user"] = self.user

        return UdPyBlog.render_template(template_file, **params)

    def render(self, template_file, **kw):
        self.write(self.render_str(template_file, **kw))

    def render_json(self, payload):
        self.response.headers['Content-Type'] = 'application/json'
        self.response.out.write(json.dumps(payload))

    def auth(self):
        logging.info("+++++++++++ 1")
        if self.logout:
            return

        logging.info("+++++++++++ 2")
        if self.user:
            UdPyBlogUser.get_by_id(int(access[1]))

        logging.info("+++++++++++ 3")
        if "access" in self.request.cookies:
            if not self.request.cookies.get("access") and not self.restricted:
                access = self.request.cookies.get("access").split("|")
                return

            logging.info("+++++++++++ 5")

            access = self.request.cookies.get("access").split("|")
            if len(access) == 2:
                logging.info("+++++++++++ 6")
                user = UdPyBlogUser.get_by_id(int(access[1]))
                if user and self.validate_user(user, access):
                    logging.info("+++++++++++ 7 LOGGED IN AS {}".format(user.username))
                    self.user = user
                    return

                logging.info("+++++++++++ 8")

                if not self.restricted:
                    logging.info("+++++++++++ 9")
                    return
        if not self.restricted:
            logging.info("+++++++++++ 10")
            return

        logging.info("+++++++++++ 11")
        # store the original url in order to redirect on success!
        self.session["redirect"] = self.request.url
        logging.info("+++++++++++ 12")
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

    def no_cache(self):
        self.response.headers.add_header("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
        self.response.headers.add_header("Expires","0")

    def process_images(self, content, post_key):
        return
        logging.info("checking fo r " + str(post_key));

        images = re.findall("encoded_gs_file:[a-zA-Z0-9]+",content)
        images_mapped = []
        for image_mapped in UdPyBlogImage.all().filter('post_key =', str(post_key)):
            images_mapped.append(image_mapped)

        images_dropped = list(set(images_mapped) - set(images))
        logging.info("RRemoving " + ",".join(images_dropped))

        for image in images_dropped:
            for image_placed in UdPyBlogImage.filter('blob_key = ', image):
                image_placed.delete()

        for image in images:
            logging.info("Adding image " + image)
            image_placed = UdPyBlogImage.all().filter('blob_key = ', image).get()
            image_placed.post_key = str(post_key)
            image_placed.put()

class UdPyBlogImageUploadPrepareHandler(blobstore_handlers.BlobstoreUploadHandler, UdPyBlogHandler):
    def get(self):
        self.no_cache()
        bucket = app_identity.get_default_gcs_bucket_name()
        upload_url = blobstore.create_upload_url(
            '/image/upload',
            gs_bucket_name=bucket
        )
        self.render_json({
            "upload_url": upload_url
        })

class UdPyBlogImageUploadHandler(blobstore_handlers.BlobstoreUploadHandler, UdPyBlogHandler):
    def post(self):
        self.auth()
        try:
            upload = self.get_uploads()[0]
            uploaded_image = UdPyBlogImage(
                session=self.request.cookies["session"],
                user=self.user,
                blob_key=upload.key()
            )
            uploaded_image.put()
            self.render_json(
                {
                  "location": self.url_prefixed('%s%s' % (UdPyBlog.image_view_url_part, upload.key()))
                }
            )

        except:
            self.error(500)

class UdPyBlogImageViewHandler(blobstore_handlers.BlobstoreDownloadHandler, UdPyBlogHandler):
    def get(self, image_key):
        self.auth()
        logging.info("VIEWER")
        if not blobstore.get(image_key):
            self.error(404)
        else:
            self.send_blob(image_key)

class UdPyBlogPostViewHandler(UdPyBlogHandler):
    url = "post"
    def get(self, post_id):
        self.auth()
        logging.info("auth")
        if post_id.isdigit():
            logging.info("digit")
            try:
                logging.info(post_id)
                logging.info(UdPyBlogPost.get_by_id(int(post_id)))
                post = UdPyBlogPost.get_by_id(int(post_id))
                likes_post = False
                if self.user and self.user.liked_posts.filter('post = ',post.key()).count() == 1:
                    logging.info("current user likes this post")
                    likes_post = True

                logging.info("likes or not")
                logging.info(UdPyBlogPostComment.empty())

                logging.info({ "post": post, "user": self.user })
                self.render(
                    "blog_post.html",
                    **{
                        "post": post,
                        "comment": UdPyBlogPostComment.empty()
                    }
                )
                return

            except:
                logging.info(sys.exc_info())
                self.render("blog_main.html",error = "Error {} ({}))".format(post_id, sys.exc_info()[0]))
                return

        else:
            self.redirect_prefixed('')

class UdPyBlogSignupSuccessHandler(UdPyBlogHandler):
    restricted = True
    def get(self):
        self.auth()
        self.render("blog_welcome.html")

class UdPyBlogSignupHandlerLogout(UdPyBlogHandler):
    logout = True
    restricted = False
    def get(self):
        self.auth()
        self.response.headers.add_header("Set-Cookie", str("%s=%s; path=/" % ( "session","" ) ) )
        self.response.headers.add_header("Set-Cookie", str("%s=%s; path=/" % ( "access","" ) ) )
        if not self.user:
            self.redirect_prefixed("")
            return

        self.user = None
        self.redirect_prefixed("")

class UdPyBlogPostLikeHandler(UdPyBlogHandler):
    """Register or unregister (toggle) likes for a specific post. Only
    logged in users other than the author are allowed to like a post."""

    restricted = True
    def post(self, post_id):
        logging.info("<><><><>LIKE HANDLER CALLES<><><>")

        if self.request.referer:
            self.session["redirect"] = self.request.referer

        self.auth()
        if not self.user:
            logging.info("||||||||||||||||||< BAD LOGO!!!!!!!!!!!! <<<<")
            self.redirect_prefixed("")
            return

        post = UdPyBlogPost.get_by_id(int(post_id))
        if not post or post.user.username == self.user.username:
            if not post:
                logging.info(")))))))))))))))) BAD POST <<<<")
            if post.user.username == self.user.username:
                logging.info("(((((((((((((((( BAD UUUUUUUUSER <<<<")

            if self.session["redirect"]:
                redirect_url = self.session["redirect"]
                self.session["redirect"] = ""
                self.redirect(redirect_url)
                return

            self.error("403")
            self.render("error.html")
            return

        logging.info(":::::::::::::::::::: ALIIIIIIIIIIIIIIIIIIIIIIIIII BAD POST <<<<")
        posts_user_likes = UdPyBlogPostLikes.all().filter('post =',post.key()).filter('user =',self.user.key())
        logging.info("<><><>>>>>> 1 <<<<><><><>>>>>>>")
        logging.info("post has likes: " + str(posts_user_likes.count()))
        logging.info("<><><>>>>>> 2 <<<<><><><>>>>>>>")
        if posts_user_likes.count():
            logging.info("<><><>>>>>> 3 <<<<><><><>>>>>>>")
            for post_user_likes in posts_user_likes:
                logging.info("<><><>>>>>> 4 <<<<><><><>>>>>>>")
                post_user_likes.delete()
        else:
            logging.info("<><><>>>>>> 5 <<<<><><><>>>>>>>")
            post_like = UdPyBlogPostLikes(
                post=post,
                user=self.user
            )
            logging.info("<><><>>>>>> 6 <<<<><><><>>>>>>>")
            post_like.put()

        logging.info("<><><>>>>>> 7 <<<<><><><>>>>>>>")
        if "redirect" in self.session:
            logging.info("<><><>>>>>> 8 <<<<><><><>>>>>>>")
            logging.info(" <| <| <|  <|  <|  <|  <|  <|  <|  <|  <|  <| REDIREC SET: " + self.session["redirect"])
            redirect_url = self.session["redirect"]
            self.session["redirect"] = ""
            self.redirect(redirect_url)
            return

        logging.info(" <| <| <|  <|  <|  <|  <|  <|  <|  <|  <|  <| HOOOOOOOOOOOOOOME")
        self.redirect_prefixed("")
        return

class UdPyBlogMainHandler(UdPyBlogHandler):
    def get(self):
        self.auth()
        posts = UdPyBlogPost.all()
        self.render(
            "blog_main.html",
            **{
                "posts": posts
            }
        )

class UdPyBlogSignupHandler(UdPyBlogHandler):
    signup = True
    fields = [ 'username','password','verify','email' ]
    required = [ 'username','password' ]

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
            blog_entity_context = {
                "username": user.username
            }
            self.response.headers.add_header(
                "Blog-Entity-Context",
                json.dumps(blog_entity_context)
            )
            self.redirect_prefixed("welcome")

    def validate(self,field):

        # Check for validity of entered data agains re and length reqs
        # Higher level checks only if no error here
        error = UdPyBlog.validate_input(
            field,
            self.request.get(field),
            field in self.required
        )
        if error != True:
            self.errors += 1
            return (self.request.get(field),error)

        if field == "username":
            if not self.login:
                if UdPyBlogUser.all().filter('username =', self.request.get(field)).count() > 0:
                    self.errors += 1
                    return (self.request.get(field),"That user already exists")

            return (self.request.get(field),'')

        if field == "verify":
            input_verify = self.request.get(field)
            if "password" in self.args and self.args["password"] != "":
                if self.args["password"] != input_verify:
                    self.errors += 1
                    return ('',"Your passwords didn't match")
                return (input_verify, "")
            return ('','')

        if field == "email":
            input_email = self.request.get(field)
            if input_email == "":
                return ('','')

        if field == "post_id":
            input_post_id = self.request.get(field)
            if input_post_id.isdigit():
                return (input_post_id,"")

            else:
                self.errors += 1
                return ("","Post id missing")

        return (self.request.get(field),'')

class UdPyBlogPostHandler(UdPyBlogSignupHandler):
    restricted = True
    fields = [ 'subject', 'summary', 'content' ]
    required = fields

    def post(self, post_id=None):
        self.auth()
        self.args["update"] = self.update

        for field in self.fields:
            self.args[field],self.args['error_' + field] = '',''
            self.args[field],self.args['error_' + field] = self.validate(field)

        self.args["update"] = self.update
        self.args["cover_image"] = None
        self.args["cover_image_url"] = None
        if self.request.get('cover_image_url'):
            self.args["cover_image_url"] = self.request.get('cover_image_url')
            self.args["cover_image"] = UdPyBlogImage.all().filter(
                "blob_key =",
                os.path.basename(
                    self.request.get('cover_image_url')
                )
            ).get()

        if self.errors > 0:
            logging.info("ERRORS: " + str(self.errors) + "")
            self.args["upload_url_source"] = self.url_prefixed("image/upload_url")
            self.render(
                "blog_form.html",
                **self.args
            )
            return

        else:
            if not self.update:
                cover_image_key = None
                if self.args["cover_image"]:
                    cover_image_key = self.args["cover_image"].key()
                post = UdPyBlogPost(
                    subject = self.request.get("subject"),
                    summary = self.request.get("summary"),
                    cover_image = cover_image_key,
                    content = UdPyBlog.sanitize_post(self.request.get("content")),
                    user = self.user
                )
            else:
                post = UdPyBlogPost.get_by_id(int(self.args["post_id"]))
                if not post or post.user.username != self.user.username:
                    self.redirect_prefixed("post/{0}".format(self.args["post_id"]))
                    return

                post.content = self.args["content"]
                post.summary = self.args["summary"]
                post.subject = self.args["subject"]
                if self.args["cover_image"]:
                    post.cover_image = self.args["cover_image"]

                elif post.cover_image:
                    logging.info("Deleteing previous cover")
                    blobstore.delete(post.cover_image.blob_key.key())
                    post.cover_image.delete()
                    post.cover_image = None

            post.put()
            if self.args["cover_image"]:
                self.args["cover_image"].post = post.key()
                self.args["cover_image"].put()

            blog_entity_context = {
                "post_id": post.key().id(),
                "username": self.user.username
            }

            self.response.headers.add_header(
                "Blog-Entity-Context",
                json.dumps(blog_entity_context)
            )
            self.redirect_prefixed("post/{0}".format(post.key().id()))
            return

        self.render(
            "blog_form.html",
            **self.args
        )

    def get(self):
        self.auth()
        self.render(
            "blog_form.html",
            **{
                "subject": self.request.get("subject"),
                "content": self.request.get("content"),
                "post_id": None,
                "update": self.update,
                "upload_url_source": self.url_prefixed("image/upload_url")
            }
        )

class UdPyBlogPostUpdateHandler(UdPyBlogPostHandler):
    update=True
    def get(self, post_id):
        self.no_cache()
        self.auth()
        if post_id.isdigit():
            post = UdPyBlogPost.get_by_id(int(post_id))
            if post:
                if post.user.key() != self.user.key():
                    self.redirect_prefixed('post/{}'.format(post_id))
                    return

                self.render(
                    "blog_form.html",
                    **{
                        "subject": post.subject,
                        "summary": post.summary,
                        "content": post.content,
                        "post_id": post_id,
                        "update": self.update,
                        "cover_image_url": post.cover_image and self.url_prefixed("{0}{1}".format(UdPyBlog.image_view_url_part,post.cover_image.blob_key.key())),
                        "upload_url_source": self.url_prefixed("image/upload_url")
                    }
                )
                return

            else:
                logging.info("ERROR")
                self.render("blog_main.html",error = "ID not found (" + str(post_id) + ")")
                return
        else:
            self.redirect_prefixed('')

class UdPyBlogPostCommentHandler(UdPyBlogPostHandler):
    """Handling comments posted on a post"""

    fields = [ 'subject', 'content' ]
    required = fields
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
            logging.info(self.args)
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

            blog_entity_context = {
                "post_id": post.key().id(),
                "comment_id": comment.key().id(),
                "username": self.user.username
            }

            self.response.headers.add_header(
                "Blog-Entity-Context",
                json.dumps(blog_entity_context)
            )

            self.redirect_prefixed("post/{0}".format(comment.key().id()))
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
            blog_entity_context = {
                "post_id": post.key().id(),
                "comment_id": comment.key().id(),
                "username": self.user.username
            }

            self.response.headers.add_header(
                "Blog-Entity-Context",
                json.dumps(blog_entity_context)
            )

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
    required = fields
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
            logging.info("ERRROOROROR!!! " + str(self.errors))
            return

        else:
            user = UdPyBlogUser.all().filter('username =', self.args["username"]).get()
            if user:
                logging.info("User match!!!")
                if self.make_hash(self.args["password"], user.salt ) == user.password:
                    logging.info("Password match!!!")
                    self.response.headers.add_header("Set-Cookie", str("%s=%s|%s; path=/" % ( "access", self.make_hash(user.username, user.salt ), user.key().id() ) ) )
                    blog_entity_context = {
                        "username": user.username
                    }
                    self.response.headers.add_header(
                        "Blog-Entity-Context",
                        json.dumps(blog_entity_context)
                    )
                    if 'redirect' in self.session and self.session['redirect']:
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
        ('post/([0-9]+)', UdPyBlogPostViewHandler),
        ('post/([0-9]+)/like', UdPyBlogPostLikeHandler),
        ('post/([0-9]+)/update', UdPyBlogPostUpdateHandler),
        ('post/([0-9]+)/comment', UdPyBlogPostCommentHandler),
        ('post/([0-9]+)/comment/([0-9]+)/edit', UdPyBlogPostCommentEditHandler),
        ('post/([0-9]+)/comment/([0-9]+)/delete', UdPyBlogPostCommentDeleteHandler),
        ('init', UdPyBlogInitHandler),
        ('newpost', UdPyBlogPostHandler),
        ('image/upload_url',UdPyBlogImageUploadPrepareHandler),
        ('image/upload',UdPyBlogImageUploadHandler)
    ]

    regexp = {
        "username": r"[a-zA-Z0-9_-]+",
        "email": r"[\S]+@[\S]+\.[\S]",
        "subject": r"[^\r\n\t]"
    }

    template_folder = "dist/templates"
    blog_prefix = "/"
    static_path_prefix = ""
    jinja_env = None
    input_requirements = {
        "password": {
            "min": 3,
            "max": 20
        },
        "username": {
            "min": 3,
            "max": 20
        },
        "summary": {
            "min": 10,
            "max": 500
        },
        "subject": {
            "min": 6,
            "max": 500
        },
        "content": {
            "min": 10,
            "max": 10000
        }
    }
    @classmethod
    def prepare(cls, config = None):
        if config:
            if "template_folder" in config:
                cls.template_folder = config["template_folder"]

            if "blog_prefix" in config:
                cls.blog_prefix = config["blog_prefix"]

            if "forbidden_tags" in config:
                cls.forbidden_tags = config["forbidden_tags"]

            if "image_view_url_part" in config:
                cls.image_view_url_part = config["image_view_url_part"]

            if "input_requirements" in config:
                cls.input_requirements = cls.merge_dicts(
                    cls.input_requirements,
                    config["input_requirements"]
                )

        cls.template_dir = os.path.join(
            os.path.dirname(__file__),
            cls.template_folder
        )
        cls.jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(cls.template_dir))

    @classmethod
    def get_routes(cls):
        cls.routes.append((UdPyBlog.image_view_url_part + "(.+)",UdPyBlogImageViewHandler))
        if cls.blog_prefix:
            routes_prefixed = []
            for route in cls.routes:
                routes_prefixed.append((cls.blog_prefix + route[0],route[1]))
            return routes_prefixed
        else:
            return cls.routes

    @classmethod
    def validate_input(cls, field, input, required):
        if not input:
            if required:
                return "Field empty"
            else:
                return True

        if field in cls.input_requirements:
            if len(input) < cls.input_requirements[field]["min"]:
                return "Input too short"

            if len(input) > cls.input_requirements[field]["max"]:
                return "Input too long"

        if field in cls.regexp:
            if not re.match(
                cls.regexp[field],
                input
            ):
                return "Input contains illegal characters"
        return True

    @classmethod
    def sanitize_post(cls, content):
        """Fix all blob references to actual image viewing urls. Replace/filter forbidden tags."""
        quoteds = re.findall(r'["\'][^"\']+["\']',content)
        for quoted in quoteds:
            match = re.search(r'encoded_gs_file:[^"\']+(["\'])$',quoted)
            if match:
                content = content.replace(quoted, match.group(1) + self.url_prefixed("image/view") + match.group(0))

        for (tag, replacement) in cls.forbidden_tags:
            if replacement:
                replacer = ('<' + tag, '<' + replacement), ('</' + tag + '>', '</' + replacement + '>')
            else:
                replacer = ('<' + tag, ''), ('</' + tag + '>', '')

            logging.info(replacer)
            content= reduce(lambda a, kv: a.replace(*kv), replacer, content)
        logging.info("SANETIZED: "  + content)

        return content

    @classmethod
    def error_handler(cls, request, response, exception):
        response.out.write(
            cls.render_template(
                "error.html",
                exception=exception,
                response=response,
                user=UdPyBlogUser.empty()
            )
        )

    @classmethod
    def render_template(cls, template_file, **params):
        logging.info("recieved to render!")
        logging.info(params)

        logging.info("----------" + template_file + "-------------")

        template = cls.jinja_env.get_template(template_file)
        logging.info("-------q---" + template_file + "-------------")
        logging.info(template.render)
        logging.info(params)

        return template.render(**params)

    @classmethod
    def inject(cls, app):
        app.error_handlers[404] = cls.error_handler
        app.error_handlers[403] = cls.error_handler
        app.error_handlers[500] = cls.error_handler

    @classmethod
    def merge_dicts(cls, *dict_args):
        """
        Given any number of dicts, shallow copy and merge into a new dict,
        precedence goes to key value pairs in latter dicts.
        """
        result = {}
        for dictionary in dict_args:
            result.update(dictionary)
        return result
