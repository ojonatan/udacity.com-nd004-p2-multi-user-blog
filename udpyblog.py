#!/usr/bin/env python
# -*- coding: utf-8 -*

"""UdPyBlog: Multi User Blog Module"""

import os
import jinja2
import hashlib
import hmac
import string
import random
import datetime
import webapp2
import re
import logging
import json
import sys
import cgi
import time
from paging import PagedQuery
from webapp2_extras import sessions

from google.appengine.ext import db
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from google.appengine.api import app_identity
from google.appengine.api import memcache

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


class UdPyBlogUser(UdPyBlogEntity):
    legit = True
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    lastlog = db.DateTimeProperty(auto_now_add = True)

    def get_fancy_date(self):
        return self.created.strftime(UdPyBlog.config["post_date_template"])

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
    summary = db.StringProperty(required = True, multiline = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    categories = db.ListProperty(db.Key)
    user = db.ReferenceProperty(UdPyBlogUser, collection_name='posts')

    def get_fancy_date(self):
        return self.created.strftime(UdPyBlog.config["post_date_template"])

    def get_likes_count(self):
        return self.users_who_like.count()

    def get_comments_count(self):
        return self.comments.count()

    def get_summary(self):
        return re.sub(r"\r?\n","<br>",self.summary)


class UdPyBlogPostComment(UdPyBlogEntity):
    legit = True
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    categories = db.ListProperty(db.Key)
    user = db.ReferenceProperty(UdPyBlogUser, collection_name='users')
    post = db.ReferenceProperty(UdPyBlogPost, collection_name='comments')
    @classmethod
    def empty(cls, **attributes):
        defaults = {
            "subject": "",
            "content": "",
            "created": "",
            "categories": "",
            "user": None,
            "post": None
        }
        defaults.update(attributes)
        return UdPyBlogEmptyModel(defaults)

    def get_fancy_date(self):
        return self.created.strftime(UdPyBlog.config["post_date_template"])

    def get_content(self):
        return re.sub(r"\r?\n","<br>",self.content)

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
    created = db.DateTimeProperty(auto_now_add = True)

    def get_fancy_date(self):
        return self.created.strftime(UdPyBlog.config["post_date_template"])

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

    def get_fancy_date(self):
        return self.created.strftime(UdPyBlog.config["post_date_template"])

class UdPyBlogHandler(webapp2.RequestHandler):
    signup = False
    login = False
    restricted = False
    update = False
    user = None
    secret = "HmacSecret"
    salt_length = 13
    logout = False
    request_override = {}

    def get_request_var(self, var):
        if self.request_override:
            if var in self.request_override:
                return self.request_override[var]

        return self.request.get(var)

    def dispatch(self):
        self.request_override = {}
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
        return self.session_store.get_session(backend='memcache')

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def url_prefixed(self, fragment):
        return self.request.scheme + "://" + self.request.host + UdPyBlog.config["blog_prefix"] + fragment

    def redirect_prefixed(self, fragment, code=None):
        self.redirect(UdPyBlog.config["blog_prefix"] + fragment, code=code)

    def render_str(self, template_file, **params):
        params = params or {}
        params["image_url_prefix"] = self.url_prefixed(UdPyBlog.config["image_view_url_part"])
        params["login_page"] = self.login
        params["signup_page"] = self.signup
        params["url_prefix"] = UdPyBlog.config["blog_prefix"]
        params["config"] = UdPyBlog.config
        params["user"] = UdPyBlogUser.empty()
        if self.user:
            params["user"] = self.user

        return UdPyBlog.render_template(template_file, **params)

    def render(self, template_file, **kw):
        self.write(self.render_str(template_file, **kw))

    def render_json(self, payload):
        self.response.headers['Content-Type'] = 'application/json'
        self.response.out.write(json.dumps(payload))

    def get_redirection(self, rightaway=True):
        if not "redirect" in self.session:
            return

        if not self.session.get("redirect"):
            logging.info("NOOOOOOO2OOOOOOOOO REDIT")
            return

        logging.info(">>>>>>>>>>>>>>>>>> Checking for redirection >> {}|{}!!! {}".format(self.session.get("redirect"),self.session["redirect"],rightaway))
        redirects = self.session.get("redirect")
        redirect = redirects.pop(0)

        logging.info(">>>>>>>>>>>>>>>>>> REEEEEEEEEEEEDIRECT {}".format(redirect))
        self.session["redirect"] = redirects
        if not rightaway:
            return redirect

        if redirect:
            self.redirect(redirect)
            return True

        return False

    def auth(self):
        logging.info("+++++++++++ 1")

        try:
            logging.info("+++++++++++ XXXXXXXXXXXXXXXX")
            if not self.session.get("created"):
                self.session["created"] = time.time()
            logging.info("+++++++++++ YYYYYYYYYYYYYYYYYY")
        except:
            logging.info(sys.exc_info())
            self.error(500)

        logging.info("+++++++++++ 2")
        if self.user:
            UdPyBlogUser.get_by_id(int(access[1]))

        logging.info("+++++++++++ 3")
        if "access" in self.request.cookies:
            if not self.request.cookies.get("access") and not self.restricted:
                logging.info("+++++++++++ 3 free access no ccokie")
                return True

            access = self.request.cookies.get("access").split("|")

            logging.info("+++++++++++ 5")

            access = self.request.cookies.get("access").split("|")
            if len(access) == 2:
                logging.info("+++++++++++ 6")
                user = UdPyBlogUser.get_by_id(int(access[1]))
                if user and self.validate_user(user, access):
                    logging.info("+++++++++++ 7 LOGGED IN AS {}".format(user.username))
                    self.user = user
                    logging.info("REDIRECTION CHECK 1")
                    # do not redirect if override is mulidict - pending post!!
                    if self.request_override.__class__.__name__ != "UnicodeMultiDict":
                        if self.get_redirection():
                            return False

                    return True

                logging.info("+++++++++++ 8")

                if not self.restricted:
                    logging.info("+++++++++++ 9")
                    return True

        if not self.restricted:
            logging.info("+++++++++++ 10 NOT RESTRICTED!!!!!!!!!")
            return True


        # if something goes wrong and we are on the way to log out, no redir
        # logout handler will kill all
        if self.logout:
            return True

        logging.info("+++++++++++ 11")
        # store the original url in order to redirect on success!

        redirects = [ self.request.url ]
        if self.request.method == "POST":
            # freeze vars for thaw in get

            logging.info(self.request.POST.__class__.__name__)
            logging.info(self.request.cookies["session"])
            logging.info("+++++TTTTTTTTTTTTTT++++++ 11")
            logging.info("URL " + self.request.url)
            logging.info(self.request.POST)

            self.session["request_override"] = self.request.POST

            redirects.append(self.request.referer)

        self.session["redirect"] = redirects

        logging.info("+++++++++++ REDIR! 12")
        logging.info("%%%%%%%%%%%%CREATED: {}!!!!!!!!! ".format(self.session.get("created")))

        self.redirect_prefixed("login")
        return False

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

    def get_image_upload_url(self):
        self.no_cache()
        bucket = app_identity.get_default_gcs_bucket_name()
        return blobstore.create_upload_url(
            '/image/upload',
            gs_bucket_name=bucket
        )

    def process_images(self, post=None, expiry=None):
        """
        This function should be triggered by new/update post post requests.
        It assigns uploaded images as detected in the content to the
        post_id in the parameter and deletes all the remaining images
        """

        if post:
            logging.info("checking for {}".format(post.key()));

            images_stored = UdPyBlogImage.all().filter('user =', self.user.key())
            images_check = []
            for image in images_stored:
                if post.cover_image and post.cover_image.blob_key.key() == image.blob_key.key():
                    logging.info("Skipping cover image...");
                    continue

                if not image.post or image.post.key() == post.key():
                    images_check.append(str(image.blob_key.key()))

            images = re.findall("encoded_gs_file:[a-zA-Z0-9]+",post.content)

            if images:
                logging.info("Post references {} images: {}".format(len(images),images));
            else:
                images = []

            logging.info("Images found that are related to this post or not yet to any: {}".format(images_check));
            images_dropped = list(set(images_check) - set(images))

            logging.info("Purging {} unmapped images. ({}...)".format(len(images_dropped),images_dropped[0:3]))
        else:
            if self.user:
                images_stored = UdPyBlogImage.all().filter('user =', self.user.key()).filter('post =', None)
                images_dropped = []
                for image in images_stored:
                    images_dropped.append(str(image.blob_key.key()))

            elif expiry:
                logging.info("Purging expired images ({})".format(expiry));
                images_stored = UdPyBlogImage.all().filter('post =', None).filter('created <', expiry)
                images_dropped = []
                for image in images_stored:
                    images_dropped.append(str(image.blob_key.key()))


        for image in images_dropped:
            logging.info("KEY::::::::::{}:::::".format(image))
            for image_placed in UdPyBlogImage.all().filter('blob_key = ', image):
                logging.info("Purging {}".format(image_placed.blob_key.key()))
                blob_info = blobstore.BlobInfo.get(image_placed.blob_key.key())
                if blob_info:
                    blob_info.delete()

                image_placed.delete()

        if post:
            for blob_key in images:
                try:
                    logging.info("Adding image " + blob_key)
                    image_placed = UdPyBlogImage.all().filter('blob_key = ', blob_key).get()
                    image_placed.post = post.key()
                    image_placed.put()
                except:
                    logging.info(sys.exc_info())
                    self.error(500)

class UdPyBlogTaskHandler(UdPyBlogHandler):
    def auth(self):
        return self.request.headers.get("X-AppEngine-Cron") == "true"

class UdPyBlogImageUploadPrepareHandler(blobstore_handlers.BlobstoreUploadHandler, UdPyBlogHandler):
    def get(self):
        self.no_cache()
        self.render_json({
            "upload_url": self.get_image_upload_url()
        })

class UdPyBlogImageUploadHandler(blobstore_handlers.BlobstoreUploadHandler, UdPyBlogHandler):
    def post(self):
        if not self.auth():
            return

        try:
            logging.info("_________________________________________________________")
            upload = self.get_uploads()[0]
            uploaded_image = UdPyBlogImage(
                session=self.request.cookies["session"],
                user=self.user,
                blob_key=upload.key()
            )
            uploaded_image.put()
            self.render_json(
                {
                  "location": self.url_prefixed('%s%s' % (UdPyBlog.config["image_view_url_part"], upload.key()))
                }
            )

        except:
            logging.info("_________________________________________________________")
            logging.info(self.request.cookies)
            logging.info(sys.exc_info())
            self.error(500)

class UdPyBlogImageViewHandler(blobstore_handlers.BlobstoreDownloadHandler, UdPyBlogHandler):
    def get(self, image_key):
        if not self.auth():
            return

        logging.info("VIEWER")
        if not blobstore.get(image_key):
            self.error(404)
        else:
            self.send_blob(image_key)

class UdPyBlogPostViewHandler(UdPyBlogHandler):
    url = "post"
    def get(self, post_id):

        if not self.auth():
            return

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

        if not self.auth():
            return

        self.render(
            "blog_welcome.html",
            **{
                "redirect": self.get_redirection(False)
            }
        )

class UdPyBlogSignupHandlerLogout(UdPyBlogHandler):
    logout = True
    restricted = False
    def get(self):

        if not self.auth():
            return

        if self.user:
            self.process_images()

        self.session.clear()
        self.response.headers.add_header("Set-Cookie", str("%s=%s; path=/" % ( "session","" ) ) )

        if "access" in self.request.cookies:
            self.response.headers.add_header(
                "Set-Cookie",
                str("%s=%s; path=/" % ( "access","" ) )
            )

        if not self.user:
            self.redirect_prefixed("")
            return

        self.user = None
        self.redirect_prefixed("")

class UdPyBlogPostLikeHandler(UdPyBlogHandler):
    """Register or unregister (toggle) likes for a specific post. Only
    logged in users other than the author are allowed to like a post."""

    restricted = True

    def get(self, post_id):
        logging.info("____________ forward to post {}".format(self.request.cookies["session"]))
        logging.info(self.session.get("request_override"))
        logging.info(self.session.get("created"))
        if self.session.get("request_override").__class__.__name__ == "UnicodeMultiDict":
            logging.info("->->->->-> REQUEST OVERRIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIDE")
            self.request_override = self.session.get("request_override")
            self.session["request_override"] = None
            self.post(post_id, thaw=True)
            return

        logging.info(self.session)
        self.error(403)
        return

    def post(self, post_id, thaw=False):
        logging.info("****************LIKIKNE")
        if not thaw and self.request.referer:
            try:

                redirects = self.session.get("redirect")
                if redirects:
                    redirects.append(self.request.referer)
                    self.session["redirect"] = redirects
            except:
                logging.info(sys.exc_info())

        if not self.auth():
            return

        if not self.user:
            self.redirect_prefixed("")
            return

        post = UdPyBlogPost.get_by_id(int(post_id))
        if not post or post.user.username == self.user.username:
            if not post:
                logging.info("Post <<{}>> doesn't exist".format(post_id))

            if post.user.username == self.user.username:
                logging.info("User {} may not like his own post!".format(self.user.username))

            self.error("403")
            self.render("error.html")
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


        if self.get_redirection():
            return

        self.redirect_prefixed("")
        return

class UdPyBlogMainHandler(UdPyBlogHandler):
    def get(self, page_id=None):

        if not self.auth():
            return

        posts = []
        posts_query = PagedQuery(UdPyBlogPost.all().order('-created'), UdPyBlog.config["posts_per_page"])
        pages_total = posts_query.page_count()

        if not page_id:
            page_id = 1
        else:
            page_id = int(page_id)

        posts = posts_query.fetch_page(page_id)
        page_next=None
        if pages_total > page_id:
            page_next = (page_id + 1)

        page_prev=None
        if page_id > 1:
            page_prev = (page_id - 1)

        self.render(
            "blog_main.html",
            **{
                "posts": posts,
                "pages": pages_total,
                "page_prev": page_prev,
                "page_next": page_next
            }
        )

class UdPyBlogSignupHandler(UdPyBlogHandler):
    signup = True
    fields = [ 'username','password','verify','email' ]
    required = [ 'username','password' ]

    errors = 0
    args = {}

    def get(self):

        if not self.auth():
            return

        for field in self.fields:
            self.args[field], self.args['error_' + field] = '',''

        self.render("signup.html", **self.args )

    def post(self):
        if not self.auth():
            return

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
        logging.info("VAAAAAAAAAAAAAAAAAAA1>>>>>>>>>>>")
        try:
            logging.info(self.get_request_var(field))
        except:
            logging.info("EEEEEEEEEEEEEEEEEE>>>>>>>>>>>")
            logging.info(sys.exc_info())

        # Check for validity of entered data agains re and length reqs
        # Higher level checks only if no error here
        error = UdPyBlog.validate_input(
            field,
            self.get_request_var(field),
            field in self.required
        )
        logging.info("VAAAAAAAAAAAAAAAAAAA 2 >>>>>>>>>>>")
        if error != True:
            self.errors += 1
            return (self.get_request_var(field),error)

        if field == "username":
            if not self.login:
                if UdPyBlogUser.all().filter('username =', self.get_request_var(field)).count() > 0:
                    self.errors += 1
                    return (self.get_request_var(field),"That user already exists")

            return (self.get_request_var(field),'')

        if field == "subject":
            return (cgi.escape(self.get_request_var(field)),'')

        if field == "summary":
            return (cgi.escape(self.get_request_var(field)),'')

        if field == "verify":
            input_verify = self.get_request_var(field)
            if "password" in self.args and self.args["password"] != "":
                if self.args["password"] != input_verify:
                    self.errors += 1
                    return ('',"Your passwords didn't match")
                return (input_verify, "")
            return ('','')

        if field == "email":
            input_email = self.get_request_var(field)
            if input_email == "":
                return ('','')

        if field == "post_id":
            input_post_id = self.get_request_var(field)
            if input_post_id.isdigit():
                return (input_post_id,"")

            else:
                self.errors += 1
                return ("","Post id missing")

        return (self.get_request_var(field),'')

class UdPyBlogPostHandler(UdPyBlogSignupHandler):
    restricted = True
    fields = [ 'subject', 'summary', 'content' ]
    required = fields

    def post(self, post_id=None):
        if not self.auth():
            return

        self.args["update"] = self.update

        for field in self.fields:
            self.args[field],self.args['error_' + field] = '',''
            self.args[field],self.args['error_' + field] = self.validate(field)

        self.args["update"] = self.update
        self.args["cover_image"] = None
        self.args["cover_image_url"] = None
        if self.get_request_var('cover_image_url'):
            self.args["cover_image_url"] = self.get_request_var('cover_image_url')
            self.args["cover_image"] = UdPyBlogImage.all().filter(
                "blob_key =",
                os.path.basename(
                    self.get_request_var('cover_image_url')
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
                    subject = self.args["subject"],
                    summary = self.args["summary"],
                    cover_image = cover_image_key,
                    content = UdPyBlog.sanitize_post(self.args["content"]),
                    user = self.user
                )

            else:
                post = UdPyBlogPost.get_by_id(int(post_id))
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

            logging.info("Processing contained and dropped images from the current post...")
            self.process_images(post=post)

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

        if not self.auth():
            return

        self.render(
            "blog_form.html",
            **{
                "subject": self.get_request_var("subject"),
                "content": self.get_request_var("content"),
                "post_id": None,
                "update": self.update,
                "upload_url": self.get_image_upload_url(),
                "upload_url_source": self.url_prefixed("image/upload_url")
            }
        )

class UdPyBlogPostUpdateHandler(UdPyBlogPostHandler):
    update=True
    def get(self, post_id):
        self.no_cache()

        if not self.auth():
            return

        if post_id.isdigit():
            post = UdPyBlogPost.get_by_id(int(post_id))
            if post:
                if post.user.key() != self.user.key():
                    self.redirect_prefixed('post/{}'.format(post.key().id()))
                    return

                self.render(
                    "blog_form.html",
                    **{
                        "subject": post.subject,
                        "summary": post.summary,
                        "content": post.content,
                        "post_id": post_id,
                        "update": self.update,
                        "cover_image_url": post.cover_image and self.url_prefixed("{0}{1}".format(UdPyBlog.config["image_view_url_part"],post.cover_image.blob_key.key())),
                        "upload_url": self.get_image_upload_url(),
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
    def validate(self,field):

        # Check for validity of entered data agains re and length reqs
        # Higher level checks only if no error here
        error = UdPyBlog.validate_input(
            field,
            self.get_request_var(field),
            field in self.required
        )
        if error != True:
            self.errors += 1
            return (self.get_request_var(field),error)

        if field == "subject":
            return (cgi.escape(self.get_request_var(field)),'')

        if field == "content":
            return (cgi.escape(self.get_request_var(field)),'')

    def get(self, post_id):
        logging.info("COMMENT POST VIA GET!!!!!!!!!!!!!!!!!!!!")
        logging.info(self.session.get("request_override"))
        # calling this per get requests requires a frozen post!
        if self.session.get("request_override").__class__.__name__ == "UnicodeMultiDict":
            self.request_override = self.session.get("request_override")
            self.session["request_override"] = None
            self.post(post_id, thaw=True)
            return

        self.error(403)
        return

    def post(self, post_id, thaw=False):
        if not self.auth():
            return

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
            self.args["comment"] = UdPyBlogPostComment.empty(
                **{
                    "subject": self.args["subject"],
                    "content": self.args["content"]
                }
            )

            self.render(
                "blog_post.html",
                **self.args
            )
            return

        else:
            if not self.update:
                comment = UdPyBlogPostComment(
                    subject = self.args["subject"],
                    content = self.args["content"],
                    post = post,
                    user = self.user
                )

            else:
                comment = UdPyBlogPostComment.get_by_id(int(self.args["comment_id"]))
                if not post or post.user.username != self.user.username:
                    self.redirect_prefixed("post/{0}".format(int(post_id)))
                    return

                comment.content = self.args["content"]
                comment.subject = self.args["subject"]

            comment.put()

            blog_entity_context = {
                "post_id": post.key().id(),
                "comment_id": comment.key().id()
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
                "comment": UdPyBlogPostComment.empty(
                    **{
                        "subject": self.args["content"],
                        "content": self.args["subject"]
                    }
                ),
                "post": post
            }
        )

class UdPyBlogPostCommentDeleteHandler(UdPyBlogPostCommentHandler):
    """Handling comment deletions on a post"""

    restricted = True
    def get(self, post_id, comment_id):

        if not self.auth():
            return

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

        if not self.auth():
            return

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
        if not self.auth():
            return

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
                    subject = self.get_request_var('subject'),
                    content = self.get_request_var('content'),
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
                "subject": self.get_request_var("subject"),
                "content": self.get_request_var("content"),
                "created": self.get_request_var("created")
            }
        )

class UdPyBlogInitHandler(UdPyBlogSignupHandler):
    fields = [ "password" ]
    def get(self):

        if not self.auth():
            return

        self.render( "init.html" )

    def post(self):
        if not self.auth():
            return

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

class UdPyBlogPostCleanUpHandler(UdPyBlogTaskHandler):
    def get(self):
        if self.auth():
            try:
                logging.info("Starting Clean Up")
                self.process_images(
                    expiry=(
                        datetime.datetime.today()
                        +
                        datetime.timedelta(
                            seconds=(
                                UdPyBlog.config["blob_expiry_seconds"] * -1
                            )
                        )
                    )
                )
            except:
                logging.info(sys.exc_info())
            self.code(200)
            return

        self.code(403)
        return

class UdPyBlogSignupHandlerLogin(UdPyBlogSignupHandler):
    fields = [ "username","password" ]
    required = fields
    login = True
    def get(self):
        logging.info("///////////////////////////////////>>>>>>>>>>>")

        if not self.auth():
            return

        self.response.headers.add_header("Set-Cookie", str("%s=%s; path=/" % ( "access","" ) ) )
        self.render( "login.html" )

    def post(self):
        logging.info("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX>>>>>>>>>>>")
        if not self.auth():
            return

        logging.info("LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO>>>>>>>>>>>")

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

                    self.user = user
                    self.process_images()

                    logging.info("REDIRECTION CHECK 3 {}".format(self.user))
                    if self.get_redirection():
                        logging.info("REDIRECTION SUCCCESSFUL!!! ".format(self.user))
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
        ('page/([0-9]+)', UdPyBlogMainHandler),
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
        ('image/upload',UdPyBlogImageUploadHandler),
        ('_cleanup', UdPyBlogPostCleanUpHandler) # featured by cron
    ]

    config = {
        "template_folder": "dist/templates",
        "blog_prefix": "/",
        "blob_expiry_seconds": (5*24*3600),
        "static_path_prefix": "",
        "post_date_template": "%d, %b %Y, %I:%M%p",
        "comment_date_template": "%d, %b %Y, %I:%M%p",
        "posts_per_page": 4,
        "input_requirements": {
            "email": {
                "min": 6,
                "max": 250
            },
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
                "max": 250
            },
            "subject": {
                "min": 6,
                "max": 80
            },
            "content": {
                "min": 10,
                "max": 10000
            }
        }
    }

    regexp = {
        "username": r"[a-zA-Z0-9_-]+",
        "email": r"[\S]+@[\S]+\.[\S]",
        "subject": r"[^\r\n\t]"
    }
    jinja_env = None

    @classmethod
    def prepare(cls, config = None):
        if config:
            if "template_folder" in config:
                cls.config["template_folder"] = config["template_folder"]

            if "blog_prefix" in config:
                cls.config["blog_prefix"] = config["blog_prefix"]

            if "forbidden_tags" in config:
                cls.config["forbidden_tags"] = config["forbidden_tags"]

            if "image_view_url_part" in config:
                cls.config["image_view_url_part"] = config["image_view_url_part"]

            if "blob_expiry_seconds" in config:
                cls.config["blob_expiry_seconds"] = config["blob_expiry_seconds"]

            if "post_date_template" in config:
                cls.config["post_date_template"] = config["post_date_template"]

            if "comment_date_template" in config:
                cls.config["comment_date_template"] = config["comment_date_template"]

            if "posts_per_page" in config:
                cls.config["posts_per_page"] = config["posts_per_page"]

            if "input_requirements" in config:
                cls.config["input_requirements"] = cls.merge_dicts(
                    cls.config["input_requirements"],
                    config["input_requirements"]
                )

        cls.template_dir = os.path.join(
            os.path.dirname(__file__),
            cls.config["template_folder"]
        )
        cls.jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(cls.template_dir))

    @classmethod
    def get_routes(cls):
        cls.routes.append((UdPyBlog.config["image_view_url_part"] + "(.+)",UdPyBlogImageViewHandler))
        if cls.config["blog_prefix"]:
            routes_prefixed = []
            for route in cls.routes:
                routes_prefixed.append((cls.config["blog_prefix"] + route[0],route[1]))
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

        if field in cls.config["input_requirements"]:
            if len(input) < cls.config["input_requirements"][field]["min"]:
                return "Input too short"

            if len(input) > cls.config["input_requirements"][field]["max"]:
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

        for (tag, replacement) in cls.config["forbidden_tags"]:
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
        logging.info("EORORROORORORRORO"+request.url)
        logging.info(sys.exc_info())
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

        logging.info(sys.exc_info())
        logging.info("---A-------<<{}>> --------------".format(template_file))

        template = cls.jinja_env.get_template(template_file)
        logging.info("---B----q---" + template_file + "-------------")
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
