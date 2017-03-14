import os
import jinja2
import hashlib
import hmac
import string
import random
import webapp2
import re
import logging
from google.appengine.ext import db
from udpyblog import *

config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'dfs8df7sdkljjlkj',
}

config['udpyblog'] = {
    "blog_prefix": "/",
    "template_folder": "dist/templates",
    "init_pass": "reset all data!",
    "forbidden_tags": [ ('h1','h3'), ('h2','h4'), ('script','p'), ('a','span') ],
    "image_view_url_part": "image/view/",
    "input_requirements": {
        "password": {
            "min": 3,
            "max": 20
        }
    },
    "image_view_url_part": "image/view/"
}

UdPyBlog.prepare(config['udpyblog'])
app = webapp2.WSGIApplication(
    [] + UdPyBlog.get_routes(),
    config=config,
    debug=True
)
UdPyBlog.inject(app)
