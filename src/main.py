import os
import jinja2
import hashlib
import hmac
import string
import random
import webapp2
import re
import logging

config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'dfs8df7sdkljjlkj',
}
from google.appengine.ext import db

from udpyblog import *
udpyblog_prefix = "/"

app = webapp2.WSGIApplication(
    [] + udpyblog_get_routes(udpyblog_prefix),
    config=config,
    debug=True
)
