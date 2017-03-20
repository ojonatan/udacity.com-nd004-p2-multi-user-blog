#!/usr/bin/env python
# -*- coding: utf-8 -*

"""UdPyBlog: Multi User Blog APP"""

import os
import jinja2
import hashlib
import hmac
import string
import random
import webapp2
import re
import logging
import udpyblog_config
from google.appengine.ext import db
from udpyblog import *

config = udpyblog_config.config
config['webapp2_extras.sessions'] = {
    'secret_key': 'dfs8df7sdkljjlkj'
}

UdPyBlog.prepare(config['udpyblog'])
app = webapp2.WSGIApplication(
    [] + UdPyBlog.get_routes(),
    config=config,
    debug=True
)
UdPyBlog.inject(app)
