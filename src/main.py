import os
import jinja2
import hashlib
import hmac
import string
import random
import webapp2
import re
from google.appengine.ext import db

from udpyblog import *
udpyblog_prefix = ""

app = webapp2.WSGIApplication([
] + udPygetRoutes(udpyblog_prefix), debug=True)
