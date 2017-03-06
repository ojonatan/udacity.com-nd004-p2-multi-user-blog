#!/usr/bin/env python
# -*- coding: utf-8 -*

"""Generating/updating project related files"""

import hashlib
import re
import os
import binascii
import datetime
import time

genrated = datetime.datetime.now().isoformat()

readme_template = open("README.md-template").read()
readme = readme_template.format(
    genrated=genrated
)

readme_file = open("README.md","w+")
readme_file.write(readme)
readme_file.close()
