#!/usr/bin/env python
# -*- coding: utf-8 -*

"""Generating/updating project related files"""

import hashlib
import re
import os
import binascii
import datetime
import time
import logging
import sys
import subprocess
import json
import textwrap
import test_report

def read_file(uri):
    with open(uri, 'r') as file:
        return file.read()

path = os.path.dirname(os.path.realpath(__file__))

prefix = 'build-{}-'.format(int(time.time()))
prefix_file_name = 'udpyblog_test_prefix.py'
prefix_file = open('udpyblog_test_prefix.py','w+')
prefix_file.write('prefix = "{}"'.format(prefix))
prefix_file.close()

cmd = r'nosetests -s -v --with-gae --gae-lib-root="C:\Users\oschleede\AppData\Local\Google\Cloud SDK\google-cloud-sdk\platform\google_appengine" udpyblog_test.py 2> log.txt'

tests = not os.system( cmd )

os.remove( prefix_file_name )

test_report = test_report.format_report(
    **{
        'prefix': prefix
    }
)

report_name = prefix + 'udpyblog_test.txt'
report_file = open(report_name,'w+')
report_file.write("\n".join(test_report))
report_file.close()

genrated = datetime.datetime.now().isoformat()

readme_template = open("README.md-template").read()
readme = readme_template.format(
    genrated=genrated,
    test_report="\n".join(test_report)
)

readme_file = open("README.md","w+")
readme_file.write(readme)
readme_file.close()
