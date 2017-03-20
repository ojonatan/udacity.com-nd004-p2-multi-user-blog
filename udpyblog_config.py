#!/usr/bin/env python
# -*- coding: utf-8 -*

"""UdPyBlog Configuration"""

config = {
    "udpyblog": {
        "blog_prefix": "/",
        "template_folder": "dist/templates",
        "init_pass": "reset all data!",
        "forbidden_tags": [ ('h1','h3'), ('h2','h4'), ('script','p'), ('a','span') ],
        "blob_expiry_seconds": (3600),
        "input_requirements": {
            "password": {
                "min": 3,
                "max": 20
            }
        },
        "image_view_url_part": "image/view/"
    }
}