#!/usr/bin/env python
# -*- coding: utf-8 -*

"""UdPyBlog Configuration"""

config = {
    "udpyblog": {
        # Freely define what URL root path the module is served under
        "blog_prefix": "/blog/",

        # Path to the jinja2 html templates, relative to the app.yaml
        "template_folder": "dist/templates",

        # Tags to be replaced, if encountered. Rich text fields only
        "forbidden_tags": [ ('h1','h3'), ('h2','h4'), ('script','p'), ('a','span') ],

        # Cron flag to define, when an uploaded BLOB not connected to a post is being purged
        "blob_expiry_seconds": (3600),

        # Pagination for the main page
        "posts_per_page": 8,

        # Override input restrictions
        "input_requirements": {
            "password": {
                "min": 3,
                "max": 20
            }
        },

        # Use this template to print the post dates
        "post_date_template": "Posted %d, %b %Y, %I:%M %p",

        # Use this template to print the comment dates
        "comment_date_template": "%d, %b %Y, %I:%M %p",

        # Password secret for hashing
        "password_secret": "jkoz98zOIH98zih)(&(/iugIUuzgJHgUZGUztIUT",

        # URL under wich uploaded images can be accessed
        "image_view_url_part": "image/view/"
    }
}