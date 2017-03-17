scenarios = {
    # [[request-]][scope]-[in|out]-[status]
    # Scenarios with requests leading up to a successful user registration
    'post-signup-out-success': [
        {
            'scope': 'signup',
            'subject': 'Signup works',
            'request': {
                'method': 'post',
                'url': '/signup'
            },
            'reset': True,
            'data': {
                'username': None,
                'password': 'testpass',
                'verify': '',
                'email': 'o@cccccX.com',
                'submit': [
                    'username',
                    'password',
                    'verify',
                    'email'
                ],
                'statements': [
                    'data["verify"] = data["password"]'
                ]
            },
            'assertions': {
                'in': [
                    ' data-blog-control="get-home"',
                    ' data-blog-control="get-post-create"'
                ]
            },
            'overrides': {}
        }
    ],
    # Scenarios with successful logins
    'post-login-out-success': [
        {
            'scope': 'login',
            'subject': 'Login with <<{username}>> works',
            'request': {
                'method': 'post',
                'url': '/login'
            },
            'reset': True, # reset cookies before execution
            'data': {
                'username': None,
                'password': 'testpass',
                'submit': [
                    'username',
                    'password'
                ]
            },
            'assertions': {
                'in': [
                    ' data-blog-control="get-logout"',
                ]
            },
            'overrides': {}
        }
    ],
    # Testing the default view
    'get-main-out-success': [
        {
            'subject': "Testing, if the initial view features the logged out view of the blog",
            'reset': True,
            'request': {
                'method': 'get',
                'url': '/'
            },
            'assertions': {
                'in': [
                    ' data-blog-control="get-login"',
                    ' data-blog-control="get-signup"'
                ]
            },
            'overrides': {}
        }
    ],
    # Scenarios testing the logout functionality
    'get-logout-in-success': [
        {
            'subject': 'Logout after login works',
            'request': {
                'method': 'get',
                'url': '/logout'
            },
            'reset': False, # reset cookies before execution
            'assertions': {
                'in': [
                    ' data-blog-control="get-login"',
                    ' data-blog-control="get-signup"'
                ]
            },
            'overrides': {}
        }
    ],
    # Scenarios testing the new post form
    'get-post-create-in-success': [
        {
            'subject': 'Post create form is accessible and is fully featured',
            'request': {
                'method': 'get',
                'url': '/newpost'
            },
            'reset': False, # reset cookies before execution
            'assertions': {
                'in': [
                    ' data-blog-control="get-logout"',
                    ' data-blog-form="post-post-create"'
                ],
                're': [
                    r'data-blog-error="subject"[^>]*>\s*<',
                    r'data-blog-error="summary"[^>]*>\s*<',
                    r'data-blog-error="cover"[^>]*>\s*<',
                    r'data-blog-error="content"[^>]*>\s*<'
                ]
            },
            'overrides': {}
        }
    ],
    # Scenarios testing the update post form
    'get-post-update-in-success': [
        {
            'scope': 'get-post-update',
            'subject': 'Post update form is accessible and is fully featured',
            'request': {
                'method': 'get',
                'url': None
            },
            'reset': False, # reset cookies before execution
            'assertions': {
                'in': [
                    ' data-blog-control="get-logout"',
                    ' data-blog-form="post-post-update"'
                ],
                're': [
                    r'<input(?!name="subject").+name="subject"(?!value=").+value="([^"]+)"',
                    r'<textarea(?!name="summary").+name="summary"[^>]*>((?!<\/textarea>).+)<\/textarea>',
                    r'<textarea(?!name="content").+name="content"[^>]*>((?!<\/textarea>).+)<\/textarea>'
                ]
            },
            'overrides': {}
        }
    ],
    'get-post-view-in-success': [
        {
            'subject': 'Viewing posts signed in working',
            'scope': 'post-view',
            'request': {
                'method': 'get',
                'url': None
            },
            'reset': False, # reset cookies before execution
            'assertions': {
                'in': [
                    ' data-blog-control="get-logout"',
                    ' data-blog-control="get-post-create"'
                ],
                're': []
            },
            'overrides': {}
        }
    ],
    # Testing bad input in the post creation form
    'post-post-create-in-failure': [
        {
            'subject': 'Blog post fails: too short input for subject, summary and content',
            'request': {
                'method': 'post',
                'url': '/newpost'
            },
            'reset': False,
            'data': {
                'subject': 'dd',
                'summary': 'dd',
                'content': 'dd',
                'submit': [
                    'subject',
                    'summary',
                    'content'
                ]
            },
            'assertions': {
                'in': [
                    ' data-blog-form="post-post-create"',
                    ' data-blog-control="post-post-create"',
                    ' data-blog-control="get-home"'
                ],
                're': [
                    r'data-blog-error="subject"[^>]*>\s*[^<\s]+',
                    r'data-blog-error="summary"[^>]*>\s*[^<\s]+',
                    r'data-blog-error="content"[^>]*>\s*[^<\s]+'
                ]
            },
            'overrides': {}
        }
    ],
    # Paste a perfectly ok blog post, but add nasty things to it to validate escaping
    'post-post-create-in-success': [
        {
            'subject': 'Blog post creation: Paste a perfectly ok blog post, but add nasty things to it to validate escaping',
            'scope': 'newpost',
            'request': {
                'method': 'post',
                'url': '/newpost'
            },
            'reset': False,
            'data': {
                'subject': 'Posison!',
                'summary': 'This post contains unwanted tags en masse',
                'content': '<script>alert("das darf nicht wahr sein!!!");</script><h1>Aufschneider</h1><a href="javascript:alert(\'Konkurrenz\')"></a>',
                'submit': [
                    'subject',
                    'summary',
                    'content'
                ]
            },
            'assertions': {
                'in': [
                    ' data-blog-control="get-logout"',
                    ' data-blog-control="get-post-create"',
                    ' data-blog-control="get-home"'
                ],
                're': [
                    r'(?<=<!--post-start-->)((?!<h[12]|</[12]).)+(?=<!--post-end-->)',
                    r'(?<=<!--post-start-->)((?!<script\s|</script).)+(?=<!--post-end-->)',
                    r'(?<=<!--post-start-->)((?!<a\s|</a).)+(?=<!--post-end-->)',
                ]
            },
            'overrides': {}
        }
    ],
    # Add a 'like' to a post
    'post-post-like-in-failure': [
        {
            'subject': 'Liking an own blog post',
            'scope': 'like',
            'request': {
                'method': 'post',
                'url': '/post',
                'status': 403
            },
            'reset': False,
            'data': {},
            'assertions': {
                'in': [
                    ' data-blog-error'
                ]
            },
            'overrides': {}
        }
    ],
    # Add a 'like' to a post
    'post-post-like-in-success': [
        {
            'subject': 'Liking a blog post from another owner',
            'scope': 'like',
            'request': {
                'method': 'post',
                'url': '/post'
            },
            'reset': False,
            'data': {},
            'assertions': {
                'in': [
                    ' data-blog-control="post-unlike"'
                ]
            },
            'overrides': {}
        },
        {
            'subject': 'UnLiking a blog post from another owner',
            'scope': 'unlike',
            'request': {
                'method': 'post',
                'url': None
            },
            'reset': False,
            'data': {},
            'assertions': {
                'in': [
                    ' data-blog-control="post-like"'
                ]
            },
            'overrides': {}
        }
    ],
    # Scenarios testing the fitness othe signup page
    'get-signup-out-success': [
        {
            'subject': "Signup page has form, submit button and a login button",
            'reset': True,
            'request': {
                'method': 'get',
                'url': '/signup'
            },
            'assertions': {
                'in': [
                    ' data-blog-control="post-signup"',
                    ' data-blog-form="post-signup"',
                    ' data-blog-control="get-login"',
                ]
            },
            'overrides': {}
        },
        {
            'subject': "Signup page has no signup link",
            'reset': True,
            'request': {
                'method': 'get',
                'url': '/signup'
            },
            'assertions': {
                'not_in': [
                    ' data-blog-control="get-signup"'
                ]
            },
            'overrides': {}
        },
        {
            'subject': "Plain form has no error messages",
            'reset': True,
            'request': {
                'method': 'get',
                'url': '/signup'
            },
            'context': 'signup_session',
            'assertions': {
                're': [
                    r'data-blog-error="username"[^>]*>\s*<',
                    r'data-blog-error="password"[^>]*>\s*<',
                    r'data-blog-error="verify"[^>]*>\s*<',
                    r'data-blog-error="email"[^>]*>\s*<'
                ]
            },
            'overrides': {}
        },
        {
            'subject': "Plain form features all nescessary input elements",
            'request': {
                'method': 'get',
                'url': '/signup'
            },
            'reset': True,
            'assertions': {
                're': [
                    r'<input((?!name="username").)+name="username"',
                    r'<input((?!name="username").)+name="password"',
                    r'<input((?!name="username").)+name="verify"',
                    r'<input((?!name="username").)+name="email"'
                ]
            },
            'overrides': {}
        }
    ],
    # Scenarios testing bad input in signup request
    'post-signup-out-failure': [
        {
            'scope': 'signup-twice',
            'subject': 'Username exists',
            'request': {
                'method': 'post',
                'url': '/signup'
            },
            'reset': True,
            'data': {
                'username': None, #overridden
                'password': 'testpass',
                'verify': '',
                'email': 'o@ccccc.com',
                'submit': [
                    'username',
                    'password',
                    'verify',
                    'email'
                ],
                'statements': [
                    'data["verify"] = data["password"]'
                ]
            },
            'assertions': {
                're': [
                    r'data-blog-error="username"[^>]*>\s*[^<\s]+',
                    r'data-blog-error="password"[^>]*>\s*<',
                    r'data-blog-error="verify"[^>]*>\s*<',
                    r'data-blog-error="email"[^>]*>\s*<'
                ]
            },
            'overrides': {}
        },
        {
            'subject': 'Username too short',
            'request': {
                'method': 'post',
                'url': '/signup'
            },
            'reset': True,
            'data': {
                'username': 'ww',
                'password': 'assdfasdfasdf',
                'verify': '',
                'email': 'o@ccccc.com',
                'submit': [
                    'username',
                    'password',
                    'verify',
                    'email'
                ],
                'statements': [
                    'data["verify"] = data["password"]'
                ]
            },
            'assertions': {
                're': [
                    r'data-blog-error="username"[^>]*>\s*[^<\s]+',
                    r'data-blog-error="password"[^>]*>\s*<',
                    r'data-blog-error="verify"[^>]*>\s*<',
                    r'data-blog-error="email"[^>]*>\s*<'
                ]
            },
            'overrides': {}
        },
        {
            'subject': 'Password too short',
            'request': {
                'method': 'post',
                'url': '/signup'
            },
            'reset': True,
            'data': {
                'username': 'testuser',
                'password': 'f',
                'verify': '',
                'email': 'o@ccccc.com',
                'submit': [
                    'username',
                    'password',
                    'verify',
                    'email'
                ],
                'statements': [
                    'data["verify"] = data["password"]'
                ]
            },
            'assertions': {
                're': [
                    r'data-blog-error="username"[^>]*>\s*<',
                    r'data-blog-error="password"[^>]*>\s*[^<\s]+',
                    r'data-blog-error="verify"[^>]*>\s*<',
                    r'data-blog-error="email"[^>]*>\s*<'
                ]
            },
            'overrides': {}
        },
        {
            'subject': "Passwords don't match",
            'request': {
                'method': 'post',
                'url': '/signup'
            },
            'reset': True,
            'data': {
                'username': 'testuser',
                'password': 'f234refdf',
                'verify': 'rrsdddrr',
                'email': 'o@ccccc.com',
                'submit': [
                    'username',
                    'password',
                    'verify',
                    'email'
                ]
            },
            'assertions': {
                're': [
                    r'data-blog-error="username"[^>]*>\s*<',
                    r'data-blog-error="password"[^>]*>\s*<',
                    r'data-blog-error="verify"[^>]*>\s*[^<\s]+',
                    r'data-blog-error="email"[^>]*>\s*<'
                ]
            },
            'overrides': {}
        },
        {
            'subject': "Bad email address",
            'request': {
                'method': 'post',
                'url': '/signup'
            },
            'reset': True,
            'data': {
                'username': 'testuser',
                'password': 'awefwefaawefewf',
                'verify': '',
                'email': 'oxxxccccc.com',
                'submit': [
                    'username',
                    'password',
                    'verify',
                    'email'
                ],
                'statements': [
                    'data["verify"] = data["password"]'
                ]
            },
            'assertions': {
                're': [
                    r'data-blog-error="username"[^>]*>\s*<',
                    r'data-blog-error="password"[^>]*>\s*<',
                    r'data-blog-error="verify"[^>]*>\s*<',
                    r'data-blog-error="email"[^>]*>\s*[^<\s]+'
                ]
            },
            'overrides': {}
        }
    ]
}

tests = {
    'test_000_signup_signup_post_works': {
        'desc': "Test if user signup works - creating initial testuser for later use",
        'scenarios': [
            {
                "group": "post-signup-out-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "signup": [
                            {
                                "field": "username",
                                "template": "t_{timestamp}",
                                "replace": {
                                    "username": [
                                        {
                                            "tool": "makeTimestamp",
                                            "field": "timestamp"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            }
        ]
    },
    'test_002_signup_signup_post_functional_error_handling': {
        'desc': "Submitting signups with bad data",
        'scenarios': [
            {
                "group": "post-signup-out-failure",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "signup-twice": [
                            {
                                "field": "username",
                                "template": "{username}",
                                "replace": {
                                    "username": [
                                         {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "signup",
                                                "field": "username"
                                            },
                                            "field": "username"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            }
        ]
    },
    'test_003_home_page_logged_out': {
        'desc': "Testing, if the initial view features the logged out view of the blog",
        'scenarios': [
            {
                "group": "get-main-out-success"
            }
        ]
    },
    'test_100_login_works': {
        'desc': "Log in with existing user works",
        'scenarios': [
            {
                "group": "post-login-out-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "login": [
                            {
                                "field": "username",
                                "template": "{username}",
                                "replace": {
                                    "username": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "signup",
                                                "field": "username"
                                            },
                                            "field": "username"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            }
        ]
   },
   'test_101_logout_after_login_works': {
       'desc': "Log out right after login works",
       'scenarios': [
           {
                "group": "post-login-out-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "login": [
                            {
                                "field": "username",
                                "template": "{username}",
                                "replace": {
                                    "username": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "signup",
                                                "field": "username"
                                            },
                                            "field": "username"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "get-main-out-success"
            }
       ]
    },
    'test_102_logout_after_signup_works': {
        'desc': "Log out right after signup works",
        'scenarios': [
            {
                "group": "post-signup-out-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "signup": [
                            {
                                "field": "username",
                                "template": "t_{timestamp}{suffix}",
                                "replace": {
                                    "username": [
                                        {
                                            "tool": "makeTimestamp",
                                            "field": "timestamp"
                                        },
                                        {
                                            "tool": "makeString",
                                            "tool_args": {
                                                "length": 4
                                            },
                                            "field": "suffix"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "get-logout-in-success"
            }
       ]
    },
    'test_103_create_blog_post_form_works': {
        'desc': "The create blog post form is there and ready for input",
        'scenarios': [
            {
                "group": "post-login-out-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "login": [
                            {
                                "field": "username",
                                "template": "{username}",
                                "replace": {
                                    "username": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "signup",
                                                "field": "username"
                                            },
                                            "field": "username"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "get-post-create-in-success"
            }
       ]
    },
    'test_104_create_blog_post_submit_error_handling': {
        'desc': "Post too short input for a blog post and see 3 errors",
        'scenarios': [
            {
                "group": "post-login-out-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "login": [
                            {
                                "field": "username",
                                "template": "{username}",
                                "replace": {
                                    "username": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "signup",
                                                "field": "username"
                                            },
                                            "field": "username"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "post-post-create-in-failure"
            }
       ]
    },
    'test_105_create_blog_post_submit_works': {
        'desc': "Create a poisoned but formal correct new blog post and verify sanitization",
        'scenarios': [
            {
                "group": "post-login-out-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "login": [
                            {
                                "field": "username",
                                "template": "{username}",
                                "replace": {
                                    "username": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "signup",
                                                "field": "username"
                                            },
                                            "field": "username"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "post-post-create-in-success"
            }
        ]
    },
    'test_106_users_can_only_like_posts_from_authors_other_then_themselves': {
        'desc': "Users can only like/unlike posts from authors other then themselves",
        'scenarios': [
            {
                "group": "post-signup-out-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "signup": [
                            {
                                "field": "username",
                                "template": "t_{timestamp}_{suffix}",
                                "replace": {
                                    "username": [
                                        {
                                            "tool": "makeTimestamp",
                                            "field": "timestamp"
                                        },
                                        {
                                            "tool": "makeString",
                                            "tool_args": {
                                                "length": 4
                                            },
                                            "field": "suffix"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "get-post-view-in-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "post-view": [
                            {
                                "field": "url",
                                "template": "/post/{post_id}",
                                "replace": {
                                    "url": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "newpost",
                                                "field": "post_id"
                                            },
                                            "field": "post_id"
                                        }
                                    ]
                                },
                                "target": [ "request" ]
                            },
                        ]
                    }
                }
            },
            {
                "group": "post-post-like-in-success",
                "filter": {
                    "selected": "like",
                    "overrides": {
                        "like": [
                            {
                                "field": "url",
                                "template": "/post/{post_id}/like",
                                "replace": {
                                    "url": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "newpost",
                                                "field": "post_id"
                                            },
                                            "field": "post_id"
                                        }
                                    ]
                                },
                                "target": [ "request" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "post-post-like-in-success",
                "filter": {
                    "selected": "unlike",
                    "overrides": {
                        "unlike": [
                            {
                                "field": "url",
                                "template": "/post/{post_id}/like",
                                "replace": {
                                    "url": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "newpost",
                                                "field": "post_id"
                                            },
                                            "field": "post_id"
                                        }
                                    ]
                                },
                                "target": [ "request" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "post-post-create-in-success"
            },
            {
                "group": "post-post-like-in-failure",
                "filter": {
                    "selected": "like",
                    "overrides": {
                        "like": [
                            {
                                "field": "url",
                                "template": "/post/{post_id}/like",
                                "replace": {
                                    "url": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "newpost",
                                                "field": "post_id"
                                            },
                                            "field": "post_id"
                                        }
                                    ]
                                },
                                "target": [ "request" ]
                            }
                        ]
                    }
                }
            }
        ]
    },
    'test_107_update_blog_post_and_verify_changes': {
        'desc': "Update blog post and verify changes",
        'scenarios': [
            {
                "group": "post-login-out-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "login": [
                            {
                                "field": "username",
                                "template": "{username}",
                                "replace": {
                                    "username": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "signup",
                                                "field": "username"
                                            },
                                            "field": "username"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "post-post-create-in-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "newpost": [
                            {
                                "field": "subject",
                                "template": "TestPost: {subject}",
                                "replace": {
                                    "subject": [
                                        {
                                            "tool": "makeString",
                                            "tool_args": {
                                                "length": 20
                                            },
                                            "field": "subject"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            },
                            {
                                "field": "summary",
                                "template": "TestSummary: {summary}",
                                "replace": {
                                    "summary": [
                                        {
                                            "tool": "makeString",
                                            "tool_args": {
                                                "length": 50
                                            },
                                            "field": "summary"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            },
                            {
                                "field": "content",
                                "template": "TestContent: {content}",
                                "replace": {
                                    "content": [
                                        {
                                            "tool": "makeString",
                                            "tool_args": {
                                                "length": 50
                                            },
                                            "field": "content"
                                        }
                                    ]
                                },
                                "target": [ "data" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "get-post-view-in-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "post-view": [
                            {
                                "field": "url",
                                "template": "/post/{post_id}",
                                "replace": {
                                    "url": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "newpost",
                                                "field": "post_id"
                                            },
                                            "field": "post_id"
                                        }
                                    ]
                                },
                                "target": [ "request" ]
                            },
                            {
                                "field": "subject",
                                "template": 'View details of just created blog post with subject <<{test_subject}>>',
                                "replace": {
                                    "test_subject": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "key": "out",
                                                "scope": "newpost",
                                                "field": "subject"
                                            },
                                            "field": "subject"
                                        }
                                    ]
                                },
                                "target": [ ]
                            },
                            {
                                "field": "re",
                                "template": ' data-blog-content-element="subject"[^>]*>\s*{subject}\s*<',
                                "replace": {
                                    "subject": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "key": "out",
                                                "scope": "newpost",
                                                "field": "subject"
                                            },
                                            "field": "subject"
                                        }
                                    ]
                                },
                                "target": [ "assertions" ]
                            },
                            {
                                "field": "re",
                                "template": ' data-blog-content-element="summary"[^>]*>\s*{summary}\s*<',
                                "replace": {
                                    "summary": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "key": "out",
                                                "scope": "newpost",
                                                "field": "summary"
                                            },
                                            "field": "summary"
                                        }
                                    ]
                                },
                                "target": [ "assertions" ]
                            },
                            {
                                "field": "re",
                                "template": ' data-blog-content-element="content"[^>]*>\s*{content}\s*<',
                                "replace": {
                                    "content": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "key": "out",
                                                "scope": "newpost",
                                                "field": "content"
                                            },
                                            "field": "content"
                                        }
                                    ]
                                },
                                "target": [ "assertions" ]
                            }
                        ]
                    }
                }
            },
            {
                "group": "get-post-update-in-success",
                "filter": {
                    "selected": "*",
                    "overrides": {
                        "get-post-update": [
                            {
                                "field": "url",
                                "template": "/post/{post_id}/update",
                                "replace": {
                                    "url": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "scope": "newpost",
                                                "field": "post_id"
                                            },
                                            "field": "post_id"
                                        }
                                    ]
                                },
                                "target": [ "request" ]
                            },
                            {
                                "field": "subject",
                                "template": 'View details of just created blog post with subject <<{test_subject}>>',
                                "replace": {
                                    "test_subject": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "key": "out",
                                                "scope": "newpost",
                                                "field": "subject"
                                            },
                                            "field": "subject"
                                        }
                                    ]
                                },
                                "target": [ ]
                            },
                            {
                                "field": "re",
                                "template": r'<input(?!name="subject").+name="subject"(?!value=").+value="{subject}"',
                                "replace": {
                                    "subject": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "key": "out",
                                                "scope": "newpost",
                                                "field": "subject"
                                            },
                                            "field": "subject"
                                        }
                                    ]
                                },
                                "target": [ "assertions" ]
                            },
                            {
                                "field": "re",
                                "template": r'<textarea(?!name="summary").+name="summary"[^>]*>{summary}<\/textarea>',
                                "replace": {
                                    "summary": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "key": "out",
                                                "scope": "newpost",
                                                "field": "summary"
                                            },
                                            "field": "summary"
                                        }
                                    ]
                                },
                                "target": [ "assertions" ]
                            },
                            {
                                "field": "re",
                                "template": r'<textarea(?!name="content").+name="content"[^>]*>{content}<\/textarea>',
                                "replace": {
                                    "content": [
                                        {
                                            "tool": "getBlogEntityContext",
                                            "tool_args": {
                                                "key": "out",
                                                "scope": "newpost",
                                                "field": "content"
                                            },
                                            "field": "content"
                                        }
                                    ]
                                },
                                "target": [ "assertions" ]
                            }
                        ]
                    }
                }
            }
        ]
    }
}
