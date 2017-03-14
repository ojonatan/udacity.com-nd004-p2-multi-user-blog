from webtest import TestApp
import unittest
from main import app
from google.appengine.ext import testbed
from google.appengine.api import memcache, apiproxy_stub_map, datastore_file_stub
from google.appengine.ext import db
import string
import random
import sys
from cookielib import CookieJar
import time
import hashlib
import re
import os
import logging
import json
import copy

# Helper functions
def make_string(length):
    return "".join( random.choice(string.letters + string.digits) for x in xrange(length) )

def merge_copy_dict(d1, d2):
    result = copy.deepcopy(d1)
    merge_dict(result, d2)
    return result

def merge_dict(d1, d2):
    for k in d2:
        if k in d1 and isinstance(d1[k], dict) and isinstance(d2[k], dict):
            merge_dict(d1[k], d2[k])
        else:
            d1[k] = d2[k]
def deunicodify_hook(pairs):
    new_pairs = []
    for key, value in pairs:
        if isinstance(value, unicode):
            value = value.encode('utf-8')
        if isinstance(key, unicode):
            key = key.encode('utf-8')
        new_pairs.append((key, value))
    return dict(new_pairs)

class ExpectingTestCase(unittest.TestCase):
    tests_run = 0
    def run(self, result=None):
        self._result = result
        self._num_expectations = 0
        super(ExpectingTestCase, self).run(result)

    def _fail(self, failure):
        try:
            raise failure
        except failure.__class__:
            self._result.addFailure(self, sys.exc_info())

    def expect_in(self, needle, haystack, msg=''):
        self.tests_run += 1
        self._num_expectations += 1
        if haystack.find(needle) == -1:
            self.dump(re.sub(r'[^a-zA-Z0-9,]','_',msg),"String: {}\n-----------\nHTML:\n".format(needle,haystack))
            msg = '({}) Test: {} expected to contain {}. '.format(self._num_expectations, msg, needle)
            self._fail(self.failureException(msg))
            return False
        return True

    def expect_not_in(self, needle, haystack, msg=''):
        self.tests_run += 1
        self._num_expectations += 1
        if haystack.find(needle) != -1:
            self.dump(re.sub(r'[^a-zA-Z0-9,]','_',msg),"String: {}\n-----------\nHTML:\n".format(needle,haystack))
            msg = '({}) Test: {} expected to contain {}. '.format(self._num_expectations, msg, needle)
            self._fail(self.failureException(msg))
            return False
        return True

    def expect_re(self, regexp, haystack, msg=''):
        self.tests_run += 1
        self._num_expectations += 1
        if not re.search(regexp, haystack, re.MULTILINE|re.DOTALL):
            logging.info("NOT FOUND: {}".format(regexp))
            self.dump(re.sub(r'[^a-zA-Z0-9,]','_',msg),"Regexp: {}\n-----------\nHTML:\n".format(regexp,haystack))
            msg = '({}) Test: {} expected to contain {}. '.format(self._num_expectations, msg, regexp)
            self._fail(self.failureException(msg))
            return False
        return True

    def expect_not_re(self, regexp, haystack, msg=''):
        self.tests_run += 1
        self._num_expectations += 1
        if re.search(regexp, haystack, re.MULTILINE|re.DOTALL):
            self.dump(re.sub(r'[^a-zA-Z0-9,]','_',msg),"Regexp: {}\n-----------\nHTML:\n".format(regexp,haystack))
            msg = '({}) Test: {} expected to contain {}. '.format(self._num_expectations, msg, regexp)
            self._fail(self.failureException(msg))
            return False
        return True

    def dump(self, filename, content):
        dump_file = open(
            "{}{}-{}.dump".format(
                self.prefix,
                filename,
                self.tests_run
            ),
            'w+'
        )
        dump_file.write(content)
        dump_file.close()

class TestUdPyBlog(ExpectingTestCase):
    """
    Testing the UdPyBlog module. Multiple tests can be configured
    stored in the self.tests dictionary to test multiple scenarios

    1) Plain form has no error messages
    Test if error containers are present and empty

    2) Plain form features all nescessary input elements
    Test if all inputs required for registration are present

    3) Signup works
    Test if user signup works given the submission of valid field data

    4) Username exists
    Tests, if the repeated, fresh submission of the same field data as in 3)
    yields an error message in the username field



    """

    blog_entity_context = {}
    nosegae_datastore_v3 = True
    nosegae_datastore_v3_kwargs = {
        'datastore_file': os.path.join(
            'tests',
            'nosegae.sqlite3'
        ),
        'use_sqlite': True
    }
    tests = {
        # [[request-]][scope]-[in|out]-[status]
        # Scenarios with requests leading up to a successful user registration
        'post-signup-out-success': [
            {
                'id': 'signup',
                'subject': 'Signup works',
                'url': ('post','/signup'),
                'reset': False,
                'data': {
                    'username': 'testuser',
                    'password': 'testpass',
                    'verify': '',
                    'email': 'o@o.cx',
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
                }
            }
        ],
        # Scenarios with successful logins
        'post-login-out-success': [
            {
                'subject': 'Login with <<testuser>> works',
                'url': ('post','/login'),
                'reset': True, # reset cookies before execution
                'data': {
                    'username': 'testuser',
                    'password': 'testpass',
                    'submit': [
                        'username',
                        'password'
                    ],
                    'statements': [
                        'data["verify"] = data["password"]'
                    ]
                },
                'assertions': {
                    're': [
                        r'class="user-status user-logged-in"'
                    ]
                }
            }
        ],
        # Testing the default view
        'get-main-out-success': [
            {
                'subject': "Testing, if the initial view features the logged out view of the blog",
                'reset': True,
                'url': ('get','/'),
                'assertions': {
                    'in': [
                        ' data-blog-control="get-login"',
                        ' data-blog-control="get-signup"'
                    ]
                }
            }
        ],
        # Scenarios testing the logout functionality
        'get-logout-in-success': [
            {
                'subject': 'Logout after login works',
                'url': ('get','/logout'),
                'reset': False, # reset cookies before execution
                'assertions': {
                    'in': [
                        ' data-blog-control="get-login"',
                        ' data-blog-control="get-signup"'
                    ]
                }
            }
        ],
        # Scenarios testing the new post form
        'get-post-create-in-success': [
            {
                'subject': 'Post create form is accessible and is fully featured',
                'url': ('get','/newpost'),
                'reset': False, # reset cookies before execution
                'assertions': {
                    'in': [
                        ' data-blog-control="get-logout"',
                        ' data-blog-form="post-post-create"'
                    ],
                    're': [
                        r'class="((?!\berror-subject\b).)+\berror-subject\b[^>]*>\s*<',
                        r'class="((?!\berror-summary\b).)+\berror-summary\b[^>]*>\s*<',
                        r'class="((?!\berror-cover\b).)+\berror-cover\b[^>]*>\s*<',
                        r'class="((?!\berror-content\b).)+\berror-content\b[^>]*>\s*<'
                    ]
                }
            }
        ],
        'get-post-view-in-success': [
            {
                'subject': 'Viewing posts signed in working',
                'id': 'post-view',
                'url': ('get','/post/'),
                'reset': False, # reset cookies before execution
                'assertions': {
                    'in': [
                        ' data-blog-control="get-logout"',
                        ' data-blog-control="get-post-create"'
                    ]
                }
            }
        ],



        # Testing bad input in the post creation form
        'post-post-create-in-failure': [
            {
                'subject': 'Blog post fails: too short input for subject, summary and content',
                'url': ('post','/newpost'),
                'reset': False,
                'data': {
                    'subject': make_string(1),
                    'summary': make_string(1),
                    'content': make_string(1),
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
                        r'class="((?!\berror-subject\b).)+\berror-subject\b[^>]*>.+<',
                        r'class="((?!\berror-summary\b).)+\berror-summary\b[^>]*>.+<',
                        r'class="((?!\berror-content\b).)+\berror-content\b[^>]*>.+<'
                    ]
                }
            }
        ],
        # Paste a perfectly ok blog post, but add nasty things to it to validate escaping
        'post-post-create-in-success': [
            {
                'subject': 'Blog post creation: Paste a perfectly ok blog post, but add nasty things to it to validate escaping',
                'id': 'newpost',
                'url': ('post','/newpost'),
                'reset': False,
                'data': {
                    'subject': make_string(30),
                    'summary': make_string(60),
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
                }
            }
        ],
        # Add a 'like' to a post
        'post-post-like-in-success': [
            {
                'subject': 'Liking a blog post from another owner',
                'id': 'like',
                'url': ('post','/post'),
                'reset': False,
                'data': {},
                'assertions': {
                    'in': [
                        ' data-blog-control="post-unlike"'
                    ]
                }
            },
            {
                'subject': 'UnLiking a blog post from another owner',
                'id': 'unlike',
                'url': ('post','/post'),
                'reset': False,
                'data': {},
                'assertions': {
                    'in': [
                        ' data-blog-control="post-like"'
                    ]
                }
            }
        ],
        # Scenarios testing the fitness othe signup page
        'get-signup-out-success': [
            {
                'subject': "Signup page has form, submit button and a login button",
                'reset': True,
                'url': ('get','/signup'),
                'assertions': {
                    'in': [
                        ' data-blog-control="post-signup"',
                        ' data-blog-form="post-signup"',
                        ' data-blog-control="get-login"',
                    ]
                }
            },
            {
                'subject': "Signup page has no signup link",
                'reset': True,
                'url': ('get','/signup'),
                'assertions': {
                    'not_in': [
                        ' data-blog-control="get-signup"'
                    ]
                }
            },
            {
                'subject': "Plain form has no error messages",
                'reset': True,
                'url': ('get','/signup'),
                'context': 'signup_session',
                'assertions': {
                    're': [
                        r'<span class="error error-username">\s*</span',
                        r'<span class="error error-password">\s*</span',
                        r'<span class="error error-verify">\s*</span',
                        r'<span class="error error-email">\s*</span'
                    ]
                }
            },
            {
                'subject': "Plain form features all nescessary input elements",
                'url': ('get','/signup'),
                'reset': True,
                'assertions': {
                    're': [
                        r'<input((?!name="username").)+name="username"',
                        r'<input((?!name="username").)+name="password"',
                        r'<input((?!name="username").)+name="verify"',
                        r'<input((?!name="username").)+name="email"'
                    ]
                }
            }
        ],
        # Scenarios testing bad input in signup request
        'post-signup-out-failure': [
            {
                'subject': 'Username exists',
                'url': ('post','/signup'),
                'reset': True,
                'data': {
                    'username': 'testuser',
                    'password': make_string(5),
                    'verify': '',
                    'email': 'o@o.cx',
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
                        r'<span class="error error-password"></span',
                        r'<span class="error error-verify"></span',
                        r'<span class="error error-email"></span'
                    ],
                    're': [
                        r'<span class="error error-username">((?!</span).)+</span'
                    ]
                }
            },
            {
                'subject': 'Username too short',
                'url': ('post','/signup'),
                'reset': True,
                'data': {
                    'username': make_string(2),
                    'password': make_string(5),
                    'verify': '',
                    'email': 'o@o.cx',
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
                        r'<span class="error error-username">((?!</span).)+</span',
                        r'<span class="error error-password"></span',
                        r'<span class="error error-password"></span'
                    ]
                }
            },
            {
                'subject': 'Password too short',
                'url': ('post','/signup'),
                'reset': True,
                'data': {
                    'username': make_string(5),
                    'password': make_string(2),
                    'verify': '',
                    'email': 'o@o.cx',
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
                        r'<span class="error error-username"></span',
                        r'<span class="error error-verify"></span'
                    ],
                    're': [
                        r'<span class="error error-password">((?!</span).)+</span'
                    ]
                }
            },
            {
                'subject': "Passwords don't match",
                'url': ('post','/signup'),
                'reset': True,
                'data': {
                    'username': make_string(5),
                    'password': make_string(5),
                    'verify': make_string(6),
                    'email': 'o@o.cx',
                    'submit': [
                        'username',
                        'password',
                        'verify',
                        'email'
                    ]
                },
                'assertions': {
                    'in': [
                        r'<span class="error error-username"></span',
                        r'<span class="error error-password"></span'
                    ],
                    're': [
                        r'<span class="error error-verify">((?!</span).)+</span'
                    ]
                }
            },
            {
                'subject': "Bad email address",
                'url': ('post','/signup'),
                'reset': True,
                'data': {
                    'username': make_string(5),
                    'password': make_string(5),
                    'verify': '',
                    'email': 'oxxxo.cx',
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
                        r'<span class="error error-username"></span',
                        r'<span class="error error-password"></span',
                        r'<span class="error error-verify"></span'
                    ]
                }
            }
        ]
    }

    def setUp(self):
        self.app = TestApp(app,cookiejar=CookieJar())
        self.testbed = testbed.Testbed()
        self.testbed.activate()
        self.testbed.setup_env(app_id='dev~None') #udacity-160512
        self.testbed.init_datastore_v3_stub(
            datastore_file=os.path.join(
                'tests',
                'datastore.sqlite3'
            ),
            use_sqlite=True
        )
        self.testbed.init_memcache_stub()
        self.prefix = 'tests-' + str(time.time()) + '-'
        self.test_user = make_string(6)
        for test_func in self.tests:
            for test_case in self.tests[test_func]:
                if "data" in test_case:
                    data = test_case["data"]
                    if "statements" in data:
                        for statement in data["statements"]:
                            exec(statement,{"data": data})

                        test_case["data"] = data

        self.tests_md5 = hashlib.md5(json.dumps(self.tests)).hexdigest()

    def tearDown(self):
            # Don't forget to deactivate the testbed after the tests are
            # completed. If the testbed is not deactivated, the original
            # stubs will not be restored.
            self.testbed.deactivate()
            self.app.cookies.clear()

    # we should seperate between logged in and logged out tests
    # 00 should be a successful signup.
    # it would be great if successful login test settings could be centralized
    # like 00 ist the signup, 001-099 logged out tests, 100..199 logged id
    # run tests could allow for a 2 parm overriding scenario props

    # tests schould be an array of dictionaries.
    # they should be categorized by group and each test function shloud
    # select arbitrary tests from that list to run.

    # post-signup-success
    # post-signup-failure
    # get-signup-success
    # get-signup-failure
    # get-main-success
    # get-main-failure
    # get-login-success
    # get-login-failure
    # get-post_update-...
    # post-post_update-...
    # ....-post_insert-...
    # ....-login-...
    # macros sind nur subject-status, sie enthalten gglfs den clickstream fur eine gewahlte aktion
    # ein test der ein login (success) und dann einen post simulieren will
    # wurde so aussehen.
    # die liste enthalt dictionaries mit targets im stil von "[id]:[group]" ist id nicht gesetetzt werden alle
    # scenarios der gruppe ubernommen.
    # der scenario selector ist ubrigends der schlussel zu einem override dict
    # das enthalt einstellungen die auf alle scenarien appliziert werden
    # die auf den selector passen
    # wichtig: die dicts durfen durch die tests nicht verandert werden!!!!
    # self._run_tests(
    #    [{":login-success":{"data": {"username": "testuser"}}},":post-success"],{"*":{}}
    # success or failure only matter to requests, that
    # provide an interface for bad input.
    # normal page handlers only serve static input.
    # those only make sense to test for success

    def test_000_signup_signup_post_works(self):
        """
        Test if user signup works - creating initial testuser for later use
        """
        self.assertTrue(
            self._run_tests(
                [
                    {"post-signup-out-success": {}} # overrides not nescessary. default settings ok!
                ]
            )
        )

    def test_001_signup_form_functional(self):
        """
        Is the signup form functional
        """
        self.assertTrue(
            self._run_tests(
                [
                    {"get-signup-out-success": {}} # overrides not nescessary. default settings ok!
                ]
            )
        )


    def test_002_signup_signup_post_functional_error_handling(self):
        """Submitting signups with bad data"""
        self.assertTrue(
            self._run_tests(
                [
                    {"post-signup-out-failure": {}} # overrides not nescessary. default settings ok!
                ]
            )
        )

    def test_003_home_page_logged_out(self):
        """Testing, if the initial view features the logged out view of the blog"""
        self.assertTrue(
            self._run_tests(
                [
                    {"get-main-out-success": {}} # overrides not nescessary. default settings ok!
                ]
            )
        )

    def test_100_login_works(self):
        """Log in with existing user works"""
        self.assertTrue(
            self._run_tests(
                [
                    {"post-login-out-success": {}} # overrides not nescessary. default settings ok!
                ]
            )
        )

    def test_101_logout_after_login_works(self):
        """Log out right after login works"""
        self.assertTrue(
            self._run_tests(
                [
                    {"post-login-out-success": {}}, # overrides not nescessary. default settings ok!
                    {"get-logout-in-success": {}}
                ]
            )
        )

    def test_101_logout_after_signup_works(self):
        """Log out right after signup works"""

        self.assertTrue(
            self._run_tests(
                [
                    {
                        "post-signup-out-success": {
                            "signup": {
                                "data": {
                                    "username": make_string(5)
                                }
                            }
                        }
                    }, # overrides not nescessary. default settings ok!
                    {"get-logout-in-success": {}}
                ]
            )
        )

    def test_102_create_blog_post_form_works(self):
        """The create blog post form is there and ready for input"""

        self.assertTrue(
            self._run_tests(
                [
                    {"post-login-out-success": {}}, # overrides not nescessary. default settings ok!
                    {"get-post-create-in-success": {}},
                ]
            )
        )

    def test_103_create_blog_post_submit_error_handling(self):
        """Post too short input for a blog post and see 3 errors"""

        self.assertTrue(
            self._run_tests(
                [
                    {"post-login-out-success": {}}, # overrides not nescessary. default settings ok!
                    {"post-post-create-in-failure": {}}
                ]
            )
        )

    def test_104_create_blog_post_submit_works(self):
        """Create a poisoned but formal correct new blog post and verify sanitization"""

        logging.info("BLOGENI")
        logging.info(TestUdPyBlog.blog_entity_context)
        self.assertTrue(
            self._run_tests(
                [
                    {"post-login-out-success": {}}, # overrides not nescessary. default settings ok!
                    {"post-post-create-in-success": {}}
                ]
            )
        )

    def test_105_users_can_only_like_posts_from_authors_other_then_themselves(self):
        """Users can only like/unlike posts from authors other then themselves"""
        self.assertTrue(
            self._run_tests(
                [
                    {
                        "post-signup-out-success": {
                            "signup": {
                                "data": {
                                    "username": "testuser2"
                                }
                            }
                        }
                    },
                    { #view the recently created post and check if it is likeable
                        "get-post-view-in-success": {
                            "post-view": {
                                "url": (
                                    "get",
                                    "/post/{}".format(TestUdPyBlog.blog_entity_context["newpost"]["post_id"][-1])
                                )
                            }
                        }
                    },
                    {
                        "post-post-like-in-success": {
                            "like": {
                                "url": (
                                    "post",
                                    "/post/{}/like".format(TestUdPyBlog.blog_entity_context["newpost"]["post_id"][-1])
                                )
                            }
                        }
                    },
                    {
                        "post-post-like-in-success": {
                            "unlike": {
                                "url": (
                                    "post",
                                    "/post/{}/like".format(TestUdPyBlog.blog_entity_context["newpost"]["post_id"][-1])
                                )
                            }
                        }
                    }
                ]
            )
        )

    def _run_tests(self, selectors):
        result = True
        logging.info("root")
        logging.info(selectors)

        scenarios = []
        for selector in selectors:
            # a selector is a dict, keys are subset_selectors. only "*" and "id" currently supported
            for group_selector in selector:
                logging.info("Adding scenarios from the <<{}>> selector ({} scenarios available)".format(group_selector,len(self.tests[group_selector])))
                if selector[group_selector]:
                    # TBD select ranges, ids, subsets here
                    for subset_selector in selector[group_selector]:
                        # subset_selector holds the subset selector
                        # we loop incrementally to allow for numeric subsets
                        # at start we ill only supprt ids
                        # wildcards allow for settings applied to all scenarios
                        #

                        # a specific numeric offset. good for random selection
                        if subset_selector.isdigit():
                            if subset_selector >= 0:
                                if subset_selector < len(self.tests[group_selector]):
                                    scenarios.append(
                                        merge_copy_dict(
                                            self.tests[group_selector][subset_selector],
                                            selector[group_selector][subset_selector]
                                        )
                                    )
                                else:
                                    logging.info("Subset selector '{}' out of range. Group cotains only {} scenarios".format(subset_selector,len(self.tests[group_selector])))

                            # subset_selector is negative. getting only the last x entries
                            else:
                                if abs(subset_selector) < len(self.tests[group_selector]):
                                    for scenario in range(self.tests[group_selector][(subset_selector):]):
                                        scenarios.append(
                                            merge_copy_dict(
                                                scenario,
                                                selector[group_selector][subset_selector]
                                            )
                                        )

                                logging.info("Subset selector '{}' out of range. Group cotains only {} scenarios".format(subset_selector,len(self.tests[group_selector])))

                        # only the first x scenarios
                        elif subset_selector[0] == ":" and subset_selector[1:].isdigit():
                            if subset_selector[1:] < len(self.tests[group_selector]):
                                for scenario in range(self.tests[group_selector][:(subset_selector[1:])]):
                                    scenarios.append(
                                        merge_copy_dict(
                                            scenario,
                                            selector[group_selector][subset_selector]
                                        )
                                    )

                            logging.info("Subset selector '{}' out of range. Group cotains only {} scenarios".format(subset_selector[1:],len(self.tests[group_selector])))

                        # no subset selector? must be an id then
                        else:
                            for i in range(len(self.tests[group_selector])):
                                if subset_selector == "*" or self.tests[group_selector][i]["id"] == subset_selector:
                                    logging.info("looping pos {}, group: {}, subset: {}".format(i,group_selector,subset_selector))
                                    scenario = self.tests[group_selector][i]
                                    logging.info(selector[group_selector][subset_selector])
                                    scenario = merge_copy_dict(
                                        scenario,
                                        selector[group_selector][subset_selector]
                                    )
                                    logging.info("PRODUKT")
                                    logging.info(scenario)
                                    scenarios.append(scenario)


                elif group_selector in self.tests:
                    scenarios += self.tests[group_selector]

        if not scenarios:
            logging.info("No scenarios found!")
            return False

        logging.info("Running {} subtests".format(len(scenarios)))
        for scenario in scenarios:
            logging.info(scenario)
            if scenario["reset"] == True:
                logging.info("clearing cookies")
                self.app.cookiejar.clear()

            if not self._verify_tests():
                logging.info("Checksum modification detected at test <<{}>>!".format(scenario["subject"]))
                return False

            response = None
            if scenario["url"]:
                logging.info("Accessing handler for <<{}>>!".format(scenario["url"]))
                if scenario["url"][0] == "get":
                    response = self.app.get(
                        scenario["url"][1]
                    )

                else:
                    response = self.app.post(
                        scenario["url"][1],
                        self._prepare_data(scenario["data"])
                    )
                    logging.info("returning " + str(response.status_code))
                    logging.info(response.headers)

                if "Blog-Entity-Context" in dict(response.headers):
                    logging.info(dict(response.headers)["Blog-Entity-Context"])
                    context = json.loads(dict(response.headers)["Blog-Entity-Context"], object_pairs_hook=deunicodify_hook)
                    logging.info("JSON PARSED ENTITIES")
                    logging.info(context)
                    if "id" in scenario:
                        if not scenario["id"] in TestUdPyBlog.blog_entity_context:
                            TestUdPyBlog.blog_entity_context[scenario["id"]] = {}

                        for field in context:
                            logging.info("adding json field: " + field)
                            if not field in TestUdPyBlog.blog_entity_context[scenario["id"]]:
                                TestUdPyBlog.blog_entity_context[scenario["id"]][field] = []

                            TestUdPyBlog.blog_entity_context[scenario["id"]][field].append(context[field])

                logging.info("BLOGENI")
                logging.info(TestUdPyBlog.blog_entity_context)

                if response.status_code == 302:
                    response = self.app.get(
                        dict(response.headers)["Location"]
                    )

            logging.info("RESOPONSE: {} ({})".format(re.sub(r'\s+',' ',response.body),response.status_code))
            logging.info(scenario["assertions"])
            negate = "negate" in scenario and scenario["negate"]
            for type in scenario["assertions"]:
                if type == "in":
                    for assertion in scenario["assertions"][type]:
                        logging.info("... {} (negate: {})".format(assertion,negate))
                        if negate:
                            if not self.expect_not_in(assertion,response.body,scenario["subject"]):
                                result = False
                        else:
                            if not self.expect_in(assertion,response.body,scenario["subject"]):
                                result = False

                if type == "not_in":
                    for assertion in scenario["assertions"][type]:
                        logging.info("... {} (negate: {})".format(assertion,negate))
                        if negate:
                            if not self.expect_in(assertion,response.body,scenario["subject"]):
                                result = False
                        else:
                            if not self.expect_not_in(assertion,response.body,scenario["subject"]):
                                result = False

                if type == "re":
                    for assertion in scenario["assertions"][type]:
                        logging.info("... {} (negate: {})".format(assertion,negate))
                        if negate:
                            if not self.expect_not_re(assertion,response.body,scenario["subject"]):
                                result = False

                        else:
                            if not self.expect_re(assertion,response.body,scenario["subject"]):
                                result = False

                if type == "not_re":
                    for assertion in scenario["assertions"][type]:
                        logging.info("... {} (negate: {})".format(assertion,negate))
                        if negate:
                            if not self.expect_re(assertion,response.body,scenario["subject"]):
                                result = False

                        else:
                            if not self.expect_not_re(assertion,response.body,scenario["subject"]):
                                result = False

        return result

    def _prepare_data(self, context):
        if "submit" in context:
            return dict(((field, context[field]) for field in context["submit"]))
        return {}

    def _verify_tests(self):
        if hashlib.md5(json.dumps(self.tests)).hexdigest() == self.tests_md5:
            return True

        logging.info("Checksums differ: {} != {}".format(hashlib.md5(json.dumps(self.tests)).hexdigest(), self.tests_md5))
