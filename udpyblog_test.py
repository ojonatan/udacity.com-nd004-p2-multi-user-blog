#!/usr/bin/env python
# -*- coding: utf-8 -*

"""UdPyBlog Tests"""

from webtest import TestApp
import unittest
from main import app
from google.appengine.ext import testbed
from google.appengine.api import memcache, apiproxy_stub_map, datastore_file_stub
from google.appengine.api.app_identity import app_identity_stub

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

path = os.path.dirname(os.path.realpath(__file__))

# Helper functions

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

    def _expect(self, scenario, response):
        negate = "negate" in scenario and scenario["negate"]
        subtest = 0

        test = scenario["subject"]
        if "data" in scenario:
            test = scenario["subject"].format(**scenario["data"])

        self.results[self.testcase]["tests"][scenario["id"]]["test"] = test

        # register assertions
        id = 0
        for type in scenario["assertions"]:

            for assertion in scenario["assertions"][type]:
                self._register_assertion(
                    scenario,
                    "{}:{}:{}".format(
                        scenario["id"],
                        type,
                        id
                    ),
                    assertion,
                    type
                )
                id += 1

        extras = [ "", " not" ]
        for assertion_id in self.results[self.testcase]['tests'][scenario["id"]]['assertions']:
            assertion = self.results[self.testcase]['tests'][scenario["id"]]['assertions'][assertion_id]
            subtest += 1
            self.tests_run += 1
            self._num_expectations += 1
            yes = True
            if assertion["type"] == "in":
                check_func = lambda assertion,data: bool(data.find(assertion["assertion"]) > -1)

            elif assertion["type"] == "not_in":
                yes = False
                check_func = lambda assertion,data: bool(data.find(assertion["assertion"]) == -1)

            if assertion["type"] == "re":
                check_func = lambda assertion,data: bool(re.search(assertion["assertion"], data, re.MULTILINE|re.DOTALL))

            if assertion["type"] == "not_re":
                yes = False
                check_func = lambda assertion,data: bool(not re.search(assertion["assertion"], data, re.MULTILINE|re.DOTALL))

            extra = extras[int(yes == negate)]

            # evaluating the tests itself. each test can contain x subtests

            test_result = check_func(assertion, response.body)

            result = (test_result != bool(negate))

            self._report_assertion(assertion, result)

            if not result:

                self._dump(
                    re.sub(r'[^a-zA-Z0-9,]','_',subject),
                    assertion["assertion"],
                    response
                )

                msg = self._format_error(
                    **{
                        "msg": subject,
                        "extra": extra,
                        "assertion": assertion["assertion"],
                        "html": response.body
                    }
                )

                self._fail(self.failureException(msg))

    def _format_error(self, **args):
        errors = self._extract_errors(args["html"])
        error_messages = ""
        if errors:
            error_messages = "\n------------------------------\n Errors in form:\n ...... {errors}".format(
                errors="\n ...... ".join(errors)
            )

        msg = """
Test({counter}): {msg} expected{extra} to contain '{assertion}'.{error_messages}
""".format(
            **{
                "counter": self._num_expectations,
                "msg": args["msg"],
                "extra": args["extra"],
                "assertion": args["assertion"],
                "error_messages": error_messages
            }
        )
        return msg

    def _extract_errors(self, html):
        return [
            "{}: {}".format(
                error[2].upper(),
                error[3]
            ) for error in re.findall(
                r'<(?P<tag>[a-z1-6]+)\s((?!>|data-blog-error).)*data-blog-error="([^"]+)"[^>]*>((?!</(?P=tag)).+)</(?P=tag)',
                html
            )
        ]

    def _dump(self, filename, needle, response):
        dump_file = open(
            os.path.join(
                'dumps',
                "{}{}-{}.dump".format(
                    TestUdPyBlog.prefix,
                    filename,
                    self.tests_run
                )
            ),
            'w+'
        )
        dump_file.write(
            """
Needle: {}
-----------------------
Header:
-----------------------
{}

Body:
------------------
{}
            """.format(
                needle,
                response.headers,
                response.body
            )
        )
        dump_file.close()

class TestUdPyBlogTools():
    def makeString(self, params):
        return "".join( random.choice(string.letters + string.digits) for x in xrange(params["length"]) )

    def makeTimestamp(self):
        return int(time.time())

    def getBlogEntityContext(self, params):
        return TestUdPyBlog._get_blog_entity_context(params)


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

    prefix = 'tests-{}-'.format(int(time.time()))
    if os.path.isfile(
        os.path.join(
            path,
            "udpyblog_test_prefix.py"
        )
    ):
        import udpyblog_test_prefix
        prefix = udpyblog_test_prefix.prefix

    blog_entity_context = {}
    nosegae_datastore_v3 = True
    nosegae_datastore_v3_kwargs = {
        'datastore_file': os.path.join(
            'tests',
            'nosegae.sqlite3'
        ),
        'use_sqlite': True
    }

    def setUp(self):
        # load tests/scenarios
        import udpyblog_test_scenarios
        self.tests = copy.deepcopy(udpyblog_test_scenarios.tests)
        self.scenarios = copy.deepcopy(udpyblog_test_scenarios.scenarios)
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
        self.tools = TestUdPyBlogTools()
        self.testbed.init_blobstore_stub()
        self.testbed.init_memcache_stub()
        self.testbed.init_app_identity_stub()

        self.results = {}
        self.testcase = None

        for test_func in self.tests:
            self.results[test_func] = {
                "function": test_func,
                "desc": self.tests[test_func]["desc"],
                "tests": {},
                "scores": {
                    "OK": 0,
                    "NOT TESTED": 0,
                    "FAIL": 0
                }
            }

            # assertion level, scenario level, testcase lebvel
            # w
            for test_case in self.tests[test_func]["scenarios"]:
                id = 0
                for test_scenario in self.scenarios[test_case["scenario"]]:
                    test_scenario["id"] = "{}:{}".format(test_case["scenario"],id)
                    id += 1
                    if "filter" in test_scenario and test_scenario["filter"]["selected"] != "*" and test_scenario["filter"]["selected"] != test_scenario[test_scenario["scope"]]:
                        continue

                    self.results[test_func]["tests"][test_scenario["id"]] = {
                        "id": test_scenario["id"],
                        "test": test_scenario["subject"],
                        "url": None,
                        "result": None,
                        "assertions": {}, # each assertion will be added like {assertion, result}
                        "scores": {
                            "OK": 0,
                            "NOT TESTED": 0,
                            "FAIL": 0
                        },
                        "status": "NOT TESTED",
                        "time": 0
                    }

                if "data" in test_case:
                    data = test_case["data"]
                    if "statements" in data:
                        for statement in data["statements"]:
                            exec(statement,{"data": data})

                        test_case["data"] = data


        logging.info(self.results)
        self.scenarios_md5 = hashlib.md5(json.dumps(self.scenarios)).hexdigest()

    def tearDown(self):
        # prepare results, build summaries etc

        report_filename = "{}{}-report.json".format(TestUdPyBlog.prefix,self.testcase)
        self._prepare_results()

        self.report = open(report_filename,'a+')
        self.report.write(json.dumps(self.results[self.testcase]))
        self.report.close()

        self.index = open("{}reports".format(TestUdPyBlog.prefix),'a+')
        self.index.write(report_filename + "\n")
        self.index.close()

        self.testbed.deactivate()
        self.app.cookies.clear()

    def _prepare_results(self):
        for test_id in self.results[self.testcase]["tests"]:
            result = True
            test_case = self.results[self.testcase]["tests"][test_id]
            for assertion_id in test_case["assertions"]:
                assertion = test_case["assertions"][assertion_id]
                test_case["scores"][assertion["status"]] += 1
                if not assertion["result"]:
                    result = False

            if len(test_case["assertions"]) == test_case["scores"]["NOT TESTED"]:
                test_case["status"] = "NOT TESTED"

            else:
                test_case["result"] = len(test_case["assertions"]) == test_case["scores"]["OK"]
                test_case["status"] = "FAIL"
                if test_case["result"]:
                    test_case["status"] = "OK"

            self.results[self.testcase]["scores"][test_case["status"]] += 1

        if len(self.results[self.testcase]["tests"]) == self.results[self.testcase]["scores"]["NOT TESTED"]:
            self.results[self.testcase]["status"] = "NOT TESTED"

        else:
            self.results[self.testcase]["result"] = (len(self.results[self.testcase]["tests"]) == self.results[self.testcase]["scores"]["OK"])
            self.results[self.testcase]["status"] = "FAIL"
            if self.results[self.testcase]["result"]:
                self.results[self.testcase]["status"] = "OK"

    def _register_assertion(self, scenario, id, assertion, type):
        self.results[self.testcase]['tests'][scenario["id"]]['assertions'][id] = {
            'id': id,
            'assertion': assertion,
            'type': type,
            'result': None,
            'status': 'NOT TESTED'
        }

    def _get_assertions(self, id):
        return self.results[self.testcase]['tests'][id]['assertions']

    def _report_assertion(self, assertion, result):
        assertion["result"] = result
        assertion["status"] = "FAIL"
        if result:
            assertion["status"] = "OK"

    def test_000_signup_signup_post_works(self):
        """Test if user signup works - creating initial testuser for later use"""
        self._run_tests("test_000_signup_signup_post_works")

    def test_101_logout_after_login_works(self):
        """Log out right after login works"""
        self._run_tests("test_101_logout_after_login_works")

    def test_002_signup_signup_post_functional_error_handling(self):
        """Submitting signups with bad data"""
        self._run_tests("test_002_signup_signup_post_functional_error_handling")

    def test_003_home_page_logged_out(self):
        """Testing, if the initial view features the logged out view of the blog"""
        self._run_tests("test_003_home_page_logged_out")

    def test_100_login_works(self):
        """Log in with existing user works"""
        self._run_tests("test_100_login_works")

    def test_101_logout_after_login_works(self):
        """Log out right after login works"""
        self._run_tests("test_101_logout_after_login_works")

    def test_102_logout_after_signup_works(self):
        """Log out right after signup works"""
        self._run_tests("test_102_logout_after_signup_works")

    def test_103_create_blog_post_form_works(self):
        """The create blog post form is there and ready for input"""
        self._run_tests("test_103_create_blog_post_form_works")

    def test_104_create_blog_post_submit_error_handling(self):
        """Post too short input for a blog post and see 3 errors"""
        self._run_tests("test_104_create_blog_post_submit_error_handling")

    def test_105_create_blog_post_submit_works(self):
        """Create a poisoned but formal correct new blog post and verify sanitization"""
        self._run_tests("test_105_create_blog_post_submit_works")

    def test_106_users_can_only_like_posts_from_authors_other_then_themselves(self):
        """Users can only like/unlike posts from authors other then themselves"""
        self._run_tests("test_106_users_can_only_like_posts_from_authors_other_then_themselves")

    def test_107_update_blog_post_and_verify_changes(self):
        """Update blog post and verify changes"""
        self._run_tests("test_107_update_blog_post_and_verify_changes")

    def test_108_redirect_to_protected_url_after_captive_login_success(self):
        """Redirect to protected URL after successful login using the captive login form"""
        self._run_tests("test_108_redirect_to_protected_url_after_captive_login_success")

    def _run_tests(self, testcase):
        self.testcase = testcase
        result = True
        desc = self.tests[testcase]["desc"]
        scenarios_selected = []
        for selector in self.tests[testcase]["scenarios"]:

            group_selector = selector["scenario"]
            logging.info("Adding scenarios from the <<{}>> selector ({} scenarios available)".format(group_selector,len(self.scenarios[group_selector])))
            # selected scenarios might be a key with an empty dict. in this case the scenario is just taken as is
            if "filter" in selector:

                scenario_filter = selector["filter"]

                # overrides exist!
                subset_selector = "*"
                if "selected" in scenario_filter:
                    subset_selector = scenario_filter["selected"]
                    if subset_selector != "*":
                        logging.info("ALEEEEEEEEEERT: " + subset_selector + " SELECTOR FOUND!")

                # a specific numeric offset. good for random selection
                if subset_selector.isdigit():
                    if subset_selector >= 0:
                        if subset_selector < len(self.scenarios[group_selector]):
                            # we want the overrides to be applied at a later point. or inside the testfunc
                            scenario = copy.deepcopy(self.scenarios[group_selector][subset_selector])
                            if "overrides" in scenario_filter:
                                if "scope" not in scenario or "*" in scenario_filter["overrides"] or scenario["scope"] in scenario_filter["overrides"]:
                                    scenario["overrides"] = copy.deepcopy(scenario_filter["overrides"])

                            scenarios_selected.append(scenario)
                        else:
                            logging.info("Subset selector '{}' out of range. Group cotains only {} scenarios".format(subset_selector,len(self.scenarios[group_selector])))

                    # subset_selector is negative. getting only the last x entries
                    else:
                        if abs(subset_selector) < len(self.scenarios[group_selector]):
                            for scenario_ref in range(self.scenarios[group_selector][(subset_selector):]):
                                scenario = copy.deepcopy(scenario_ref)
                                if "overrides" in scenario_filter:
                                    if "scope" not in scenario or "*" in scenario_filter["overrides"] or scenario["scope"] in scenario_filter["overrides"]:
                                        scenario["overrides"] = copy.deepcopy(scenario_filter["overrides"])

                                scenarios_selected.append(scenario)

                        logging.info("Subset selector '{}' out of range. Group cotains only {} scenarios".format(subset_selector,len(self.scenarios[group_selector])))

                # only the first x scenarios
                elif subset_selector[0] == ":" and subset_selector[1:].isdigit():
                    if subset_selector[1:] < len(self.scenarios[group_selector]):
                        for scenario_ref in range(self.scenarios[group_selector][(subset_selector):]):
                            scenario = copy.deepcopy(scenario_ref)
                            if "overrides" in scenario_filter:
                                if "scope" not in scenario or "*" in scenario_filter["overrides"] or scenario["scope"] in scenario_filter["overrides"]:
                                    scenario["overrides"] = copy.deepcopy(scenario_filter["overrides"])

                            scenarios_selected.append(scenario)

                    logging.info("Subset selector '{}' out of range. Group cotains only {} scenarios".format(subset_selector[1:],len(self.scenarios[group_selector])))

                else:
                    for i in range(len(self.scenarios[group_selector])):
                        if subset_selector == "*" or self.scenarios[group_selector][i]["scope"] == subset_selector:
                            scenario = copy.deepcopy(self.scenarios[group_selector][i])
                            if "overrides" in scenario_filter:
                                if "*" in scenario_filter["overrides"] or ("scope" in scenario and scenario["scope"] in scenario_filter["overrides"]):
                                    scenario["overrides"] = copy.deepcopy(scenario_filter["overrides"])

                            scenarios_selected.append(scenario)

            elif group_selector in self.scenarios:
                for scenario_ref in self.scenarios[group_selector]:
                    scenario = copy.deepcopy(scenario_ref)
                    scenarios_selected.append(scenario)

            if not scenarios_selected:
                return False


        logging.info("Running {} subtests".format(len(scenarios_selected)))
        for scenario in scenarios_selected:
            self._scenario_override(scenario)
            logging.info(scenario)
            if scenario["reset"] == True:
                logging.info("clearing cookies")
                self.app.cookiejar.clear()

            response = None
            if scenario["request"]:
                logging.info("Accessing handler for <<{}>>!".format(scenario["request"]["url"]))
                if scenario["request"]["method"] == "get":
                    response = self.app.get(
                        scenario["request"]["url"]
                    )

                else:
                    logging.info(">>>>>>>>>>>>>>>>>POST:")
                    logging.info(self._prepare_data(scenario["data"]))
                    status=None
                    if "code" in scenario["request"]:
                        status=scenario["request"]["code"]

                    logging.info(">>>>>>>>>>>>>>>>>>expecting  " + str(status))
                    expect_errors = False
                    if "expect_errors" in scenario:
                        expect_errors = scenario["expect_errors"]

                    response = self.app.post(
                        scenario["request"]["url"],
                        self._prepare_data(scenario["data"]),
                        status=status,
                        expect_errors=expect_errors
                    )

                logging.info("returning " + str(response.status_code))
                logging.info(response.headers)

                if "Blog-Entity-Context" in dict(response.headers):

                    context = json.loads(dict(response.headers)["Blog-Entity-Context"], object_pairs_hook=deunicodify_hook)
                    logging.info("Blog-Entity-Context HEADER FOUND " + str(context))
                    if "scope" in scenario:
                        TestUdPyBlog._add_blog_entity_context(scenario["scope"], context)

                    logging.info(TestUdPyBlog.blog_entity_context)


#                if "code" in scenario["request"]:
#                    if response.status_code != scenario["request"]["code"]:
#                        # the right return code is only one aspect
#                        pass

                if response.status_code == 302:
                    response = self.app.get(
                        dict(response.headers)["Location"]
                    )

            self._expect(scenario, response)

        return result

    def _scenario_override(self, scenario):
        """
        Interpolate data with current test context
        """

        logging.info("<<<<<<<<<<<<<<<<<<<<<<< BLOG CONTEXT ")
        logging.info(TestUdPyBlog.blog_entity_context)

        scenario_overridden = scenario
        if not scenario["overrides"]:
            logging.info("!!!!!!!!!!!!!!!!!!!!!!! EMPTY OVERRRIDE <<" + scenario["subject"] + ">>?!?!?!? ")

        logging.info(scenario["overrides"])
        for scope in scenario["overrides"]:
            logging.info("CHECKIG SCOPE " + scope)
            if scope == "*" or scope in scenario["overrides"]:
                overrides = scenario["overrides"][scope]
                args = {}
                for override in overrides:
                    for replace_field in override["replace"]:
                        args[replace_field] = ""
                        for replacer in override["replace"][replace_field]:
                            if "tool" in replacer:
                                func = getattr(self.tools,replacer["tool"])
                                if func:
                                    params = None
                                    if "tool_args" in replacer:
                                        params = replacer["tool_args"]
                                        args[replacer["field"]] = func(params)
                                    else:
                                        args[replacer["field"]] = func()

                                logging.info("!!!!!!!!!!!!!!AAAAAAAAAAAEG")
                                logging.info(args)

                        scenario_cursor = scenario_overridden
                        logging.info("######### LOOOOOOOOOOOOOOOOOOOOOOOOOOP AAEG -- FIED {}".format(replace_field))
                        logging.info(scenario_overridden)
                        context_scope = "_root"
                        if override["target"]:
                            context_scope = override["target"][0]
                            path = override["target"][:]
                            while path:
                                fragment = path.pop(0)
                                if fragment not in scenario_cursor:
                                    logging.info("BAD FRAGMENT DETECTED: " + fragment)
                                    logging.info(scenario_cursor)
                                scenario_cursor = scenario_cursor[fragment]
                                logging.info("######### LOOOOOOOOOOOOOOOOOOOOOOOOOOP sub")
                                logging.info(scenario_cursor)

                        if isinstance(scenario_cursor[override["field"]], list):
                            context = {
                                "key": "out",
                                "scope": context_scope,
                                replace_field: override["template"].format(**args)
                            }
                            TestUdPyBlog._add_blog_entity_context(scope, context)
                            scenario_cursor[override["field"]].append(context[replace_field])
                            logging.info("---------adding {} to {} [ARGS BELO]".format(context[replace_field],scenario_cursor[override["field"]] ) )
                            logging.info(args )

                        else:
                            context = {
                                "key": "out",
                                "scope": context_scope,
                                replace_field: override["template"].format(**args)
                            }
                            TestUdPyBlog._add_blog_entity_context(scope, context)
                            scenario_cursor[override["field"]] = context[replace_field]
                            logging.info("overriding " + override["template"] + " with " + scenario_cursor[override["field"]] )

                        logging.info("+-+-+-+-ARGS+-+-+-+-+")
                        logging.info(args)
                        logging.info("+-+-+-+-OVERRIDE+-+-+-+-+")
                        logging.info(scenario_cursor)


        return scenario_overridden

    @classmethod
    def _get_blog_entity_context(cls, context):
        """
        Retrieves the context information retrieved from the header
        for use in other methods. Usually only the most recent value
        is needed.
        """

        key = "in"
        if "key" in context:
            key = context["key"]

        logging.info(">>>>>>>>>>>>>>ssss>>>>>>>>>>>>>>>>" )
        logging.info(context )
        if key in cls.blog_entity_context:
            if context["scope"] in cls.blog_entity_context[key]:
                if context["field"] in cls.blog_entity_context[key][context["scope"]]:
                    return cls.blog_entity_context[key][context["scope"]][context["field"]][-1]

        return ""

    @classmethod
    def _add_blog_entity_context(cls, scope, context):
        """
        Stores the context information retrieved from the header in an array
        for use in other methods
        """

        key = "in"
        if "key" in context:
            key = context["key"]

        if not key in TestUdPyBlog.blog_entity_context:
            TestUdPyBlog.blog_entity_context[key] = {}

        if not scope in TestUdPyBlog.blog_entity_context[key]:
            TestUdPyBlog.blog_entity_context[key][scope] = {}

        for field in context:
            if field == "key":
                continue

            logging.info("adding json field: " + field)
            if not field in TestUdPyBlog.blog_entity_context[key][scope]:
                TestUdPyBlog.blog_entity_context[key][scope][field] = []

            TestUdPyBlog.blog_entity_context[key][scope][field].append(context[field])

    def _prepare_data(self, context):
        if "submit" in context:
            return dict(((field, context[field]) for field in context["submit"]))
        return {}

    def _verify_tests(self):
        if hashlib.md5(json.dumps(self.scenarios)).hexdigest() == self.scenarios_md5:
            return True

        return False

