# FSND P2 - Multi User Blog

A Multi User Blog module

## Highlights

This blog implementation focuses on the following aspects

* Security
* Comprehensive and adaptive Testing
* Modularity

The blog features rich media content powered by jQuery Plugins. Hooks on log in/log out and on post update and creation help to keep the system free of orphaned BLOBS. A cron task checks periodically for expired images.

## TODO

* Add markup/ CSS to make the blog appear in shape
* EXTRA pagination!
* EXTRA Maybe add some testing scenarios for redirects and comments

## Live URL

https://udacity-160512.appspot.com/blog

## Installation (development only)

This is only required if you want to work with the sources. Grunt is used to do CSS processing and
filewatching. ```dist/``` contains the static files that get deployed.

```
npm install
bower install
```

## Test results

```
                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
The create blog post form is there and ready for input                2/ 0/ 0/ 2
--------------------------------------------------------------------------------
 .. Login with <<t_1490196245Bg43>> works                             1/ 0/ 0/ 1
    > [in]  data-blog-control="get-logout"                            OK

 .. Post create form is accessible and is fully featured              6/ 0/ 0/ 6
    > [in]  data-blog-control="get-logout"                            OK
    > [in]  data-blog-form="post-post-create"                         OK
    > [re] data-blog-error="cover"[^>]*>\s*<                          OK
    > [re] data-blog-error="content"[^>]*>\s*<                        OK
    > [re] data-blog-error="subject"[^>]*>\s*<                        OK
    > [re] data-blog-error="summary"[^>]*>\s*<                        OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Redirect to protected URL after successful login using the            2/ 0/ 0/ 2
captive login form
--------------------------------------------------------------------------------
 .. Enforcing login                                                   1/ 0/ 0/ 1
    > [in] data-blog-form="post-login"                                OK

 .. Login with <<t_1490196246_pMDQ>> works                            1/ 0/ 0/ 1
    > [in]  data-blog-form="post-post-create"                         OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Log in with existing user works                                       1/ 0/ 0/ 1
--------------------------------------------------------------------------------
 .. Login with <<t_1490196245>> works                                 1/ 0/ 0/ 1
    > [in]  data-blog-control="get-logout"                            OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Create a poisoned but formal correct new blog post and                2/ 0/ 0/ 2
verify sanitization
--------------------------------------------------------------------------------
 .. Login with <<t_1490196245Bg43>> works                             1/ 0/ 0/ 1
    > [in]  data-blog-control="get-logout"                            OK

 .. Blog post creation: Paste a perfectly ok blog post, but           6/ 0/ 0/ 6
 .. add nasty things to it to validate escaping
    > [in]  data-blog-control="get-logout"                            OK
    > [in]  data-blog-control="get-home"                              OK
    > [in]  data-blog-control="get-post-create"                       OK
    > [re] (?<=<!--post-start-->)((?!<a\s|</a                         OK
    > ).)+(?=<!--post-end-->)
    > [re] (?<=<!--post-start-->)((?!<script\s|</script               OK
    > ).)+(?=<!--post-end-->)
    > [re] (?<=<!--post-start-->)((?!<h[12]|</[12                     OK
    > ]).)+(?=<!--post-end-->)

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Log out right after login works                                       2/ 0/ 0/ 2
--------------------------------------------------------------------------------
 .. Login with <<t_1490196245>> works                                 1/ 0/ 0/ 1
    > [in]  data-blog-control="get-logout"                            OK

 .. Testing, if the initial view features the logged out              2/ 0/ 0/ 2
 .. view of the blog
    > [in]  data-blog-control="get-signup"                            OK
    > [in]  data-blog-control="get-login"                             OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Log out right after signup works                                      2/ 0/ 0/ 2
--------------------------------------------------------------------------------
 .. Signup works                                                      2/ 0/ 0/ 2
    > [in]  data-blog-control="get-post-create"                       OK
    > [in]  data-blog-control="get-home"                              OK

 .. Logout after login works                                          2/ 0/ 0/ 2
    > [in]  data-blog-control="get-login"                             OK
    > [in]  data-blog-control="get-signup"                            OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Testing, if the initial view features the logged out view of          1/ 0/ 0/ 1
the blog
--------------------------------------------------------------------------------
 .. Testing, if the initial view features the logged out              2/ 0/ 0/ 2
 .. view of the blog
    > [in]  data-blog-control="get-signup"                            OK
    > [in]  data-blog-control="get-login"                             OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Post too short input for a blog post and see 3 errors                 2/ 0/ 0/ 2
--------------------------------------------------------------------------------
 .. Blog post fails: too short input for subject, summary             6/ 0/ 0/ 6
 .. and content
    > [re] data-blog-error="content"[^>]*>\s*[^<\s]+                  OK
    > [re] data-blog-error="subject"[^>]*>\s*[^<\s]+                  OK
    > [re] data-blog-error="summary"[^>]*>\s*[^<\s]+                  OK
    > [in]  data-blog-form="post-post-create"                         OK
    > [in]  data-blog-control="post-post-create"                      OK
    > [in]  data-blog-control="get-home"                              OK

 .. Login with <<t_1490196245Bg43>> works                             1/ 0/ 0/ 1
    > [in]  data-blog-control="get-logout"                            OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Users can only like/unlike posts from authors other then              6/ 0/ 0/ 6
themselves
--------------------------------------------------------------------------------
 .. Liking an own blog post                                           1/ 0/ 0/ 1
    > [in]  data-blog-error                                           OK

 .. Signup works                                                      2/ 0/ 0/ 2
    > [in]  data-blog-control="get-post-create"                       OK
    > [in]  data-blog-control="get-home"                              OK

 .. Blog post creation: Paste a perfectly ok blog post, but           6/ 0/ 0/ 6
 .. add nasty things to it to validate escaping
    > [in]  data-blog-control="get-logout"                            OK
    > [in]  data-blog-control="get-home"                              OK
    > [in]  data-blog-control="get-post-create"                       OK
    > [re] (?<=<!--post-start-->)((?!<a\s|</a                         OK
    > ).)+(?=<!--post-end-->)
    > [re] (?<=<!--post-start-->)((?!<script\s|</script               OK
    > ).)+(?=<!--post-end-->)
    > [re] (?<=<!--post-start-->)((?!<h[12]|</[12                     OK
    > ]).)+(?=<!--post-end-->)

 .. Liking a blog post from another owner                             1/ 0/ 0/ 1
    > [in]  data-blog-control="post-unlike"                           OK

 .. UnLiking a blog post from another owner                           1/ 0/ 0/ 1
    > [in]  data-blog-control="post-like"                             OK

 .. Viewing posts signed in working                                   2/ 0/ 0/ 2
    > [in]  data-blog-control="get-post-create"                       OK
    > [in]  data-blog-control="get-logout"                            OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Submitting signups with bad data                                      5/ 0/ 0/ 5
--------------------------------------------------------------------------------
 .. Bad email address                                                 4/ 0/ 0/ 4
    > [re] data-blog-error="username"[^>]*>\s*<                       OK
    > [re] data-blog-error="password"[^>]*>\s*<                       OK
    > [re] data-blog-error="verify"[^>]*>\s*<                         OK
    > [re] data-blog-error="email"[^>]*>\s*[^<\s]+                    OK

 .. Password too short                                                4/ 0/ 0/ 4
    > [re] data-blog-error="verify"[^>]*>\s*<                         OK
    > [re] data-blog-error="email"[^>]*>\s*<                          OK
    > [re] data-blog-error="username"[^>]*>\s*<                       OK
    > [re] data-blog-error="password"[^>]*>\s*[^<\s]+                 OK

 .. Passwords don't match                                             4/ 0/ 0/ 4
    > [re] data-blog-error="password"[^>]*>\s*<                       OK
    > [re] data-blog-error="username"[^>]*>\s*<                       OK
    > [re] data-blog-error="email"[^>]*>\s*<                          OK
    > [re] data-blog-error="verify"[^>]*>\s*[^<\s]+                   OK

 .. Username exists                                                   4/ 0/ 0/ 4
    > [re] data-blog-error="username"[^>]*>\s*[^<\s]+                 OK
    > [re] data-blog-error="password"[^>]*>\s*<                       OK
    > [re] data-blog-error="verify"[^>]*>\s*<                         OK
    > [re] data-blog-error="email"[^>]*>\s*<                          OK

 .. Username too short                                                4/ 0/ 0/ 4
    > [re] data-blog-error="email"[^>]*>\s*<                          OK
    > [re] data-blog-error="verify"[^>]*>\s*<                         OK
    > [re] data-blog-error="password"[^>]*>\s*<                       OK
    > [re] data-blog-error="username"[^>]*>\s*[^<\s]+                 OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Update blog post and verify changes                                   5/ 0/ 0/ 5
--------------------------------------------------------------------------------
 .. Login with <<t_1490196246_pMDQ>> works                            1/ 0/ 0/ 1
    > [in]  data-blog-control="get-logout"                            OK

 .. View details of just created blog post with subject <<>>          5/ 0/ 0/ 5
    > [in]  data-blog-control="get-post-update"                       OK
    > [re]  data-blog-content-                                        OK
    > element="subject"[^>]*>\s*TestSubjectUPDATE: TestPost:
    > Jtn8fxy3ztuh2BkgpLe2\s*<
    > [re]  data-blog-content-                                        OK
    > element="summary"[^>]*>\s*TestSummaryUPDATE:
    > TestSummary:
    > vOScjay8d83jamfOvGN4qDkxizRTZ0aJY0EZBl5FkiF3W7Hvfl\s*<
    > [re]  data-blog-content-                                        OK
    > element="content"[^>]*>\s*TestContentUPDATE:
    > TestContent:
    > eFMoJ7e9a2ZIM9oT9gs1xHKdf47UCNSoWPLmK1q9fqczmWIViR\s*<
    > [in]  data-blog-control="get-logout"                            OK

 .. Blog post creation: Paste a perfectly ok blog post, but           6/ 0/ 0/ 6
 .. add nasty things to it to validate escaping
    > [in]  data-blog-control="get-logout"                            OK
    > [in]  data-blog-control="get-home"                              OK
    > [in]  data-blog-control="get-post-create"                       OK
    > [re] (?<=<!--post-start-->)((?!<a\s|</a                         OK
    > ).)+(?=<!--post-end-->)
    > [re] (?<=<!--post-start-->)((?!<script\s|</script               OK
    > ).)+(?=<!--post-end-->)
    > [re] (?<=<!--post-start-->)((?!<h[12]|</[12                     OK
    > ]).)+(?=<!--post-end-->)

 .. View details of just created blog post with subject <<>>          8/ 0/ 0/ 8
    > [re] <textarea(?!name="content").+name="content"[^>]*>          OK
    > TestContent: eFMoJ7e9a2ZIM9oT9gs1xHKdf47UCNSoWPLmK1q9f
    > qczmWIViR<\/textarea>
    > [re] <textarea(?!name="summary").+name="summary"[^>]*>          OK
    > TestSummary: vOScjay8d83jamfOvGN4qDkxizRTZ0aJY0EZBl5Fk
    > iF3W7Hvfl<\/textarea>
    > [re] <textarea(?!name="summary").+name="summary"[^>]*>          OK
    > ((?!<\/textarea>).+)<\/textarea>
    > [re] <input(?!name="subject").+name="subject"(?!value=          OK
    > ").+value="([^"]+)"
    > [re] <input(?!name="subject").+name="subject"(?!value=          OK
    > ").+value="TestPost: Jtn8fxy3ztuh2BkgpLe2"
    > [re] <textarea(?!name="content").+name="content"[^>]*>          OK
    > ((?!<\/textarea>).+)<\/textarea>
    > [in]  data-blog-form="post-post-update"                         OK
    > [in]  data-blog-control="get-logout"                            OK

 .. View details of just created blog post with subject               5/ 0/ 0/ 5
 .. <<TestPost: Jtn8fxy3ztuh2BkgpLe2>>
    > [re]  data-blog-content-                                        OK
    > element="content"[^>]*>\s*TestContent:
    > eFMoJ7e9a2ZIM9oT9gs1xHKdf47UCNSoWPLmK1q9fqczmWIViR\s*<
    > [re]  data-blog-content-                                        OK
    > element="summary"[^>]*>\s*TestSummary:
    > vOScjay8d83jamfOvGN4qDkxizRTZ0aJY0EZBl5FkiF3W7Hvfl\s*<
    > [re]  data-blog-content-                                        OK
    > element="subject"[^>]*>\s*TestPost:
    > Jtn8fxy3ztuh2BkgpLe2\s*<
    > [in]  data-blog-control="get-logout"                            OK
    > [in]  data-blog-control="get-post-create"                       OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Test if user signup works - creating initial testuser for             1/ 0/ 0/ 1
later use
--------------------------------------------------------------------------------
 .. Signup works                                                      2/ 0/ 0/ 2
    > [in]  data-blog-control="get-post-create"                       OK
    > [in]  data-blog-control="get-home"                              OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

```

## Version

2017-03-22T16:24:06.913000