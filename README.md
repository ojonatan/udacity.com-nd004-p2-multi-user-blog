# FSND P2 - Multi User Blog

A Multi User Blog module

## Highlights

This blog implementation focuses on the following aspects

* Security
* Comprehensive and adaptive Testing
* Modularity

The blog features rich media content powered by jQuery Plugins. The uploaded
Files - images - require some maintenance work per request.

## Live URL

https://udacity-160512.appspot.com/blog

## Installation

```
npm install
bower install
```

## Test results

```
                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
The create blog post form is there and ready for input                2/ 0/ 0/ 2
 .. Login with <<{username}>> works                                   1/ 0/ 0/ 1
    >  data-blog-control="get-logout"                                 OK

 .. Post create form is accessible and is fully featured              6/ 0/ 0/ 6
    >  data-blog-control="get-logout"                                 OK
    >  data-blog-form="post-post-create"                              OK
    > data-blog-error="cover"[^>]*>\s*<                               OK
    > data-blog-error="content"[^>]*>\s*<                             OK
    > data-blog-error="subject"[^>]*>\s*<                             OK
    > data-blog-error="summary"[^>]*>\s*<                             OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Log in with existing user works                                       1/ 0/ 0/ 1
 .. Login with <<{username}>> works                                   1/ 0/ 0/ 1
    >  data-blog-control="get-logout"                                 OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Create a poisoned but formal correct new blog post and                2/ 0/ 0/ 2
verify sanitization
 .. Login with <<{username}>> works                                   1/ 0/ 0/ 1
    >  data-blog-control="get-logout"                                 OK

 .. Blog post creation: Paste a perfectly ok blog post, but           6/ 0/ 0/ 6
 .. add nasty things to it to validate escaping
    >  data-blog-control="get-logout"                                 OK
    >  data-blog-control="get-home"                                   OK
    >  data-blog-control="get-post-create"                            OK
    > (?<=<!--post-start-->)((?!<a\s|</a).)+(?=<!--post-              OK
    > end-->)
    > (?<=<!--post-start-->)((?!<script\s|</script                    OK
    > ).)+(?=<!--post-end-->)
    > (?<=<!--post-start-->)((?!<h[12]|</[12                          OK
    > ]).)+(?=<!--post-end-->)

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Log out right after login works                                       2/ 0/ 0/ 2
 .. Login with <<{username}>> works                                   1/ 0/ 0/ 1
    >  data-blog-control="get-logout"                                 OK

 .. Testing, if the initial view features the logged out              2/ 0/ 0/ 2
 .. view of the blog
    >  data-blog-control="get-signup"                                 OK
    >  data-blog-control="get-login"                                  OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Log out right after signup works                                      2/ 0/ 0/ 2
 .. Signup works                                                      2/ 0/ 0/ 2
    >  data-blog-control="get-post-create"                            OK
    >  data-blog-control="get-home"                                   OK

 .. Logout after login works                                          2/ 0/ 0/ 2
    >  data-blog-control="get-login"                                  OK
    >  data-blog-control="get-signup"                                 OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Testing, if the initial view features the logged out view of          1/ 0/ 0/ 1
the blog
 .. Testing, if the initial view features the logged out              2/ 0/ 0/ 2
 .. view of the blog
    >  data-blog-control="get-signup"                                 OK
    >  data-blog-control="get-login"                                  OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Post too short input for a blog post and see 3 errors                 2/ 0/ 0/ 2
 .. Blog post fails: too short input for subject, summary             6/ 0/ 0/ 6
 .. and content
    > data-blog-error="content"[^>]*>\s*[^<\s]+                       OK
    > data-blog-error="subject"[^>]*>\s*[^<\s]+                       OK
    > data-blog-error="summary"[^>]*>\s*[^<\s]+                       OK
    >  data-blog-form="post-post-create"                              OK
    >  data-blog-control="post-post-create"                           OK
    >  data-blog-control="get-home"                                   OK

 .. Login with <<{username}>> works                                   1/ 0/ 0/ 1
    >  data-blog-control="get-logout"                                 OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Users can only like/unlike posts from authors other then              6/ 0/ 0/ 6
themselves
 .. Liking an own blog post                                           1/ 0/ 0/ 1
    >  data-blog-error                                                OK

 .. Signup works                                                      2/ 0/ 0/ 2
    >  data-blog-control="get-post-create"                            OK
    >  data-blog-control="get-home"                                   OK

 .. Blog post creation: Paste a perfectly ok blog post, but           6/ 0/ 0/ 6
 .. add nasty things to it to validate escaping
    >  data-blog-control="get-logout"                                 OK
    >  data-blog-control="get-home"                                   OK
    >  data-blog-control="get-post-create"                            OK
    > (?<=<!--post-start-->)((?!<a\s|</a).)+(?=<!--post-              OK
    > end-->)
    > (?<=<!--post-start-->)((?!<script\s|</script                    OK
    > ).)+(?=<!--post-end-->)
    > (?<=<!--post-start-->)((?!<h[12]|</[12                          OK
    > ]).)+(?=<!--post-end-->)

 .. Liking a blog post from another owner                             1/ 0/ 0/ 1
    >  data-blog-control="post-unlike"                                OK

 .. UnLiking a blog post from another owner                           1/ 0/ 0/ 1
    >  data-blog-control="post-like"                                  OK

 .. Viewing posts signed in working                                   2/ 0/ 0/ 2
    >  data-blog-control="get-post-create"                            OK
    >  data-blog-control="get-logout"                                 OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Submitting signups with bad data                                      5/ 0/ 0/ 5
 .. Bad email address                                                 4/ 0/ 0/ 4
    > data-blog-error="username"[^>]*>\s*<                            OK
    > data-blog-error="password"[^>]*>\s*<                            OK
    > data-blog-error="verify"[^>]*>\s*<                              OK
    > data-blog-error="email"[^>]*>\s*[^<\s]+                         OK

 .. Password too short                                                4/ 0/ 0/ 4
    > data-blog-error="verify"[^>]*>\s*<                              OK
    > data-blog-error="email"[^>]*>\s*<                               OK
    > data-blog-error="username"[^>]*>\s*<                            OK
    > data-blog-error="password"[^>]*>\s*[^<\s]+                      OK

 .. Passwords don't match                                             4/ 0/ 0/ 4
    > data-blog-error="password"[^>]*>\s*<                            OK
    > data-blog-error="username"[^>]*>\s*<                            OK
    > data-blog-error="email"[^>]*>\s*<                               OK
    > data-blog-error="verify"[^>]*>\s*[^<\s]+                        OK

 .. Username exists                                                   4/ 0/ 0/ 4
    > data-blog-error="username"[^>]*>\s*[^<\s]+                      OK
    > data-blog-error="password"[^>]*>\s*<                            OK
    > data-blog-error="verify"[^>]*>\s*<                              OK
    > data-blog-error="email"[^>]*>\s*<                               OK

 .. Username too short                                                4/ 0/ 0/ 4
    > data-blog-error="email"[^>]*>\s*<                               OK
    > data-blog-error="verify"[^>]*>\s*<                              OK
    > data-blog-error="password"[^>]*>\s*<                            OK
    > data-blog-error="username"[^>]*>\s*[^<\s]+                      OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Update blog post and verify changes                                   5/ 0/ 0/ 5
 .. Login with <<{username}>> works                                   1/ 0/ 0/ 1
    >  data-blog-control="get-logout"                                 OK

 .. Update post works                                                 5/ 0/ 0/ 5
    >  data-blog-control="get-post-update"                            OK
    >  data-blog-content-                                             OK
    > element="subject"[^>]*>\s*TestSubjectUPDATE: TestPost:
    > x1M8wGj1f0iaZgi3LQFa\s*<
    >  data-blog-content-                                             OK
    > element="summary"[^>]*>\s*TestSummaryUPDATE:
    > TestSummary:
    > UFam0GkCxxxO9WFyDgzlTOsJZwMit6l45SuWP5O4thlYEeZi4X\s*<
    >  data-blog-content-                                             OK
    > element="content"[^>]*>\s*TestContentUPDATE:
    > TestContent:
    > uDBvNYU6aBV1GcigIztXQp8BIM0RX8iPtHpkklUec4ZCOionee\s*<
    >  data-blog-control="get-logout"                                 OK

 .. Blog post creation: Paste a perfectly ok blog post, but           6/ 0/ 0/ 6
 .. add nasty things to it to validate escaping
    >  data-blog-control="get-logout"                                 OK
    >  data-blog-control="get-home"                                   OK
    >  data-blog-control="get-post-create"                            OK
    > (?<=<!--post-start-->)((?!<a\s|</a).)+(?=<!--post-              OK
    > end-->)
    > (?<=<!--post-start-->)((?!<script\s|</script                    OK
    > ).)+(?=<!--post-end-->)
    > (?<=<!--post-start-->)((?!<h[12]|</[12                          OK
    > ]).)+(?=<!--post-end-->)

 .. Post update form is accessible and is fully featured              8/ 0/ 0/ 8
    > <textarea(?!name="content").+name="content"[^>]*>TestC          OK
    > ontent: uDBvNYU6aBV1GcigIztXQp8BIM0RX8iPtHpkklUec4ZCOi
    > onee<\/textarea>
    > <textarea(?!name="summary").+name="summary"[^>]*>TestS          OK
    > ummary: UFam0GkCxxxO9WFyDgzlTOsJZwMit6l45SuWP5O4thlYEe
    > Zi4X<\/textarea>
    > <textarea(?!name="summary").+name="summary"[^>]*>((?!<          OK
    > \/textarea>).+)<\/textarea>
    > <input(?!name="subject").+name="subject"(?!value=").+v          OK
    > alue="([^"]+)"
    > <input(?!name="subject").+name="subject"(?!value=").+v          OK
    > alue="TestPost: x1M8wGj1f0iaZgi3LQFa"
    > <textarea(?!name="content").+name="content"[^>]*>((?!<          OK
    > \/textarea>).+)<\/textarea>
    >  data-blog-form="post-post-update"                              OK
    >  data-blog-control="get-logout"                                 OK

 .. Viewing posts signed in working                                   5/ 0/ 0/ 5
    >  data-blog-content-                                             OK
    > element="content"[^>]*>\s*TestContent:
    > uDBvNYU6aBV1GcigIztXQp8BIM0RX8iPtHpkklUec4ZCOionee\s*<
    >  data-blog-content-                                             OK
    > element="summary"[^>]*>\s*TestSummary:
    > UFam0GkCxxxO9WFyDgzlTOsJZwMit6l45SuWP5O4thlYEeZi4X\s*<
    >  data-blog-content-element="subject"[^>]*>\s*TestPost:          OK
    > x1M8wGj1f0iaZgi3LQFa\s*<
    >  data-blog-control="get-logout"                                 OK
    >  data-blog-control="get-post-create"                            OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

                                                                      +/ -/ O/ #
--------------------------------------------------------------------------------
Test if user signup works - creating initial testuser for             1/ 0/ 0/ 1
later use
 .. Signup works                                                      2/ 0/ 0/ 2
    >  data-blog-control="get-post-create"                            OK
    >  data-blog-control="get-home"                                   OK

--------------------------------------------------------------------------------
                                                         Test Results:OK

```

## Version

2017-03-19T17:41:11.276000