import json
from django.http import HttpResponse
from django.contrib.auth import views as auth_views
from django.contrib import auth as auth_helpers
from django.views.decorators import debug
from django.shortcuts import render
from django.core import mail
from django import conf

from django.contrib.auth import models as auth_models

from oauth2_provider import views as oauth_views
from sesame import utils as token_utils

from dreamjub.models import Student


@debug.sensitive_post_parameters()
def login(request, template_name='login/login.html'):
    """
    :param request: HTTP Request
    :param template_name: Name of the login template to use
    :return: On POST, returns a JSON object indicating the status of the login.
             On GET, renders the default Django login view.
    """
    if request.method == 'POST':
        response_data = {}

        username = request.POST['username']
        password = request.POST['password']
        user = auth_helpers.authenticate(username=username, password=password)
        if user is not None:
            auth_helpers.login(request, user)

            response_data['login'] = True
        else:
            # Return an 'invalid login' error message.
            response_data['login'] = False
            response_data['detail'] = 'Username or password is invalid.'

        return HttpResponse(json.dumps(response_data),
                            content_type="application/json")

    if request.method == 'GET':
        return auth_views.login(request, template_name=template_name)


@debug.sensitive_post_parameters()
def magic_login(request, template_name='login/magic_login.html'):
    # POST => Send an email and handle the actual login
    if request.method == 'POST':

        # flag indicating if we found something
        success = False

        # read parameters
        email = request.POST['email']
        try:
            next = request.POST['next']
        except KeyError:
            next = '/'

        # try to get the user with the given email
        try:
            user = auth_models.User.objects.get(email=email)

        # if that fails, try to create a new student with that email
        except auth_models.User.DoesNotExist:
            try:
                student = Student.objects.get(email=email)
                user = student.get_or_create_user()
            except Student.DoesNotExist:
                user = None

        # if the user is not None, write them an email
        if user is not None:

            # link for the user to click
            link = "https://{0}{1}{2}".format(request.META['HTTP_HOST'],
                                              next, token_utils.
                                              get_query_string(user))

            # we need some content for the email
            email_content = """Hey {0},
did you just try to log in?

If yes, you may do so by clicking the following link:

{1}

If no, please just ignore this mail.



DO NOT REPLY TO THIS MAIL.
WE WILL NOT READ IT.
""".format(user.first_name, link)

            response = mail.send_mail('dreamjub login link', email_content,
                                      conf.settings.EMAIL_HOST_USER,
                                      [user.email])

            success = response == 1
        else:
            success = True

        # and return success
        return HttpResponse({'success': success},
                            content_type="application/json")

    # GET => render the login template and show everyone a lovely form
    if request.method == 'GET':
        return render(request, template_name=template_name,
                      context={'next': request.GET['next']})


class AuthorizationView(oauth_views.AuthorizationView):
    template_name = "login/authorize.html"
