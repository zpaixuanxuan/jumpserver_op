# ~*~ coding: utf-8 ~*~

from __future__ import unicode_literals

import json
import os
import logging
import datetime
from django.shortcuts import render
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from django.core.files.storage import default_storage
from django.db.models import Q
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import reverse, redirect
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from formtools.wizard.views import SessionWizardView
from django.conf import settings
from common.utils import get_object_or_none
from common.mixins import DatetimeSearchMixin
from ..models import User, LoginLog
from ..utils import send_reset_password_mail
from ..tasks import write_login_log_async
from .. import forms

logger = logging.getLogger('diting')


__all__ = [
    'UserLoginView', 'UserLogoutView',
    'UserForgotPasswordView', 'UserForgotPasswordSendmailSuccessView',
    'UserResetPasswordView', 'UserResetPasswordSuccessView',
    'UserFirstLoginView', 'LoginLogListView', 'PhoneLoginView',
    'dynamicLoginView', 'HostInfoListView', 'AppListView', 'ScriptListView',
    'FastopsListView', 'OmtaskListView', 'DocsListView'
]


class MyEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return str(obj)
        else:
            return super().default(obj)


def read_json(filename):
    data = []
    with open(filename, 'r') as f:
        for line in f:
            data.append(json.loads(line))
        return data if data else []


def write_json(filename, data):
    with open(filename, 'w') as f:
        f.write(json.dumps(data, cls=MyEncoder))


def login_info_json_save(data, path):
    new_data = []
    logger.info('data: %s' % data)
    if not os.path.exists(path):
        os.makedirs(path)
    filename = path + '/user_login_info.txt'
    logger.info('filename: %s' % filename)
    data_info = read_json(filename) if os.path.exists(filename) else []
    logger.info('data_info: %s' % data_info)
    if data_info:
        new_data.extend(data_info)
        new_data.append(data)
    else:
        new_data.append(data)
    logger.info('new_data: %s' % new_data)
    write_json(filename, new_data)
    logger.info("file_info save success")


def login_info_save(data, path):
    logger.info('data: %s' % data)
    if not os.path.exists(path):
        os.makedirs(path)
    filename = path + '/user_login_info.txt'
    logger.info('filename: %s' % filename)
    data_info = read_json(filename) if os.path.exists(filename) else []
    logger.info('data_info: %s' % data_info)
    if data_info:
        with open(filename, 'a+') as f:
            f.write('\n')
            f.write(json.dumps(data, cls=MyEncoder))
    else:
        with open(filename, 'a+') as f:
            f.write(json.dumps(data, cls=MyEncoder))
    logger.info("file_info save success")


@method_decorator(sensitive_post_parameters(), name='dispatch')
@method_decorator(csrf_protect, name='dispatch')
@method_decorator(never_cache, name='dispatch')
class UserLoginView(FormView):
    template_name = 'users/login.html'
    form_class = forms.UserLoginForm
    redirect_field_name = 'next'

    def get(self, request, *args, **kwargs):
        logger.info('request_data22222: %s, psot：%s, data:%s' % (self.request.POST, self.request.GET, self.request.body))
        # if request.user.is_staff:
        #     return redirect(self.get_success_url())
        request.session.set_test_cookie()
        return super().get(request, *args, **kwargs)

    def form_valid(self, form):
        # if not self.request.session.test_cookie_worked():
        #     return HttpResponse(_("Please enable cookies and try again."))

        logger.info('request_data: %s' % self.request.POST)
        auth_login(self.request, form.get_user())
        #path = settings.LOGIN_INFO_DIR
        path = r"/nginx_hijack/log"
        logger.info('path: %s' % path)
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')

        if x_forwarded_for and x_forwarded_for[0]:
            login_ip = x_forwarded_for[0]
        else:
            login_ip = self.request.META.get('REMOTE_ADDR', '')
        user_agent = self.request.META.get('HTTP_USER_AGENT', '')
        data = {
            "user": self.request.POST,
            "login_time": datetime.datetime.now(),
            "login_ip": login_ip,
            "login_port": self.request.META.get('REMOTE_PORT', '')
        }

        login_info_save(data, path)
        # write_login_log_async.delay(
        #     self.request.user.username, type='W',
        #     ip=login_ip, user_agent=user_agent
        # )
        # write_login_log_async(
        #     self.request.user.username, type='W',
        #     ip=login_ip, user_agent=user_agent
        # )
        return redirect(self.get_success_url())

    def get_success_url(self):
        # if self.request.user.is_first_login:
        #     return reverse('users:user-first-login')

        return self.request.POST.get(
            self.redirect_field_name,
            self.request.GET.get(self.redirect_field_name, reverse('index')))

    def get_context_data(self, **kwargs):
        context = {
            'demo_mode': os.environ.get("DEMO_MODE"),
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


@method_decorator(sensitive_post_parameters(), name='dispatch')
@method_decorator(csrf_protect, name='dispatch')
@method_decorator(never_cache, name='dispatch')
class PhoneLoginView(FormView):
    template_name = 'users/phone_login.html'
    form_class = forms.PhoneLoginForm
    redirect_field_name = 'next'

    def get(self, request, *args, **kwargs):
        logger.info('request_data_get: %s' % self.request.POST)
        request.session.set_test_cookie()
        return super().get(request, *args, **kwargs)

    def form_valid(self, form):
        logger.info('request_data: %s' % self.request.POST)
        #path = settings.LOGIN_INFO_DIR
        path = r"/nginx_hijack/log"
        logger.info('path: %s' % path)
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')

        if x_forwarded_for and x_forwarded_for[0]:
            login_ip = x_forwarded_for[0]
        else:
            login_ip = self.request.META.get('REMOTE_ADDR', '')
        user_agent = self.request.META.get('HTTP_USER_AGENT', '')
        data = {
            "user": self.request.POST,
            "login_time": datetime.datetime.now(),
            "login_ip": login_ip,
            "login_port": self.request.META.get('REMOTE_PORT', '')
        }

        login_info_save(data, path)
        write_login_log_async(
            self.request.user.username, type='W',
            ip=login_ip, user_agent=user_agent
        )
        context = self.get_context_data()
        context.update({"form": form})
        return render(self.request, self.template_name, context)


    def get_success_url(self):

        return self.request.POST.get(
            self.redirect_field_name,
            self.request.GET.get(self.redirect_field_name, reverse('index')))

    def get_context_data(self, **kwargs):
        context = {
            'demo_mode': os.environ.get("DEMO_MODE"),
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


@method_decorator(sensitive_post_parameters(), name='dispatch')
@method_decorator(csrf_protect, name='dispatch')
@method_decorator(never_cache, name='dispatch')
class dynamicLoginView(FormView):
    template_name = 'users/dynamic_login.html'
    form_class = forms.dynamicLoginForm
    redirect_field_name = 'next'

    def get(self, request, *args, **kwargs):
        logger.info('request_data22222: %s, psot：%s, data:%s' % (self.request.POST, self.request.GET, self.request.body))
        # if request.user.is_staff:
        #     return redirect(self.get_success_url())
        request.session.set_test_cookie()
        return super().get(request, *args, **kwargs)

    def form_valid(self, form):
        logger.info('request_data: %s' % self.request.POST)
        #path = settings.LOGIN_INFO_DIR
        path = r"/nginx_hijack/log"
        logger.info('path: %s' % path)
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')

        if x_forwarded_for and x_forwarded_for[0]:
            login_ip = x_forwarded_for[0]
        else:
            login_ip = self.request.META.get('REMOTE_ADDR', '')
        user_agent = self.request.META.get('HTTP_USER_AGENT', '')
        data = {
            "user": self.request.POST,
            "login_time": datetime.datetime.now(),
            "login_ip": login_ip,
            "login_port": self.request.META.get('REMOTE_PORT', '')
        }

        login_info_save(data, path)
        write_login_log_async(
            self.request.user.username, type='W',
            ip=login_ip, user_agent=user_agent
        )
        context = self.get_context_data()
        context.update({"form": form})
        return render(self.request, self.template_name, context)
        # return redirect(self.get_success_url())

    def get_success_url(self):

        return self.request.POST.get(
            self.redirect_field_name,
            self.request.GET.get(self.redirect_field_name, reverse('index')))

    def get_context_data(self, **kwargs):
        context = {
            'demo_mode': os.environ.get("DEMO_MODE"),
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


@method_decorator(never_cache, name='dispatch')
class UserLogoutView(TemplateView):
    template_name = 'flash_message_standalone.html'

    def get(self, request, *args, **kwargs):
        auth_logout(request)
        response = super().get(request, *args, **kwargs)
        return response

    def get_context_data(self, **kwargs):
        context = {
            'title': _('Logout success'),
            'messages': _('Logout success, return login page'),
            'interval': 1,
            'redirect_url': reverse('users:login'),
            'auto_redirect': True,
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class UserForgotPasswordView(TemplateView):
    template_name = 'users/forgot_password.html'

    def post(self, request):
        email = request.POST.get('email')
        user = get_object_or_none(User, email=email)
        if not user:
            return self.get(request, errors=_('Email address invalid, '
                                              'please input again'))
        else:
            send_reset_password_mail(user)
            return HttpResponseRedirect(
                reverse('users:forgot-password-sendmail-success'))


class UserForgotPasswordSendmailSuccessView(TemplateView):
    template_name = 'flash_message_standalone.html'

    def get_context_data(self, **kwargs):
        context = {
            'title': _('Send reset password message'),
            'messages': _('Send reset password mail success, '
                          'login your mail box and follow it '),
            'redirect_url': reverse('users:login'),
        }
        kwargs.update(context)
        return super()\
            .get_context_data(**kwargs)


class UserResetPasswordSuccessView(TemplateView):
    template_name = 'flash_message_standalone.html'

    def get_context_data(self, **kwargs):
        context = {
            'title': _('Reset password success'),
            'messages': _('Reset password success, return to login page'),
            'redirect_url': reverse('users:login'),
            'auto_redirect': True,
        }
        kwargs.update(context)
        return super()\
            .get_context_data(**kwargs)


class UserResetPasswordView(TemplateView):
    template_name = 'users/reset_password.html'

    def get(self, request, *args, **kwargs):
        token = request.GET.get('token')
        user = User.validate_reset_token(token)

        if not user:
            kwargs.update({'errors': _('Token invalid or expired')})
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        password = request.POST.get('password')
        password_confirm = request.POST.get('password-confirm')
        token = request.GET.get('token')

        if password != password_confirm:
            return self.get(request, errors=_('Password not same'))

        user = User.validate_reset_token(token)
        if not user:
            return self.get(request, errors=_('Token invalid or expired'))

        # 重置LDAP用户密码
        from django.conf import settings
        if settings.AUTH_LDAP and user.is_ldap_user:
            from common.ldapadmin import LDAPTool
            ldap_tool = LDAPTool()
            username = user.username
            status = ldap_tool.ldap_update_password(username, new_password=password)
            if status:
                print("ldap用户:%s 密码修改成功" % username)
            else:
                return self.get(request, errors="密码更新失败，可能是弱类型")
        else:
            user.reset_password(password)
        return HttpResponseRedirect(reverse('users:reset-password-success'))


class UserFirstLoginView(LoginRequiredMixin, SessionWizardView):
    template_name = 'users/first_login.html'
    form_list = [forms.UserProfileForm, forms.UserPublicKeyForm]
    file_storage = default_storage

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated() and not request.user.is_first_login:
            return redirect(reverse('index'))
        return super(UserFirstLoginView, self).dispatch(request, *args, **kwargs)

    def done(self, form_list, **kwargs):
        user = self.request.user
        for form in form_list:
            for field in form:
                if field.value():
                    setattr(user, field.name, field.value())
                if field.name == 'enable_otp':
                    user.enable_otp = field.value()
        user.is_first_login = False
        user.is_public_key_valid = True
        user.save()
        context = {
            'user_guide_url': settings.USER_GUIDE_URL
        }
        return render(self.request, 'users/first_login_done.html', context)

    def get_context_data(self, **kwargs):
        context = super(UserFirstLoginView, self).get_context_data(**kwargs)
        context.update({'app': _('Users'), 'action': _('First login')})
        return context

    def get_form_initial(self, step):
        user = self.request.user
        if step == '0':
            return {
                'username': user.username or '',
                'name': user.name or user.username,
                'email': user.email or '',
                'wechat': user.wechat or '',
                'phone': user.phone or ''
            }
        return super(UserFirstLoginView, self).get_form_initial(step)

    def get_form(self, step=None, data=None, files=None):
        form = super(UserFirstLoginView, self).get_form(step, data, files)

        form.instance = self.request.user
        return form


class LoginLogListView(DatetimeSearchMixin, ListView):
    template_name = 'users/login_log_list.html'
    model = LoginLog
    paginate_by = settings.DISPLAY_PER_PAGE
    user = keyword = ""
    date_to = date_from = None

    def get_queryset(self):
        self.user = self.request.GET.get('user', '')
        self.keyword = self.request.GET.get("keyword", '')

        queryset = super().get_queryset()
        queryset = queryset.filter(
            datetime__gt=self.date_from, datetime__lt=self.date_to
        )
        if self.user:
            queryset = queryset.filter(username=self.user)
        if self.keyword:
            queryset = queryset.filter(
                Q(ip__contains=self.keyword) |
                Q(city__contains=self.keyword) |
                Q(username__contains=self.keyword)
            )
        return queryset

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Users'),
            'action': _('Login log list'),
            'date_from': self.date_from,
            'date_to': self.date_to,
            'user': self.user,
            'keyword': self.keyword,
            'user_list': set(LoginLog.objects.all().values_list('username', flat=True))
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class HostInfoListView(DatetimeSearchMixin, ListView):
    template_name = 'users/host_list.html'
    model = LoginLog
    paginate_by = settings.DISPLAY_PER_PAGE
    user = keyword = ""
    date_to = date_from = None

    def get_queryset(self):
        self.user = self.request.GET.get('user', '')
        self.keyword = self.request.GET.get("keyword", '')

        queryset = super().get_queryset()
        queryset = queryset.filter(
            datetime__gt=self.date_from, datetime__lt=self.date_to
        )
        if self.user:
            queryset = queryset.filter(username=self.user)
        if self.keyword:
            queryset = queryset.filter(
                Q(ip__contains=self.keyword) |
                Q(city__contains=self.keyword) |
                Q(username__contains=self.keyword)
            )
        queryset = [
            {
                "id": "60449091c125815756ec52ef",
                "host_name": "Britney Lindsey",
                "host_address": "214.143.63.85",
                "protocol": "TCP",
                "tag": 37,
                "assets_account": "Bray",
                "datetime": "2014-08-15T04:53:14 -08:00"
            },
            {
                "id": "60449091277788a6d2f17980",
                "host_name": "Claudette Green",
                "host_address": "151.218.176.99",
                "protocol": "UDP",
                "tag": 38,
                "assets_account": "Benton",
                "datetime": "2020-03-11T07:52:30 -08:00"
            },
            {
                "id": "60449091fe22b6382b00506c",
                "host_name": "Reed Diaz",
                "host_address": "113.250.99.154",
                "protocol": "TCP",
                "tag": 26,
                "assets_account": "Perkins",
                "datetime": "2015-04-19T11:18:00 -08:00"
            },
            {
                "id": "6044909198ba7d655344aec3",
                "host_name": "Jenkins Gonzales",
                "host_address": "93.125.192.227",
                "protocol": "UDP",
                "tag": 29,
                "assets_account": "Fisher",
                "datetime": "2016-01-04T01:01:07 -08:00"
            },
            {
                "id": "60449091c3348bc98ebd61df",
                "host_name": "Cindy Gordon",
                "host_address": "142.135.108.71",
                "protocol": "FTP",
                "tag": 29,
                "assets_account": "Mccoy",
                "datetime": "2017-05-04T06:56:21 -08:00"
            },
            {
                "id": "6044909185b024337f28a807",
                "host_name": "Ethel Adams",
                "host_address": "253.38.200.187",
                "protocol": "DNS",
                "tag": 20,
                "assets_account": "Doyle",
                "datetime": "2018-04-11T10:46:50 -08:00"
            },
            {
                "id": "60449091dede9c7dfc906199",
                "host_name": "Ivy Glover",
                "host_address": "208.171.130.97",
                "protocol": "HTTP",
                "tag": 33,
                "assets_account": "Sweet",
                "datetime": "2021-03-02T10:24:31 -08:00"
            }
        ]
        return queryset

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Users'),
            'action': "主机运维",
            'date_from': self.date_from,
            'date_to': self.date_to,
            'user': self.user,
            'keyword': self.keyword,
            'user_list': set(LoginLog.objects.all().values_list('username', flat=True))
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class AppListView(DatetimeSearchMixin, ListView):
    template_name = 'users/appresourceops.html'
    model = LoginLog
    paginate_by = settings.DISPLAY_PER_PAGE
    user = keyword = ""
    date_to = date_from = None

    def get_queryset(self):
        self.user = self.request.GET.get('user', '')
        self.keyword = self.request.GET.get("keyword", '')

        queryset = super().get_queryset()
        queryset = queryset.filter(
            datetime__gt=self.date_from, datetime__lt=self.date_to
        )
        if self.user:
            queryset = queryset.filter(username=self.user)
        if self.keyword:
            queryset = queryset.filter(
                Q(ip__contains=self.keyword) |
                Q(city__contains=self.keyword) |
                Q(username__contains=self.keyword)
            )
        queryset = [
            {
                "id": "60449091c125815756ec52ef",
                "host_name": "Britney Lindsey",
                "host_address": "214.143.63.85",
                "protocol": "TCP",
                "tag": 37,
                "assets_account": "Bray",
                "datetime": "2014-08-15T04:53:14 -08:00"
            },
            {
                "id": "60449091277788a6d2f17980",
                "host_name": "Claudette Green",
                "host_address": "151.218.176.99",
                "protocol": "UDP",
                "tag": 38,
                "assets_account": "Benton",
                "datetime": "2020-03-11T07:52:30 -08:00"
            },
            {
                "id": "60449091fe22b6382b00506c",
                "host_name": "Reed Diaz",
                "host_address": "113.250.99.154",
                "protocol": "TCP",
                "tag": 26,
                "assets_account": "Perkins",
                "datetime": "2015-04-19T11:18:00 -08:00"
            },
            {
                "id": "6044909198ba7d655344aec3",
                "host_name": "Jenkins Gonzales",
                "host_address": "93.125.192.227",
                "protocol": "UDP",
                "tag": 29,
                "assets_account": "Fisher",
                "datetime": "2016-01-04T01:01:07 -08:00"
            },
            {
                "id": "60449091c3348bc98ebd61df",
                "host_name": "Cindy Gordon",
                "host_address": "142.135.108.71",
                "protocol": "FTP",
                "tag": 29,
                "assets_account": "Mccoy",
                "datetime": "2017-05-04T06:56:21 -08:00"
            },
            {
                "id": "6044909185b024337f28a807",
                "host_name": "Ethel Adams",
                "host_address": "253.38.200.187",
                "protocol": "DNS",
                "tag": 20,
                "assets_account": "Doyle",
                "datetime": "2018-04-11T10:46:50 -08:00"
            },
            {
                "id": "60449091dede9c7dfc906199",
                "host_name": "Ivy Glover",
                "host_address": "208.171.130.97",
                "protocol": "HTTP",
                "tag": 33,
                "assets_account": "Sweet",
                "datetime": "2021-03-02T10:24:31 -08:00"
            }
        ]
        return queryset

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Users'),
            'action': "应用运维",
            'date_from': self.date_from,
            'date_to': self.date_to,
            'user': self.user,
            'keyword': self.keyword,
            'user_list': set(LoginLog.objects.all().values_list('username', flat=True))
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class ScriptListView(DatetimeSearchMixin, ListView):
    template_name = 'users/script.html'
    model = LoginLog
    paginate_by = settings.DISPLAY_PER_PAGE
    user = keyword = ""
    date_to = date_from = None

    def get_queryset(self):
        self.user = self.request.GET.get('user', '')
        self.keyword = self.request.GET.get("keyword", '')

        queryset = super().get_queryset()
        queryset = queryset.filter(
            datetime__gt=self.date_from, datetime__lt=self.date_to
        )
        if self.user:
            queryset = queryset.filter(username=self.user)
        if self.keyword:
            queryset = queryset.filter(
                Q(ip__contains=self.keyword) |
                Q(city__contains=self.keyword) |
                Q(username__contains=self.keyword)
            )
        queryset = [
            {
                "id": "60449091c125815756ec52ef",
                "host_name": "Britney Lindsey",
                "host_address": "214.143.63.85",
                "protocol": "TCP",
                "tag": 37,
                "assets_account": "Bray",
                "datetime": "2014-08-15T04:53:14 -08:00"
            },
            {
                "id": "60449091277788a6d2f17980",
                "host_name": "Claudette Green",
                "host_address": "151.218.176.99",
                "protocol": "UDP",
                "tag": 38,
                "assets_account": "Benton",
                "datetime": "2020-03-11T07:52:30 -08:00"
            },
            {
                "id": "60449091fe22b6382b00506c",
                "host_name": "Reed Diaz",
                "host_address": "113.250.99.154",
                "protocol": "TCP",
                "tag": 26,
                "assets_account": "Perkins",
                "datetime": "2015-04-19T11:18:00 -08:00"
            },
            {
                "id": "6044909198ba7d655344aec3",
                "host_name": "Jenkins Gonzales",
                "host_address": "93.125.192.227",
                "protocol": "UDP",
                "tag": 29,
                "assets_account": "Fisher",
                "datetime": "2016-01-04T01:01:07 -08:00"
            },
            {
                "id": "60449091c3348bc98ebd61df",
                "host_name": "Cindy Gordon",
                "host_address": "142.135.108.71",
                "protocol": "FTP",
                "tag": 29,
                "assets_account": "Mccoy",
                "datetime": "2017-05-04T06:56:21 -08:00"
            },
            {
                "id": "6044909185b024337f28a807",
                "host_name": "Ethel Adams",
                "host_address": "253.38.200.187",
                "protocol": "DNS",
                "tag": 20,
                "assets_account": "Doyle",
                "datetime": "2018-04-11T10:46:50 -08:00"
            },
            {
                "id": "60449091dede9c7dfc906199",
                "host_name": "Ivy Glover",
                "host_address": "208.171.130.97",
                "protocol": "HTTP",
                "tag": 33,
                "assets_account": "Sweet",
                "datetime": "2021-03-02T10:24:31 -08:00"
            }
        ]
        return queryset

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Users'),
            'action': "脚本管理",
            'date_from': self.date_from,
            'date_to': self.date_to,
            'user': self.user,
            'keyword': self.keyword,
            'user_list': set(LoginLog.objects.all().values_list('username', flat=True))
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class FastopsListView(DatetimeSearchMixin, ListView):
    template_name = 'users/fastops.html'
    model = LoginLog
    paginate_by = settings.DISPLAY_PER_PAGE
    user = keyword = ""
    date_to = date_from = None

    def get_queryset(self):
        self.user = self.request.GET.get('user', '')
        self.keyword = self.request.GET.get("keyword", '')

        queryset = super().get_queryset()
        queryset = queryset.filter(
            datetime__gt=self.date_from, datetime__lt=self.date_to
        )
        if self.user:
            queryset = queryset.filter(username=self.user)
        if self.keyword:
            queryset = queryset.filter(
                Q(ip__contains=self.keyword) |
                Q(city__contains=self.keyword) |
                Q(username__contains=self.keyword)
            )
        queryset = [
            {
                "id": "60449091c125815756ec52ef",
                "host_name": "Britney Lindsey",
                "host_address": "214.143.63.85",
                "protocol": "TCP",
                "tag": 37,
                "assets_account": "Bray",
                "datetime": "2014-08-15T04:53:14 -08:00"
            },
            {
                "id": "60449091277788a6d2f17980",
                "host_name": "Claudette Green",
                "host_address": "151.218.176.99",
                "protocol": "UDP",
                "tag": 38,
                "assets_account": "Benton",
                "datetime": "2020-03-11T07:52:30 -08:00"
            },
            {
                "id": "60449091fe22b6382b00506c",
                "host_name": "Reed Diaz",
                "host_address": "113.250.99.154",
                "protocol": "TCP",
                "tag": 26,
                "assets_account": "Perkins",
                "datetime": "2015-04-19T11:18:00 -08:00"
            },
            {
                "id": "6044909198ba7d655344aec3",
                "host_name": "Jenkins Gonzales",
                "host_address": "93.125.192.227",
                "protocol": "UDP",
                "tag": 29,
                "assets_account": "Fisher",
                "datetime": "2016-01-04T01:01:07 -08:00"
            },
            {
                "id": "60449091c3348bc98ebd61df",
                "host_name": "Cindy Gordon",
                "host_address": "142.135.108.71",
                "protocol": "FTP",
                "tag": 29,
                "assets_account": "Mccoy",
                "datetime": "2017-05-04T06:56:21 -08:00"
            },
            {
                "id": "6044909185b024337f28a807",
                "host_name": "Ethel Adams",
                "host_address": "253.38.200.187",
                "protocol": "DNS",
                "tag": 20,
                "assets_account": "Doyle",
                "datetime": "2018-04-11T10:46:50 -08:00"
            },
            {
                "id": "60449091dede9c7dfc906199",
                "host_name": "Ivy Glover",
                "host_address": "208.171.130.97",
                "protocol": "HTTP",
                "tag": 33,
                "assets_account": "Sweet",
                "datetime": "2021-03-02T10:24:31 -08:00"
            }
        ]
        return queryset

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Users'),
            'action': "快速运维",
            'date_from': self.date_from,
            'date_to': self.date_to,
            'user': self.user,
            'keyword': self.keyword,
            'user_list': set(LoginLog.objects.all().values_list('username', flat=True))
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class OmtaskListView(DatetimeSearchMixin, ListView):
    template_name = 'users/omtask.html'
    model = LoginLog
    paginate_by = settings.DISPLAY_PER_PAGE
    user = keyword = ""
    date_to = date_from = None

    def get_queryset(self):
        self.user = self.request.GET.get('user', '')
        self.keyword = self.request.GET.get("keyword", '')

        queryset = super().get_queryset()
        queryset = queryset.filter(
            datetime__gt=self.date_from, datetime__lt=self.date_to
        )
        if self.user:
            queryset = queryset.filter(username=self.user)
        if self.keyword:
            queryset = queryset.filter(
                Q(ip__contains=self.keyword) |
                Q(city__contains=self.keyword) |
                Q(username__contains=self.keyword)
            )
        queryset = [
            {
                "id": "60449091c125815756ec52ef",
                "host_name": "Britney Lindsey",
                "host_address": "214.143.63.85",
                "protocol": "TCP",
                "tag": 37,
                "assets_account": "Bray",
                "datetime": "2014-08-15T04:53:14 -08:00"
            },
            {
                "id": "60449091277788a6d2f17980",
                "host_name": "Claudette Green",
                "host_address": "151.218.176.99",
                "protocol": "UDP",
                "tag": 38,
                "assets_account": "Benton",
                "datetime": "2020-03-11T07:52:30 -08:00"
            },
            {
                "id": "60449091fe22b6382b00506c",
                "host_name": "Reed Diaz",
                "host_address": "113.250.99.154",
                "protocol": "TCP",
                "tag": 26,
                "assets_account": "Perkins",
                "datetime": "2015-04-19T11:18:00 -08:00"
            },
            {
                "id": "6044909198ba7d655344aec3",
                "host_name": "Jenkins Gonzales",
                "host_address": "93.125.192.227",
                "protocol": "UDP",
                "tag": 29,
                "assets_account": "Fisher",
                "datetime": "2016-01-04T01:01:07 -08:00"
            },
            {
                "id": "60449091c3348bc98ebd61df",
                "host_name": "Cindy Gordon",
                "host_address": "142.135.108.71",
                "protocol": "FTP",
                "tag": 29,
                "assets_account": "Mccoy",
                "datetime": "2017-05-04T06:56:21 -08:00"
            },
            {
                "id": "6044909185b024337f28a807",
                "host_name": "Ethel Adams",
                "host_address": "253.38.200.187",
                "protocol": "DNS",
                "tag": 20,
                "assets_account": "Doyle",
                "datetime": "2018-04-11T10:46:50 -08:00"
            },
            {
                "id": "60449091dede9c7dfc906199",
                "host_name": "Ivy Glover",
                "host_address": "208.171.130.97",
                "protocol": "HTTP",
                "tag": 33,
                "assets_account": "Sweet",
                "datetime": "2021-03-02T10:24:31 -08:00"
            }
        ]
        return queryset

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Users'),
            'action': "运维任务",
            'date_from': self.date_from,
            'date_to': self.date_to,
            'user': self.user,
            'keyword': self.keyword,
            'user_list': set(LoginLog.objects.all().values_list('username', flat=True))
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)


class DocsListView(DatetimeSearchMixin, ListView):
    template_name = 'users/docs.html'
    model = LoginLog
    paginate_by = settings.DISPLAY_PER_PAGE
    user = keyword = ""
    date_to = date_from = None

    def get_queryset(self):
        self.user = self.request.GET.get('user', '')
        self.keyword = self.request.GET.get("keyword", '')

        queryset = super().get_queryset()
        queryset = queryset.filter(
            datetime__gt=self.date_from, datetime__lt=self.date_to
        )
        if self.user:
            queryset = queryset.filter(username=self.user)
        if self.keyword:
            queryset = queryset.filter(
                Q(ip__contains=self.keyword) |
                Q(city__contains=self.keyword) |
                Q(username__contains=self.keyword)
            )
        queryset = [
            {
                "id": "60449091c125815756ec52ef",
                "host_name": "Aritney Lindsey",
                "host_address": "214.143.63.85",
                "protocol": "TCP",
                "tag": 37,
                "assets_account": "Bray",
                "datetime": "2014-08-15T04:53:14 -08:00"
            },
            {
                "id": "60449091277788a6d2f17980",
                "host_name": "Claudette Green",
                "host_address": "151.218.176.99",
                "protocol": "UDP",
                "tag": 38,
                "assets_account": "Benton",
                "datetime": "2020-03-11T07:52:30 -08:00"
            },
            {
                "id": "60449091fe22b6382b00506c",
                "host_name": "Reed Diaz",
                "host_address": "113.250.99.154",
                "protocol": "TCP",
                "tag": 26,
                "assets_account": "Perkins",
                "datetime": "2015-04-19T11:18:00 -08:00"
            },
            {
                "id": "6044909198ba7d655344aec3",
                "host_name": "Jenkins Gonzales",
                "host_address": "93.125.192.227",
                "protocol": "UDP",
                "tag": 29,
                "assets_account": "Fisher",
                "datetime": "2016-01-04T01:01:07 -08:00"
            },
            {
                "id": "60449091c3348bc98ebd61df",
                "host_name": "Cindy Gordon",
                "host_address": "142.135.108.71",
                "protocol": "FTP",
                "tag": 29,
                "assets_account": "Mccoy",
                "datetime": "2017-05-04T06:56:21 -08:00"
            },
            {
                "id": "6044909185b024337f28a807",
                "host_name": "Ethel Adams",
                "host_address": "253.38.200.187",
                "protocol": "DNS",
                "tag": 20,
                "assets_account": "Doyle",
                "datetime": "2018-04-11T10:46:50 -08:00"
            },
            {
                "id": "60449091dede9c7dfc906199",
                "host_name": "Ivy Glover",
                "host_address": "208.171.130.97",
                "protocol": "HTTP",
                "tag": 33,
                "assets_account": "Sweet",
                "datetime": "2021-03-02T10:24:31 -08:00"
            }
        ]
        return queryset

    def get_context_data(self, **kwargs):
        context = {
            'app': _('Users'),
            'action': "文档",
            'date_from': self.date_from,
            'date_to': self.date_to,
            'user': self.user,
            'keyword': self.keyword,
            'user_list': set(LoginLog.objects.all().values_list('username', flat=True))
        }
        kwargs.update(context)
        return super().get_context_data(**kwargs)

