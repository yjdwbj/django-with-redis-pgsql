"""mqtt_auth URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from django import views
from user_manager.views import *
from django.conf.urls.static import static
from django.contrib.staticfiles import views


urlpatterns = [
    url(r'^admin/', admin.site.urls),

    url(r'^iot/v1.0/dev/active/(?P<account>\w+)/(?P<pwd>\w+)/$', IotDevActive),
    url(
        r'^iot/v1.0/app/findpwd/(?P<account>\w+)/(?P<captcha>\d{6})/$', AppFindPwd),
    url(
        r'^iot/v1.0/app/active/(?P<Md5sum>\w+)/(?P<smscode>\d{5})/$', AppVerifyPhone),
    # url(r'^iot/v1.0/app/opt/(?P<token>\w+)/(?P<target>\w+)/(?P<action>\w+)/$',AppAction1),
    url(
        r'^iot/v1.0/app/opt/(?P<target>[a-fA-F0-9]{32})/(?P<action>\w+)/$', AppAction),
    url(
        r'^iot/v1.0/app/resetpwd/(?P<Md5sum>[a-fA-F0-9]{32})/(?P<newpass>\w+)/(?P<smscode>\d{5})/$', AppResetPwd),
    url(r'^iot/v1.0/app/sendsms/(?P<account>[a-fA-F0-9]{32})/$', AppSendSms),
    # url(r'^iot/v1.0/app/(?P<token>\w+)/(?P<action>\w+)/$',AppQuery1),
    url(r'^iot/v1.0/app/(?P<action>\w+)/$', AppQuery),
    # url(r'^iot/v1.0/dev/changedev/(?P<token>\w+)/(?P<newname>\w+)/$',ChangeDevName1),
    url(r'^iot/v1.0/dev/changedev/(?P<newname>\w+)/$', ChangeDevName),
    url(r'^iot/v1.0/app/auth/(?P<account>\w+)/(?P<pwd>\w+)/$', IotAppAuth),
    url(r'^iot/v1.0/dev/auth/(?P<account>\w+)/(?P<pwd>\w+)/$', IotDevAuth),
    url(r'^iot/v1.0/app/register/$', IotAppRegister),
    # url(r'^iot/v1.0/ping/(?P<token>\w+)/$', IotPing1),
    url(r'^iot/v1.0/ping/$', IotPing),
    # url(
    #      r'^iot/v1.0/querycert/(?P<token>\w+)/(?P<ipaddr>[0-9.]{7,15})/$',
    #      QueryCert1),
    url(r'^iot/v1.0/querycert/(?P<ipaddr>[0-9.]{7,15})/$', QueryCert),
    #     url(r'^register/$',AppRegister),
    url(r'^get_code/$', get_verify_code)

]


if settings.DEBUG is False:
    urlpatterns += [
        url(r'^static/(?P<path>.*)$', views.serve),
    ]

if settings.DEBUG is False:  # if DEBUG is True it will be served automatically
    urlpatterns.append(
        url(r'^static/(?P<path>.*)$', views.static.serve,
            {'document_root': settings.STATIC_ROOT}),
    )
