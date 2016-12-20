# coding: utf-8

from django.shortcuts import render, render_to_response
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
import json
import hashlib, hmac
import md5, time
import random
from collections import OrderedDict
from user_manager.models import *
from django.db.models import Max, Min, F
from django.template import RequestContext
from .forms import *
from django.contrib.sites.shortcuts import get_current_site

from django.views.decorators.debug import sensitive_post_parameters
import base64
import captcha

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError


from django.core.cache import cache as redis_pool


from django_redis import get_redis_connection
redis_pool = get_redis_connection("default")


from django.db.models.query import IntegrityError

from django.utils.encoding import force_text
from django.core import serializers
import sendsms
from sendsms import ErrDict
from urllib2 import HTTPError

from models import *
from django.core.files import File
from django.db.models.query import Q
from operator import __or__ as OR
from uuid import UUID
import mimetypes

import magic
from django.db import connection, transaction


from django.contrib.auth.hashers import check_password


G_OLDPASS = 'oldpass'
G_NEWPASS = 'newpass'
G_REGISTER = 'register'
G_PHONE = 'phone'
G_UUID = 'uuid'
G_KEY = 'key'
G_EMAIL = 'email'
G_PASSWORD = 'password'
G_IPADDR = 'ipaddr'
G_SIGN = 'sign'
G_CAPTCHA = 'captcha'
G_NAME = 'name'
G_UNAME = 'uname'
G_REMOTE_ADDR = 'REMOTE_ADDR'
G_SMSCODE = 'smscode'
G_CSRFTOKEN = 'csrftoken'
G_DEVID  = 'devid'
G_APPID = 'appid'
G_TOPICS = 'topics'
G_DKEY   = 'dkey'
G_MSG = 'msg'
G_OK = 'ok'
G_ERR = 'err'
G_DATA = 'data'
G_EXPIRE = 'expire'
G_SRVS = 'srvs'
G_VER = 'ver'

UnkownSignMethod = json.dumps({G_ERR:"UnkownSignMethod",
                G_MSG:u"未知签名方法", G_OK:False}, ensure_ascii=False)
SignError = json.dumps({G_ERR:"SignError", G_MSG:u"签名错误", G_OK:False}, ensure_ascii=False)
DataMiss = json.dumps({G_ERR:"DataMiss", G_MSG:u"信息不完整", G_OK:False}, ensure_ascii=False)
UserNotExists = json.dumps({G_ERR: "UserNotExists", G_MSG:u"用户不存在", G_OK:False}, ensure_ascii=False)
UnAuth = json.dumps({G_ERR: "UnAuth", G_MSG:u"无权访问", G_OK:False}, ensure_ascii=False)
TargetNotExists = json.dumps({G_ERR: "TargetNotExists", G_MSG:u"目标不存在", G_OK:False}, ensure_ascii=False)
TargetIsSelf = json.dumps({G_ERR: "TargetIsSelf", G_MSG:u"目标不能是自已", G_OK:False}, ensure_ascii=False)
UnkownAction = json.dumps({G_ERR:"UnkownAction", G_MSG:u"未识别的操作", G_OK:False}, ensure_ascii=False)
BindError = json.dumps({G_ERR:"BindError", G_MSG:u"已经绑定", G_OK:False}, ensure_ascii=False)
BindPWDError = json.dumps({G_ERR:"BindError", G_MSG:u"无权绑定", G_OK:False}, ensure_ascii=False)
UserError = json.dumps({G_ERR:"UserError", G_MSG:u"用户名已存在", G_OK:False}, ensure_ascii=False)
EmailError = json.dumps({G_ERR:"EmailError", G_MSG:u"邮箱已存在", G_OK:False}, ensure_ascii=False)
PhoneError = json.dumps({G_ERR:"PhoneError", G_MSG:u"手机号已存在", G_OK:False}, ensure_ascii=False)
PwdError = json.dumps({G_ERR:"PwdError", G_MSG:u"用户或者密码错误", G_OK:False}, ensure_ascii=False)
ArgError = json.dumps({G_ERR:"ArgError", G_MSG:u"参数错误", G_OK:False}, ensure_ascii=False)
CaptchaError = json.dumps({G_ERR:"CaptchaError", G_MSG:u"验证码错误", G_OK:False}, ensure_ascii=False)
IpAddrError = json.dumps({G_ERR:"IpAddrError", G_MSG:u"IP错误", G_OK:False}, ensure_ascii=False)
InternalError = json.dumps({G_ERR:"InternalError", G_MSG:u"服务器内部错误", G_OK:False}, ensure_ascii=False)
SmsOverError = json.dumps({G_ERR:"SmsOverError", G_MSG:u"该手机号已经超过发送次数", G_OK:False}, ensure_ascii=False)
SmsIntervalError = json.dumps({G_ERR:"SmsIntervalError", G_MSG:u"发送间隔太短", G_OK:False}, ensure_ascii=False)
OtherError = json.dumps({G_ERR:"OtherError", G_MSG:u"发送间隔太短", G_OK:False}, ensure_ascii=False)
PhoneInactive = json.dumps({G_ERR:"PhoneInactive", G_MSG:u"该手机号没有验证激活", G_OK:False}, ensure_ascii=False)
FormatError = json.dumps({G_ERR:"FormatError", G_MSG:u"格式错误", G_OK:False}, ensure_ascii=False)
DevActError = json.dumps({G_ERR:"DevActError", G_MSG:u"设备未出厂", G_OK:False}, ensure_ascii=False)
DevGrantError = json.dumps({G_ERR:"DevGrantError", G_MSG:u"设备未授权", G_OK:False}, ensure_ascii=False)
DupActError = json.dumps({G_ERR:"DupActError", G_MSG:u"设备已经激活", G_OK:False}, ensure_ascii=False)
SizeError = json.dumps({G_ERR:"SizeError", G_MSG:u"文件内容超大", G_OK:False}, ensure_ascii=False)
ShareError = json.dumps({G_ERR:"ShareError", G_MSG:u"无权分享该主题", G_OK:False}, ensure_ascii=False)




JsonType = 'application/json; charset=utf-8'
ReturnOK = HttpResponse(json.dumps({G_OK:True}),content_type = JsonType)


# Create your views here.

def HttpReturn(ret,ctx = JsonType):
    return HttpResponse(ret,content_type=ctx)


def get_verify_code(request):
    txt, img = captcha.get_code()
    request.session[request.COOKIES.get(G_CSRFTOKEN)] = txt
#     data = AppUser.objects.all()[0].avatar
#     return HttpResponse(base64.b64decode(data), content_type='image/png')
    return HttpResponse(img.decode('base64'), content_type='image/png')

def QueryCert(request,token,ipaddr):
    if not redis_pool.hget(token, G_UUID):
        return HttpReturn(UnAuth)
        
    # ## 更新登录状态时间
    redis_pool.expire(token, settings.SESSION_COOKIE_AGE)

    retdict = {}
    retdict[G_OK]  = True     
    try:
        srv = SrvList.objects.get(ipaddr=ipaddr)   
    except (ObjectDoesNotExist, IndexError) as e:
        retdict['cert'] = None
    else:
        #retdict['cert'] = srv.pubkey
        ## 小机端不支持zlib
#         print "cert is ",srv.cert
#         import zlib
        retdict['cert'] =str(srv.cert)
      
    return HttpReturn(json.dumps(retdict))
        
    

def PreCheckRequest(request, obj, data):   
#     print len(data),data;
#     signMethod = data.get('signMethod','')
    rawpwd = data.get(G_KEY, '')
#     print "request key", rawpwd,obj.key
    if not check_password(rawpwd, obj.key):
        return HttpReturn(UnAuth)
    
#     srvobj = SrvList.objects.annotate(max_mark=Min('concount')).filter(concount=F('max_mark'))
    # ##选取最小的连接数的服务器
    srvipaddr = '0.0.0.0'
    retdict = {}
    hkey = 'null'
    try:
        srvipaddr = SrvList.objects.values_list(G_IPADDR).annotate(Min('concount')).order_by('concount')[0]   
    except (ObjectDoesNotExist, IndexError) as e:
        retdict[G_SRVS] = None
#         retdict[G_VER] = None
    else:
        srvobj = SrvList.objects.get(ipaddr=srvipaddr[0])
        ### 这里新的不再返回服务器的证
#         resflag = data.get('resFlag', 'all')
#         if not cmp(resflag, 'ip'):
#             retdict['servers'] = ':'.join([srvobj.ipaddr, str(srvobj.port)])  
#         elif not cmp(resflag, 'cert'):
#             retdict['pubkey'] = base64.b64encode(srvobj.pubkey)
#         else:
#             retdict['servers'] = ':'.join([srvobj.ipaddr, str(srvobj.port)])
#             retdict['pubkey'] = base64.b64encode(srvobj.pubkey) 
#         retdict[G_VER] = srvobj.mver
        retdict[G_SRVS] = ':'.join([srvobj.ipaddr, str(srvobj.port)])
    retdict['time'] = str(int(time.time()))
    retdict[G_EXPIRE] = settings.SESSION_COOKIE_AGE

    hasher, iterations, salt, code = obj.key.split('$')

    retdict[G_SIGN] = hmac.new(str(salt), str(time.time())).hexdigest().upper()
    retdict[G_OK] = True
    hkey = retdict[G_SIGN]
    
    
    
    ipaddr, state = IpAddress.objects.get_or_create(ipaddr=request.META.get(G_REMOTE_ADDR))
#     print "ipaddr",ipaddr
    redis_pool.hmset(hkey, {G_PASSWORD: hashlib.sha256(rawpwd).hexdigest(),
                             G_IPADDR: ipaddr.ipaddr, G_UUID: obj.uuid.hex})
    redis_pool.expire(hkey, settings.SESSION_COOKIE_AGE)
 
#     print "request",request.META   
#     print "request",request.path
    if 'dev' in request.path:
        DevicesLoginHistory.objects.create(devices=obj, inout=True, ipaddr=ipaddr)
    else:
        AppUserLoginHistory.objects.create(user=obj, inout=True, ipaddr=ipaddr)
        retdict[G_UUID] = obj.uuid.hex
    return HttpReturn(json.dumps(retdict))

def IotAppAuth(request):
    data = request.POST
    
    if not data:
        data = request.GET
        
    token = data.get(G_UUID, '')
    key = data.get(G_KEY, '')
#     sign = data.get('sign','')
    obj = None;
    if not token or not key:
        return HttpReturn(DataMiss)
    
#     t = time.time()
#     Person.objects.raw('SELECT * FROM myapp_person WHERE last_name = %s', [lname])
    try:
        val = UUID(token, version=4)
        obj = AppUser.objects.raw('SELECT * FROM user_manager_appuser where uname = %s OR email = %s OR uuid = %s OR phone= %s',
                                  [token,token,token,token])[0]
    except (ObjectDoesNotExist,IndexError) as e:
        return HttpReturn(UserNotExists)
    except ValueError:
        # If it's a value error, then the string 
        # is not a valid hex code for a UUID.
        try:
            obj = AppUser.objects.raw('SELECT * FROM user_manager_appuser where uname = %s OR email = %s  OR phone= %s',
                                  [token,token,token])[0]
        except:
            return HttpReturn(UserNotExists)
            
    # ##　email,phone,uuid 都在数据库里找不到    
    if not obj:
        return HttpReturn(UserNotExists)
    if not obj.phone_active:
        return HttpReturn(PhoneInactive)

    
    
    return PreCheckRequest(request, obj, data)
    
    


def IotDevAuth(request):
    data = request.POST
    
    if not data:
        data = request.GET
    key = data.get(G_KEY, '')
    uuid = data.get(G_UUID, '')
    
    if not uuid or not key:
        return HttpReturn(DataMiss)
    obj = None    
    try:
        obj = Devices.objects.get(uuid=uuid)
    except (ObjectDoesNotExist,ValueError) as e:
        return HttpReturn(UserNotExists)
        
    return PreCheckRequest(request, obj, data)


def IotAppRegister(request):
    data = request.POST
    if not data:
        data = request.GET
        
    email = data.get(G_EMAIL, None)
    uname = data.get(G_NAME, None)
    phone = data.get(G_PHONE, None)
    key = data.get(G_KEY, None)
    captcha = data.get(G_CAPTCHA, None)
#     print "my captcha", request.session.pop(request.COOKIES.get(G_CSRFTOKEN))
    
    mycaptcha = None
    try:
        mycaptcha = request.session.pop(request.COOKIES.get(G_CSRFTOKEN))
    except KeyError:
        pass
        
    if captcha:
        if cmp(mycaptcha, captcha):
            return HttpReturn(CaptchaError)
    else:
        return HttpReturn(ArgError)
    
    if uname:
        try:
            tmp = AppUser.objects.get(uname=uname)
        except :
            pass
        else:
            return HttpReturn(UserError)
    else:
        return HttpReturn(ArgError)
        
    if phone:
        try:
            tmp = AppUser.objects.get(phone=phone)
        except :
            pass
        else:
            return HttpReturn(PhoneError)
    else:
        return HttpReturn(ArgError, content_type=JsonType)
        
    if email:
        try:
            tmp = AppUser.objects.get(email=email)
        except :
            pass
        else:
            return HttpReturn(EmailError)
    else:
        return HttpReturn(ArgError)
    
    ### 注册成功,验证手机激活帐号#####
    sendsms_code= hashlib.md5(phone + str(time.time())).hexdigest().upper()
    nuuid = uuid.uuid4().hex
    ipaddr = request.META.get(G_REMOTE_ADDR)
    redis_pool.hmset(sendsms_code,{G_EMAIL:email,G_KEY:key,G_UNAME:uname,G_UUID:nuuid
                     ,G_REGISTER:1,G_PHONE: phone,G_IPADDR: ipaddr})
    
    redis_pool.expire(sendsms_code, settings.SESSION_COOKIE_AGE)
    return HttpReturn(json.dumps({G_OK:True, G_UUID:nuuid, G_SMSCODE:sendsms_code}))
   


def AppRegister(request):
    if cmp(request.method, 'POST'):
        return render(request, 'register.html',
                                  {'form':AppRegForm()})
    form = AppRegForm(request.POST, request=request)
    if form.is_valid():
        if request.session.pop(request.COOKIES.get(G_CSRFTOKEN, '')) == form.get_captcha():
            try:
                form.save()
            except IntegrityError as e:
                msg = str(e)
                if G_EMAIL in msg:
                    form.add_error(G_EMAIL, u'邮箱已经存在')
#                     form.fields['email'].widget.attr['value'] =''
                    return render(request, 'register.html',
                                            {'form':form})
                elif G_PHONE in msg:
                    form.add_error(G_PHONE, u'手机已经存在')
#                     form.fields[G_PHONE].widget.attr['value'] =''
                    return render(request, 'register.html',
                                  {'form':form})
    
            return HttpResponseRedirect('')
        else:
            form.add_error(G_CAPTCHA, u'验证码不正确')
#             form.fields[G_CAPTCHA].widget.render('value','')
#             form.fields[G_CAPTCHA].widget.attr['value'] =''
            return render(request, 'register.html',
                                  {'form':form})
    else:
        form.fields[G_CAPTCHA].widget.attrs['value'] = ''
        return render(request, 'register.html',
                                  {'form':form})



def IotPing(request,token):
    if not redis_pool.hget(token, G_UUID):
        return HttpReturn(UnAuth)
    redis_pool.expire(token, settings.SESSION_COOKIE_AGE)
    return ReturnOK
        
def GetRequestBody(request):
    if request.body:
        try:
            return json.loads(request.body.decode('utf-8'))
        except ValueError:
#             print "出错了............................."
#             print "request.body", request.body
            return None
    else:
        return None

@transaction.atomic
def CheckBindDev(request, key, dev_uuid, user):
#     print "check bind dev ",key,dev_uuid,user
#     print "dev_uuid key ", dev_uuid.key
    
    if not check_password(key, dev_uuid.key):
        return HttpResponse(PwdError,
                                content_type=JsonType)
    devuidhex = None
    if isinstance(dev_uuid.uuid, unicode):
        devuidhex = dev_uuid.uuid
    else:
        devuidhex = dev_uuid.uuid.hex
    try:
        AppBindDevList.objects.get(devid=dev_uuid)
    except (ObjectDoesNotExist,ValueError) as e :
        topic,ok =  MqttTopics.objects.get_or_create(topic="/%s/#" % devuidhex)
        MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None,
                                         app =user,
                                        access=3, topic="/%s/#" % devuidhex)
        MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None,
                                         dev_id =devuidhex,
                                      access=3, topic="/%s/#" % devuidhex)
        
        
        topic,ok =  MqttTopics.objects.get_or_create(topic="/%s/#" % user.uuid.hex)
#         MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None,
#                                          app =user.uuid.hex,
#                                          access=3, topic=topic)
        MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None, 
                                         dev_id =devuidhex,
                                         access=3, topic="/%s/#" % user.uuid.hex)
        
        AppBindDevList.objects.create(appid=user, devid=dev_uuid)
        
        return ReturnOK
    else:
        return HttpReturn(BindError)  # 已经绑定了


def AppCheckBindDev(request,user,uuid):
    body = GetRequestBody(request)
    if not body:
        return HttpResponse(ArgError, content_type=JsonType)
    dev_key = body.get(G_DKEY, '')
    try:
        dev_uuid = Devices.objects.get(uuid=uuid)
    except (ObjectDoesNotExist, ValueError) as e:
        return HttpResponse(json.dumps({G_OK:True, "bound": False}),
                            content_type=JsonType)
    if not check_password(dev_key, dev_uuid.key):
        return HttpResponse(PwdError, content_type=JsonType)
    bound = True
    try:
        AppBindDevList.objects.get(devid=dev_uuid)
    except (ObjectDoesNotExist, ValueError) as e:
        bound = False
    return HttpReturn(json.dumps({G_OK:True, "bound": bound}))

@transaction.atomic
def AppBindDev(request, user, uuid):
   
#     print "request POST",request.POST
#     for (k,v) in request.__dict__.items():
#         if k != 'META' and k != 'environ':
#             print "key:",k,"value is  ------------->",v
    
    body = GetRequestBody(request)
#     print "body is", body
    if not body:
        return HttpReturn(ArgError)
    
    ipaddr, ok = IpAddress.objects.get_or_create(ipaddr=request.META.get(G_REMOTE_ADDR))    
    try:
        dev_uuid = Devices.objects.get(uuid=uuid)
    except (ObjectDoesNotExist,ValueError) as e:
#         return HttpResponse(TargetNotExists,
#                             content_type=JsonType)
#         ### 本地DB没有找到去设备生产DB找
        try:
#             print "type str is", type(uuid)
            iot_dev = DevicesMaker.objects.using('devdb').get(iot_uuid=uuid)
        except (ObjectDoesNotExist,ValueError) as e:
            return HttpReturn(TargetNotExists)
        else:
            if iot_dev.status < 3:
                return HttpReturn(DevActError)
            else:
                dev_uuid = Devices(mac=iot_dev.iot_mac,
                                       uuid=iot_dev.iot_uuid,
                                       appkey=iot_dev.app_key,
                                       key=iot_dev.iot_key,
                                       name=iot_dev.app_name,
                                       regip=ipaddr,
                                       regtime=timezone.now())
                dev_uuid.save()
                return CheckBindDev(request, body.get(G_DKEY, ''), dev_uuid, user)
                 
    else:
        return CheckBindDev(request, body.get(G_DKEY, ''), dev_uuid, user)

    
@transaction.atomic
def AppDropDev(request, user, target):
    try:
        dev_uuid = Devices.objects.get(uuid=target)
    except (ObjectDoesNotExist,ValueError) as e:
        return HttpReturn(TargetNotExists)
    else:
        # 删除绑定,同时删除ＡＣＬ,这里对于数据库要用到事务.
        try:                    
#             MqttAcl.objects.filter(username=user.uuid.hex, topic="/%s/#" % target).delete()
#             MqttAcl.objects.filter(app=user.uuid.hex, topic="/%s/#" % target).delete()   
            MqttAcl.objects.filter(app=user.uuid.hex, topic__iexact="/%s/#" % target).delete()
        except :
            pass
        
        try:                    
#             MqttAcl.objects.filter(username=target, topic='/%s/#' % user.uuid.hex).delete()
            MqttAcl.objects.filter(dev=target, topic='/%s/#' % user.uuid.hex).delete()    
        except :
            pass
        try:
            AppBindDevList.objects.get(appid=user, devid=dev_uuid).delete()
        except :
            pass
        return ReturnOK     
    


def IotDevActive(request,account,pwd):
    devid = account.upper()
    try:
        tmp = Devices.objects.get(uuid = devid)
    except (ObjectDoesNotExist,ValueError) as e:
        pass
    else:
        return HttpReturn(DupActError)
        
    try:
       
        iot_dev = DevicesMaker.objects.using('devdb').get(iot_uuid=devid)
    except (ObjectDoesNotExist,ValueError) as e:
        return HttpReturn(TargetNotExists)
   
    else:
        if iot_dev.status < 2:
            return HttpReturn(DevGrantError)
        else:
            if not check_password(pwd, iot_dev.iot_key):
                return HttpReturn(PwdError)
                
            ipobj,ok = IpAddress.objects.get_or_create(ipaddr=request.META.get(G_REMOTE_ADDR),
                                                    geoip=None)
            f = lambda x: x if not x else "empty"
            obj,ok = Devices.objects.get_or_create(mac=iot_dev.iot_mac,
                                   uuid=iot_dev.iot_uuid,
                                   appkey=iot_dev.app_key,
                                   key=iot_dev.iot_key,
                                   name=f(iot_dev.app_name),
                                   regip=ipobj,
                                   regtime=timezone.now())
            
            return ReturnOK
            
    

@transaction.atomic
def AcceptBindLink(request, user, uuid):
#     print "accept user %s to bind uuid %s" % (user.uuid.hex, uuid)
    shared_keys = redis_pool.hgetall(uuid)
#     print "shared_keys",shared_keys,"type",type(shared_keys)
   
    if not shared_keys:
        return HttpReturn(UnAuth)
    
    if user.uuid.hex == shared_keys[G_APPID]:
        return HttpReturn(UnAuth)  
#     print "shared redis key",shared_keys,'type is',type(shared_keys)
#     print "shared topics",type(shared_keys[G_TOPICS]),shared_keys[G_TOPICS]

#     topic,ok =  MqttTopics.objects.get_or_create(topic="/%s/#" % user.uuid.hex)
    
#     SharedDevList.objects.get_or_create(host_id = shared_keys[G_APPID],
#                                         guest = user,
#                                         sdevice_id = shared_keys[G_DEVID],
#                                         topics = shared_keys[G_TOPICS])
    tdict = json.loads(shared_keys[G_TOPICS])
    shared_keys[G_TOPICS] = tdict
#     print "topic dict is ",tdict
    for item in tdict :
#         topic,ok =  MqttTopics.objects.get_or_create(topic=item)
        MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None,
                                         app = user,
                                         access=3, topic="/%s/%s/#" % (shared_keys[G_DEVID],item))
    
    ### 记录分享者,接受者,设备uuid,主题
    redis_pool.expire(uuid,1)
#     for k,v in shared_keys.items():
#         redis_pool.hdel(uuid,key)
    return HttpReturn(json.dumps({G_OK:True, G_DATA:shared_keys}))
#         return JsonResponse({G_OK:True,G_DATA:res},safe = False)

def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError
    
def AppAcceptedShared(request,owner):
    ###查询自已接受分享的设备
    slist = MqttAcl.objects.filter(app = owner)
    devices = AppBindDevList.objects.filter(appid = owner)
    lst1 = [ '/%s/#' % x.devid_id.hex for x in devices]
#     print "owner uuid ",owner.uuid.hex
    
    lst2 = [x.topic for x in slist]
    lst3 = list(set(lst2).difference(set(lst1))) #取两个表的差集.
#     print "list3 is",lst3
    userdict = {}
    def package(lst):
        if len(lst) > 1:
            key = lst[0]
            abd = AppBindDevList.objects.filter(devid_id = key)
            if len(abd) > 0:
                user = abd[0].appid_id.hex
                if user in userdict:
                    if key in userdict[user]:
                        [userdict[user][key].add(x) for x in lst[1:]]
                    else:
                        userdict[user][key] = set()
                        [userdict[user][key].add(x) for x in lst[1:]]
                else:
                    userdict[user] ={} 
                    userdict[user][key] = set()
                    [userdict[user][key].add(x) for x in lst[1:]]

    for x in lst3:
        lst = x.split("/")[1:-1]
        package(lst)
            
    return HttpReturn(json.dumps({G_OK:True,G_DATA:userdict},default=set_default))
    
def AppGetMySharedOut(request,owner):
    ###　查询自已分享出去的设备,与那些人接受了这些设备.
    devices = AppBindDevList.objects.filter(appid = owner)
    lst = [x.devid_id.hex for x in devices]
    
#     filter_qs = Q()
    shardict = {}
    for x in lst:
#         print "bind dev",x
        topics = MqttAcl.objects.filter(Q(topic__startswith = "/%s" % x) & ~Q(app=owner) & ~Q(dev_id=x))
        for y in topics:
#             print "my shared topic",y
            tlist = y.topic.split("/")[1:-1] # /uuid/# --> uuid
            dev = tlist[0]
            uid = y.app_id.hex
            if dev in shardict:
                if uid in shardict[dev]:
                    shardict[dev][uid].add(tlist[1])
                else:
                    shardict[dev][uid] = set()
                    shardict[dev][uid].add(tlist[1])
            else:
                shardict[dev] = {}
                l = {}
                l[uid] = set()
                l[uid].add(tlist[1])
                shardict[dev] = l
        
    return HttpReturn(json.dumps({G_OK:True,G_DATA:shardict},default=set_default))
    

def AppDelShareDev(request,owner):
    USERS = 'users'
    TOPICS = "topics"
    DEVS="devs"
    ALL = "*"
    deldict = GetRequestBody(request)
    if not deldict or not all(x in deldict for x in [USERS,TOPICS,DEVS]):
        return HttpReturn(ArgError)
    
    ## 先通过绑定表,找出该用户的所有绑定设备.
    devices = AppBindDevList.objects.filter(appid = owner)
    if isinstance(deldict[USERS],list):
        def deleteTopic3(user,dev,topic):
            txt = '/%s/%s/#' % (dev,topic)
#             print "{'users':[...],G_TOPICS:[...],'devs':*",txt
#             print "user is ----> ",user
            MqttAcl.objects.filter(app_id = user,topic = txt).delete()
            
        
        def deleteTopic(user,dev):
                txt = '/%s' % (dev)
#                 print "{'users':[...],G_TOPICS:all,'devs':*",txt
                MqttAcl.objects.filter(app_id = user,topic__contains = txt).delete()
        if isinstance(deldict[TOPICS],list):
            if isinstance(deldict[DEVS],list):
                # {'users':[...],G_TOPICS:[...],'devs':[...]}
                lst1 = [u.devid_id.hex for u in devices]
                lst2 =list(set(lst1).intersection(set(deldict[DEVS])))
#                 print "users -------=--------= ",deldict[USERS]
                [deleteTopic3(user,dev,topic) for user in deldict[USERS] for dev in lst2 for topic in deldict[TOPICS]]
            else:
                # {'users':[...],G_TOPICS:[...],'devs':all}
                [deleteTopic3(user,dev.devid_id.hex,topic) for user in deldict[USERS] for dev in devices for topic in deldict[TOPICS]]
                
        else:
            
            if isinstance(deldict[DEVS],list):
                # {'users':[...],G_TOPICS:all,'devs':[...]}
                lst1 = [u.devid_id.hex for u in devices]
                # 取两个列表的交集.
                lst2 =list(set(lst1).intersection(set(deldict[DEVS])))
                [deleteTopic(user,dev) for user in deldict[USERS] for dev in lst2]
                
            else:
                # {'users':[...],G_TOPICS:all,'devs':'all'}
                [deleteTopic(user,dev) for user in deldict[USERS] for dev in devices]
               
    else:
        if isinstance(deldict[TOPICS],list):
            def deleteTopic(dev,topic):
                    txt = '/%s/%s/#' % (dev,topic)
#                     print "{'users':'all',G_TOPICS:[...],'devs':*}",txt
                    MqttAcl.objects.filter(topic__contains=txt).delete()
#             devices = AppBindDevList.objects.filter(appid = user)
            if isinstance(deldict[DEVS],list):
                # {'users':'all',G_TOPICS:[...],'devs':[...]}
#                 lst = [Q(devid_id = x) for x in deldict['devs']]
#                 devices = AppBindDevList.objects.filter(appid = user,reduce(OR,lst))
                lst1 = [u.devid_id.hex for u in devices]
                lst2 =list(set(lst1).intersection(set(deldict[DEVS])))
                [deleteTopic(dev,topic) for dev in lst2 for topic in deldict[TOPICS]]
                
            else:
                # {'users':'all',G_TOPICS:[...],'devs':'all'}
                
                [deleteTopic(dev.devid_id.hex,topic) for dev in devices for topic in deldict[TOPICS]]
 
        else:
            if isinstance(deldict[DEVS],list):
                # {'users':'all',G_TOPICS:'all','devs':[...]}
                lst1 = [u.devid_id.hex for u in devices]
                lst2 =list(set(lst1).intersection(set(deldict[DEVS])))
                for dev in lst2: 
                    txt = '/%s' % (dev)
#                     print " {'users':'all',G_TOPICS:'all','devs':[...]}",txt
                    MqttAcl.objects.filter(topic__contains=txt).delete()
                        
            else:
                # {'users':'all',G_TOPICS:'all','devs':'all'}
#                 devices = AppBindDevList.objects.filter(appid = user)
                
                for dev in devices:
                    txt = '/%s' % (dev.devid_id.hex)
#                     print "{'users':'all',G_TOPICS:'all','devs':'all'}",txt
                    MqttAcl.objects.filter(topic__contains=txt).delete()
    
    return ReturnOK
                    

def AppShareDev(request, user, devuuid):
    try:
#         results = AppBindDevList.objects.raw("SELECT devid_id from bindlist WHERE appid_id = %s AND devid_id=%s",
#                                          [user.uuid.hex,devuuid])
        results = AppBindDevList.objects.filter(devid_id = devuuid,appid = user)[0]
    except (ObjectDoesNotExist,IndexError) as e:
        return HttpReturn(TargetNotExists)
#     print "result id ",results
    if results.devid.uuid.hex != devuuid:
        return HttpReturn(TargetNotExists)

    otpuuid = uuid.uuid4().hex
    
    body = GetRequestBody(request)
    if not body or not isinstance(body,dict):
        return HttpReturn(ArgError)
    topics = body.get(G_TOPICS,None)
#     print "share topics is ",topics
    ## 检查topics 是否为空,是否是为列表类型,是否全部为真.
    if not topics or  not isinstance(topics,list):
        return HttpReturn(ArgError)
    
#     if not  all(devuuid in item for item in topics):
#         return HttpReturn(ShareError)
        
#         full_url = ''.join(['http://', get_current_site(request).domain, 
#                             '/shared/%s' % otpuuid])
    expire = settings.SESSION_COOKIE_AGE * 6
    res = {G_OK:True, 'otp':otpuuid,G_EXPIRE:expire}
    redis_pool.hmset(otpuuid,{G_APPID:user.uuid.hex,G_DEVID:devuuid,G_TOPICS:json.dumps(topics)})
    redis_pool.expire(otpuuid,expire)
    
#         return JsonResponse(res,safe=False) 
    return HttpReturn(json.dumps(res))
        
                

def AppAddFriend(request, user, uuid):
    try:
        friend = AppUser.objects.get(uuid=uuid)
    except (ObjectDoesNotExist,ValueError) as e:
        return HttpReturn(TargetNotExists)
    else:
        if friend == user:
            return HttpReturn(TargetIsSelf)
            
        AppFriendList.objects.get_or_create(my_uuid=user, friend=friend)
    return ReturnOK


def AppRemoveFriend(request, user, uuid):
    try:
        friend = AppUser.objects.get(uuid=uuid)
        AppFriendList.objects.get(my_uuid=user, friend=friend).delete()
    except :
        return HttpReturn(TargetNotExists)
    else:
        return ReturnOK
    

@transaction.atomic
def AppVerifyPhone(request, Md5sum, smscode):
    adict = redis_pool.hgetall(Md5sum)
    
    if not adict or  not all(x in adict for x in [G_PHONE,'sms']):
        return HttpReturn(UnAuth)
    if cmp(adict.get('sms',None), smscode):
        return HttpReturn(CaptchaError)
        
#     print "verify phone adict is", adict
    
    ipobj, ok = IpAddress.objects.get_or_create(ipaddr=request.META.get(G_REMOTE_ADDR))
    # 注册成功之后,添加注册记录,并添加一条 /uuid/# 的记录到mqtt_acl
    if G_REGISTER in adict:
        AppUser.objects.create(email =adict[G_EMAIL],
                               phone = adict[G_PHONE],
                               key = make_password(adict[G_KEY]),
                               uname = adict[G_UNAME],
                               uuid = adict[G_UUID],
                               regtime = timezone.now(),
                               regip = ipobj,
                               phone_active = True,
                               data = {'null':'null'})
        
      
        topic,ok =  MqttTopics.objects.get_or_create(topic="/%s/#" % adict[G_UUID])
        MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None,
                                             app_id =adict[G_UUID],
                                             access=3, topic=topic)
    else:
        obj = AppUser.objects.get(phone = adict[G_PHONE])
        obj.phone_active = True
        obj.save()
    
    #### 已经验证了,清除内存
    for (k,v) in adict.items():
        redis_pool.hdel(Md5sum,k)
    
    return ReturnOK


actionFunc = {'bind':AppBindDev,
              'checkbind':AppCheckBindDev,
              'unbind':AppDropDev,
              'add':AppAddFriend,
              'del':AppRemoveFriend,
              'reqshare':AcceptBindLink,
              'sharedev':AppShareDev,
              }


def AppAction(request, token, target, action):
    ipaddr = request.META.get(G_REMOTE_ADDR)
    mem_addr = redis_pool.hget(token, G_IPADDR)
     
    if not mem_addr or  cmp(mem_addr, ipaddr):
        return HttpReturn(UnAuth)
    # ## 更新登录状态时间
    redis_pool.expire(token, settings.SESSION_COOKIE_AGE)
    
    user = AppUser.objects.get(uuid=redis_pool.hget(token, G_UUID))        
    if action in actionFunc:
        return actionFunc[action](request, user, target)
    else:
        return HttpReturn(UnkownAction)

def AppSetAvatar(request,user):
#     print "request is",request.__dict__  
    
    datalen = len(request.body)
   
    btype = magic.Magic().id_buffer(request.body)
#     print "data len: ",datalen,"type is",btype
    if not any(ext in btype for ext in ['JPEG','PNG','GIF']):
        return HttpResponse(FormatError,
                            content_type=JsonType)
    if datalen > 102410:
        return HttpReturn(SizeError)
#     user.avator = request.body
  
    cursor = connection.cursor()
#     print "user.uuid",user.uuid.hex

    cursor.execute('UPDATE user_manager_appuser set avatar = %s where uuid = %s',
                              [base64.b64encode(request.body),str(user.uuid.hex)])
#     transaction.set_dirty()        
    transaction.commit()
    return ReturnOK

def AppGetAvatar(request,user):
    return HttpResponse(base64.b64decode(user.avatar),content_type=user.get_mimetype)        


def AppUserChange(request, user):
    body = GetRequestBody(request)
    if not body:
        return HttpReturn(ArgError)
    
    oldpass = body.get(G_OLDPASS, None)
    
#     if cmp(oldpass,user.key):   #### 修改信息必须要用原密码
    if not check_password(oldpass, user.key):
        return HttpReturn(PwdError)
    newpass = body.get(G_NEWPASS, None)
#
    for k,v in body.items():
        if k in [G_EMAIL,'nickname',G_PHONE,'sex']:
#             print k, " set value ",type(v)
            setattr(user,k,v)
        if k == G_PHONE:  ### 更改了手机要重新激活帐号
            setattr(user,"phone_active",False)
    if newpass:
#         print "set newpass ",newpass
        user.key = make_password(newpass)
    
    user.save()
    
    return ReturnOK



def ChangeDevName(request,token,newname):
#     body = GetRequestBody(request)
#     if not body or not body.get('name',None):
#         return HttpReturn(ArgError)
    
    devuuid = redis_pool.hget(token,G_UUID)
   
    if not devuuid:
        return HttpReturn(UnAuth) 
    try:
        devobj =  Devices.objects.get(uuid=devuuid)
    except:
        return HttpReturn(TargetNotExists)
    else:
        devobj.name = newname
        devobj.save()
        return ReturnOK

    
        
        

def AppQueryApp(request, user):
    applist = AppFriendList.objects.filter(my_uuid=user) 
    
    results = [ob.as_json() for ob in AppUser.objects.filter(friend_user__in=applist)]
    return HttpReturn(json.dumps({"list":results, G_OK:True}))

def AppQueryDev(request, user):
    devlist = AppBindDevList.objects.filter(appid=user)
    lst = [x.devid.uuid.hex for x in devlist]
    l = Devices.objects.filter(pk__in=lst)
    results = [ ob.as_json() for ob in l]
    return HttpReturn(json.dumps({"list":results ,
                                    G_OK:True}))
    
 
def AppRsyncData(request,user):
    return HttpReturn(json.dumps({G_OK:True,
                                    G_DATA:user.data}))
    
def AppGetInfo(request,user):
    return HttpReturn(json.dumps({G_OK:True,"info":user.as_json()}))
    
 
def AppSyncData(request, user):
    body = GetRequestBody(request)
    if not body:
        return HttpReturn(ArgError)
#     print "-----------------------sync body is",body,type(user)
    user.data = body
    user.save()
    return ReturnOK
 

def AppSendSms(request, account):
    SENDCOUNT = 'sendcount'
#     phone = redis_pool.hget(account, G_PHONE)
    adict= redis_pool.hgetall(account)
#     print "all key is",adict
    
    if G_PHONE not in adict:
        return HttpReturn(UnAuth)
        
#     redis_pool.hdel(account, G_PHONE)
#     print "phone number ", phone 
    
    ### 同一号24小时只能发送三次短信. ###
    sendnum = redis_pool.hget(adict[G_PHONE], SENDCOUNT)
#     print "gettxt from redis", sendnum
    if sendnum and int(sendnum) == 3:
        return HttpReturn(SmsOverError)
    
    sendtime = redis_pool.hget(adict[G_PHONE], 'lastime')
    
    if sendtime and (time.time() - int(sendtime)) < settings.SESSION_COOKIE_AGE / 10:
        return HttpReturn(SmsIntervalError)
        
#     ipaddr = request.META.get('REMOTE_ADDR')
    ipobj, ok = IpAddress.objects.get_or_create(ipaddr=request.META.get(G_REMOTE_ADDR))
    oldaddr = redis_pool.hget(account, G_IPADDR)
    if cmp(ipobj.ipaddr, oldaddr):
        return HttpReturn(IpAddrError)
    
    try:
        (sms, state) = sendsms.SendSMS(adict[G_PHONE])
    except HTTPError:
        return HttpReturn(InternalError)
    except IndexError:
        SmsErrorLog.objects.create(-100, ipobj, timezone.now, adict[G_PHONE])
        return HttpReturn(InternalError)
    if state == 0:
        redis_pool.expire(adict[G_PHONE], settings.SESSION_COOKIE_AGE)
        redis_pool.hset(adict[G_PHONE], 'lastime', int(time.time()))
#         redis_pool.expire(phone,settings.SESSION_COOKIE_AGE)
        if redis_pool.hget(adict[G_PHONE], SENDCOUNT):
            redis_pool.hincrby(adict[G_PHONE], SENDCOUNT, 1)
        else:
            redis_pool.hset(adict[G_PHONE], SENDCOUNT, 1)
        resetcode = hashlib.md5(adict[G_PHONE] + str(time.time())).hexdigest().upper()
        if G_REGISTER in adict:
            for (k,v) in adict.items():
                redis_pool.hset(resetcode,k,v)
        
        redis_pool.hmset(resetcode, {G_PHONE: adict[G_PHONE], 'sms': sms})
#         print "reset code dict is",redis_pool.hgetall(resetcode)
        redis_pool.expire(resetcode, settings.SESSION_COOKIE_AGE)
        redis_pool.hdel(account, G_PHONE) ## 删除这个键,一次有效
        return HttpReturn(json.dumps({G_OK:True, 'rescode':resetcode}))
    else:
        if state in ErrDict:
            errobj = SmsErrorTable.objects.get(errcode=state)
            SmsErrorLog.objects.create(errcode=errobj, ipaddr=ipobj,
                                       addtime=timezone.now(), phone=adict[G_PHONE])
        if state == 10006 or state == 10007 or state == 10005:
            return HttpReturn(json.dumps({G_ERR:"OtherError", G_MSG:ErrDict[state]}))
        else:
            return HttpReturn(InternalError)
    

    
QueryFunc = {'querydev':AppQueryDev,
             'queryapp':AppQueryApp,
             'sync':AppSyncData,
             'rsync':AppRsyncData,
             'getinfo':AppGetInfo,
             'change':AppUserChange,
             'setavatar':AppSetAvatar,
             'getavatar':AppGetAvatar,
             'sendsms':AppSendSms,
             'delshare':AppDelShareDev,
             'sharedout':AppGetMySharedOut,
             'sharedrecv':AppAcceptedShared}    
 
 
def AppResetPwd(request, Md5sum, newpass, smscode):
    
    phone = redis_pool.hget(Md5sum, G_PHONE)
    mysms = redis_pool.hget(Md5sum, 'sms')
    
    
    if not phone or not smscode:
        return HttpReturn(UnAuth)
    if cmp(mysms, smscode):
        return HttpReturn(CaptchaError)
    
    #### 已经验证了,清除内存
    redis_pool.hdel(Md5sum, G_PHONE)
    redis_pool.hdel(Md5sum, 'sms')
    
    try:
        user = AppUser.objects.get(phone=phone)
        user.key = make_password(newpass)
        user.save()
    except:
        pass
    
    return ReturnOK
    
def AppFindPwd(request, account, captcha):
#     print "find pwd first", account, captcha
    if not account or not captcha:
        return HttpReturn(ArgError)
    try:    
        mycaptcha = request.session.pop(request.COOKIES.get(G_CSRFTOKEN))
    except KeyError:
        return HttpReturn(CaptchaError)
    if cmp(mycaptcha, captcha):
        return HttpReturn(CaptchaError)

    try:
        accobj = AppUser.objects.raw('SELECT * FROM user_manager_appuser where uname = %s OR email = %s  OR phone= %s',
                              [account,account,account])[0]
    except:
        return HttpReturn(UserNotExists)
    else:
            
        if not accobj:
            return HttpReturn(TargetNotExists)
         
        smscode = hashlib.md5(accobj.phone + str(time.time())).hexdigest().upper()
        ipaddr = request.META.get(G_REMOTE_ADDR)
        redis_pool.hmset(smscode, {G_PHONE: accobj.phone, G_IPADDR: ipaddr})
        redis_pool.expire(smscode, settings.SESSION_COOKIE_AGE)
        
        res = {'name': accobj.uname,
                              G_PHONE: "%s****%s" % (accobj.phone[:3], accobj.phone[-4:]),
                              G_SMSCODE: smscode,
                              G_OK:True}
        return HttpReturn(json.dumps(res))
    
        
    
def AppQuery(request, token, action):
#     data = json.loads(cache.get(token))
    ipaddr = request.META.get(G_REMOTE_ADDR)
    mem_addr = redis_pool.hget(token, G_IPADDR)
#     print "action from signid ",data,' ipaddr ',ipaddr
    if not mem_addr or mem_addr != ipaddr:
        return HttpReturn(UnAuth)
    
    if action == 'logout':
#         print "request", request.path
        ipobj, state = IpAddress.objects.get_or_create(ipaddr=ipaddr)
        if 'dev' in request.path:
            obj = Devices.objects.get(uuid=redis_pool.hget(token, G_UUID))
            DevicesLoginHistory.objects.create(user=obj, inout=False, ipaddr=ipobj, optime=timezone.now())
        else:
            obj = AppUser.objects.get(uuid=redis_pool.hget(token, G_UUID))
            AppUserLoginHistory.objects.create(user=obj, inout=False, ipaddr=ipobj, optime=timezone.now())
        redis_pool.expire(token, 1)
        redis_pool.hdel(token, G_IPADDR)
        redis_pool.hdel(token, G_UUID)
        return ReturnOK
    
    user = AppUser.objects.get(uuid=redis_pool.hget(token, G_UUID))
    # ## 更新登录状态时间
    redis_pool.expire(token, settings.SESSION_COOKIE_AGE)
    if action in QueryFunc:
        return QueryFunc[action](request, user)
    else:
        return HttpReturn(UnkownAction)
     
        
