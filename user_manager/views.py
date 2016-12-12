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
from uuid import UUID
import mimetypes

import magic
from django.db import connection, transaction







from django.contrib.auth.hashers import check_password



UnkownSignMethod = json.dumps({"err":"UnkownSignMethod",
                "msg":u"未知签名方法", "ok":False}, ensure_ascii=False)
SignError = json.dumps({"err":"SignError", "msg":u"签名错误", "ok":False}, ensure_ascii=False)
DataMiss = json.dumps({"err":"DataMiss", "msg":u"信息不完整", "ok":False}, ensure_ascii=False)
UserNotExists = json.dumps({"err": "UserNotExists", "msg":u"用户不存在", "ok":False}, ensure_ascii=False)
UnAuth = json.dumps({"err": "UnAuth", "msg":u"无权访问", "ok":False}, ensure_ascii=False)
TargetNotExists = json.dumps({"err": "TargetNotExists", "msg":u"目标不存在", "ok":False}, ensure_ascii=False)
TargetIsSelf = json.dumps({"err": "TargetIsSelf", "msg":u"目标不能是自已", "ok":False}, ensure_ascii=False)
UnkownAction = json.dumps({"err":"UnkownAction", "msg":u"未识别的操作", "ok":False}, ensure_ascii=False)
BindError = json.dumps({"err":"BindError", "msg":u"已经绑定", "ok":False}, ensure_ascii=False)
BindPWDError = json.dumps({"err":"BindError", "msg":u"无权绑定", "ok":False}, ensure_ascii=False)
UserError = json.dumps({"err":"UserError", "msg":u"用户名已存在", "ok":False}, ensure_ascii=False)
EmailError = json.dumps({"err":"EmailError", "msg":u"邮箱已存在", "ok":False}, ensure_ascii=False)
PhoneError = json.dumps({"err":"PhoneError", "msg":u"手机号已存在", "ok":False}, ensure_ascii=False)
PwdError = json.dumps({"err":"PwdError", "msg":u"用户或者密码错误", "ok":False}, ensure_ascii=False)
ArgError = json.dumps({"err":"ArgError", "msg":u"参数错误", "ok":False}, ensure_ascii=False)
CaptchaError = json.dumps({"err":"CaptchaError", "msg":u"验证码错误", "ok":False}, ensure_ascii=False)
IpAddrError = json.dumps({"err":"IpAddrError", "msg":u"IP错误", "ok":False}, ensure_ascii=False)
InternalError = json.dumps({"err":"InternalError", "msg":u"服务器内部错误", "ok":False}, ensure_ascii=False)
SmsOverError = json.dumps({"err":"SmsOverError", "msg":u"该手机号已经超过发送次数", "ok":False}, ensure_ascii=False)
SmsIntervalError = json.dumps({"err":"SmsIntervalError", "msg":u"发送间隔太短", "ok":False}, ensure_ascii=False)
OtherError = json.dumps({"err":"OtherError", "msg":u"发送间隔太短", "ok":False}, ensure_ascii=False)
PhoneInactive = json.dumps({"err":"PhoneInactive", "msg":u"该手机号没有验证激活", "ok":False}, ensure_ascii=False)
FormatError = json.dumps({"err":"FormatError", "msg":u"格式错误", "ok":False}, ensure_ascii=False)
DevActError = json.dumps({"err":"DevActError", "msg":u"设备未出厂", "ok":False}, ensure_ascii=False)
DupActError = json.dumps({"err":"DupActError", "msg":u"设备已经激活", "ok":False}, ensure_ascii=False)
SizeError = json.dumps({"err":"SizeError", "msg":u"文件内容超大", "ok":False}, ensure_ascii=False)
ShareError = json.dumps({"err":"ShareError", "msg":u"无权分享该主题", "ok":False}, ensure_ascii=False)


JsonType = 'application/json; charset=utf-8'


# Create your views here.

def HttpReturn(ret,ctx = JsonType):
    return HttpResponse(ret,content_type=ctx)


def get_verify_code(request):
    txt, img = captcha.get_code()
    request.session[request.COOKIES.get('csrftoken')] = txt
#     data = AppUser.objects.all()[0].avatar
#     return HttpResponse(base64.b64decode(data), content_type='image/png')
    return HttpResponse(img.decode('base64'), content_type='image/png')

def QueryCert(request,token,ipaddr):
    if not redis_pool.hget(token, 'uuid'):
        return HttpReturn(UnAuth)
        
    # ## 更新登录状态时间
    redis_pool.expire(token, settings.SESSION_COOKIE_AGE)

    retdict = {}
    retdict["ok"]  = True     
    try:
        srv = SrvList.objects.get(ipaddr=ipaddr)   
    except (ObjectDoesNotExist, IndexError) as e:
        retdict['cert'] = None
    else:
        import zlib
        retdict['cert'] =base64.b64encode(zlib.compress(base64.b64decode(srv.pubkey),9))
    
    return HttpReturn(json.dumps(retdict))
        
    

def PreCheckRequest(request, obj, data):   
#     print len(data),data;
#     signMethod = data.get('signMethod','')
    rawpwd = data.get('key', '')
#     print "request key", rawpwd
    if not check_password(rawpwd, obj.key):
        return HttpReturn(UnAuth)
    
#     srvobj = SrvList.objects.annotate(max_mark=Min('concount')).filter(concount=F('max_mark'))
    # ##选取最小的连接数的服务器
    srvipaddr = '0.0.0.0'
    retdict = {}
    hkey = 'null'
    try:
        srvipaddr = SrvList.objects.values_list('ipaddr').annotate(Min('concount')).order_by('concount')[0]   
    except (ObjectDoesNotExist, IndexError) as e:
        retdict['servers'] = None
        retdict['mqttver'] = None
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
        retdict['mqttver'] = srvobj.mver
        retdict['servers'] = ':'.join([srvobj.ipaddr, str(srvobj.port)])
    retdict['time'] = str(int(time.time()))
    retdict['expire'] = settings.SESSION_COOKIE_AGE

    hasher, iterations, salt, code = obj.key.split('$')

    retdict['sign'] = hmac.new(str(salt), str(time.time())).hexdigest().upper()
    retdict['ok'] = True
    hkey = retdict['sign']
    
    
    ipaddr, state = IpAddress.objects.get_or_create(ipaddr=request.META.get('REMOTE_ADDR'))
#     print "ipaddr",ipaddr
    redis_pool.hset(hkey, 'password', hashlib.sha256(rawpwd).hexdigest())
    redis_pool.hset(hkey, 'ipaddr', ipaddr.ipaddr)
    redis_pool.hset(hkey, 'uuid', obj.uuid.hex)
    redis_pool.expire(hkey, settings.SESSION_COOKIE_AGE)
 
#     print "request",request.META   
#     print "request",request.path
    if 'dev' in request.path:
        DevicesLoginHistory.objects.create(devices=obj, inout=True, ipaddr=ipaddr, optime=timezone.now())
    else:
        AppUserLoginHistory.objects.create(user=obj, inout=True, ipaddr=ipaddr, optime=timezone.now())
    return HttpResponse(json.dumps(retdict))

def SqlTimeStatus(request):
    avgtime = 0.0
    try:
        avgtime = settings.ALLTIME /settings.CONNUM  
    except:
        pass
    status = str("numbers: %d\n" % settings.CONNUM) + str("alltime: %f\n" % settings.ALLTIME) \
        +str("mintime: %f\n" % settings.MINTIME) \
        +str("maxtime: %f\n" % settings.MAXTIME) \
        + "avgtime: %f\n" % avgtime
    return HttpResponse(status)


def IotAppAuth(request):
    data = request.POST
    
    if not data:
        data = request.GET
        
    token = data.get('uuid', '')
    key = data.get('key', '')
#     sign = data.get('sign','')
    obj = None;
    if not token or not key:
        return HttpResponse(DataMiss,
                                content_type=JsonType)
    
#     t = time.time()
#     Person.objects.raw('SELECT * FROM myapp_person WHERE last_name = %s', [lname])
    try:
        val = UUID(token, version=4)
        obj = AppUser.objects.raw('SELECT * FROM user_manager_appuser where uname = %s OR email = %s OR uuid = %s OR phone= %s',
                                  [token,token,token,token])[0]
    except (ObjectDoesNotExist,IndexError) as e:
        return HttpResponse(UserNotExists,
                                content_type=JsonType)
    except ValueError:
        # If it's a value error, then the string 
        # is not a valid hex code for a UUID.
        try:
            obj = AppUser.objects.raw('SELECT * FROM user_manager_appuser where uname = %s OR email = %s  OR phone= %s',
                                  [token,token,token])[0]
        except:
            return HttpResponse(UserNotExists,
                                content_type=JsonType)
            
    # ##　email,phone,uuid 都在数据库里找不到    
    if not obj:
        return HttpResponse(UserNotExists,
                                content_type=JsonType)
    if not obj.phone_active:
        return HttpResponse(PhoneInactive, content_type=JsonType)
    
    return PreCheckRequest(request, obj, data)
    
    


def IotDevAuth(request):
    data = request.POST
    
    if not data:
        data = request.GET
    key = data.get('key', '')
    uuid = data.get('uuid', '')
    
    if not uuid or not key:
        return HttpResponse(DataMiss,
                                content_type=JsonType)
    obj = None    
    try:
        obj = Devices.objects.get(uuid=uuid)
    except (ObjectDoesNotExist,ValueError) as e:
        return HttpResponse(UserNotExists,
                                content_type=JsonType)
        
    return PreCheckRequest(request, obj, data)


def IotAppRegister(request):
    data = request.POST
    if not data:
        data = request.GET
        
    email = data.get('email', None)
    uname = data.get('name', None)
    phone = data.get('phone', None)
    key = data.get('key', None)
    captcha = data.get('captcha', None)
#     print "my captcha", request.session.pop(request.COOKIES.get('csrftoken'))
    
    mycaptcha = None
    try:
        mycaptcha = request.session.pop(request.COOKIES.get('csrftoken'))
    except KeyError:
        pass
        
    if captcha:
        if cmp(mycaptcha, captcha):
            return HttpResponse(CaptchaError, content_type=JsonType)
    else:
        return HttpResponse(ArgError, content_type=JsonType)
    
    if uname:
        try:
            tmp = AppUser.objects.get(uname=uname)
        except :
            pass
        else:
            return HttpResponse(UserError,
                                content_type=JsonType)
    else:
        return HttpResponse(ArgError, content_type=JsonType)
        
    if phone:
        try:
            tmp = AppUser.objects.get(phone=phone)
        except :
            pass
        else:
            return HttpResponse(PhoneError,
                                content_type=JsonType)
    else:
        return HttpResponse(ArgError, content_type=JsonType)
        
    if email:
        try:
            tmp = AppUser.objects.get(email=email)
        except :
            pass
        else:
            return HttpResponse(EmailError,
                                content_type=JsonType)
    else:
        return HttpResponse(ArgError, content_type=JsonType)
    
#     ipobj, ok = IpAddress.objects.get_or_create(ipaddr=request.META.get('REMOTE_ADDR'))
#     obj = AppUser.objects.create(email=email, phone=phone,
#                    key=make_password(key), uuid=uuid.uuid4().hex,
#                    uname=uname,
#                    regtime=timezone.now(),
#                    regip=ipobj,
#                    data={})
#     
#     obj.save()
    ### 注册成功,验证手机激活帐号#####
    sendsms_code= hashlib.md5(phone + str(time.time())).hexdigest().upper()
    
    redis_pool.hset(sendsms_code,'email',email)
    redis_pool.hset(sendsms_code,'key',key)
    redis_pool.hset(sendsms_code,'uname',uname)
    nuuid = uuid.uuid4().hex
    redis_pool.hset(sendsms_code,'uuid',nuuid)
    redis_pool.hset(sendsms_code,'register',1)
    
    
    ipaddr = request.META.get('REMOTE_ADDR')
    redis_pool.hset(sendsms_code, 'phone', phone)
    redis_pool.hset(sendsms_code, 'ipaddr', ipaddr)
    redis_pool.expire(sendsms_code, settings.SESSION_COOKIE_AGE)
    return HttpResponse(json.dumps({"ok":True, "uuid":nuuid, 'smscode':sendsms_code}))
   


def AppRegister(request):
    if cmp(request.method, 'POST'):
        return render(request, 'register.html',
                                  {'form':AppRegForm()})
    form = AppRegForm(request.POST, request=request)
    if form.is_valid():
        if request.session.pop(request.COOKIES.get('csrftoken', '')) == form.get_captcha():
            try:
                form.save()
            except IntegrityError as e:
                msg = str(e)
                if 'email' in msg:
                    form.add_error('email', u'邮箱已经存在')
#                     form.fields['email'].widget.attr['value'] =''
                    return render(request, 'register.html',
                                            {'form':form})
                elif 'phone' in msg:
                    form.add_error('phone', u'手机已经存在')
#                     form.fields['phone'].widget.attr['value'] =''
                    return render(request, 'register.html',
                                  {'form':form})
    
            return HttpResponseRedirect('')
        else:
            form.add_error('captcha', u'验证码不正确')
#             form.fields['captcha'].widget.render('value','')
#             form.fields['captcha'].widget.attr['value'] =''
            return render(request, 'register.html',
                                  {'form':form})
    else:
        form.fields['captcha'].widget.attrs['value'] = ''
        return render(request, 'register.html',
                                  {'form':form})



def IotPing(request,token):
    if not redis_pool.hget(token, 'uuid'):
        return HttpReturn(UnAuth)
    redis_pool.expire(token, settings.SESSION_COOKIE_AGE)
    return HttpResponse(json.dumps({'ok':True}),
                            content_type=JsonType)
        
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
#         return HttpResponse(UnAuth,content_type=JsonType)
#     if key != dev_uuid.key:
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
        
#         MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None, username=user.uuid.hex,
#                                access=3, topic="/%s/#" % devuidhex)
#         MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None, username=user.uuid.hex,
#                                access=3, topic="/%s/#" % user.uuid.hex)
#         MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None, username=devuidhex,
#                                      access=3, topic="/%s/#" % user.uuid.hex)
#         MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None, username=devuidhex,
#                                      access=3, topic="/%s/#" % devuidhex)
#         AppBindDevList.objects.create(appid=user, devid=dev_uuid)
        
        return HttpResponse(json.dumps({"ok":True}), content_type=JsonType)
    else:
        return HttpResponse(BindError, content_type=JsonType)  # 已经绑定了


def AppCheckBindDev(request,user,uuid):
    body = GetRequestBody(request)
    if not body:
        return HttpResponse(ArgError, content_type=JsonType)
    dev_key = body.get('dkey', '')
    try:
        dev_uuid = Devices.objects.get(uuid=uuid)
    except (ObjectDoesNotExist, ValueError) as e:
        return HttpResponse(json.dumps({"ok":True, "bound": False}),
                            content_type=JsonType)
    if not check_password(dev_key, dev_uuid.key):
        return HttpResponse(PwdError, content_type=JsonType)
    bound = True
    try:
        AppBindDevList.objects.get(devid=dev_uuid)
    except (ObjectDoesNotExist, ValueError) as e:
        bound = False
    return HttpResponse(json.dumps({"ok":True, "bound": bound}),
                        content_type=JsonType)

@transaction.atomic
def AppBindDev(request, user, uuid):
   
#     print "request POST",request.POST
#     for (k,v) in request.__dict__.items():
#         if k != 'META' and k != 'environ':
#             print "key:",k,"value is  ------------->",v
    
    body = GetRequestBody(request)
#     print "body is", body
    if not body:
        return HttpResponse(ArgError, content_type=JsonType)
    
    ipaddr, ok = IpAddress.objects.get_or_create(ipaddr=request.META.get('REMOTE_ADDR'))    
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
            return HttpResponse(TargetNotExists,
                            content_type=JsonType)
        else:
            if iot_dev.status != 3:
                return HttpResponse(DevActError, content_type=JsonType)
            else:
                dev_uuid = Devices(mac=iot_dev.iot_mac,
                                       uuid=iot_dev.iot_uuid,
                                       appkey=iot_dev.app_key,
                                       key=iot_dev.iot_key,
                                       name=iot_dev.app_name,
                                       regip=ipaddr,
                                       regtime=timezone.now())
                dev_uuid.save()
                return CheckBindDev(request, body.get('dkey', ''), dev_uuid, user)
                 
    else:
        return CheckBindDev(request, body.get('dkey', ''), dev_uuid, user)

    
@transaction.atomic
def AppDropDev(request, user, target):
#     print "request POST",request.POST
#     for (k,v) in request.__dict__.items():
#         if k != 'META' and k != 'environ':
#             print "key:",k,"value is  ------------->",v
#     body = GetRequestBody(request) 
#     print "drop dev body is", body
#     if not body:
#         return HttpResponse(ArgError, content_type=JsonType)
    try:
        dev_uuid = Devices.objects.get(uuid=target)
    except (ObjectDoesNotExist,ValueError) as e:
        return HttpResponse(TargetNotExists,
                            content_type=JsonType)
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
        return HttpResponse(json.dumps({"ok":True}), content_type=JsonType)     
    


def IotDevActive(request,account,pwd):
    devid = account.upper()
    try:
        tmp = Devices.objects.get(uuid = devid)
    except (ObjectDoesNotExist,ValueError) as e:
        pass
    else:
        return HttpResponse(DupActError,
                            content_type=JsonType)
        
    try:
       
        iot_dev = DevicesMaker.objects.using('devdb').get(iot_uuid=devid)
    except (ObjectDoesNotExist,ValueError) as e:
        return HttpResponse(TargetNotExists,
                            content_type=JsonType)
   
    else:
        if iot_dev.status != 2:
            return HttpResponse(DevActError, content_type=JsonType)
        else:
            if not check_password(pwd, iot_dev.iot_key):
                return HttpResponse(PwdError,
                            content_type=JsonType)
                
            ipobj,ok = IpAddress.objects.get_or_create(ipaddr=request.META.get('REMOTE_ADDR'),
                                                    geoip=None)
            f = lambda x: x if not x else "empty"
            obj,ok = Devices.objects.get_or_create(mac=iot_dev.iot_mac,
                                   uuid=iot_dev.iot_uuid,
                                   appkey=iot_dev.app_key,
                                   key=iot_dev.iot_key,
                                   name=f(iot_dev.app_name),
                                   regip=ipobj,
                                   regtime=timezone.now())
            
            return HttpReturn(json.dumps({"ok":True}))
            
    

@transaction.atomic
def AcceptBindLink(request, user, uuid):
#     print "accept user %s to bind uuid %s" % (user.uuid.hex, uuid)
    shared_keys = redis_pool.hgetall(uuid)
    print "shared_keys",shared_keys,"type",type(shared_keys)
   
    if not shared_keys:
        return HttpReturn(UnAuth)
    
    if user.uuid.hex == shared_keys['appid']:
        return HttpReturn(UnAuth)
        
        
    print "shared redis key",shared_keys
    
    topic,ok =  MqttTopics.objects.get_or_create(topic="/%s/#" % user.uuid.hex)
    
    SharedDevList.objects.get_or_create(host_id = shared_keys['appid'],
                                        guest = user,
                                        sdevice_id = shared_keys['devid'],
                                        topics = shared_keys['topics'])
    
    tdict = json.loads(shared_keys['topics'])
    print "topic dict is ",tdict
    for item in tdict['topics'] :
#         topic,ok =  MqttTopics.objects.get_or_create(topic=item)
        MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None,
                                         app = user,
                                         access=3, topic="/%s/%s/#" % (shared_keys['devid'],item))
    
    ### 记录分享者,接受者,设备uuid,主题
    redis_pool.expire(uuid,1)
#     for k,v in shared_keys.items():
#         redis_pool.hdel(uuid,key)
    return HttpReturn(json.dumps({'ok':True, 'data':shared_keys}))
#         return JsonResponse({'ok':True,'data':res},safe = False)
    
def AppDelShareDev(request,user):
    pass

def AppShareDev(request, user, devuuid):

    body = GetRequestBody(request)
    
    try:
#         results = AppBindDevList.objects.raw("SELECT devid_id from bindlist WHERE appid_id = %s AND devid_id=%s",
#                                          [user.uuid.hex,devuuid])
        results = AppBindDevList.objects.filter(devid_id = devuuid,appid = user)[0]
    except (ObjectDoesNotExist,IndexError) as e:
        return HttpResponse(TargetNotExists,
                             content_type=JsonType)
    print "result id ",results
    if results.devid.uuid.hex != devuuid:
        return HttpResponse(TargetNotExists,
                             content_type=JsonType)

    otpuuid = uuid.uuid4().hex
    if not request.body:
        return HttpReturn(ArgError)
    topics = json.loads(request.body).get('topics',None)
    ## 检查topics 是否为空,是否是为列表类型,是否全部为真.
    if not topics or  not isinstance(topics,list):
        return HttpReturn(ArgError)
    
#     if not  all(devuuid in item for item in topics):
#         return HttpReturn(ShareError)
        
#         full_url = ''.join(['http://', get_current_site(request).domain, 
#                             '/shared/%s' % otpuuid])
    expire = settings.SESSION_COOKIE_AGE * 6
    res = {'ok':True, 'otp':otpuuid,'expire':expire}
    redis_pool.hset(otpuuid,"appid",user.uuid.hex)
    redis_pool.hset(otpuuid,"devid",devuuid)
    redis_pool.hset(otpuuid,"topics",request.body)
    redis_pool.expire(otpuuid,expire)
    
#         return JsonResponse(res,safe=False) 
    return HttpReturn(json.dumps(res))
        
                

def AppAddFriend(request, user, uuid):
    try:
        friend = AppUser.objects.get(uuid=uuid)
    except (ObjectDoesNotExist,ValueError) as e:
        return HttpResponse(TargetNotExists,
                            content_type=JsonType)
    else:
        if friend == user:
            return HttpResponse(TargetIsSelf,
                            content_type=JsonType)
            
        AppFriendList.objects.get_or_create(my_uuid=user, friend=friend)
        return HttpResponse(json.dumps({"ok":True}),
                            content_type=JsonType)


def AppRemoveFriend(request, user, uuid):
    try:
        friend = AppUser.objects.get(uuid=uuid)
        AppFriendList.objects.get(my_uuid=user, friend=friend).delete()
    except :
        return HttpResponse(TargetNotExists,
                            content_type=JsonType)
    else:
        return HttpResponse(json.dumps({"ok":True}),
                            content_type=JsonType)
    

def AppUploadProfile(request, user):
    pass


def AppDownloadProfile(request, user):
    pass    

@transaction.atomic
def AppVerifyPhone(request, Md5sum, smscode):
    phone = redis_pool.hget(Md5sum, 'phone')
    mysms = redis_pool.hget(Md5sum, 'sms')
    
    if not phone or not smscode:
        return HttpResponse(UnAuth,
                            content_type=JsonType)
    if cmp(mysms, smscode):
        return HttpResponse(CaptchaError,
                            content_type=JsonType)
    
    
    
    
    adict = redis_pool.hgetall(Md5sum)
    print "verify phone adict is", adict
    
    ipobj, ok = IpAddress.objects.get_or_create(ipaddr=request.META.get('REMOTE_ADDR'))
    # 注册成功之后,添加注册记录,并添加一条 /uuid/# 的记录到mqtt_acl
    if 'register' in adict:
        AppUser.objects.create(email =adict['email'],
                               phone = adict['phone'],
                               key = make_password(adict['key']),
                               uname = adict['uname'],
                               uuid = adict['uuid'],
                               regtime = timezone.now(),
                               regip = ipobj,
                               phone_active = True,
                               data = {'null':'null'})
        
      
        topic,ok =  MqttTopics.objects.get_or_create(topic="/%s/#" % adict['uuid'])
        MqttAcl.objects.get_or_create(allow=1, ipaddr=None, clientid=None,
                                             app_id =adict['uuid'],
                                             access=3, topic=topic)
    else:
        obj = AppUser.objects.get(phone = adict['phone'])
        obj.phone_active = True
        obj.save()
    
    #### 已经验证了,清除内存
    for (k,v) in adict.items():
        redis_pool.hdel(Md5sum,k)
    
    return HttpResponse(json.dumps({"ok":True}),
                            content_type=JsonType)


actionFunc = {'bind':AppBindDev,
              'checkbind':AppCheckBindDev,
              'unbind':AppDropDev,
              'add':AppAddFriend,
              'del':AppRemoveFriend,
              'reqshare':AcceptBindLink,
              'sharedev':AppShareDev,
              'delshare':AppDelShareDev}


def AppAction(request, token, target, action):
    ipaddr = request.META.get('REMOTE_ADDR')
    mem_addr = redis_pool.hget(token, 'ipaddr')
     
    if not mem_addr or  cmp(mem_addr, ipaddr):
        return HttpResponse(UnAuth,
                            content_type=JsonType)
    # ## 更新登录状态时间
    redis_pool.expire(token, settings.SESSION_COOKIE_AGE)
    
    user = AppUser.objects.get(uuid=redis_pool.hget(token, 'uuid'))        
    if action in actionFunc:
        return actionFunc[action](request, user, target)
    else:
        return HttpResponse(UnkownAction,
                            content_type=JsonType)

def AppSetAvatar(request,user):
#     print "request is",request.__dict__  
    
    datalen = len(request.body)
   
    btype = magic.Magic().id_buffer(request.body)
    print "data len: ",datalen,"type is",btype
    if not any(ext in btype for ext in ['JPEG','PNG','GIF']):
        return HttpResponse(FormatError,
                            content_type=JsonType)
    if datalen > 102410:
        return HttpResponse(SizeError,
                            content_type=JsonType)
#     user.avator = request.body
  
    cursor = connection.cursor()
    print "user.uuid",user.uuid.hex

    cursor.execute('UPDATE user_manager_appuser set avatar = %s where uuid = %s',
                              [base64.b64encode(request.body),str(user.uuid.hex)])


#     transaction.set_dirty()        
    transaction.commit()
    return HttpResponse(json.dumps({"ok":True}),
                            content_type=JsonType) 

def AppGetAvatar(request,user):
    return HttpResponse(base64.b64decode(user.avatar),content_type=user.get_mimetype)        


def AppUserChange(request, user):
    body = GetRequestBody(request)
    if not body:
        return HttpResponse(ArgError, content_type=JsonType)
    
    oldpass = body.get('oldpass', None)
    
#     if cmp(oldpass,user.key):   #### 修改信息必须要用原密码
    if not check_password(oldpass, user.key):
        return HttpResponse(PwdError,
                            content_type=JsonType)
    newpass = body.get('newpass', None)
#
    
    for k,v in body.items():
        
        if k in ['email','nickname','phone','sex']:
            print k, " set value ",type(v)
            setattr(user,k,v)
        if k == 'phone':  ### 更改了手机要重新激活帐号
            setattr(user,"phone_active",False)
    
    if newpass:
        print "set newpass ",newpass
        user.key = make_password(newpass)
    
    user.save()
    
    return HttpResponse(json.dumps({"ok":True}),
                            content_type=JsonType)


def ChangeDevName(request,token,newname):
    
    devuuid = redis_pool.hget(token,'uuid')
   
    if not devuuid:
        return HttpResponse(UnAuth,
                            content_type=JsonType) 
    try:
        devobj =  Devices.objects.get(uuid=devuuid)
    except:
        return HttpResponse(TargetNotExists, content_type=JsonType)
    else:
        devobj.name = newname
        devobj.save()
        return HttpResponse(json.dumps({"ok":True}),
                        content_type=JsonType)
    
        
        

def AppQueryApp(request, user):
    applist = AppFriendList.objects.filter(my_uuid=user) 
    
    results = [ob.as_json() for ob in AppUser.objects.filter(friend_user__in=applist)]
    return HttpResponse(json.dumps({"list":results, "ok":True}), content_type=JsonType)

def AppQueryDev(request, user):
    devlist = AppBindDevList.objects.filter(appid=user)
    lst = [x.devid.uuid.hex for x in devlist]
    l = Devices.objects.filter(pk__in=lst)
    results = [ ob.as_json() for ob in l]
    return HttpReturn(json.dumps({"list":results ,
                                    "ok":True}))
    
 
def AppRsyncData(request,user):
    return HttpReturn(json.dumps({"ok":True,
                                    "data":user.data}))
    
def AppGetInfo(request,user):
    return HttpReturn(json.dumps({"ok":True,"info":user.as_json()}))
    
 
def AppSyncData(request, user):
    body = GetRequestBody(request)
    if not body:
        return HttpResponse(ArgError, content_type=JsonType)
#     print "-----------------------sync body is",body,type(user)
    user.data = body
    user.save()
    return HttpResponse(json.dumps({"ok":True}),
                            content_type=JsonType)
 

def AppSendSms(request, account):
    SENDCOUNT = 'sendcount'
#     phone = redis_pool.hget(account, 'phone')
    adict= redis_pool.hgetall(account)
#     print "all key is",adict
    
    if 'phone' not in adict:
        return HttpResponse(UnAuth, content_type=JsonType)
        
#     redis_pool.hdel(account, 'phone')
#     print "phone number ", phone 
    
    ### 同一号24小时只能发送三次短信. ###
    sendnum = redis_pool.hget(adict['phone'], SENDCOUNT)
#     print "gettxt from redis", sendnum
    if sendnum and int(sendnum) == 3:
        return HttpResponse(SmsOverError, content_type=JsonType)
    
    sendtime = redis_pool.hget(adict['phone'], 'lastime')
    
    if sendtime and (time.time() - int(sendtime)) < settings.SESSION_COOKIE_AGE / 10:
        return HttpResponse(SmsIntervalError, content_type=JsonType)
        
#     ipaddr = request.META.get('REMOTE_ADDR')
    ipobj, ok = IpAddress.objects.get_or_create(ipaddr=request.META.get('REMOTE_ADDR'))
    oldaddr = redis_pool.hget(account, 'ipaddr')
    if cmp(ipobj.ipaddr, oldaddr):
        return HttpResponse(IpAddrError, content_type=JsonType)
    
    try:
        (sms, state) = sendsms.SendSMS(adict['phone'])
    except HTTPError:
        return HttpResponse(InternalError, content_type=JsonType)
    except IndexError:
        SmsErrorLog.objects.create(-100, ipobj, timezone.now, adict['phone'])
        return HttpResponse(InternalError, content_type=JsonType)
    if state == 0:
        redis_pool.expire(adict['phone'], settings.SESSION_COOKIE_AGE)
        redis_pool.hset(adict['phone'], 'lastime', int(time.time()))
#         redis_pool.expire(phone,settings.SESSION_COOKIE_AGE)
        if redis_pool.hget(adict['phone'], SENDCOUNT):
            redis_pool.hincrby(adict['phone'], SENDCOUNT, 1)
        else:
            redis_pool.hset(adict['phone'], SENDCOUNT, 1)
        resetcode = hashlib.md5(adict['phone'] + str(time.time())).hexdigest().upper()
        if 'register' in adict:
            for (k,v) in adict.items():
                redis_pool.hset(resetcode,k,v)
        
        redis_pool.hset(resetcode, 'phone', adict['phone'])
        redis_pool.hset(resetcode, 'sms', sms)
#         print "reset code dict is",redis_pool.hgetall(resetcode)
        redis_pool.expire(resetcode, settings.SESSION_COOKIE_AGE)
        redis_pool.hdel(account, 'phone') ## 删除这个键,一次有效
        return HttpResponse(json.dumps({"ok":True, 'rescode':resetcode}))
    else:
        if state in ErrDict:
            errobj = SmsErrorTable.objects.get(errcode=state)
            SmsErrorLog.objects.create(errcode=errobj, ipaddr=ipobj,
                                       addtime=timezone.now(), phone=adict['phone'])
        if state == 10006 or state == 10007 or state == 10005:
            return HttpReturn(json.dumps({"err":"OtherError", "msg":ErrDict[state]}))
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
             'sendsms':AppSendSms}    
 
 
def AppResetPwd(request, Md5sum, newpass, smscode):
    
    phone = redis_pool.hget(Md5sum, 'phone')
    mysms = redis_pool.hget(Md5sum, 'sms')
    
    
    if not phone or not smscode:
        return HttpResponse(UnAuth,
                            content_type=JsonType)
    if cmp(mysms, smscode):
        return HttpResponse(CaptchaError,
                            content_type=JsonType)
    
    #### 已经验证了,清除内存
    redis_pool.hdel(Md5sum, 'phone')
    redis_pool.hdel(Md5sum, 'sms')
    
    try:
        user = AppUser.objects.get(phone=phone)
        user.key = make_password(newpass)
        user.save()
    except:
        pass
    
    return HttpResponse(json.dumps({"ok":True}),
                            content_type=JsonType)
    
def AppFindPwd(request, account, captcha):
#     print "find pwd first", account, captcha
    if not account or not captcha:
        return HttpResponse(ArgError,
                            content_type=JsonType)
    try:    
        mycaptcha = request.session.pop(request.COOKIES.get('csrftoken'))
    except KeyError:
        return HttpResponse(CaptchaError,
                            content_type=JsonType)
    if cmp(mycaptcha, captcha):
        return HttpResponse(CaptchaError,
                            content_type=JsonType)

    try:
        accobj = AppUser.objects.raw('SELECT * FROM user_manager_appuser where uname = %s OR email = %s  OR phone= %s',
                              [account,account,account])[0]
    except:
        return HttpResponse(UserNotExists,
                            content_type=JsonType)
    else:
            
        if not accobj:
            return HttpResponse(TargetNotExists, content_type=JsonType)
         
        smscode = hashlib.md5(accobj.phone + str(time.time())).hexdigest().upper()
        ipaddr = request.META.get('REMOTE_ADDR')
        redis_pool.hset(smscode, 'phone', accobj.phone)
        redis_pool.hset(smscode, 'ipaddr', ipaddr)
        redis_pool.expire(smscode, settings.SESSION_COOKIE_AGE)
        
        res = {'name': accobj.uname,
                              'phone': "%s****%s" % (accobj.phone[:3], accobj.phone[-4:]),
                              'smscode': smscode,
                              'ok':True}
        return HttpResponse(json.dumps(res), content_type=JsonType)
    
        
    
def AppQuery(request, token, action):
#     data = json.loads(cache.get(token))
    ipaddr = request.META.get('REMOTE_ADDR')
    mem_addr = redis_pool.hget(token, 'ipaddr')
#     print "action from signid ",data,' ipaddr ',ipaddr
    if not mem_addr or mem_addr != ipaddr:
        return HttpResponse(UnAuth,
                                content_type=JsonType)
    
    if action == 'logout':
#         print "request", request.path
        ipobj, state = IpAddress.objects.get_or_create(ipaddr=ipaddr)
        if 'dev' in request.path:
            obj = Devices.objects.get(uuid=redis_pool.hget(token, 'uuid'))
            DevicesLoginHistory.objects.create(user=obj, inout=False, ipaddr=ipobj, optime=timezone.now())
        else:
            obj = AppUser.objects.get(uuid=redis_pool.hget(token, 'uuid'))
            AppUserLoginHistory.objects.create(user=obj, inout=False, ipaddr=ipobj, optime=timezone.now())
        redis_pool.expire(token, 1)
        redis_pool.hdel(token, 'ipaddr')
        redis_pool.hdel(token, 'uuid')
        return HttpResponse(json.dumps({"ok":True}),
                                content_type=JsonType)
    
    user = AppUser.objects.get(uuid=redis_pool.hget(token, 'uuid'))
    # ## 更新登录状态时间
    redis_pool.expire(token, settings.SESSION_COOKIE_AGE)
    if action in QueryFunc:
        return QueryFunc[action](request, user)
    else:
        return HttpResponse(UnkownAction,
                            content_type=JsonType)
     
        
