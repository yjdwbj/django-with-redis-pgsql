#coding: utf-8
from django.shortcuts import render, render_to_response
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse,HttpResponseRedirect,JsonResponse
import json
import hashlib,hmac
import md5,time
import random
from collections import OrderedDict
from user_manager.models import *
from django.db.models import Max,Min,F
from django.template import RequestContext
from .forms import *
from django.contrib.sites.shortcuts import get_current_site

from django.views.decorators.debug import sensitive_post_parameters
import base64
import captcha

from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError


from django.core.cache import cache as redis_pool
from django.conf import settings

from django_redis import get_redis_connection
redis_pool = get_redis_connection("default")


from django.db.models.query import IntegrityError

from django.utils.encoding import force_text
from django.core import serializers
import sendsms
from urllib2 import HTTPError

from models import *




UnkownSignMethod = json.dumps({"errorCode":"UnkownSignMethod",
                "message":u"未知签名方法","success":False},ensure_ascii=False)
SignError = json.dumps({"errorCode":"SignError","message":u"签名错误","success":False},ensure_ascii=False)
DataMiss =json.dumps( {"errorCode":"DataMiss","message":u"信息不完整","success":False},ensure_ascii=False)
UserNotExists = json.dumps({"errorCode": "UserNotExists","message":u"用户不存在","success":False},ensure_ascii=False)
UnAuth = json.dumps({"errorCode": "UnAuth","message":u"无权访问","success":False},ensure_ascii=False)
TargetNotExists = json.dumps({"errorCode": "TargetNotExists","message":u"目标不存在","success":False},ensure_ascii=False)
TargetIsSelf = json.dumps({"errorCode": "TargetIsSelf","message":u"目标不能是自已","success":False},ensure_ascii=False)
UnkownAction = json.dumps({"errorCode":"UnkownAction","message":u"未识别的操作","success":False},ensure_ascii=False)
BindError = json.dumps({"errorCode":"BindError","message":u"已经绑定","success":False},ensure_ascii=False)
BindPWDError = json.dumps({"errorCode":"BindError","message":u"无权绑定","success":False},ensure_ascii=False)
UserError = json.dumps({"errorCode":"UserError","message":u"用户名已存在","success":False},ensure_ascii=False)
EmailError = json.dumps({"errorCode":"EmailError","message":u"邮箱已存在","success":False},ensure_ascii=False)
PhoneError = json.dumps({"errorCode":"PhoneError","message":u"手机号已存在","success":False},ensure_ascii=False)
PwdError = json.dumps({"errorCode":"PwdError","message":u"密码错误","success":False},ensure_ascii=False)
ArgError = json.dumps({"errorCode":"ArgError","message":u"参数错误","success":False},ensure_ascii=False)
CaptchaError = json.dumps({"errorCode":"CaptchaError","message":u"验证码错误","success":False},ensure_ascii=False)
IpAddrError = json.dumps({"errorCode":"IpAddrError","message":u"IP错误","success":False},ensure_ascii=False)
InternalError = json.dumps({"errorCode":"InternalError","message":u"服务器内部错误","success":False},ensure_ascii=False)
SmsOverError = json.dumps({"errorCode":"SmsOverError","message":u"该手机号已经超过发送次数","success":False},ensure_ascii=False)
SmsIntervalError = json.dumps({"errorCode":"SmsIntervalError","message":u"发送间隔太短","success":False},ensure_ascii=False)
OtherError = json.dumps({"errorCode":"OtherError", "message":u"发送间隔太短", "success":False}, ensure_ascii=False)
PhoneInactive = json.dumps({"errorCode":"PhoneInactive","message":u"该手机号没有验证激活","success":False},ensure_ascii=False)


JsonType = 'application/json; charset=utf-8'

supportAlg = {'HmacMD5':hashlib.md5,'HmacSHA1':hashlib.sha1,'MD5':None}
# Create your views here.


@csrf_exempt
def get_verify_code(request):
    txt,img = captcha.get_code()
    request.session[request.COOKIES.get('csrftoken')] =txt
    return HttpResponse(img.decode('base64'),content_type='image/png')

def PreCheckRequest(request,obj,data):   
#     print len(data),data;
    signMethod = data.get('signMethod','')
    argdict = OrderedDict(sorted(data.items()))
    argdict.pop('sign')
    content = json.dumps(argdict)
    txt = ['%s%s' % (k,v) for k,v in argdict.items()]
    print "request content",''.join(txt)
    srvsign = None
    if signMethod:
        lst = [cmp(signMethod,x)  for x in supportAlg.keys()]
#             print "result is " ,supportAlg.keys(),lst,lst.count(0)
        if not lst.count(0):  
            return HttpResponse(UnkownSignMethod,
                                content_type=JsonType)
        else:
            srvsign = hmac.new(str(obj.key),''.join(txt),supportAlg[signMethod]).hexdigest().upper()
            print "signmethod",signMethod,'str is',srvsign
    else:
        srvsign = hmac.new(str(obj.key),''.join(txt),hashlib.md5).hexdigest().upper()
        print "srvsign md5",srvsign
    if cmp(srvsign,data.get('sign','')): ### 签名不正确
        return HttpResponse(SignError,
                                content_type=JsonType)         
    
#     srvobj = SrvList.objects.annotate(max_mark=Min('concount')).filter(concount=F('max_mark'))
    ###选取最小的连接数的服务器
    srvipaddr = '0.0.0.0'
    retdict = OrderedDict()
    hkey = 'null'
    try:
        
        srvipaddr = SrvList.objects.values_list('ipaddr').annotate(Min('concount')).order_by('concount')[0]   
    except (ObjectDoesNotExist,IndexError) as e:
        retdict['servers'] = None
        retdict['mqttver'] = None
    else:
        srvobj = SrvList.objects.get(ipaddr=srvipaddr[0])
        resflag = data.get('resFlag','all')
        if not cmp(resflag,'ip'):
            retdict['servers'] =':'.join([srvobj.ipaddr,str(srvobj.port)])  
        elif not cmp(resflag,'cert'):
            retdict['pubkey'] = base64.b64encode(srvobj.pubkey)
        else:
            retdict['servers'] =':'.join([srvobj.ipaddr,str(srvobj.port)])
            retdict['pubkey'] = base64.b64encode(srvobj.pubkey) 
        retdict['mqttver'] = srvobj.mver
    retdict['time'] = str(int(time.time()))
    retdict = OrderedDict(sorted(retdict.items()))
    txt = ['%s%s' % (k,v) for k,v in retdict.items()]
    srvsign = hmac.new(str(obj.key),''.join(txt),supportAlg[signMethod])
    #     retdict['username'] = request.COOKIES.get('csrftoken','')
    retdict['sign'] = srvsign.hexdigest().upper()
    retdict['success'] = True
    hkey = retdict['sign']
    
#     try:
#         mqttobj= MqttUser.objects.create(is_superuser=False,username=retdict['sign'],password=hashlib.sha256(obj.key).hexdigest(),salt=None)
#         mqttobj.save()
#     except :
#         pass
    
    ## 把这个登录成功状态写入一个缓存服务器,用于一些需要认证的操作.
    
#     print "con is type",type(con)
#     print "con dict ",con.__dict__
    
    redis_pool.hset(hkey,'password',hashlib.sha256(obj.key).hexdigest())
    redis_pool.hset(hkey,'ipaddr',request.META.get('REMOTE_ADDR'))
    redis_pool.hset(hkey,'uuid',obj.uuid.hex)
    redis_pool.expire(hkey,settings.SESSION_COOKIE_AGE)
#     cache.set(retdict['sign'],json.dumps({'ipaddr':request.META.get('REMOTE_ADDR'),
#                                'uuid':obj.uuid.hex,
#                                'pass':obj.key},ensure_ascii=True),
#                                 timeout = settings.LOGIN_TIME_AGE)
    
#     print "cached value is",cache.get(retdict['sign'])
#     cache.hset(sessionid,'ipaddr',request.META.get('REMOTE_ADDR'))
#     cache.set(sessionid,{'uuid':uuid,'ipaddr':request.META.get('REMOTE_ADDR')},timeout=100)
#     print "get sessionid from redis",cache.get(sessionid)        
    return HttpResponse(json.dumps(retdict))



@csrf_exempt
def IotAppAuth(request):
    data = request.POST
    
    if not data:
        data = request.GET
    token = data.get('uuid','')
    sign = data.get('sign','')
    
    if not token or not sign:
        return HttpResponse(DataMiss,
                                content_type=JsonType)
    obj = None
    try:
        obj = AppUser.objects.get(phone = token)
    except ObjectDoesNotExist:
        pass
    if not obj:
        try:
            obj = AppUser.objects.get(email = token)
        except ObjectDoesNotExist:
            pass
    if not obj:
        try:
            obj = AppUser.objects.get(uuid = token)
        except ObjectDoesNotExist:
            pass
    ###　email,phone,uuid 都在数据库里找不到    
    if not obj:
        return HttpResponse(UserNotExists,
                                content_type=JsonType)
    if not obj.phone_active:
        return HttpResponse(PhoneInactive,content_type=JsonType)
    
    return PreCheckRequest(request,obj,data)
    
    

@csrf_exempt
def IotDevAuth(request):
    data = request.POST
    
    if not data:
        data = request.GET
    sign = data.get('sign','')
    uuid = data.get('uuid','')
    
    if not uuid or not sign:
        return HttpResponse(DataMiss,
                                content_type=JsonType)
    obj = None    
    try:
        obj = Devices.objects.get(uuid = uuid)
    except ObjectDoesNotExist:
        return HttpResponse(UserNotExists,
                                content_type=JsonType)
        
    return PreCheckRequest(request,obj,data)

@sensitive_post_parameters()
@csrf_exempt
def IotAppRegister(request):
    data = request.POST
    if not data:
        data = request.GET
        
    email = data.get('email',None)
    uname = data.get('name',None)
    phone = data.get('phone',None)
    key = data.get('key',None)
    captcha = data.get('captcha',None)
#     print "my captcha", request.session.pop(request.COOKIES.get('csrftoken'))
    
    mycaptcha = None
    try:
        mycaptcha = request.session.pop(request.COOKIES.get('csrftoken'))
    except KeyError:
        pass
        
    if captcha:
        if cmp(mycaptcha,captcha):
            return HttpResponse(CaptchaError,content_type=JsonType)
    else:
        return HttpResponse(ArgError,content_type=JsonType)
    
    if uname:
        try:
            tmp =  AppUser.objects.get(uname = uname)
        except ObjectDoesNotExist:
            pass
        else:
            return HttpResponse(UserError,
                                content_type=JsonType)
    else:
        return HttpResponse(ArgError,content_type=JsonType)
        
    if phone:
        try:
            tmp =  AppUser.objects.get(phone = phone)
        except ObjectDoesNotExist:
            pass
        else:
            return HttpResponse(PhoneError,
                                content_type=JsonType)
    else:
        return HttpResponse(ArgError,content_type=JsonType)
        
    if email:
        try:
            tmp =  AppUser.objects.get(email = email)
        except ObjectDoesNotExist:
            pass
        else:
            return HttpResponse(EmailError,
                                content_type=JsonType)
    else:
        return HttpResponse(ArgError,content_type=JsonType)
    
    obj = AppUser.objects.create(email = email,phone =phone,
                   key=key,uuid = uuid.uuid4().hex,
                   uname = uname,
                   regtime = timezone.now(),
                   regip = request.META.get('REMOTE_ADDR'),
                   data = {})
    
    obj.save()
    ### 注册成功,验证手机激活帐号#####
    smscode = hashlib.md5(phone + str(time.time())).hexdigest().upper()
    
    ipaddr = request.META.get('REMOTE_ADDR')
    redis_pool.hset(smscode,'phone',phone)
    redis_pool.hset(smscode,'ipaddr',ipaddr)
    redis_pool.expire(smscode,settings.SESSION_COOKIE_AGE)
    return HttpResponse(json.dumps({"success":True,"uuid":obj.uuid,'smscode':smscode}))
   

@sensitive_post_parameters()
@csrf_exempt
def AppRegister(request):
    if cmp(request.method,'POST'):
        return render(request,'register.html',
                                  {'form':AppRegForm()})
    form = AppRegForm(request.POST,request=request)
    if form.is_valid():
        if request.session.pop(request.COOKIES.get('csrftoken','')) == form.get_captcha():
            try:
                form.save()
            except IntegrityError as e:
                msg = str(e)
                if 'email' in msg:
                    form.add_error('email',u'邮箱已经存在')
#                     form.fields['email'].widget.attr['value'] =''
                    return render(request,'register.html',
                                            {'form':form})
                elif 'phone' in msg:
                    form.add_error('phone',u'手机已经存在')
#                     form.fields['phone'].widget.attr['value'] =''
                    return render(request,'register.html',
                                  {'form':form})
    
            return HttpResponseRedirect('')
        else:
            form.add_error('captcha',u'验证码不正确')
#             form.fields['captcha'].widget.render('value','')
#             form.fields['captcha'].widget.attr['value'] =''
            return render(request,'register.html',
                                  {'form':form})
    else:
        form.fields['captcha'].widget.attrs['value'] = ''
        return render(request,'register.html',
                                  {'form':form})

@csrf_exempt
def DevActive(request):
    pass

def GetRequestBody(request):
    if request.body:
        return json.loads(request.body.decode('utf-8'))
    else:
        return None

    

@csrf_exempt 
def AppBindDev(request,user,uuid):
   
#     print "request POST",request.POST
#     for (k,v) in request.__dict__.items():
#         if k != 'META' and k != 'environ':
#             print "key:",k,"value is  ------------->",v
    body = GetRequestBody(request)
    print "body is",body
    if not body:
        return HttpResponse(ArgError,content_type=JsonType)
        
    try:
        dev_uuid = Devices.objects.get(uuid = uuid)
    except ObjectDoesNotExist:
        return HttpResponse(TargetNotExists,
                            content_type=JsonType)
    else:
        if body.get('dkey','') != dev_uuid.key:
            return HttpResponse(BindError,
                                content_type=JsonType)
        try:
            AppDevList.objects.get(devid = dev_uuid)
        except ObjectDoesNotExist:
            
            
            MqttAcl.objects.get_or_create(allow=1,ipaddr=None,clientid=None,username = user.uuid.hex,
                                   access=3,topic="/%s/#" % dev_uuid.uuid.hex)
            MqttAcl.objects.get_or_create(allow=1,ipaddr=None,clientid=None,username = user.uuid.hex,
                                   access=3,topic="/%s/#" % user.uuid.hex)
#             acl.save()
            MqttAcl.objects.get_or_create(allow=1,ipaddr = None,clientid=None,username = dev_uuid.uuid.hex,
                                         access=3,topic ="/%s/#" % user.uuid.hex)
            MqttAcl.objects.get_or_create(allow=1,ipaddr = None,clientid=None,username = dev_uuid.uuid.hex,
                                         access=3,topic ="/%s/#" % dev_uuid.uuid.hex)
#             acl.save()
            AppDevList.objects.create(appid = user,devid = dev_uuid)
            
            return HttpResponse(json.dumps({"success":True}),content_type=JsonType)
        else:
            return HttpResponse(BindError,content_type=JsonType) # 已经绑定了
    

@csrf_exempt 
def AppDropDev(request,user,target):
#     print "request POST",request.POST
#     for (k,v) in request.__dict__.items():
#         if k != 'META' and k != 'environ':
#             print "key:",k,"value is  ------------->",v
    body = GetRequestBody(request) 
    print "drop dev body is",body
    if not body:
        return HttpResponse(ArgError,content_type=JsonType)
    try:
        dev_uuid = Devices.objects.get(uuid = target)
    except ObjectDoesNotExist:
        return HttpResponse(TargetNotExists,
                            content_type=JsonType)
    else:
        if body.get('dkey','') != dev_uuid.key:
            return HttpResponse(PwdError,
                            content_type=JsonType)
        try:                    
            MqttAcl.objects.filter(username = user.uuid.hex,topic = "/%s/#" % target).delete()    
        except ObjectDoesNotExist:
            pass
        try:                    
            MqttAcl.objects.filter(username = target,topic = '/%s/#' % user.uuid.hex).delete()    
        except ObjectDoesNotExist:
            pass
        try:
            AppDevList.objects.get(appid = user,devid = dev_uuid).delete()
        except ObjectDoesNotExist:
            pass
        return HttpResponse(json.dumps({"success":True}),content_type=JsonType)     
    

@csrf_exempt 
def AcceptBindLink(request,user,uuid):
    print "accept user %s to bind uuid %s" % (user.uuid.hex,uuid)
    try:
        devlink = ShareLink.objects.get(otpuuid = uuid)
    except ObjectDoesNotExist:
        return HttpResponse(TargetNotExists,
                            content_type=JsonType)
    else:
        
        res = {'dev': {'name': devlink.sharedev.name,
                          'mac': devlink.sharedev.mac,
                          'uuid': devlink.sharedev.uuid.hex},
                   'data':devlink.bodydata}
        
        devlink.delete() ### 被人接受分享了进行删除.
        
        return HttpResponse(json.dumps({'success':True,'data':res}),
                            content_type=JsonType)
#         return JsonResponse({'success':True,'data':res},safe = False)
    
@csrf_exempt 
def AppShareDev(request,user,devuuid):
#     print "request body",request.body
#     print "body type",type(request.body)
    try:
        dev_uuid = Devices.objects.get(uuid = devuuid)
    except ObjectDoesNotExist:
        return HttpResponse(TargetNotExists,
                            content_type=JsonType)
    otpuuid = uuid.uuid4().hex
    if not request.body:
        return HttpResponse(ArgError,content_type=JsonType)
    try:    
        body = json.loads(request.body.decode('utf-8'))
    except ValueError:
        return HttpResponse(ArgError,content_type=JsonType)
#     jdata = request.body.decode('utf-8')
    ret = ShareLink.objects.create(sharer = user,
                                   sharedev = dev_uuid,
                                   otpuuid = otpuuid,
                                   bodydata = body)
    ret.save()
    
#         full_url = ''.join(['http://', get_current_site(request).domain, 
#                             '/shared/%s' % otpuuid])
    res = {'success':True,'otp':otpuuid}
#         return JsonResponse(res,safe=False) 
    return HttpResponse(json.dumps(res),
                        content_type=JsonType)
        
                
        
@csrf_exempt
def AppAddFriend(request,user,uuid):
    try:
        friend = AppUser.objects.get(uuid = uuid)
    except ObjectDoesNotExist:
        return HttpResponse(TargetNotExists,
                            content_type=JsonType)
    else:
        if friend == user:
            return HttpResponse(TargetIsSelf,
                            content_type=JsonType)
            
        AppFriendList.objects.get_or_create(my_uuid = user,friend = friend)
        return HttpResponse(json.dumps({"success":True}),
                            content_type=JsonType)

@csrf_exempt
def AppRemoveFriend(request,user,uuid):
    try:
        friend = AppUser.objects.get(uuid = uuid)
        AppFriendList.objects.get(my_uuid = user,friend = friend).delete()
    except ObjectDoesNotExist:
        return HttpResponse(TargetNotExists,
                            content_type=JsonType)
    else:
        return HttpResponse(json.dumps({"success":True}),
                            content_type=JsonType)
    
@csrf_exempt
def AppUploadProfile(request,user):
    pass

@csrf_exempt 
def AppDownloadProfile(request,user):
    pass    

@csrf_exempt 
def AppVerifyPhone(request,Md5sum,smscode):
    phone = redis_pool.hget(Md5sum,'phone')
    mysms = redis_pool.hget(Md5sum,'sms')
    
    
    if not phone or not smscode:
        return HttpResponse(UnAuth,
                            content_type=JsonType)
    if cmp(mysms,smscode):
        return HttpResponse(CaptchaError,
                            content_type=JsonType)
    
    #### 已经验证了,清除内存
    redis_pool.hdel(Md5sum,'phone')
    redis_pool.hdel(Md5sum,'sms')
    
    user = AppUser.objects.get(phone = phone)
    user.phone_active = True;
    user.save()
    
    return HttpResponse(json.dumps({"success":True}),
                            content_type=JsonType)


actionFunc = {'bind':AppBindDev,
              'unbind':AppDropDev,
              'add':AppAddFriend,
              'del':AppRemoveFriend,
              'reqshare':AcceptBindLink,
              'sharedev':AppShareDev}

@csrf_exempt
def AppAction(request,token,target,action):
#     print "app action  ",request,action
    
#     data =  json.loads(cache.get(token))
#     print "data is type ",type(data),data
    ipaddr = request.META.get('REMOTE_ADDR')
    mem_addr = redis_pool.hget(token,'ipaddr')
     
    if not mem_addr or  cmp(mem_addr,ipaddr):
        return HttpResponse(UnAuth,
                            content_type=JsonType)
    ### 更新登录状态时间
    redis_pool.expire(token,settings.SESSION_COOKIE_AGE)
    
    user  = AppUser.objects.get(uuid =redis_pool.hget(token,'uuid'))        
    if action in actionFunc:
        return actionFunc[action](request,user,target)
    else:
        return HttpResponse(UnkownAction,
                            content_type=JsonType)
    

@csrf_exempt 
def AppUserChange(request,user):
    body = GetRequestBody(request)
    if not body:
        return HttpResponse(ArgError,content_type=JsonType)
    
    oldpass = body.get('oldpass',None)
    
    if cmp(oldpass,user.key):   #### 修改信息必须要用原密码
        return HttpResponse(PwdError,
                            content_type=JsonType)
    newpass = body.get('newpass',None)
#         npass2 = body.get('npass2',None)
    
    uname = body.get('username',None)
    phone = body.get('phone',None)
    email = body.get('email',None)
    if uname:
        try:
            tmp =  AppUser.objects.get(uname = uname)
        except ObjectDoesNotExist:
            user.uname = uname
        else:
            return HttpResponse(UserError,
                                content_type=JsonType)
    if phone:
        print "change phone is",phone
        try:
            tmp =  AppUser.objects.get(phone = phone)
            
        except ObjectDoesNotExist:
            user.phone = phone
        else:
            print "return phone ",tmp.__dict__
            return HttpResponse(PhoneError,
                                content_type=JsonType)
    if email:
        try:
            tmp =  AppUser.objects.get(email = email)
        except ObjectDoesNotExist:
            user.email = email
        else:
            return HttpResponse(EmailError,
                                content_type=JsonType)
    
    
    if newpass:
        user.key = newpass
    user.save()
    
    return HttpResponse(json.dumps({"success":True}),
                            content_type=JsonType)

@csrf_exempt 
def AppQueryApp(request,user):
    applist = AppFriendList.objects.filter(my_uuid = user) 
    
    results = [ob.as_json() for ob in AppUser.objects.filter(friend_user__in = applist)]
    return HttpResponse(json.dumps({"list":results,"success":True}),content_type=JsonType)

@csrf_exempt 
def AppQueryDev(request,user):
    devlist = AppDevList.objects.filter(appid = user)
#         lst = [ x['dev_uuid_id'].hex for x in devlist]
    lst = [x.devid.uuid.hex for x in devlist]
#     print "devlist is",lst
    l =  Devices.objects.filter(pk__in = lst)
#     print "----query get device objects ",l
    results = [ ob.as_json() for ob in l]
    return HttpResponse(json.dumps({"list":results ,
                                    "success":True}),
                        content_type=JsonType)   
    
@csrf_exempt 
def AppSyncData(request,user):
    body = GetRequestBody(request)
    if not body:
        return HttpResponse(ArgError,content_type=JsonType)
#     print "-----------------------sync body is",body,type(user)
    user.data = body
    user.save()
    return HttpResponse(json.dumps({"success":True}),
                            content_type=JsonType)
 
@csrf_exempt 
def AppSendSms(request,account):
    SENDCOUNT = 'sendcount'
    phone = redis_pool.hget(account,'phone')
    
    if not phone:
        return HttpResponse(UnAuth,content_type=JsonType)
        
    redis_pool.hdel(account,'phone')
    print "phone number ",phone 
    
    ### 同一号24小时只能发送三次短信. ###
    sendnum = redis_pool.hget(phone,SENDCOUNT)
    print "gettxt from redis",sendnum
    if sendnum and int(sendnum) == 3:
        return HttpResponse(SmsOverError,content_type=JsonType)
    
    sendtime = redis_pool.hget(phone,'lastime')
    
    if sendtime and (time.time() - int(sendtime)) < settings.SESSION_COOKIE_AGE:
        return HttpResponse(SmsIntervalError,content_type=JsonType)
        
        
    
    ipaddr = request.META.get('REMOTE_ADDR')
    oldaddr = redis_pool.hget(account,'ipaddr')
    if cmp(ipaddr,oldaddr):
        return HttpResponse(IpAddrError,content_type=JsonType)
    
    
#     smsmsg = ''.join([random.SystemRandom(time.time()).choice('0123456789') for x in xrange(5)])
    
#     redis_pool.hset(account,'smscode',smsmsg)
#     redis_pool.hset(phone,'smscode',smsmsg)
#     redis_pool.expire(phone,settings.SESSION_COOKIE_AGE )
    
    try:
        (sms,state) = sendsms.SendSMS(phone)
    except HTTPError:
        return HttpResponse(InternalError,content_type=JsonType)
    except IndexError:
        SmsErrorLog.objects.create(-100,ipaddr,timezone.now,phone)
        return HttpResponse(InternalError,content_type=JsonType)
    if state == 0:
        redis_pool.expire(phone,settings.SESSION_COOKIE_AGE)
        redis_pool.hset(phone,'lastime',int(time.time()))
#         redis_pool.expire(phone,settings.SESSION_COOKIE_AGE)
        if redis_pool.hget(phone,SENDCOUNT):
            redis_pool.hincrby(phone,SENDCOUNT,1)
        else:
            redis_pool.hset(phone,SENDCOUNT,1)
        resetcode = hashlib.md5(phone + str(time.time())).hexdigest().upper()
        redis_pool.hset(resetcode,'phone',phone)
        redis_pool.hset(resetcode,'sms',sms)
        redis_pool.expire(resetcode,settings.SESSION_COOKIE_AGE)
        return HttpResponse(json.dumps({"success":True,'rescode':resetcode}))
    else:
        if state in sendsms.ErrDict:
            errobj = SmsErrorTable.objects.get(errcode=state)
            SmsErrorLog.objects.create(errcode=errobj,ipaddr = ipaddr,
                                       addtime = timezone.now(),phone =phone)
        if state == 10006 or state == 10007 or state == 10005:
            return HttpResponse(json.dumps({"errorCode":"OtherError","message":sendsms.ErrDict[state],
                                            "success":False},ensure_ascii=False))
        else:
            return HttpResponse(InternalError,content_type=JsonType)
    
    
    
QueryFunc = {'querydev':AppQueryDev,
             'queryapp':AppQueryApp,
             'sync':AppSyncData,
             'change':AppUserChange,
             'sendsms':AppSendSms}    
 

@csrf_exempt 
def AppResetPwd(request,Md5sum,newpass,smscode):
    phone = redis_pool.hget(Md5sum,'phone')
    mysms = redis_pool.hget(Md5sum,'sms')
    
    
    if not phone or not smscode:
        return HttpResponse(UnAuth,
                            content_type=JsonType)
    if cmp(mysms,smscode):
        return HttpResponse(CaptchaError,
                            content_type=JsonType)
    
    #### 已经验证了,清除内存
    redis_pool.hdel(Md5sum,'phone')
    redis_pool.hdel(Md5sum,'sms')
    
    user = AppUser.objects.get(phone = phone)
    user.key = newpass
    user.save()
    
    return HttpResponse(json.dumps({"success":True}),
                            content_type=JsonType)
        
        
    
    

@csrf_exempt 
def AppFindPwd(request,account,captcha):
    print "find pwd first",account,captcha
    if not account or not captcha:
        return HttpResponse(ArgError,
                            content_type=JsonType)
    try:    
        mycaptcha = request.session.pop(request.COOKIES.get('csrftoken'))
    except KeyError:
        return HttpResponse(CaptchaError,
                            content_type=JsonType)
    if cmp(mycaptcha,captcha):
        return HttpResponse(CaptchaError,
                            content_type=JsonType)

    accstr = None
    try:
        accstr =  AppUser.objects.get(uname = account)
    except ObjectDoesNotExist:
        pass

    try:
        accstr =  AppUser.objects.get(phone = account)
    except ObjectDoesNotExist:
        pass
    
    try:
        accstr =  AppUser.objects.get(email = account)
    except ObjectDoesNotExist:
        pass
    
    if not accstr:
        return HttpResponse(TargetNotExists,content_type=JsonType)
     
    smscode = hashlib.md5(accstr.phone + str(time.time())).hexdigest().upper()
    ipaddr = request.META.get('REMOTE_ADDR')
    redis_pool.hset(smscode,'phone',accstr.phone)
    redis_pool.hset(smscode,'ipaddr',ipaddr)
    redis_pool.expire(smscode,settings.SESSION_COOKIE_AGE)
    
    res =  {'name': accstr.uname,
                          'phone': "%s****%s" % (accstr.phone[:3],accstr.phone[-4:]),
                          'smscode': smscode, 
                          'success':True}
    return HttpResponse(json.dumps(res),content_type=JsonType)
    
        
      
        
            
        
            
     

        
@csrf_exempt    
def AppQuery(request,token,action):
#     data = json.loads(cache.get(token))
    ipaddr = request.META.get('REMOTE_ADDR')
    mem_addr = redis_pool.hget(token,'ipaddr')
#     print "action from signid ",data,' ipaddr ',ipaddr
    if not mem_addr or mem_addr != ipaddr:
        return HttpResponse(UnAuth,
                                content_type=JsonType)
    
    user = AppUser.objects.get(uuid =redis_pool.hget(token,'uuid'))
    ### 更新登录状态时间
    redis_pool.expire(token,settings.SESSION_COOKIE_AGE)
    if action in QueryFunc:
        return QueryFunc[action](request,user)
    else:
        return HttpResponse(UnkownAction,
                            content_type=JsonType)
     
        

        
@csrf_exempt 
def TestPostJson(request):
    print "request data",request.POST
    newdict = json.loads(request.body)
    print 'new dict',json.dumps(newdict)
    return HttpResponse(json.dumps({"success":True}),
                            content_type=JsonType)
    
    
        
