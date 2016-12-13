# coding:utf-8

from django.test import TestCase, RequestFactory

from django.test.client import Client

import time

from .views import IotAppAuth, IotDevAuth, AppAction, AppQuery,IotPing,ChangeDevName
from .models import *
import uuid, json, hmac, hashlib
from django.utils import timezone
from collections import OrderedDict
from django.db.backends.postgresql.base import IntegrityError

localip,ok = IpAddress.objects.get_or_create(ipaddr='127.0.0.1',geoip=None)
print "localhost ",localip

from django.contrib.auth.hashers import make_password,check_password
ConType = 'application/x-www-form-urlencoded'

class dbTogeterTestCase(TestCase):
    def setUp(self):
        self.uuid1 = uuid.uuid4().hex
#         self.uuid1 = 'b219748684854276947815fc95df17ea'
        self.uuid2 = uuid.uuid4().hex
        self.email1 = 'www@abc.com'
        self.email2 = 'aaa@abc.com'
        self.phone1 = '13811110000'
        self.phone2 = '13811110002'
        
        self.profile = {'b':'www.baidu.com',
                   'g':'www.google.com',
                   'a':'www.aplipy.com'}

        obj1 = AppUser.objects.create(
                               uname='pdpd',
                               uuid=self.uuid1,
                               email=self.email1,
                               key=make_password('aaaaaa'),
                               phone=self.phone1,
                               regtime=timezone.now(),
                               regip=localip,
                               data=self.profile,
                                   phone_active=True)
        
        obj2 = AppUser.objects.create(
                               uname='ttt',
                               uuid=self.uuid2,
                               email=self.email2,
                               key=make_password('aaaaaa'),
                               phone=self.phone2,
                               regtime=timezone.now(),
                               regip=localip,
                               data=self.profile,
                                   phone_active=True)
#         obj1.save()
        
    def test_addExistsEmail(self):
        print "test get App User"
        flag = False
        try:
            AppUser.objects.create(uuid=self.uuid2,
                                   email=self.email1,
                                   key=make_password('aaaaaa'),
                                   phone=self.phone2,
                                   regtime=timezone.now(),
                                   regip=localip,
                                   data=self.profile,
                                   phone_active=True)   
        except :
            flag = True
        self.assertEqual(True, flag)
        
    def test_addExistsPhone(self):
        flag = False
        try:
            obj2 = AppUser.objects.create(uuid=self.uuid2,
                                   email=self.email2,
                                   key=make_password('aaaaaa'),
                                   phone=self.phone1,
                                   regtime=timezone.now(),
                                   regip=localip,
                                   data=self.profile,
                                   phone_active=True)
        except :
            flag = True
        self.assertEqual(True, flag)

class IotAuthTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
#         self.uuid1 ='75da534eb81444edb016b6ef69d0b461'
        self.uuid1 = '57c6bbc2da884dec8f8250b8ef32b203'
        self.uuid2 = 'dcb862c2ef6642ecb1d2795e187ffdbe'
        self.uuid3 = '903b62c2ef6642ecb1d2795e187ffdbe'
        self.signid = None
        self.profile = {'b':'www.baidu.com',
                   'g':'www.google.com',
                   'a':'www.aplipy.com'}
        ipobj,ok = IpAddress.objects.get_or_create(ipaddr='127.0.0.1',geoip=None)
        AppUser.objects.create(
                              uname='abc',
                              uuid=self.uuid1,
#                             uuid = uuid.uuid4().hex,
                               email='www@test.com',
                               key=make_password('aaaaaa'), phone='13833339999',
                               regtime=timezone.now(),
                               regip=ipobj,
                               data=self.profile,
                                   phone_active=True)
        
        AppUser.objects.create(
                                uname='acc',
                              uuid=self.uuid2,
#                             uuid = uuid.uuid4().hex,
                               email='www@test2.com',
                               key=make_password('aaaaaa'), phone='13833339900',
                               regtime=timezone.now(),
                               regip=ipobj,
                               data=self.profile,
                                   phone_active=True)
        AppUser.objects.create(
                              uname='www',
                              uuid=self.uuid3,
#                             uuid = uuid.uuid4().hex,
                               email='www@test3.com',
                               key=make_password('aaaaaa'), phone='13833339901',
                               regtime=timezone.now(),
                               regip=ipobj,
                               data=self.profile,
                                   phone_active=True)
        
        Devices.objects.create(uuid=uuid.uuid4().hex,
                               key=make_password('aaaaaa'),
                               appkey='1111111',
                               regtime=timezone.now(),
                               name='test1',
                               regip= ipobj,
                               mac='00:11:22:33:44:55')
        
        Devices.objects.create(uuid=uuid.uuid4().hex,
                               key=make_password('aaaaaa'),
                               appkey='1111112',
                               regtime=timezone.now(),
                               name='test2',
                               regip=ipobj,
                               mac='aa:11:22:33:44:55')
        
        SrvList.objects.create(ipaddr='8.8.8.87', port=1234,
                               concount=3, mver='1.0.1',
                               pubkey='dddddddddddddddddddddddddd')
        SrvList.objects.create(ipaddr='44.5.44.87', port=1234,
                               concount=1, mver='1.0.1',
                               pubkey='dddddddddddddddddddddddddd')
        
    def test_AppBindDev(self):
        print "start test app bind dev |||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
        user = AppUser.objects.all()[0]
        user2 = AppUser.objects.all()[1]
        user3 = AppUser.objects.all()[2]
        dev = Devices.objects.all()[0]
        dev2 = Devices.objects.all()[1]

        d = self.login_request(user)
        self.assertEqual(d['ok'], True)   
        
        self.signid = d['sign']     
        ###  bind dev test ########
        url = '/iot/app/opt/%s/%s/bind/' % (self.signid, dev.uuid.hex)
        
        post_request = RequestFactory()
        post_request = post_request.post(url, json.dumps({'dkey':'aaaaaa'}), ConType)
        post_request.__dict__['body'] = json.dumps({'dkey':'aaaaaa'})
       
        
        response = AppAction(post_request, self.signid, dev.uuid.hex, 'bind')
        print " ----------------------------------------------------------"
        print 'server bind dev response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)
        
        ############## bind second devices ##########  
        
        url = '/iot/app/opt/%s/%s/bind/' % (self.signid, dev2.uuid.hex)
        post_request = RequestFactory()
        post_request = post_request.post(url, json.dumps({'dkey':'aaaaaa'}), ConType)
        post_request.__dict__['body'] = json.dumps({'dkey':'aaaaaa'})
        response = AppAction(post_request, self.signid, dev2.uuid.hex, 'bind')
        print " ----------------------------------------------------------"
        print 'server bind dev response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)
        
        
        
        ######### test device name ###################
        ##url(r'^iot/app/chamgedev/(?P<token>\w+)/(?P<target>\w+)/(?P<newname>\w+)/$',ChangeDevName),
        
        request = self.factory.get('/iot/dev/auth/?uuid=%s&key=%s' % (dev2.uuid.hex,'aaaaaa'))
       
        response = IotDevAuth(request)
        print "login Device response",response
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)   
       
        print "----------------- test change device name ---------------------------"
        url = '/iot/dev/changedev/%s/%s/' % (d['sign'] ,"test123")
        request = self.factory.get(url)
        response = ChangeDevName(request,d['sign'],"test1234")
        d = json.loads(response.content)
        print ("return d",d)
        self.assertEqual(d['ok'], True)
                
        
        
        ############## test query bind list ##########
        
        url = '/iot/app/%s/querydev/' % self.signid
        request = self.factory.get(url)
        print "query bind list request data", request.POST
        
        response = AppQuery(request, self.signid, 'querydev')

        print " ----------------------------------------------------------"
        print 'server query bind list response ', response.content
        
        d = json.loads(response.content)

        self.assertEqual(d['ok'], True)
        
        
        ################## sync data to server #########
        url = '/iot/app/%s/sync/' % self.signid
        request = self.factory.get(url)
        print "query bind list request data", request.POST
        
        testdata = {'baidu':'www.baidu.com',
                    'google':'www.google.com',
                    'gfw':'fuck '}
        
        post_request = RequestFactory()
        post_request = post_request.post(url, json.dumps(testdata), ConType)
#         post_request.__dict__['body'] = json.dumps(testdata)
        
        response = AppQuery(post_request, self.signid, 'sync')

        print " ----------------------------------------------------------"
        print 'server query bind list response ', response.content
        
        d = json.loads(response.content)

        self.assertEqual(d['ok'], True)
        
        
        ######### link shared ##############
        url = '/iot/app/opt/%s/%s/sharedev/' % (self.signid, dev2.uuid.hex)
        
        testdata = {'baidu':'www.baidu.com',
                    'google':'www.google.com',
                    'gfw':'fuck '}
        
    
        
        post_request = RequestFactory()
        testdata = {'topics':['wifi','poweroff']}
        post_request = post_request.post(url, json.dumps(testdata), ConType)
#         post_request.__dict__['body'] = json.dumps(testdata)
        
        response = AppAction(post_request, self.signid, dev2.uuid.hex, 'sharedev')
        print '----------------app shared uuid response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)
        
        ######### request dev bind ##########
        otp = d.get('otp', '')
        self.assertNotEqual(otp, None)
#         url = '/iot/app/opt/%s/%s/reqshare/' % (self.signid , otp)
#         request = self.factory.get(url)
#         response = AppAction(request, self.signid, otp, 'reqshare')
#         print '*************server request bind response,', response
#         
#         d = json.loads(response.content)
#         print "get shared info**********************", d
#         self.assertEqual(d['ok'], True)
        
        
        ####### test upload data ##########
        
        ################### del bind dev test ########
        
        url = '/iot/app/opt/%s/%s/unbind/' % (self.signid, dev.uuid.hex)
       
        post_request = RequestFactory()
        post_request = post_request.post(url, json.dumps({'dkey':'aaaaaa'}), 'application/json; charset=utf-8')
        post_request.__dict__['body'] = json.dumps({'dkey':'aaaaaa'})
        
        response = AppAction(post_request, self.signid, dev.uuid.hex, 'unbind')
        
        
        print " ----------------------------------------------------------"
        print 'delete bind dev response ', response.content
        
        d = json.loads(response.content)

        self.assertEqual(d['ok'], True)
        
        
        ###########  app add friend ################## 
        
        url = '/iot/app/opt/%s/%s/add/' % (self.signid, user2.uuid.hex)
        request = self.factory.get(url)
        print "add new friend request data", request.POST
        
        response = AppAction(request, self.signid, user2.uuid.hex, 'add')
        print " ----------------------------------------------------------"
        print 'server add new friend response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)
        
        
        ########### app seconds friend ##############
        
        url = '/iot/app/opt/%s/%s/add/' % (self.signid, user3.uuid.hex)
        request = self.factory.get(url)
        print "add  second new friend request data", request.POST
        
        response = AppAction(request, self.signid, user3.uuid.hex, 'add')
        print " ----------------------------------------------------------"
        print 'server add second new friend response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)
        
        
        ################## app add self to friend ######## 
        
        url = '/iot/app/opt/%s/%s/add/' % (self.signid, user.uuid.hex)
        request = self.factory.get(url)
        print "add self new friend request data", request.POST
        
        response = AppAction(request, self.signid, user.uuid.hex, 'add')
        print " ----------------------------------------------------------"
        print 'server add self new friend response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], False)
        
        
        
        
        ################## app query friend list ########### 
        url = '/iot/app/query/%s/queryapp/' % self.signid
        request = self.factory.get(url)
        print "query friend list request data", request.POST
        
        response = AppQuery(request, self.signid, 'queryapp')

        print " ----------------------------------------------------------"
        print 'server query friend list response ', response.content
        
        d = json.loads(response.content)

        self.assertEqual(d['ok'], True)
        
        
        ################ app remove friend ####################### 
        url = '/iot/app/opt/%s/%s/del/' % (self.signid, user2.uuid.hex)
        request = self.factory.get(url)
        print "del friend  request data", request.POST
        
        response = AppAction(request, self.signid, user2.uuid.hex, 'del')

        print " ----------------------------------------------------------"
        print 'server del friend response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)
        
        ########## test change ########
        
        url = '/iot/app/%s/change/' % self.signid
        newdata = {'oldpass': 'aaaaaa',
                'newpass':'12345678',
                'phone':'13410103330',
                'email':'test@abc.com.cn'}
        
        request = Client().post(url,
                                   content_type=ConType)
        setattr(request, 'META', {'REMOTE_ADDR':'127.0.0.1'})
        setattr(request, 'body', json.dumps(newdata))
        print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
      
        
        response = AppQuery(request, self.signid, 'change')
        
        d = json.loads(response.content)
        
        self.assertEqual(d['ok'], True)
        
        ### test iot ping ####################
        
        url = '/iot/ping/%s/' % self.signid
        request = self.factory.get(url)
        response = IotPing(request, self.signid)
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)
        
    def test_ErrorDataAction(self):
        ### 构造错识的数据来测试AppAction ######
        user = AppUser.objects.all()[0]
        user2 = AppUser.objects.all()[1]
        dev = Devices.objects.all()[0]
        
        d = self.login_request(user)
        self.assertEqual(d['ok'], True)   
        
        self.signid = d['sign']   

        ###########  error for action #################
        url = '/iot/app/opt/%s/%s/ddddd/' % (self.signid, user2.uuid.hex)
        request = self.factory.get(url)
        response = AppAction(request, self.signid, dev.uuid.hex, 'ddddd')
        d = json.loads(response.content)
        self.assertEqual(d['ok'], False)
        
        ################## error for uuid not exists #########
        nuuid = uuid.uuid4().hex
        url = '/iot/app/opt/%s/%s/bind/' % (self.signid, nuuid)
        request = self.factory.get(url)
        response = AppAction(request, self.signid, nuuid, 'bind')
        print 'server bind not exists target response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], False)
        
        
        ################## error for uuid not exists #########
       
        url = '/iot/app/opt/%s/%s/unbind/' % (self.signid, nuuid)
        request = self.factory.get(url)
        response = AppAction(request, self.signid, nuuid, 'unbind')
        print 'server del not exists target response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], False)
        
       
        url = '/iot/app/opt/%s/%s/add/' % (self.signid, nuuid)
        request = self.factory.get(url)
        response = AppAction(request, self.signid, nuuid, 'add')
        print 'server add not exists target response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], False)
        
        
        url = '/iot/app/opt/%s/%s/del/' % (self.signid, nuuid)
        request = self.factory.get(url)
        response = AppAction(request, self.signid, nuuid, 'del')
        print 'server del not exists target response ', response.content
        d = json.loads(response.content)
        self.assertEqual(d['ok'], False)
        
        
        ########## test change ########
        
        url = '/iot/app/%s/change/' % self.signid
        newdata = {'oldpass': 'dddsdddd',
                'newpass':'12345678',
                'phone':'13410103330',
                'email':'test@ab'}
        
        request = Client().post(url,
                                   content_type=ConType)
        setattr(request, 'META', {'REMOTE_ADDR':'127.0.0.1'})
        setattr(request, 'body', json.dumps(newdata))
        print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
      
        
        response = AppQuery(request, self.signid, 'change')
        
        d = json.loads(response.content)
        
        self.assertEqual(d['ok'], False)
        

    def login_request(self, user):
        data = OrderedDict()
        data ['uuid'] = user.uuid.hex
#         data['uuid'] = user.uuid.hex
#         data['key'] =  user.key
#         data['time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        data['key'] = 'aaaaaa'
#         data['signMethod'] = 'HmacMD5'
       
        request = self.factory.get('/iot/app/auth/?uuid=%s&key=%s' % (user.uname,'aaaaaa'), data, False)
       
        response = IotAppAuth(request)
        print "-----------------------------------------------------------"
        print 'server response', response.content;
        d = json.loads(response.content);
        return d
        
        
    def test_AppAuth(self):
        print "start test App Auth ......................."
        user = AppUser.objects.all()[0]
        d = self.login_request(user)

        self.assertEqual(d['ok'], True)
        
    def test_DevAuth(self):
        
        print "start test Dev Auth .........................."
        dev = Devices.objects.all()[1]
        
        
        data = OrderedDict()
        data['uuid'] = dev.uuid.hex
#         data['key'] = dev.key
        data['time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        data['resFlag'] = 'all'
        data['key'] = 'aaaaaa'
        data['signMethod'] = 'HmacSHA1'
        msg = ''.join(['%s%s' % (k, v) for k, v in  OrderedDict(sorted(data.items())).items()])
        data['sign'] = hmac.new(str(dev.key), msg,
                                hashlib.sha1).hexdigest().upper()
        get_request = RequestFactory()

        print "test DevAuth request",'&'.join(['%s=%s' % (k, v) for k, v in  OrderedDict(sorted(data.items())).items()])
        request = get_request.get('/iot/dev/auth', data, False)
        response = IotDevAuth(request)
        print "test DevAuth response",response
        d = json.loads(response.content);
        
        print "test DevAuth response",response,
        print "test DevAuth Dict ",d
        self.assertEqual(d['ok'], True)
        
   


### 分享删除主题测试.
class ShareTopicTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
#         self.uuid1 ='75da534eb81444edb016b6ef69d0b461'
        self.uuid1 = '57c6bbc2da884dec8f8250b8ef32b20a'
        self.uuid2 = 'dcb862c2ef6642ecb1d2795e187ffdbb'
        self.uuid3 = '903b62c2ef6642ecb1d2795e187ffdbc'
        self.devuuid1 = '903b62c2ef6642ecb1d2795e187ffdbe'
        self.devuuid2 = '903b62c2ef6642ecb1d2795e187ffdbf'
        self.signid = None
        self.signid2 = None
        self.profile = {'b':'www.baidu.com',
                   'g':'www.google.com',
                   'a':'www.aplipy.com'}
        ipobj,ok = IpAddress.objects.get_or_create(ipaddr='127.0.0.1',geoip=None)
        AppUser.objects.get_or_create(
                              uname='abc',
                              uuid=self.uuid1,
#                             uuid = uuid.uuid4().hex,
                               email='www@test.com',
                               key=make_password('aaaaaa'), phone='13833339999',
                               regtime=timezone.now(),
                               regip=ipobj,
                               data=self.profile,
                                   phone_active=True)
        
        AppUser.objects.get_or_create(
                                uname='acc',
                              uuid=self.uuid2,
#                             uuid = uuid.uuid4().hex,
                               email='www@test2.com',
                               key=make_password('aaaaaa'), phone='13833339900',
                               regtime=timezone.now(),
                               regip=ipobj,
                               data=self.profile,
                                   phone_active=True)
        AppUser.objects.get_or_create(
                              uname='www',
                              uuid=self.uuid3,
#                             uuid = uuid.uuid4().hex,
                               email='www@test3.com',
                               key=make_password('aaaaaa'), phone='13833339901',
                               regtime=timezone.now(),
                               regip=ipobj,
                               data=self.profile,
                                   phone_active=True)
        
        Devices.objects.get_or_create(uuid=self.devuuid1,
                               key=make_password('aaaaaa'),
                               appkey='1111111',
                               regtime=timezone.now(),
                               name='test1',
                               regip= ipobj,
                               mac='00:11:22:33:44:55')
        
        Devices.objects.get_or_create(uuid=self.devuuid2,
                               key=make_password('aaaaaa'),
                               appkey='1111112',
                               regtime=timezone.now(),
                               name='test2',
                               regip=ipobj,
                               mac='aa:11:22:33:44:55')
        
        SrvList.objects.get_or_create(ipaddr='8.8.8.87', port=1234,
                               concount=3, mver='1.0.1',
                               pubkey='dddddddddddddddddddddddddd')
        SrvList.objects.get_or_create(ipaddr='44.5.44.87', port=1234,
                               concount=1, mver='1.0.1',
                               pubkey='dddddddddddddddddddddddddd')
    
    
            
        
    def test_ShareLink(self):
        request = self.factory.get('/iot/app/auth/?uuid=%s&key=%s' % (self.uuid1,'aaaaaa'))
       
        response = IotAppAuth(request)
        print "login user response",response
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)   
        
        self.signid = d['sign']     
        ###  bind dev test ########
        url = '/iot/app/opt/%s/%s/bind/' % (self.signid, self.devuuid1)
        
        post_request = RequestFactory()
        post_request = post_request.post(url, json.dumps({'dkey':'aaaaaa'}), ConType)
        post_request.__dict__['body'] = json.dumps({'dkey':'aaaaaa'})
        response = AppAction(post_request, self.signid, self.devuuid1, 'bind')
        
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True) 
        
        self.createShareLink()
        
        ############# delete shared topic ###########
        url = '/iot/app/%s/delshare/' % (self.signid)
        
        com = [
         {'users': [self.uuid1],'devs':[self.devuuid1],'topics':'*'},
         {'users': [self.uuid1],'devs':[self.devuuid1],'topics':['wifi','poweroff','sleep']},
         {'users': [self.uuid1],'devs':'*','topics':'*'},
         {'users': [self.uuid1],'devs':'*','topics':['wifi','poweroff','sleep']},
         
         {'users':'*','devs':'*','topics':'*'},
         {'users': '*','devs':[self.devuuid1],'topics':['wifi','poweroff','sleep']},
         {'users': '*','devs':[self.devuuid1],'topics':'all'},
         {'users': '*','devs':'*','topics':['wifi','poweroff','sleep']},
         ]
        for dd in com:
            self.createShareLink()
            post_request = RequestFactory()
            post_request = post_request.post(url, json.dumps(dd), ConType)
            post_request.__dict__['body'] = json.dumps(dd)
            response = AppQuery(post_request, self.signid, 'delshare')
            d = json.loads(response.content)
            self.assertEqual(d['ok'], True) 
        
        
        
       
        
       
        
        
    def createShareLink(self):
       
        
        
        
        ################# share  devices link ################
        
        url = 'iot/app/%s/%s/sharedev/' % (self.signid,self.devuuid1)
        post_request = RequestFactory()
        dd = {'topics':['wifi','poweroff','sleep']}
        post_request = post_request.post(url, json.dumps(dd), ConType)
#         post_request.__dict__['body'] = json.dumps(dd)
        
        response = AppAction(post_request, self.signid, self.devuuid1, 'sharedev')
        
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True) 
        
        slink = d['otp']
        ############## accept shared ################################
        
        request = self.factory.get('/iot/app/auth/?uuid=%s&key=%s' % (self.uuid2,'aaaaaa'))
       
        response = IotAppAuth(request)
        print "login user response",response
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)   
        
        self.signid2 = d['sign']   


        url = '/iot/app/opt/%s/%s/reqshare/' % (self.signid2, slink)
        
        request = self.factory.get(url)
        
        response = AppAction(request, self.signid2, slink, 'reqshare')
        d = json.loads(response.content)
        self.assertEqual(d['ok'], True)   
        
        

        
        
        
        
        
        
        
        
        

# Create your tests here.


