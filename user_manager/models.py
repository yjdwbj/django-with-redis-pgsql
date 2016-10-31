#coding:utf-8
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.utils import timezone
import email
import uuid
import json
from django.contrib.postgres.fields import JSONField
# Create your models here.


class AppUser(models.Model):
    class Meta:
        verbose_name = u'用户管理'
        verbose_name_plural = verbose_name
        unique_together = ("email","phone","uuid","uname")
    
    uname = models.CharField(unique = True,max_length=64,verbose_name =u'昵称') 
    email = models.EmailField(unique=True,verbose_name=u'邮箱')
    phone = models.CharField(unique=True,max_length=11,verbose_name=u'手机号码')
    key = models.CharField(max_length=64,verbose_name=u'密钥')
    uuid = models.UUIDField(primary_key=True,unique=True,default=uuid.uuid4().hex,editable=False,
                            verbose_name=u'用户ID')
    regip = models.GenericIPAddressField(editable=False,max_length=15,verbose_name=u'注册IP')
    regtime = models.DateTimeField(default=timezone.now,verbose_name=u'注册时间')    
    data = JSONField(null=True,verbose_name=u'配置信息')
    phone_active = models.BooleanField(default=False,verbose_name=u'手机已验证')
    
    def __unicode__(self):
        return str(self.uname)  
    
    def as_json(self):
        return dict(uname = self.uname,
                    uuid = self.uuid.hex,
                    data = json.dumps(self.data))
    

class Devices(models.Model):
    class Meta:
        verbose_name = u'设备管理'
        verbose_name_plural=verbose_name
        unique_together = ("uuid","mac")
        
    mac = models.CharField(max_length=17,unique=True,blank=False,verbose_name=u'网卡地址');
    key = models.CharField(max_length=8,blank=False,verbose_name=u'密码');
    appkey = models.CharField(max_length=8,unique=True,blank=False,verbose_name=u'APP密码');
    uuid = models.UUIDField(primary_key = True,default=uuid.uuid4().hex,unique=True,verbose_name=u'设备ID');
    name = models.CharField(max_length=256,blank=True,verbose_name=u'名称');
    regtime = models.DateTimeField(default=timezone.now,verbose_name=u'注册时间')  
    
    def __unicode__(self):
        return self.name
    
    def as_json(self):
        return dict(mac = self.mac,
                    key = self.key,
                    uuid = self.uuid.hex,
                    name = self.name)

        
class ShareLink(models.Model):
    class Meta:
        verbose_name = u'分享链接'
        verbose_name_plural=verbose_name
        db_table = 'share_request'
        
    sharer = models.ForeignKey(AppUser,editable = False,on_delete = models.CASCADE ,
                               null = False,verbose_name = u'分享者')
    
#     guest = models.ForeignKey(AppUser,editable = False,on_delete = models.CASCADE,
#                               related_name = 'guest_user')
    sharedev = models.ForeignKey(Devices,editable = False,on_delete = models.CASCADE,
                                null = False,verbose_name = u'设备')
    otpuuid = models.UUIDField(verbose_name = u'一次性ID')
    bodydata = JSONField(verbose_name = u'数据')
    
class SharedDevList(models.Model):
    class Meta:
        verbose_name = u'分享设备'
        verbose_name_plural = verbose_name
        db_table ='devices_shared'
    
    host = models.ForeignKey(AppUser,editable=False,on_delete=models.CASCADE,
                             related_name='host_user',null = False,
                             verbose_name =u'所有者')    
    guest = models.ForeignKey(AppUser,editable=False,on_delete=models.CASCADE,null=False,
                              verbose_name =u'分享')
    sdevice = models.ForeignKey(Devices,editable = False,on_delete= models.CASCADE,null=False,
                            verbose_name =u'设备')
    isshared = models.BooleanField(default = False,verbose_name=u'分享成功?')
#     topic = models.CharField(max_length=256,blank=False,verbose_name=u"主题")
    
    def __unicode__(self):
        return self.guest.uuid.hex()
    
class AppDevList(models.Model):
    class Meta:
        verbose_name = u'用户设备列表'
        verbose_name_plural = verbose_name
        db_table = 'bindlist'
        unique_together = ('appid','devid')
        
    appid = models.ForeignKey(AppUser,on_delete=models.CASCADE,null=True,verbose_name=u'用户名')
    devid = models.ForeignKey(Devices,null=True,
                                    on_delete=models.CASCADE,verbose_name = u'设备')
    bindtime = models.DateTimeField(default=timezone.now,null=False,verbose_name=u'绑定时间')
    def __unicode__(self):
        return str(self.appid.uuid)
    
#     def get_dev(self):
#         return self.devid.devid
    
    
class AppFriendList(models.Model):
    class Meta:
        verbose_name = u'好友列表'
        verbose_name_plural = verbose_name
        unique_together = ('my_uuid','friend')
    my_uuid = models.ForeignKey(AppUser,editable=False,on_delete=models.CASCADE,null=False,verbose_name=u'用户名')
    friend = models.ForeignKey(AppUser,editable=False,related_name='friend_user',on_delete=models.CASCADE,null=False,verbose_name=u'好友名')
    addtime = models.DateTimeField(default=timezone.now,null=False,verbose_name=u'添加时间')
    isfriend = models.BooleanField(default=False,null=False,verbose_name=u'已经是好友?')
    def __unicode__(self):
        return str(self.my_uuid.uuid)

class MqttAcl(models.Model):
    class Meta:
        verbose_name = u'访问列表'
        db_table = "mqtt_acl"
        verbose_name_plural = verbose_name
        unique_together = ("id",)
        
    allow = models.IntegerField(verbose_name=u'允许')
    ipaddr = models.GenericIPAddressField(max_length=15,null=True,verbose_name=u'IP地址');
    username = models.CharField(max_length=100,null=True,verbose_name=u'用户名')
    clientid = models.CharField(max_length=100,null=True,verbose_name=u'客户端ID')
    access = models.IntegerField(verbose_name=u"访问级别")
    topic = models.CharField(max_length=100,verbose_name=u'主题')
    
    def __unicode__(self):
        return self.username
    
    
    
class MqttUser(models.Model):
    class Meta:
        verbose_name = u'用户'
        db_table = "mqtt_user"
        verbose_name_plural = verbose_name
    is_superuser = models.BooleanField(default=False,verbose_name=u'超级用户')
    username = models.CharField(primary_key = True,max_length=64,unique=True,verbose_name=u'用户ID');
    password = models.CharField(max_length=64,verbose_name=u'用户密码')
    salt = models.CharField(max_length=32,null=True,verbose_name=u'加盐')
    
    def __unicode__(self):
        return self.uuid
    

class SrvList(models.Model):
    class Meta:
        verbose_name = u'服务器管理'
        verbose_name_plural= verbose_name
    ipaddr = models.GenericIPAddressField(primary_key=True,max_length=15,blank=False,verbose_name=u'服务器IP');
#     node = models.CharField(primary_key = True,max_length=32,blank = False,verbose_name=u"节点名称") 
    port = models.IntegerField(default=1883,verbose_name=u'端口')
    mver = models.CharField(max_length=16,verbose_name=u'服务器版本')
    pubkey = models.TextField(max_length=2048,verbose_name=u'服务器公钥')
    http_user = models.CharField(max_length=32,default='admin',verbose_name=u'Web用户名')
    http_pass = models.CharField(max_length=32,default='public',verbose_name=u'Web密码')
    concount = models.IntegerField(verbose_name=u'用户连接数')
    def __unicode__(self):
        return self.ipaddr
#     Servre_SignMethod = models.CharField(max_length=15,verbose_name=u'签名方式')
    

class SmsErrorTable(models.Model):
    class Meta:
        verbose_name =u"发送短信错误码"
        db_table = 'smserrcode'
            
    errcode = models.IntegerField(primary_key = True,verbose_name=u"错误码")
    msg = models.CharField(max_length=100,verbose_name=u"错误描述")
    
    def __unicode__(self):
        return self.msg

class SmsErrorLog(models.Model):
    class Meta:
        db_table = 'smserr_log'
        verbose_name = u"短信错误"
        verbose_name_plural=verbose_name
        
    errcode = models.ForeignKey(SmsErrorTable,verbose_name =u'错误码')
    ipaddr = models.GenericIPAddressField(max_length=15,null=True,verbose_name=u'IP地址'); 
    addtime = models.DateTimeField(default=timezone.now,null=False,verbose_name=u'时间')
    phone = models.CharField(max_length=11,verbose_name=u'手机号码')
    
    def __unicode__(self):
        return self.phone
    
         
     