# coding:utf-8
from __future__ import unicode_literals

from django.db import models
from django.conf import settings
# from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.utils import timezone, six
from django.forms import ValidationError
import uuid
import json
import base64
import magic
from django.contrib.postgres.fields import JSONField
from django.core.exceptions import ObjectDoesNotExist
from django.core.files.uploadedfile import InMemoryUploadedFile
# Create your models here.

from django.contrib.auth.hashers import PBKDF2SHA1PasswordHasher
# from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.contrib.auth.hashers import UNUSABLE_PASSWORD_PREFIX, UNUSABLE_PASSWORD_SUFFIX_LENGTH
from django.utils.crypto import (
    constant_time_compare, get_random_string, pbkdf2,
)
from . import ffi,nettle
import warnings
warnings.filterwarnings("ignore")


def make_password(key):
    salt = MyPBKDF2PasswordHasher().salt()
    iterations = settings.PBKDF2_ITERATIONS
    algorithm  = 'pbkdf2_sha1'
    klen = len(key)
    slen = len(salt)
    key = ffi.new("uint8_t[]", bytes(key))
    s = ffi.new("uint8_t[]", bytes(salt))

    buf = ffi.new("uint8_t[20]")
    nettle.nettle_pbkdf2_hmac_sha1(
        klen, key, int(iterations), slen, s, 20, buf)

    return '$'.join([algorithm,str(iterations),salt,base64.b64encode(ffi.string(buf)).decode('utf-8')])


class MyPBKDF2PasswordHasher(PBKDF2SHA1PasswordHasher):
    """
    A subclass of PBKDF2PasswordHasher that uses 100 times more iterations.
    """
    iterations = settings.PBKDF2_ITERATIONS


# def make_password(password, salt=None):
#     """
#     Turn a plain-text password into a hash for database storage

#     Same as encode() but generates a new random salt.
#     If password is None then a concatenation of
#     UNUSABLE_PASSWORD_PREFIX and a random string will be returned
#     which disallows logins. Additional random string reduces chances
#     of gaining access to staff or superuser accounts.
#     See ticket #20079 for more info.
#     """
#     if password is None:
#         return UNUSABLE_PASSWORD_PREFIX + get_random_string(UNUSABLE_PASSWORD_SUFFIX_LENGTH)
#     hasher = MyPBKDF2PasswordHasher()
#     if not salt:
#         salt = hasher.salt()

#     return hasher.encode(password, salt)


class IpAddress(models.Model):

    class Meta:
        verbose_name = u'IP地址'
        verbose_name_plural = verbose_name
        db_table = 'iplist'

    ipaddr = models.GenericIPAddressField(unique=True, default='127.0.0.1', editable=False, max_length=15,
                                          verbose_name=u'ip地址')
    geoip = JSONField(null=True, verbose_name=u'位置信息')

    def __unicode__(self):
        return self.ipaddr

# 这里把图片用bytea对像保存在postgresql里，虽然解决图片与用户不一致的问题，但是对数据压力很大，如果保存在文件系统，只在数据库里存一个路径会快一些。

class ImageFileField(models.FileField):

    def __init__(self, max_upload_size=102410, *args, **kwargs):
        self.max_upload_size = max_upload_size
        self.attr_class.bindata = None
        self.fmt = ['JPEG', 'PNG', 'GIF']
        kwargs['help_text'] = u"只支持JPEG,PNG,GIF格式"
        super(ImageFileField, self).__init__(*args, **kwargs)

    def clean(self, *args, **kwargs):

        data = super(ImageFileField, self).clean(*args, **kwargs)
#         print "data is type",type(data)
        if not isinstance(data, buffer):
            self.attr_class.bindata = data.file.file.read()
            btype = magic.Magic().id_buffer(self.attr_class.bindata)
            if not any(ext in btype for ext in self.fmt):
                raise ValidationError(self.help_text)
            if data.file.size > self.max_upload_size:
                raise ValidationError(u'文件超过%sK' % self.max_upload_size / 1024)
    #         print "upload data is ",type(data),data
        return data

    def db_type(self, connection):
        return 'bytea'

    def from_db_value(self, value, expression, connection, context):
        #         print "value is ",value
        if value is None:
            return value or u""
        return value

    def pre_save(self, model_instance, add):
        "Returns field's value just before saving."
        try:
            file = super(ImageFileField, self).pre_save(model_instance, add)
            if file and not file._committed:
                # Commit the file to storage prior to saving the model
                file.save(file.name, file, save=False)
            return file
        except:
            pass

        return self


class AppUser(models.Model):

    class Meta:
        verbose_name = u'用户管理'
        verbose_name_plural = verbose_name
        unique_together = ("email", "phone", "uuid", "uname")
    GENDER_CHOICES = ((0, u'-'), (1, u'男'), (2, u'女'))

    uname = models.CharField(unique=True, max_length=64, verbose_name=u'用户名')
    email = models.EmailField(unique=True, verbose_name=u'邮箱')
    phone = models.CharField(unique=True, max_length=11, verbose_name=u'手机号码')
    key = models.CharField(max_length=128, verbose_name=u'密钥')
    uuid = models.UUIDField(primary_key=True, unique=True, editable=False,
                            verbose_name=u'用户ID')


#     regip = models.GenericIPAddressField(editable=False,max_length=15,verbose_name=u'注册IP')
    regip = models.ForeignKey(
        IpAddress, on_delete=models.CASCADE, verbose_name=u'注册地址')
    regtime = models.DateTimeField(default=timezone.now, verbose_name=u'注册时间')
    data = JSONField(null=True, default={'null': 'null'}, verbose_name=u'配置信息')
    phone_active = models.BooleanField(default=False, verbose_name=u'手机已验证')
    nickname = models.CharField(
        null=True, default=u"新用户", max_length=64, verbose_name=u'昵称')
    sex = models.IntegerField(choices=GENDER_CHOICES,
                              default=0, verbose_name=u'性别')
    avatar = ImageFileField(blank=True, verbose_name=u'头像')
    dkey = models.BinaryField(verbose_name=u'小机密码')

    def __unicode__(self):
        return self.uname

    def as_json(self):
        return dict(uname=self.uname,
                    uuid=self.uuid.hex,
                    email=self.email,
                    phone=self.phone,
                    nickname=self.nickname,
                    sex=self.sex)

    def avatar_url(self):
        if len(self.avatar) > 0:
            return "data:%s;base64,%s" % (self.get_mimetype, self.avatar)
        else:
            return "data:image/png;base64,AB"

    def get_mimetype(self):
        if len(self.avatar) > 0:
            #             rawdata = base64.b64decode(self.avatar)
            btype = magic.Magic().id_buffer(self.avatar)
            return "image/%s" % btype.split(' ')[0].lower()

    def save(self, *args, **kw):
        if not self.uuid:
            self.uuid = uuid.uuid4().hex
#         print "my self data ",self.uname,self.email,self.uuid
        if self.key.count('$') != 3:
            self.key = make_password(self.key)

#         print "avatar type is " ,self.avatar
        if not isinstance(self.avatar, buffer):
            if self.avatar.bindata:
                self.avatar = base64.b64encode(self.avatar.bindata)
#                 print "avatar data is ",self.avatar
        else:
            self.avatar = bytes(self.avatar)
        super(AppUser, self).save(*args, **kw)


class AppUserLoginHistory(models.Model):

    class Meta:
        verbose_name = u'用户日志'
        verbose_name_plural = verbose_name

    user = models.ForeignKey(
        AppUser, on_delete=models.CASCADE, verbose_name=u'用户名')
    inout = models.BooleanField(verbose_name=u'登入登出')
    ipaddr = models.ForeignKey(
        IpAddress, on_delete=models.CASCADE, verbose_name=u'ip地址')
#     city = models.CharField(null=True,max_length=30,verbose_name=u'位置')
    optime = models.DateTimeField(default=timezone.now, verbose_name=u'时间')

    def __unicode__(self):
        return unicode(self.user.uname)


class DevicesMaker(models.Model):

    class Meta:
        verbose_name = u'生产端'
        db_table = 'iotdevlist'
        managed = False  # 这个模武型是只读"devices"数据库的

    idlid = models.IntegerField(primary_key=True)
    iot_mac = models.CharField(max_length=45, verbose_name=u"MAC地址")
    iot_uuid = models.CharField(
        max_length=64, unique=True, verbose_name=u'设备ID')
    iot_key = models.CharField(max_length=32, verbose_name=u'密码')
    iot_oper = models.CharField(max_length=64)
    app_name = models.CharField(max_length=32)
    app_key = models.CharField(max_length=32, verbose_name=u"APP key")
    pdate = models.TimeField(verbose_name=u'生产时间')
    audate = models.TimeField(verbose_name=u'授权时间')
    acdate = models.TimeField(verbose_name=u'激活时间')
    status = models.IntegerField(verbose_name=u"状态")
    typeid = models.IntegerField(verbose_name=u"产品类型ID")
    uid = models.IntegerField(verbose_name=u'企业ID')
    imkid = models.IntegerField(verbose_name=u'人员')
    info = models.CharField(max_length=128, verbose_name=u'备注')

    def __unicode__(self):
        return self.iot_uuid


class Devices(models.Model):

    class Meta:
        verbose_name = u'设备管理'
        verbose_name_plural = verbose_name
        unique_together = ("uuid",)

    mac = models.CharField(max_length=17, blank=False, verbose_name=u'网卡地址')
    key = models.CharField(max_length=128, blank=False, verbose_name=u'密码')
    appkey = models.CharField(
        max_length=8, unique=True, blank=False, verbose_name=u'APP密码')
    uuid = models.UUIDField(
        primary_key=True, unique=True, verbose_name=u'设备ID')
    name = models.CharField(max_length=256, blank=False,
                            default=u'empty', verbose_name=u'名称')
    regip = models.ForeignKey(
        IpAddress, on_delete=models.CASCADE, verbose_name=u'注册地址')
    regtime = models.DateTimeField(default=timezone.now, verbose_name=u'注册时间')

    def __unicode__(self):
        return unicode(self.name) or u'empty'

    def as_json(self):
        #         f = lambda x: x if not x else u"empty"
        return dict(mac=self.mac,
                    uuid=self.uuid.hex,
                    name=self.name)
#                     name = f(self.name) )

    def get_name(self):
        return unicode(self.name) or u'empty'

    def save(self, *args, **kw):
        if not self.uuid:
            self.uuid = uuid.uuid4().hex
#         print "my self key ",self.key
        if self.key.count('$') != 3:
            self.key = make_password(self.key)
#         if self.pk is not None:
#             try:
#                 orig = Devices.objects.get(pk=self.pk)
#                 if orig.key != self.key and self.key.count('$') != 3:
#                     self.key = make_password(self.key)
#             except ObjectDoesNotExist:
#                 self.key = make_password(self.key)
        super(Devices, self).save(*args, **kw)


class DevicesLoginHistory(models.Model):

    class Meta:
        verbose_name = u'设备日志'
        verbose_name_plural = verbose_name

    devices = models.ForeignKey(
        Devices, on_delete=models.CASCADE, verbose_name=u'用户名')
    inout = models.BooleanField(verbose_name=u'登入登出')
    ipaddr = models.ForeignKey(
        IpAddress, on_delete=models.CASCADE, verbose_name=u'ip地址')
#     city = models.CharField(null=True,max_length=30,verbose_name=u'位置')
    optime = models.DateTimeField(default=timezone.now, verbose_name=u'时间')

    def __unicode__(self):
        return self.devices.name

    def get_uuid(self):
        return self.devices.uuid.hex
    get_uuid.short_description = u'唯一码UUID'


class SharedDevList(models.Model):

    class Meta:
        verbose_name = u'分享设备'
        verbose_name_plural = verbose_name
        db_table = "link_shared"

    host = models.ForeignKey(AppUser, editable=False, on_delete=models.CASCADE,
                             related_name='host_user', null=False,
                             verbose_name=u'所有者')
    guest = models.ForeignKey(AppUser, editable=False, on_delete=models.CASCADE, null=False,
                              verbose_name=u'接受者')
    sdevice = models.ForeignKey(Devices, editable=False, on_delete=models.CASCADE, null=False,
                                verbose_name=u'设备')
    topics = JSONField(verbose_name=u'分享主题')

    def __unicode__(self):
        return str(self.guest_id)


class AppBindDevList(models.Model):

    class Meta:
        verbose_name = u'用户设备列表'
        verbose_name_plural = verbose_name
        db_table = 'bindlist'
        unique_together = ('appid', 'devid')

    appid = models.ForeignKey(
        AppUser, on_delete=models.CASCADE, null=True, verbose_name=u'用户名')
    devid = models.ForeignKey(Devices, null=True,
                              on_delete=models.CASCADE, verbose_name=u'设备')
    bindtime = models.DateTimeField(
        default=timezone.now, null=False, verbose_name=u'绑定时间')

    def __unicode__(self):
        return str(self.appid.uuid)


class AppFriendList(models.Model):

    class Meta:
        verbose_name = u'好友列表'
        verbose_name_plural = verbose_name
        unique_together = ('my_uuid', 'friend')
    my_uuid = models.ForeignKey(
        AppUser, editable=False, on_delete=models.CASCADE, null=False, verbose_name=u'用户名')
    friend = models.ForeignKey(AppUser, editable=False, related_name='friend_user',
                               on_delete=models.CASCADE, null=False, verbose_name=u'好友名')
    addtime = models.DateTimeField(
        default=timezone.now, null=False, verbose_name=u'添加时间')
    isfriend = models.BooleanField(
        default=False, null=False, verbose_name=u'已经是好友?')

    def __unicode__(self):
        return str(self.my_uuid.uuid)


class MqttTopics(models.Model):

    class Meta:
        verbose_name = u"主题列表"
        db_table = "mqtt_topics"
        verbose_name_plural = verbose_name
        unique_together = ("id", "topic")

    topic = models.CharField(max_length=100, null=False, verbose_name=u"主题")

    def __unicode__(self):
        return self.topic


class MqttAcl(models.Model):

    class Meta:
        verbose_name = u'访问列表'
        db_table = "mqtt_acl"
        verbose_name_plural = verbose_name
        unique_together = ("id",)

    ACL_CHOICES = ((1, u'订阅'), (2, u'发布'), (3, u'订阅发布'))

    allow = models.IntegerField(verbose_name=u'允许')
    ipaddr = models.GenericIPAddressField(
        max_length=15, null=True, verbose_name=u'IP地址')
#     username = models.CharField(max_length=100,null=True,verbose_name=u'用户名')
    app = models.ForeignKey(
        AppUser, on_delete=models.CASCADE, null=True, verbose_name=u'APP端')
    dev = models.ForeignKey(Devices, null=True,
                            on_delete=models.CASCADE, verbose_name=u'设备端')
    clientid = models.CharField(
        max_length=100, null=True, verbose_name=u'客户端ID')
    access = models.IntegerField(choices=ACL_CHOICES, verbose_name=u"访问级别")
    topic = models.CharField(max_length=100, verbose_name=u'主题')
    addtime = models.DateTimeField(
        default=timezone.now, null=False, verbose_name=u'添加时间')

    def __unicode__(self):
        return str(self.app_id) or str(self.dev_id)


class BinaryFileField(models.FileField):

    def __init__(self, max_upload_size=2048, *args, **kwargs):
        self.max_upload_size = max_upload_size
        self.attr_class.bindata = None
        super(BinaryFileField, self).__init__(*args, **kwargs)

    def clean(self, *args, **kwargs):
        data = super(BinaryFileField, self).clean(*args, **kwargs)
        readlines = data.file.readlines()
        readlines = [x for x in readlines if x.rstrip()]
#         self.attr_class.bindata = ''.join(readlines[1:-1])
        import zlib
        setattr(data, 'bindata', zlib.compress(
            ''.join([x.replace('\n', '') for x in readlines[1:-1]]), 9))
#         setattr(data,'bindata',''.join(readlines[1:-1]))
        if data.file.size > self.max_upload_size:
            raise ValidationError(u'文件超过%sK' % self.max_upload_size / 1024)
#         print "upload data is ",type(data),data
        return data

    def db_type(self, connection):
        return 'bytea'

    def from_db_value(self, value, expression, connection, context):
        #         print "value is ",value
        if value is None:
            return value or u""
        return value


class SrvList(models.Model):

    class Meta:
        verbose_name = u'服务器管理'
        verbose_name_plural = verbose_name

    ipaddr = models.GenericIPAddressField(primary_key=True, max_length=15, blank=False,
                                          default="127.0.0.1", verbose_name=u'服务器IP')
#     node = models.CharField(primary_key = True,max_length=32,blank = False,verbose_name=u"节点名称")
    port = models.IntegerField(default=1883, verbose_name=u'端口')
    mver = models.CharField(max_length=16, default=1, verbose_name=u'服务器版本')
#     pubkey = models.TextField(max_length=2048,verbose_name=u'服务器公钥')
    cert = BinaryFileField(verbose_name=u"服务器证书")
#     http_user = models.CharField(max_length=32,default='admin',verbose_name=u'Web用户名')
#     http_pass = models.CharField(max_length=32,default='public',verbose_name=u'Web密码')
    concount = models.IntegerField(default=1, verbose_name=u'用户连接数')

    def __unicode__(self):
        return self.ipaddr

    def save(self, *args, **kw):
        if self.cert.bindata:
            self.cert = base64.b64encode(self.cert.bindata)
        super(SrvList, self).save(*args, **kw)
#     Servre_SignMethod = models.CharField(max_length=15,verbose_name=u'签名方式')


class SmsErrorTable(models.Model):

    class Meta:
        verbose_name = u"发送短信错误码"
        db_table = 'smserrcode'

    errcode = models.IntegerField(primary_key=True, verbose_name=u"错误码")
    msg = models.CharField(max_length=100, verbose_name=u"错误描述")

    def __unicode__(self):
        return self.msg


class SmsErrorLog(models.Model):

    class Meta:
        db_table = 'smserr_log'
        verbose_name = u"短信错误"
        verbose_name_plural = verbose_name

    errcode = models.ForeignKey(SmsErrorTable, verbose_name=u'错误码')
    ipaddr = models.ForeignKey(
        IpAddress, on_delete=models.CASCADE, verbose_name=u'注册地址')
    addtime = models.DateTimeField(
        default=timezone.now, null=False, verbose_name=u'时间')
    phone = models.CharField(max_length=11, verbose_name=u'手机号码')

    def __unicode__(self):
        return self.phone
