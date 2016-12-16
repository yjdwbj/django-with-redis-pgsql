#coding: utf-8
from django.contrib import admin
from django.forms import ModelForm
from django.forms.fields import  DateTimeField
from django import forms
from .models import *
from uuid import uuid4
import base64
from user_manager.models import SmsErrorLog
import magic

from django.utils.decorators import method_decorator
from django.db import  transaction
from django.views.decorators.csrf import csrf_protect

from django.contrib.auth.hashers import check_password
from django.http import HttpResponse
from django.utils.html import format_html




# Register your models here.

IS_POPUP_VAR = '_popup'
TO_FIELD_VAR = '_to_field'


csrf_protect_m = method_decorator(csrf_protect)



class MyCustomAdmin(admin.ModelAdmin):
    
    def view_ip(self,obj):
        
        url =  '<a href="http://www.geoip.co.uk/ipwhois.php?ip=%s">%s</a>'
        if isinstance(obj,AppUserLoginHistory) or isinstance(obj,DevicesLoginHistory):
            return url % ( obj.ipaddr.ipaddr,obj.ipaddr.ipaddr)
        else:
            return url % ( obj.regip.ipaddr,obj.regip.ipaddr)
        

    @transaction.atomic
    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        return super(MyCustomAdmin,self).changeform_view(request,object_id,form_url,extra_context)
    

    
    view_ip.short_description = u'IP地址'
    view_ip.allow_tags = True


class DevicesAdmin(MyCustomAdmin):
    list_display = ('uuid','mac','appkey','name','view_ip','regtime')
    
    def get_form(self,request,obj=None,**kwargs):
        form = super(DevicesAdmin,self).get_form(request,obj,**kwargs)
        
        if form.base_fields['regip'].queryset.count() == 0:
            ### 必选项,手动添加一个进去.
            IpAddress.objects.create(ipaddr="127.0.0.1")
            form.base_fields['regip'].queryset = IpAddress.objects.all()
        return form
    
    def save_model(self, request, obj, form, change):
#         print "start save--------------"
        data = request.GET
        if not data:
            data = request.POST
#         obj.uuid = data.get('uuid',uuid4().hex)
        ipobj,ok = IpAddress.objects.get_or_create(ipaddr=request.META.get('REMOTE_ADDR'))
        obj.regip = ipobj
#         print "save _model uuid ",obj.uuid
#         obj.key = make_password(obj.key)
        obj.save()
    

class AppUserAdmin(MyCustomAdmin):
    list_display = ('uname','uuid','email','phone','view_ip','regtime','phone_active','sex','nickname','view_avatar')
    
#     def __init__(self,*args,**kwargs):
#         super(AppUserAdmin,self).__init__(*args,**kwargs)
#         self.exclude('key')

    def view_avatar(self,obj):
        if len(obj.avatar) > 0:
            rawdata = base64.b64decode(obj.avatar)
            btype = magic.Magic().id_buffer(rawdata)
#             return HttpResponse(rawdata, content_type='image/%s' % btype.split(' ')[0].lower())
            return format_html('<img alt="avatar Image" src="data:image/%s;base64,%s" style="width:64px;height:64px;" />' %  (btype.split(' ')[0].lower(),obj.avatar))
        
    
    def get_form(self,request,obj=None,**kwargs):
        form = super(AppUserAdmin,self).get_form(request,obj,**kwargs)
         
        if form.base_fields['regip'].queryset.count() == 0:
            ### 必选项,手动添加一个进去.
            IpAddress.objects.create(ipaddr="127.0.0.1")
            form.base_fields['regip'].queryset = IpAddress.objects.all()
        return form
    
    def save_model(self, request, obj, form, change):
        ipobj,ok = IpAddress.objects.get_or_create(ipaddr=request.META.get('REMOTE_ADDR'))
        obj.regip = ipobj
#         print "new key is",obj.key
#         obj.key = make_password(obj.key)
#         obj.uuid = uuid4().hex
        obj.save()
        

        
    view_avatar.short_description = u'头像'
#     @csrf_protect_m
#     @transaction.atomic
#     def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
#         return super(AppUserAdmin,self).changeform_view(request,object_id,form_url,extra_context)                


class ReadOnlyAdmin(MyCustomAdmin):
    actions = None
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False
     
    def save_model(self, request, obj, form, change):
        pass
    
    def get_list_display_links(self, request, list_display):
        """
        Return a sequence containing the fields to be displayed as links
        on the changelist. The list_display parameter is the list of fields
        returned by get_list_display().
        """
        if self.list_display_links or self.list_display_links is None or not list_display:
            return self.list_display_links
        else:
            # Use only the first item in list_display as link
            return None
        
class AppUserLogAdmin(ReadOnlyAdmin):
    actions = None
#     change_form_template = "change_list.html"
    list_display = ("user","inout","view_ip","optime")
    

    

class DevicesLogAdmin(ReadOnlyAdmin):
    list_display = ("get_uuid","devices","inout","view_ip","optime")
    
class AppBindDevListAdmin(ReadOnlyAdmin):
    list_display = ("appid","get_dev","bindtime")
    
    def get_app(self,obj):
        pass
    
    def get_dev(self,obj):
        return obj.devid.uuid
    
    get_dev.short_description = u'设备ID'
        

    
class ServerAdmin(admin.ModelAdmin):
    list_display = ('ipaddr','port','mver','concount')
    
    
class SendSmsErrorAdmin(ReadOnlyAdmin):
    list_display = ("phone","errcode","addtime","ipaddr")
    
class MqttAclAdmin(ReadOnlyAdmin):
    list_display = ('app','dev','access','topic')
    
class SharedListAdmin(ReadOnlyAdmin):
    list_display = ('host','guest','sdevice','topics')
    


admin.site.register(Devices,DevicesAdmin)
admin.site.register(AppUser,AppUserAdmin)
admin.site.register(SrvList,ServerAdmin)
admin.site.register(SmsErrorLog,SendSmsErrorAdmin)
admin.site.register(AppUserLoginHistory,AppUserLogAdmin)
admin.site.register(DevicesLoginHistory,DevicesLogAdmin)
admin.site.register(AppBindDevList,AppBindDevListAdmin)
admin.site.register(MqttAcl,MqttAclAdmin)
admin.site.register(SharedDevList,SharedListAdmin)
# admin.site.register(DevicesMaker,IdMakerAdmin)
