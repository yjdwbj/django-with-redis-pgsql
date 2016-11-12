#coding: utf-8
from django.contrib import admin
from .models import *
from uuid import uuid4
from user_manager.models import SmsErrorLog

from django.utils.decorators import method_decorator
from django.db import  transaction
from django.views.decorators.csrf import csrf_protect

from django.contrib.auth.hashers import make_password,check_password



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
        
    @csrf_protect_m
    @transaction.atomic
    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        return super(MyCustomAdmin,self).changeform_view(request,object_id,form_url,extra_context)
    

    
    view_ip.short_description = u'IP地址'
    view_ip.allow_tags = True


class DevicesAdmin(MyCustomAdmin):
    list_display = ('uuid','mac','appkey','key','name','view_ip','regtime')
    
    def save_model(self, request, obj, form, change):
        data = request.GET
        if not data:
            data = request.POST
        obj.uuid = data.get('uuid',uuid4().hex)
        ipobj,ok = IpAddress.objects.get_or_create(ipaddr=request.META.get('REMOTE_ADDR'))
        obj.regip = ipobj
        obj.key = make_password(obj.key)
        obj.save()
    

class AppUserAdmin(MyCustomAdmin):
    list_display = ('uname','phone','view_ip','key','regtime','phone_active')
    
#     def __init__(self,*args,**kwargs):
#         super(AppUserAdmin,self).__init__(*args,**kwargs)
#         self.exclude('key')
    

    
    def save_model(self, request, obj, form, change):
        ipobj,ok = IpAddress.objects.get_or_create(ipaddr=request.META.get('REMOTE_ADDR'))
        obj.regip = ipobj
        obj.key = make_password(obj.key)
#         obj.uuid = uuid4().hex
        obj.save()
        
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
    
#     def get_list_display_links(self, request, list_display):
#         """
#         Return a sequence containing the fields to be displayed as links
#         on the changelist. The list_display parameter is the list of fields
#         returned by get_list_display().
#         """
#         if self.list_display_links or self.list_display_links is None or not list_display:
#             return self.list_display_links
#         else:
#             # Use only the first item in list_display as link
#             return None
# #     def get_readonly_fields(self, request, obj=None):
# #         return self.fields or [f.name for f in self.model._meta.fields]
#         
#     def has_add_permission(self, request):
#         return False
#     
#     def has_delete_permission(self, request, obj=None):
#         return False
#      
#     def save_model(self, request, obj, form, change):
#         pass
    

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
    
    
class SendSmsErrorAdmin(admin.ModelAdmin):
    list_display = ("phone","errcode","addtime")
    
# class IdMakerAdmin(admin.ModelAdmin):
#     using ='devdb'
#     list_display = ('iot_uuid','iot_mac','iot_key','app_key','app_name','status','uid','typeid','info')
#     
#     def save_model(self, request, obj, form, change):
#         # Tell Django to save objects to the 'other' database.
#         obj.save(using=self.using)
# 
#     def delete_model(self, request, obj):
#         # Tell Django to delete objects from the 'other' database
#         obj.delete(using=self.using)
# 
#     def get_queryset(self, request):
#         # Tell Django to look for objects on the 'other' database.
#         return super(IdMakerAdmin, self).get_queryset(request).using(self.using)
# 
#     def formfield_for_foreignkey(self, db_field, request, **kwargs):
#         # Tell Django to populate ForeignKey widgets using a query
#         # on the 'other' database.
#         return super(IdMakerAdmin, self).formfield_for_foreignkey(db_field, request, using=self.using, **kwargs)
# 
#     def formfield_for_manytomany(self, db_field, request, **kwargs):
#         # Tell Django to populate ManyToMany widgets using a query
#         # on the 'other' database.
#         return super(IdMakerAdmin, self).formfield_for_manytomany(db_field, request, using=self.using, **kwargs)
#     
        

admin.site.register(Devices,DevicesAdmin)
admin.site.register(AppUser,AppUserAdmin)
admin.site.register(SrvList,ServerAdmin)
admin.site.register(SmsErrorLog,SendSmsErrorAdmin)
admin.site.register(AppUserLoginHistory,AppUserLogAdmin)
admin.site.register(DevicesLoginHistory,DevicesLogAdmin)
admin.site.register(AppBindDevList,AppBindDevListAdmin)
# admin.site.register(DevicesMaker,IdMakerAdmin)
