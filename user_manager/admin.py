from django.contrib import admin
from .models import Devices,AppUser,SrvList
from uuid import uuid4
from user_manager.models import SmsErrorLog

from django.utils.decorators import method_decorator
from django.db import  transaction
from django.views.decorators.csrf import csrf_protect



# Register your models here.

IS_POPUP_VAR = '_popup'
TO_FIELD_VAR = '_to_field'


csrf_protect_m = method_decorator(csrf_protect)


class DevicesAdmin(admin.ModelAdmin):
    list_display = ('uuid','mac','appkey','name','key')
    
    def save_model(self, request, obj, form, change):
        print "request is",request.__dict__
        data = request.GET
        if not data:
            data = request.POST
        obj.uuid = data.get('uuid',uuid4().hex)
        obj.save()
        
    @csrf_protect_m
    @transaction.atomic
    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        return super(DevicesAdmin,self).changeform_view(request,object_id,form_url,extra_context)

class AppUserAdmin(admin.ModelAdmin):
    list_display = ('uname','phone','key','regip','regtime','phone_active')
    
    def save_model(self, request, obj, form, change):
        obj.regip = request.META.get('REMOTE_ADDR')
#         obj.uuid = uuid4().hex
        obj.save()
        
    @csrf_protect_m
    @transaction.atomic
    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        return super(AppUserAdmin,self).changeform_view(request,object_id,form_url,extra_context)                
        
class ServerAdmin(admin.ModelAdmin):
    list_display = ('ipaddr','port','mver','concount')
    
    
class SendSmsErrorAdmin(admin.ModelAdmin):
    list_display = ("phone","errcode","ipaddr","addtime")
    
        

admin.site.register(Devices,DevicesAdmin)
admin.site.register(AppUser,AppUserAdmin)
admin.site.register(SrvList,ServerAdmin)
admin.site.register(SmsErrorLog,SendSmsErrorAdmin)
