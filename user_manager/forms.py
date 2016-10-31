#coding: utf-8

from django import forms
from .models import *
from .views import *

from django.db import IntegrityError


class AppRegForm(forms.Form):     
    password = forms.CharField(
        label=u'密码',
        help_text=u'',
        min_length=6,max_length=8,
        widget=forms.PasswordInput(attrs={'class':'form-control'}),
        )
    
    confirm_password = forms.CharField(
        label=u'密码',
        help_text=u'',
        min_length=6,max_length=8,
        widget=forms.PasswordInput(attrs={'class':'form-control'}),
        )
    
    email = forms.EmailField(
        label=u'邮箱',
        help_text=u'请输入有效的邮箱,请把service@jieli.net的邮箱设置白名单',
        max_length=60,
        widget=forms.EmailInput(attrs={'class':'form-control'}),
        )
    
    phone = forms.CharField(
        label=u'手机号码',
        help_text = u'请输入有效的手机号,以便接收短信验证',
        max_length=11,
        widget =forms.TextInput(attrs={'class':'form-control'}),
        )
    
    captcha = forms.CharField(
        label=u'验证码',
        min_length=6,max_length=6,
        widget = forms.TextInput(attrs={'class':'form-control'}),
        )
    
    def __init__(self,*args,**kwargs):
        self.request = kwargs.pop('request',None)
        super(AppRegForm,self).__init__(*args,**kwargs)
        self.fields['captcha'].initial=''
        
    def get_captcha(self):
        code = self.data['captcha']
        if not code or len(code) != 6:
            raise forms.ValidationError(u'验证码错误')
        return code
        
    def save(self):
        email = self.cleaned_data['email']
        phone = self.cleaned_data['phone']
        password = self.cleaned_data['password']
        uname  = uuid.uuid4().hex
#         try:
        obj = AppUser.objects.create(email = email,phone =phone,
                           key=password,uuid = uname,
                           uname = uname[:6],
                           regtime = timezone.now(),
                           regip = self.request.META.get('REMOTE_ADDR'),
                           data = {})
    
        obj.save()
#         except IntegrityError as e:
#             print "except is---------------",e ,type(e)
#             print "---------------------------"
#             msg = str(e)
#             if 'email' in msg:
#                 raise forms.ValidationError(u'邮箱已经存在')
#             elif 'phone' in msg:
#                 raise forms.ValidationError(u'手机已经存在')

                
            
        
    
        