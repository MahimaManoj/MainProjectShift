from django.contrib import admin
from .models import Account, BTruck
from django.contrib.auth.models import Group
# Register your models here.

admin.site.unregister(Group)
from django.contrib import admin
from django.contrib. auth.models import Group
import csv
from django.http import HttpResponse
from .models import Account
# admin.site.register(Account)
def export_reg(modeladmin, request, queryset):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="registration.csv"'
    writer = csv.writer(response)
    writer.writerow(['Name','Email','Phone','Address','City', 'Zip code','District','Role'])
    registration = queryset.values_list('name','email','phone','address2','city','pincode','district','Role')
    for i in registration:
        writer.writerow(i)
    return response


export_reg.short_description = 'Export to csv'


class RegAdmin(admin.ModelAdmin):
    list_display = ['name','email','phone','address2','city','pincode','district','role']
    actions = [export_reg]
admin.site.register(Account,RegAdmin)


# admin.site.register(BTruck)

class BookAdmin(admin.ModelAdmin):
    list_display = ['p_cit','d_cit','statu']
    def has_add_permission(self,request):
        return False 
    
admin.site.register(BTruck,BookAdmin)

     


