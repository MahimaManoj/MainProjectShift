from django.contrib import admin
import csv
from django.http import HttpResponse
from .models import CompanyTruck
from django.contrib.auth.models import Group
# Register your models here.


def export_vehicle(modeladmin, request, queryset):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="CompanyTruck.csv"'
    writer = csv.writer(response)
    writer.writerow(['Registered No','Registered Owner','Registered Address','Makers Class', 'Vehicle Class','Engine','Insurance'])
    registration = queryset.values_list('registeration_no','registered_owner','registered_address','makerss_class','truck_class','engine_name','insurance_year')
    for i in registration:
        writer.writerow(i)
    return response

export_vehicle.short_description = 'Export to csv'

class RegAdmin(admin.ModelAdmin):
    list_display = ['registeration_no','registered_owner','registered_address','makerss_class','truck_class','engine_name','insurance_year']
    actions = [export_vehicle]
admin.site.register(CompanyTruck,RegAdmin)

# def export_driver(modeladmin, request, queryset):
#     response = HttpResponse(content_type='text/csv')
#     response['Content-Disposition'] = 'attachment; filename="Driver.csv"'
#     writer = csv.writer(response)
#     writer.writerow(['Driver Name','Driver Address','Email ','Phone', 'Licence NO'])
#     registration = queryset.values_list('driver_name','driver_address','driver_email','driver_phone','driver_licence')
#     for i in registration:
#         writer.writerow(i)
#     return response

# export_driver.short_description = 'Export to csv'


# class RegAdmin(admin.ModelAdmin):
#     list_display = ['driver_name','driver_address','driver_email','driver_phone','driver_licence']
#     actions = [export_driver]
# admin.site.register(Driver,RegAdmin)


