from django.contrib import admin
from django.urls import include, path
from . import views

urlpatterns = [
    path('Reg/',views.registration,name='registration'),
    path('viewlogin/',views.viewlogin,name='viewlogin'),
    path('book/',views.Book1,name='book'),
    path('driverhome/',views.DriverHome,name='driverhome'),
    path('consignorhome/',views.ConsignorHome,name='consignorhome'),
    path('viewfuel/',views.ViewFuel,name='viewfuel'),
    path('driverprofile/',views.DriverProfile,name='driverprofile'),
    path('resetpassword_validate/<uidb64>/<token>/', views.resetpassword_validate, name='resetpassword_validate'),
    path('forgotPassword/', views.forgotPassword, name='forgotPassword'),
    path('resetPassword/', views.resetPassword, name='resetPassword'),
    path('addfuel/', views.AddFuel, name='addfuel'),
    path('driverbasic/', views.DriverBasic, name='driverbasic'),
    path('driverconsignment/', views.DriverConsignment, name='driverconsignment'),
    path('logout/', views.logout, name='logout'),
    path('consignorprofile/', views.ConsignorProfile, name='consignorprofile'),
    path('drlog/', views.Driverlog, name='drlog'),
    path('drotp/', views.Driverotp, name='drotp'),
    path('viewbooking/', views.ViewBooking, name='viewbooking'),
    path('addtruckdriver/<boo_id>/', views.addtruckdriver, name='addtruckdriver'),
    path('adminfreight/', views.AdminFreight, name='adminfreight'),
    path('adminbooking/', views.AdminBooking, name='adminbooking'),
    path('adminprofile/', views.AdminProfile, name='adminprofile'),
    path('adminlocations/', views.AdminLocation, name='adminlocations'),
    path('pin/', views.pincode_view, name='pin'),
    path('bookingsummary/<boo_id>/', views.BookingSummary, name='bookingsummary'),
    path('addfueldemo/', views.AddFuelDemo, name='addfueldemo'),
    path('viewfuel/', views.ViewFuel, name='viewfuel'),
    path('payment_page/', views.payment_page, name='consignorpayment'),
    path('consignerbookingsummary/<boo_id>/', views.ConsignerBookingSummary, name='consignerbookingsummary'),
    path('pay/', views.Pay, name='pay'),
     
    # path('consignorReg/',views.ConsignorReg,name='ConsignorReg'),
    # path('commonmanReg/',views.CommonManReg,name='CommonManReg'),

]
