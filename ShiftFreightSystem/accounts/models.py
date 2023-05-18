from distutils.command.upload import upload
from email.policy import default
from unittest.util import _MAX_LENGTH
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager,PermissionsMixin, AbstractUser
import datetime
# from Home.models import vehicle
from Home.models import CompanyTruck
import datetime
from location_field.models.plain import PlainLocationField



class MyAccountManager(BaseUserManager):
    def create_user(self,name,address1,address2,city,pincode,district,state,phone,email,is_consignor,password=None):

        if not email:
            raise ValueError('User must have an email address')
        
        user = self.model(
            email = self.normalize_email(email),
            name=name, 
            address1=address1,
            address2=address2,
            city=city,
            pincode=pincode,
            district = district,
            state=state,
            phone = phone,
            is_consignor=is_consignor,


        )

        user.set_password(password)
        user.save(using=self._db)
        return user
    

    def create_superuser(self,password,email,**extra_fields):
        user = self.create_user(
            email = self.normalize_email(email),
            password = password, **extra_fields
        
        )

        user.is_admin = True
        user.is_active = True
        user.is_staff = True
        user.is_superadmin = True
        user.save(using=self._db)
        return user
    
class Account(AbstractBaseUser,PermissionsMixin):
    status_choices=(('Approved','Approved'),('Pending','Pending'), ('None','None'))
    role_choices=(('is_admin','is_admin'),('is_consignor','is_consignor'),('is_driver','is_driver'))
    district_choices=(
        ('Kozhikode','Kozhikode'),
        ('Malappuram','Malappuram'),
        ('Kannur','Kannur'),
        # ('Trivandrum','Trivandrum'),
        ('Palakkad','Palakkad'),
        ('Thrissur','Thrissur'),
        ('Kottayam','Kottayam'),
        ('Alappuzha','Alappuzha'),
        ('Idukki','Idukki'),
        ('Kollam','Kollam'), 
        ('Ernakulam','Ernakulam'),
        ('Wayanad','Wayanad'),
        ('Kasaragod','Kasaragod'),
        ('Pathanamthitta','Pathanamthitta'),
        ('Thiruvananthapuram','Thiruvananthapuram'),
        ('None','None'),
    )


    id            = models.AutoField(primary_key=True)
    name          = models.CharField(max_length=100, default='')
    phone         = models.BigIntegerField(default=0,unique=True)
    email         = models.EmailField(max_length=100, unique=True)
    address1      = models.CharField(max_length=100, default='')
    address2      = models.CharField(max_length=100, default='')
    city          = models.CharField(max_length=100, default='')
    state          = models.CharField(max_length=100, default='')
    district      = models.CharField(max_length=50,choices=district_choices,default='None')
    pincode       = models.BigIntegerField(default=0)
    role          = models.CharField(max_length=100,choices=role_choices)
    
    # dob           = models.DateField(blank=True,null=True)
    # gender        = models.CharField(max_length=50,choices=gender_choices,default='None')
    
    # required
    date_joined     = models.DateTimeField(auto_now_add=True)
    last_login      = models.DateTimeField(auto_now_add=True)
    is_admin        = models.BooleanField(default=False)
    is_consignor      = models.BooleanField(default=False)
    is_driver      = models.BooleanField(default=False)
    

    is_active       = models.BooleanField(default=True)
    is_superadmin   = models.BooleanField(default=False)
    is_staff      = models.BooleanField(default=False) 
    is_superadmin     = models.BooleanField(default=False) 

    is_booked = models.BooleanField(default=False)


    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone', 'address1','address2','city','state','pincode','district','is_consignor']
    # REQUIRED_FIELDS = [,'password']


    objects = MyAccountManager()

    # def full_name(self):
    #     return f'{self.first_name} {self.last_name}'

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, add_label):
        return True
    


class BTruck(models.Model):
    statu = (
        ('Approved','Approved'),
        ('Pending','Pending'), 
        ('None','None')
    )
    good_typ = (
        ('Household','Household'),
        ('Beverages','Beverages'),
        ('Paints','Paints'),
        ('Steel','Steel'),
        ('Electronics','Electronic'),
        ('others','others'),
        ('None','None')
    )
    service =(
        ('Loading','Loading'),
        ('Unloading','Unloading'),
        ('Cardboard Packing','Cardboard Packing'),
        ('Storage','Storage')
    )
    boo_id = models.AutoField(primary_key=True)
    us_id = models.ForeignKey(Account,related_name='consignor', on_delete=models.CASCADE)
    dr_id =models.ForeignKey(Account,related_name='driver', on_delete=models.CASCADE,blank=True,null = True)
    veh_id = models.ForeignKey(CompanyTruck,on_delete=models.CASCADE,blank=True,null=True)
    p_cit = models.CharField(max_length=100)
    p_addres1 = models.CharField(max_length=100,blank=True,null=True)
    p_addres2 = models.CharField(max_length=100,blank=True,null=True)
    p_distric = models.CharField(max_length=100)
    p_stat = models.CharField(max_length=100,blank=True,null=True)
    p_pincod = models.CharField(max_length=100)
    d_cit = models.CharField(max_length=100,blank=True,null=True)
    d_addres1 = models.CharField(max_length=100,blank=True,null=True)
    d_addres2 = models.CharField(max_length=100,blank=True,null=True)
    d_distric = models.CharField(max_length=100,blank=True,null=True)
    d_stat = models.CharField(max_length=100,blank=True,null=True)
    d_pincod = models.CharField(max_length=100,blank=True,null=True)
    good_typ = models.CharField(max_length=50,choices=good_typ,default='None')
    bookingdat = models.DateTimeField(blank=True,null=True)
    weigh = models.CharField(max_length=100,blank=True,null=True)
    service = models.CharField(max_length=50,choices=service,default='None')
    load_descriptio = models.CharField(max_length=100,blank=True,null=True)
    statu = models.CharField(choices=statu,max_length=100,default='Pending')
    location = PlainLocationField(based_fields=['d_cit'], zoom=7,blank=True,null=True)
    def __str__(self):
        return "%s - %s - %s"%(self.p_cit,self.d_cit,self.statu)
   

class FuelDetail(models.Model):
    fuel_id = models.AutoField(primary_key=True)
    added_driver_id= models.ForeignKey(Account, related_name='truck_driver', on_delete=models.CASCADE,blank=True,null=True)
    truck = models.CharField(max_length=50)
    fuel_type = models.CharField(max_length=50)
    odometer_reading = models.CharField(max_length=6)
    fill_date = models.DateField()
    quantity = models.DecimalField(max_digits=10, decimal_places=2)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    comment = models.TextField()
    bill_image = models.ImageField(upload_to='images/fuel_bills/')

    def __str__(self):
        return "%s - %s - %s - %s"%(self.fuel_id,self.added_driver_id,self.truck,self.quantity)
  