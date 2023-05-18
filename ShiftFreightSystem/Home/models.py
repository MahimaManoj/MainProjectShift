
from django.db import models
# Create your models here.

class vehicle(models.Model):
    vehicle_id = models.AutoField(primary_key=True)
    register_no=models.CharField(max_length=100,unique=True)
    regd_owner=models.CharField(max_length=100)
    reg_address=models.CharField(max_length=100)
    makers_class=models.CharField(max_length=100)
    vehicle_class=models.CharField(max_length=100)
    fuel=models.CharField(max_length=100)
    engine=models.CharField(max_length=100)
    insurance=models.CharField(max_length=100)
    
    def __str__(self):
            return self. register_no

class Truck(models.Model):
      v_id = models.AutoField(primary_key=True)
      register_num = models.CharField(max_length=100,unique=True)
      reg_owner = models.CharField(max_length=100)
      regd_address = models.CharField(max_length=100)
      maker_class = models.CharField(max_length=100)
      vehicles_class = models.CharField(max_length=100)
      fuel = models.CharField(max_length=100)
      engine = models.CharField(max_length=100)
      insurance = models.CharField(max_length=100)
      is_booked = models.BooleanField(default=False)

      def __str__(self):
            return self. register_num

class CompanyTruck(models.Model):
      truck_id = models.AutoField(primary_key=True)
      registeration_no = models.CharField(max_length=100,unique=True)
      registered_owner = models.CharField(max_length=100)
      registered_address = models.CharField(max_length=200)
      makerss_class = models.CharField(max_length=100)
      truck_class = models.CharField(max_length=100)
      fuel_type = models.CharField(max_length=100)
      engine_name = models.CharField(max_length=100)
      insurance_year = models.CharField(max_length=100)
      is_booked = models.BooleanField(default=False)
      def __str__(self):
            return self.registeration_no

class Services(models.Model):
      service_id= models.AutoField(primary_key=True)
      service_name = models.CharField(max_length=100)
      service_description = models.CharField(max_length=200)
      

# class AddFuel(models.Model):
#     fuel_id = models.AutoField(primary_key=True)
#     user_id = models.ForeignKey(Account, on_delete=models.CASCADE)
#     vehicle_id = models.ForeignKey(vehicle, on_delete=models.CASCADE)
#     driver_id = models.ForeignKey(Driver, on_delete=models.CASCADE)
#     fuel_quantity = models.CharField(max_length=200)
#     odometer_reading = models.CharField(max_length=200)
#     fill_date = models.DateField()
#     amount = models.CharField(max_length=200)
#     comment = models.CharField(max_length=200)
#     def __str__(self):
#             return self.fuel_id


