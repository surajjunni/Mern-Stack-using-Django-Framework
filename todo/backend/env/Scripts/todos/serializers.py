from rest_framework import serializers
from rest_framework_mongoengine import serializers as mongoserializers

from .models import client_reposit
class client_repositSerializer(mongoserializers.DocumentSerializer):
	
   class Meta:
       fields = '__all__'
       model = client_reposit