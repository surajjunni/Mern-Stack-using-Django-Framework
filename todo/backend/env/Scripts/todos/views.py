from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .models import client_reposit
from .serializers import client_repositSerializer
from django.shortcuts import redirect,get_object_or_404
from django.db.models import Count

@api_view(['GET', 'POST','OPTIONS'])
def client_reposit_list(request):
    """
    List all code snippets, or create a new snippet.
    """
    if request.method == 'GET':
        snippets = client_reposit.objects.all()
        serializer = client_repositSerializer(snippets, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
         MAC = request.data.get('ue_mac')
         print(MAC)
         a=client_reposit.objects.filter(ue_mac=str(MAC))
         print(a)
         if(a.count!=0):
            a.delete()
         print(1)
         serializer = client_repositSerializer(data=request.data)
         if serializer.is_valid():
                recipe = serializer.save()
                recipe.user = request.user
                recipe.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
         else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
         
@api_view(['GET'])
def ios_view(request):
    if request.method == 'GET':
        icount=dict()         
        ios = client_reposit.objects.filter(os_type = 'iOS')
        c1=ios.count()
        if ios is not None:
            for i in ios:
                if i.os_version in icount:
                    icount[str(i.os_version)] += 1
                else:
                    icount[str(i.os_version)] = 1
        print(icount)            
        return Response({'icount':icount,'count':c1})

@api_view(['GET'])
def android_view(request):
    if request.method == 'GET':
        acount=dict()
        queryset=client_reposit.objects.filter(os_type='Android')
        c2=queryset.count()
        if queryset is not None:
            for i in queryset:
                if i.os_version in acount:
                    acount[str(i.os_version)] += 1
                else:
                    acount[str(i.os_version)] = 1
        print(acount)            
        return Response({'acount':acount,'count':c2})

@api_view(['GET'])
def mac_view(request):
    if request.method == 'GET':
        mcount=dict() 
        mac = client_reposit.objects.filter(os_type='Mac OS')
        c3= mac.count()
        if mac is not None:
            for i in mac:
                if i.os_version in mcount:
                    mcount[str(i.os_version)] += 1
                else:
                    mcount[str(i.os_version)] = 1
        print(mcount)
        return Response({'mcount':mcount,'count':c3})

@api_view(['GET'])
def windows_view(request):
    if request.method == 'GET':
        wcount=dict()


        windows = client_reposit.objects.filter(os_type='Windows')
        c4=windows.count()
        if windows is not None:
            for j in windows:
                if j.os_version in wcount:
                    print(j.os_version)
                    wcount[str(j.os_version)] += 1
                else:
                    wcount[str(j.os_version)] = 1
        return Response({'wcount':wcount,'count':c4})

         
@api_view(['POST'])
def user_ogin(request):
        user_data=request.data
        for i in user_data:
            MAC=i.get('ue_mac')
            b=client_reposit.objects.filter(ue_mac=MAC)
            print(b.count)
            if(b.count!=0):
                b.delete()
        serializer = client_repositSerializer(data=request.data,many=True)
        if serializer.is_valid():
            serializer.save()       
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
     
@api_view(['POST'])
def del_data(request):
        user_data=request.data
        b=client_reposit.objects.all()
        b.delete()
        serializer = client_repositSerializer(data=request.data,many=True)
        if serializer.is_valid():
            serializer.save()       
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
