from django.urls import path
from django.conf.urls import url

from . import views

urlpatterns = [
    path('', views.client_reposit_list),
    path('tool/',views.user_ogin),
    path('android/',views.android_view),
    path('ios/',views.ios_view),
	path('windows/',views.windows_view),
	path('mac/',views.mac_view),
    path('del/',views.del_data)
]