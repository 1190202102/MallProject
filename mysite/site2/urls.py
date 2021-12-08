"""mysite URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.urls import path
from . import views
urlpatterns = [

    path('user/',views.user,name="user"),


    #下面是正确有用的页面
    # path('',views.login,name="login"),
    path('logon/',views.logon,name="logon"),
    path('process_login/',views.process_login,name="process_login"),
    path('register/process_logon/',views.process_logon,name="process_logon"),
    path('process/',views.process,name="process"),
    path('register/send_certi/',views.send_certi,name="send_certi"),
    path('hash_accept',views.hash_accept,name='hash_accept'),
    path('challenge_sender',views.challenge_sender,name='challenge_sender'),
    path('',views.mall_home,name='mall_home'),
    path('display_products/',views.send_prod_home_info,name='display_products'),
    path('404/',views.notfound,name='notfound'),
    path('forget/',views.forgetpwd,name='forgetpwd'),
    path('index/',views.index,name='index'),
    path('login/',views.login_mall,name='login_mall'),
    path('register/',views.register,name='register'),
    path('shopcart/',views.shopcart,name='shopcart'),
    path('tables/',views.tables,name='tables'),
    path('goods',views.detail_goods,name='goods'),
]
handler404 = 'site2.views.notfound'