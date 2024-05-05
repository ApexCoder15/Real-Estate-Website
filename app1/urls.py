from django.urls import path, include
from . import views
from django.contrib.auth import views as auth_views
from app1.forms import customAuthenticationForm

urlpatterns = [
    path("", views.ekyc_verf, name='EkycVer'),
    path("login", auth_views.LoginView.as_view(template_name="home_login.html", authentication_form=customAuthenticationForm)),
    path('home', views.home_page, name='HomePage'),
    path('verifyproplist', views.verify_prop_listing, name='VerifyPL'),
    path('verifyproplistdb', views.verify_prop_listing_db, name='VerifyPLDB'),
    path('contractbuyer', views.view_contract_buyer, name='ContractBuyer'),
    path('contractseller', views.view_contract_seller, name='ContractSeller'),
    path('list_curr_prop', views.curr_prop_list, name='CurrPropList'),
    path('delete_curr_prop/<int:prop_id>/', views.delete_curr_prop, name='DeleteCurrProp'),
    path('verifyuser', views.verify_user, name='VerifyUser'),
    path('logout', views.logout_view, name='Logout'),
    path('otpsendlogin', views.otp_send_login, name='OtpSendLogin'),
    path('otpsendverf', views.otp_send_verif, name='OtpSendVerf'),
    path('signup', views.signup, name='SignUp'),
    path('aggreq', views.agg_req_list, name='AggReq'),
    path('download_private', views.download_private_key, name='DownloadPrivate'),
    path('addprop', views.add_prop, name='AddProp'),
    path('listprop', views.prop_listing_buyer, name='ListProp'),
    path('contractlist', views.contract_list, name='ContractList'),
    path('userlist', views.user_list, name='UserList'),
    path('verify/<str:contract_name>/', views.verify_contract, name='VerifyContract'),
    path('download_cont/<str:cont_name>/', views.download_contract, name='DownloadContract'),
    path('payment/<int:prop_id>/', views.initiate_payment, name='Payment'),
    path('report/<int:prop_id>/', views.report_user, name='Report'),
    path('userdelete/<int:user_id>/', views.user_delete, name='UserDelete'),
    path('removereport/<int:user_id>/', views.remove_report, name='RemoveReport'),
    path('userapprove/<int:user_id>/', views.approve_agg, name='UserApprove'),
]
