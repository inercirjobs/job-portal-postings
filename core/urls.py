from django.urls import path, include,re_path
from rest_framework.routers import DefaultRouter
from . import views


router = DefaultRouter()
router.register(r'users', views.UserViewSet)

urlpatterns = [
    
    
    # Authentication
    path('auth/google-login/', views.google_login_view, name='google-login'),
    path('auth/register/', views.register_view, name='register'),
    path('auth/login/', views.login_view, name='login'),
    path('auth/logout/', views.logout_view, name='logout'),
    

        
    path('users/request-otp/', views.RequestOTP.as_view(), name='request-otp'),
    path('users/verify-otp/', views.VerifyOTP.as_view(), name='verify-otp'),
    path('users/reset-password/', views.ResetPassword.as_view(), name='reset-password'),


    
    
    path('contact', views.contact_view, name='contact'),
    
    path('jobs/available/', views.available_jobs_view, name='available-jobs'),
    
    path('jobs/available/stream/', views.available_jobs_stream_view, name='available-jobs-stream'),
    
    path('jobs/available/pagination/', views.available_jobs_pagination_view, name='available-jobs-pagination'),
    path('jobs/available/pagination/skills/', views.available_jobs_pagination_view_by_skills, name='available-jobs-pagination'),
    
    
    
    path('jobs/<str:job_id>/apply/', views.apply_to_job, name='apply-job'),
    
    path('applications/applied/', views.my_applications_view, name='my-applications'),
    
    path('company/<str:pk>/', views.company_detail_view, name='company-detail'),
    
    path('users/companies-list/', views.UserViewSet.as_view({'get': 'companies_list'}), name='companies-list'),
    
    

    


    
    path('users/dashboard/', views.UserViewSet.as_view({'get': 'dashboard_data'}), name='dashboard-data'),
    
    

    
    path('users/profile/', views.UserViewSet.as_view({'get': 'profile'}), name='user-profile'),
    path('users/change-password/', views.UserViewSet.as_view({'patch': 'change_password'}), name='change-password'),
    path('users/profile/edit/', views.UserViewSet.as_view({'patch': 'edit_profile'}), name='user-profile-edit'),

    # path('users/companies-list/', views.UserViewSet.as_view({'get': 'profile'}), name='user-profile'),

    path('users/upload-resume/', views.UserViewSet.as_view({'post': 'upload_resume'}), name='user-upload-resume'),
    path('users/upload-profile-image/', views.UserViewSet.as_view({'post': 'upload_profile_image'}), name='upload-profile-image'),
    path('users/subscribe/', views.UserViewSet.as_view({'post': 'subscribe'}), name='user-subscribe'),
    
    # urls.py
    path('users/generate-payment-link/', views.UserViewSet.as_view({'post': 'generate_payment_link'}), name='generate-payment-link'),
    # path('users/razorpay-subscribe/',views.UserViewSet.as_view({'post': 'razorpay_subscribe'}), name='user-subscribe'),
    # path('users/payment-handler/', views.UserViewSet.as_view({'get': 'payment_handler'}), name='payment-handler'),
    path('users/confirm-subscription-payment/', views.UserViewSet.as_view({'post': 'confirm_subscription_payment'}), name='confirm-subscription-payment'),


    path("create-subscription/", views.create_subscription, name="create-subscription"),
    path("raise-subscription-charge/", views.raise_subscription_charge, name="raise-subscription-charge"),
    path("cashfree/webhook/", views.cashfree_webhook, name="subscription-webhook"),




    # API routes
    path('', include(router.urls)),
]
