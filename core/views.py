import boto3
import time
import os
import csv
import io
import re

import razorpay
import random
from botocore.exceptions import ClientError
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from .models import User, AdminUser,Job,JobApplication,Contact,Subscription
from django.utils import timezone
from .serializers import (
    UserRegistrationSerializer, UserSerializer, LoginSerializer,
    AdminUserSerializer,JobSerializer,JobApplicationSerializer,CompanySerializer,HrUserSerializer,
    ResetPasswordSerializer,RequestOTPSerializer,VerifyOTPSerializer,ChangePasswordSerializer,ContactSerializer,
    UserSubscriptionSerializer
)
from django.utils.timezone import now
# from .utils.s3_signed import generate_presigned_url
from core.utils import build_presigned_get_url, generate_presigned_url

from google.oauth2 import id_token
# from google.oauth2 import id_token
# from google.auth.transport import requests
import requests 
from google.auth.transport import requests as googleRequest

import hmac
from django.shortcuts import get_object_or_404
import hashlib
from rest_framework.parsers import MultiPartParser, FormParser,JSONParser
from .utils import get_redirect_url
import uuid
from rest_framework.views import APIView
from django.core.cache import cache
from django.core.mail import send_mail
from rest_framework.decorators import action
from rest_framework.response import Response
from django.db.models import Q
# from razorpay_client import client
from django.utils import timezone
from datetime import timedelta
import razorpay
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.http import HttpResponseBadRequest
from razorpay.errors import SignatureVerificationError
client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
from django.http import StreamingHttpResponse
import pytz
from datetime import datetime, timedelta

import tempfile

ist = pytz.timezone('Asia/Kolkata')
schedule_time = datetime.now(ist) + timedelta(minutes=2)
payment_schedule_date = schedule_time.isoformat()

def verify_signature(payment_id, subscription_id, signature, secret):
    msg = f"{payment_id}|{subscription_id}".encode()
    generated_signature = hmac.new(
        key=secret.encode(),
        msg=msg,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(generated_signature, signature)
# Custom Permissions
class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.user == request.user

class IsHROrAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role in ['hr', 'admin']

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'
class AllowAnyPermission(permissions.BasePermission):
    """
    Custom permission that always allows access.
    Equivalent to rest_framework.permissions.AllowAny
    """
    def has_permission(self, request, view):
        return True


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def google_login_view(request):
    token_from_client = request.data.get('token')

    if not token_from_client:
        return Response({'error': 'Token not provided'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        CLIENT_ID = "117920625230-nt6koku002p7jb66h1t22uk3r5qd1dga.apps.googleusercontent.com"  # <-- Your actual client ID here
        idinfo = id_token.verify_oauth2_token(
            token_from_client,
            googleRequest.Request(),
            CLIENT_ID,
            clock_skew_in_seconds=10  # Add 10 seconds skew allowance
        )

        email = idinfo['email']
        name = idinfo.get('name', '')
        picture = idinfo.get('picture', '')

        full_name = name
        username = email.split("@")[0]

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': username,
                'full_name': full_name,
                'image': picture,
                'role': 'user',
                'is_verified': 'approved',
            }
        )

        if not user.image and picture:
            user.image = picture
            user.save()

        token, _ = Token.objects.get_or_create(user=user)

        return Response({
            'message': 'Login successful',
            'token': token.key,
            'user': UserSerializer(user).data,
            'redirect_url': get_redirect_url(user.role)
        })

    except ValueError as e:
        return Response({'error': 'Invalid token', 'details': str(e)}, status=status.HTTP_400_BAD_REQUEST)
   
# Authentication Views
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register_view(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        token, created = Token.objects.get_or_create(user=user)
        
        return Response({
            'message': 'Registration successful' if user.role != 'hr' else 'Registration submitted for verification',
            'token': token.key,
            'user': UserSerializer(user).data,
            'redirect_url': get_redirect_url(user.role)
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        
        return Response({
            'message': 'Login successful',
            'token': token.key,
            'user': UserSerializer(user).data,
            'redirect_url': get_redirect_url(user.role)
        })

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def logout_view(request):
    try:
        request.user.auth_token.delete()
        return Response({'message': 'Successfully logged out'})
    except:
        return Response({'error': 'Error logging out'}, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def contact_view(request):

    data = request.data.copy()
    data['id'] = data.get('id') or str(uuid.uuid4().hex[:20])

    serializer = ContactSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response({
            'message': 'Contact form submitted successfully.',
            'contact': serializer.data
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# def get_redirect_url(role):
#     role_urls = {
#         'user': '/dashboard/jobseeker',
#         'hr': '/dashboard/company', 
#         'admin': '/dashboard/admin'
#     }
#     return role_urls.get(role, '/dashboard')

# ViewSets
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('-created_at')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser,JSONParser]
    
    def get_queryset(self):
        if self.request.user.role == 'admin':
            return User.objects.all().order_by('-created_at')
        else:
            return User.objects.filter(id=self.request.user.id)
        
        

        
    @action(detail=False, methods=['get'], url_path='dashboard-data')
    def dashboard_data(self, request):
        user = request.user
        
        user_data = self.get_serializer(user).data
        available_jobs = Job.objects.filter(status='active').order_by('-created_at')[:5]
        available_jobs_data = JobSerializer(available_jobs, many=True).data
        
        recent_apps = JobApplication.objects.filter(applied_by=user).order_by('-applied_on')[:5]
        recent_apps_data = JobApplicationSerializer(recent_apps, many=True).data
        
        # Parse user skills string to list
        user_skills_list = []
        if user.skills:
            user_skills_list = [skill.strip().lower() for skill in user.skills.split(',') if skill.strip()]
        
        # Get job IDs user has applied for
        applied_job_ids = JobApplication.objects.filter(applied_by=user).values_list('job_id', flat=True)
        
        # Filter recommended jobs manually by checking skills overlap
        recommended_jobs_qs = Job.objects.filter(status='active').exclude(id__in=applied_job_ids).order_by('-created_at')
        
        recommended_jobs_filtered = []
        for job in recommended_jobs_qs:
            if not job.skills:
                continue
            job_skills_list = [skill.strip().lower() for skill in job.skills.split(',') if skill.strip()]
            if set(user_skills_list) & set(job_skills_list):  # check intersection
                recommended_jobs_filtered.append(job)
            if len(recommended_jobs_filtered) >= 5:
                break
        
        recommended_jobs_data = JobSerializer(recommended_jobs_filtered, many=True).data
        
        data = {
            "user_profile": user_data,
            "available_jobs": available_jobs_data,
            "recent_applications": recent_apps_data,
            "recommended_jobs": recommended_jobs_data,
        }
        
        return Response(data)


    @action(detail=False, methods=['get'])
    def profile(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'], url_path='companies-list')
    def companies_list(self, request):
        companies = User.objects.filter(role='hr').order_by('-created_at')
        serializer = self.get_serializer(companies, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['patch'], url_path='profile/edit')
    def edit_profile(self, request):
        user = request.user
        serializer = self.get_serializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "detail": "Profile updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    @action(detail=False, methods=['patch'], url_path='change-password')
    def change_password(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        current_password = serializer.validated_data['current_password']
        new_password = serializer.validated_data['new_password']

        if not user.check_password(current_password):
            return Response({"detail": "Current password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()

        return Response({"detail": "Password changed successfully."}, status=status.HTTP_200_OK)

    

    @action(detail=False, methods=['post'], url_path='upload-resume')
    def upload_resume(self, request):
        user = request.user

        if user.role != 'user':
            return Response({"detail": "Only job seekers can upload resumes."}, status=status.HTTP_403_FORBIDDEN)

        file = request.FILES.get('resume')
        if not file:
            return Response({"detail": "No resume file provided."}, status=status.HTTP_400_BAD_REQUEST)

        s3 = boto3.client('s3',
                        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                        region_name=settings.AWS_S3_REGION_NAME)

        # Delete previous resume if exists
        # if user.resume_key:
        #     try:
        #         s3.delete_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=user.resume_key)
        #     except Exception as e:
        #         print("Resume deletion failed:", e)

        # Upload new resume
        resume_key = f"resumes/resume_{uuid.uuid4().hex}.pdf"
        try:
            s3.upload_fileobj(
                file,
                settings.AWS_STORAGE_BUCKET_NAME,
                resume_key,
                ExtraArgs={'ContentType': file.content_type}
            )
        except Exception as e:
            return Response({"detail": "Resume upload failed.", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Generate a pre-signed URL
        try:
            presigned_url = s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': settings.AWS_STORAGE_BUCKET_NAME, 'Key': resume_key},
                ExpiresIn=3600  # 1 hour
            )
        except ClientError as e:
            return Response({"detail": "Failed to generate pre-signed URL.", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Save the full pre-signed URL in resume field, and also store key if needed
        user.resume = presigned_url
        user.resume_key = resume_key  # optional: keep this if you want to track the key separately
        user.save()

        return Response({
            "detail": "Resume uploaded successfully.",
            "resume_url": presigned_url
        }, status=status.HTTP_200_OK)

        
        
    @action(detail=False, methods=['get'], url_path='resume-url')
    def get_resume_url(self, request):
        user = request.user

        if not user.resume_key:
            return Response({"detail": "No resume uploaded."}, status=status.HTTP_404_NOT_FOUND)

        s3 = boto3.client('s3',
                        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                        region_name=settings.AWS_S3_REGION_NAME)

        try:
            presigned_url = s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': settings.AWS_STORAGE_BUCKET_NAME, 'Key': user.resume_key},
                ExpiresIn=3600
            )
        except ClientError as e:
            return Response({"detail": "Failed to generate pre-signed URL.", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "resume_url": presigned_url
        }, status=status.HTTP_200_OK)




    @action(detail=False, methods=['post'], url_path='upload-profile-image')
    def upload_profile_image(self, request):
        user = request.user
        file = request.FILES.get('image')

        if not file:
            return Response({"detail": "No image file provided."}, status=status.HTTP_400_BAD_REQUEST)

        # Delete previous image if it exists
        if user.image:
            try:
                s3 = boto3.client(
                    's3',
                    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                    region_name=settings.AWS_S3_REGION_NAME
                )
                key = user.image.split(f"{settings.AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com/")[-1]
                s3.delete_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=key)
            except Exception as e:
                print("Image deletion failed:", e)

        # Upload new image
        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        image_key = f"profile_images/profile_{uuid.uuid4().hex}.{file.name.split('.')[-1]}"
        try:
            s3.upload_fileobj(
                file,
                settings.AWS_STORAGE_BUCKET_NAME,
                image_key,
                ExtraArgs={'ContentType': file.content_type}
            )
        except Exception as e:
            return Response({"detail": "Image upload failed.", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        image_url = f"https://{settings.AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com/{image_key}"
        user.image = image_url
        user.save()

        return Response({
            "detail": "Profile image uploaded successfully.",
            "image_url": image_url
        }, status=status.HTTP_200_OK)
        
        
        
    @action(detail=False, methods=['post'], url_path='subscribe')
    def subscribe(self, request):
        user = request.user
        new_plan = request.data.get('plan')

        if new_plan not in dict(User.PLAN_CHOICES):
            return Response({"detail": "Invalid plan selected."}, status=status.HTTP_400_BAD_REQUEST)

        # Only update if plan is different
        if user.plan != new_plan:
            user.plan = new_plan
            user.subscribe_date = timezone.now()
            user.save()
            return Response({
                "detail": f"Subscription updated to {new_plan}.",
                "plan": user.plan,
                "subscribe_date": user.subscribe_date
            }, status=status.HTTP_200_OK)
        
        return Response({"detail": "You are already subscribed to this plan."}, status=status.HTTP_200_OK)
    


    @action(detail=False, methods=['post'], url_path='generate-payment-link')
    def generate_payment_link(self, request):
        user = request.user
        if user.role != 'user':
            return Response({"detail": "Only job seekers can initiate payment."}, status=status.HTTP_403_FORBIDDEN)

        plan_id = request.data.get('plan_id')
        if not plan_id:
            return Response({"detail": "plan_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            subscription_data = {
                "plan_id": plan_id,
                "total_count": 12,
                "customer_notify": 1,
                "notes": {"user_id": str(user.id), "user_email": user.email}
            }
            subscription = client.subscription.create(data=subscription_data)

            return Response({
                "subscription_id": subscription["id"],
                "plan_id": subscription["plan_id"],
                "subscription_link": subscription.get("short_url"),  # Razorpay's hosted link
                "customer_id": subscription.get("customer_id"),
                "next_due_on": subscription.get("current_end") or subscription.get("charge_at"),
                "created_at": subscription.get("created_at"),
                "status": subscription.get("status"),
                "razorpay_key": settings.RAZORPAY_KEY_ID,  # 🔑 Include Razorpay public key
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"detail": "Subscription link creation failed.", "error": str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
            
            # 🔝 this working
            

    @action(detail=False, methods=['post'], url_path='confirm-subscription-payment')
    def confirm_subscription_payment(self, request):
        user = request.user
        data = request.data

        razorpay_payment_id = data.get('razorpay_payment_id')
        razorpay_subscription_id = data.get('razorpay_subscription_id')
        razorpay_signature = data.get('razorpay_signature')

        if not all([razorpay_payment_id, razorpay_subscription_id, razorpay_signature]):
            return Response({"detail": "Missing payment information."}, status=status.HTTP_400_BAD_REQUEST)

        # Manually verify signature
        if not verify_signature(
            razorpay_payment_id,
            razorpay_subscription_id,
            razorpay_signature,
            settings.RAZORPAY_KEY_SECRET
        ):
            return Response({"detail": "Invalid payment signature."}, status=status.HTTP_400_BAD_REQUEST)

        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

        try:
            subscription_details = client.subscription.fetch(razorpay_subscription_id)
        except Exception as e:
            return Response({
                "detail": "Failed to fetch subscription details.",
                "error": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

        plan_id = subscription_details.get('plan_id')
        plan_amount = 0
        plan_name = ''

        if plan_id:
            try:
                plan_details = client.plan.fetch(plan_id)
                plan_amount = plan_details.get('amount', 0)  # amount is in paise
                plan_name = plan_details.get('item', {}).get('name', '')
            except Exception:
                plan_amount = 0
                plan_name = ''

        sub_obj, created = UserSubscription.objects.get_or_create(
            user=user,
            razorpay_subscription_id=razorpay_subscription_id,
            defaults={
                'plan_name': plan_name,
                'plan_amount': plan_amount / 100,  # paise to INR
                'subscribe_date': timezone.now(),
                'end_date': timezone.now() + timedelta(days=30 * 12),
                'next_renewal_date': timezone.now() + timedelta(days=30),
            }
        )

        # ✅ Update user model as well
        user.plan = plan_name
        user.subscribe_date = timezone.now()
        user.save()

        return Response({
            "detail": "Subscription verified and saved successfully.",
            "subscription": UserSubscriptionSerializer(sub_obj).data
        }, status=status.HTTP_200_OK)




# Utility function to clean and convert ; to \n
def normalize_multiline_field(value):
    return "\n".join(part.strip() for part in re.split(r"\r?\n|;", value or "") if part.strip())

    
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def apply_to_job(request, job_id):
    try:
        job = Job.objects.get(id=job_id)
    except Job.DoesNotExist:
        return Response({"error": "Job not found"}, status=status.HTTP_404_NOT_FOUND)

    user = request.user

    # Prevent duplicate application
    if JobApplication.objects.filter(job=job, applied_by=user).exists():
        return Response({"error": "You have already applied to this job."}, status=status.HTTP_400_BAD_REQUEST)
    application = JobApplication.objects.create(
        job=job,
        name=user.full_name,
        role=job.job_type,
        applied_by=user,
        resume_url=user.resume_key, 
        applied_on=timezone.now(),
    )

    job.application_count += 1
    job.save()

    return Response({
        "message": "Application submitted successfully.",
        "application_id": application.application_id
    }, status=status.HTTP_201_CREATED)
    
    
# update status of application
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import permissions
from .models import JobApplication




def send_status_update_email(application,old_status, new_status):
    user = application.applied_by
    job = application.job
    status_display = new_status.replace('_', ' ').title()
    if new_status == 'under_review':
        message_body = f"Your application for {job.title} is currently under review."
    elif new_status == 'interview_scheduled':
        message_body = f"Your application for {job.title} is under review. Please wait for the interview call."
    elif new_status == 'rejected':
        message_body = f"We're sorry to inform you that your application for {job.title} has been rejected. Please explore more jobs on our platform."
    elif new_status == 'hired':
        message_body = f"🎉 Congratulations! You have been selected for the role of {job.title} at {job.created_by.company_name}."
    else:
        message_body = f"Your application status has been updated to {status_display}."

    # subject = f"Your Job Application Status Changed to '{new_status.title().replace('_', ' ')}'"
    subject = f"Your Job Application Status `{job.title}` at `{job.created_by.company_name}`" 
    message = f"""
Hi {user.username},

{message_body}

Thank you for choosing incircleJobs.

Best,
Recruitment Team
"""

    send_mail(
        subject,
        message.strip(),
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
        fail_silently=False,
    )


# streaming method

import json
@api_view(['GET'])
@permission_classes([AllowAnyPermission])
def available_jobs_stream_view(request):
    def job_stream():
        for job in Job.objects.filter(status='active').order_by('-created_at'):
            serializer = JobSerializer(job)
            yield json.dumps(serializer.data) + '\n'  # NDJSON format

    return StreamingHttpResponse(job_stream(), content_type='application/x-ndjson')


# direct method

@api_view(['GET'])
@permission_classes([AllowAnyPermission])  # or use IsAuthenticated if you want only logged-in users
def available_jobs_view(request):
    jobs = Job.objects.filter(status='active').order_by('-created_at')
    serializer = JobSerializer(jobs, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


# pagination method
from rest_framework.pagination import PageNumberPagination
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.db.models import Q

class JobPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

@api_view(['GET'])
@permission_classes([AllowAnyPermission])
def available_jobs_pagination_view(request):
    job_id = request.GET.get('id', None)
    
    # If job_id is provided, return that specific job
    if job_id:
        job = get_object_or_404(Job, id=job_id, status='active')
        serializer = JobSerializer(job)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # Continue with the paginated listing
    search = request.GET.get('search', '')
    location = request.GET.get('location', '')
    job_type = request.GET.get('job_type', '')
    department = request.GET.get('department', '')
    experience_level = request.GET.get('experience_level', '')
    education = request.GET.get('education', '')
    min_salary = request.GET.get('min_salary', None)
    max_salary = request.GET.get('max_salary', None)
    company_type = request.GET.get('company_type', '')

    queryset = Job.objects.filter(status='active').order_by('-created_at')

    if search:
        queryset = queryset.filter(
            Q(title__icontains=search) | 
            Q(skills__icontains=search)
        )
    if location:
        queryset = queryset.filter(location__icontains=location)
    if job_type and job_type != 'all':
        queryset = queryset.filter(job_type=job_type)
    if department:
        departments = [d.strip() for d in department.split(',')]
        queryset = queryset.filter(department__in=departments)
    if experience_level:
        levels = [lvl.strip() for lvl in experience_level.split(',')]
        queryset = queryset.filter(experience_level__in=levels)
    if education:
        educations = [ed.strip() for ed in education.split(',')]
        queryset = queryset.filter(education__in=educations)
    if min_salary:
        queryset = queryset.filter(min_salary__gte=min_salary)
    if max_salary:
        queryset = queryset.filter(max_salary__lte=max_salary)
    if company_type:
        company_types = [ct.strip() for ct in company_type.split(',')]
        queryset = queryset.filter(created_by__company_type__in=company_types)

    paginator = JobPagination()
    page = paginator.paginate_queryset(queryset, request)
    serializer = JobSerializer(page, many=True)

    return paginator.get_paginated_response(serializer.data)


@api_view(['GET'])
@permission_classes([AllowAnyPermission])  # Change to IsAuthenticatedOrReadOnly if needed
def available_jobs_pagination_view_by_skills(request):
    job_id = request.GET.get('id', None)

    # If specific job ID is requested
    if job_id:
        job = get_object_or_404(Job, id=job_id, status='active')
        serializer = JobSerializer(job)
        return Response(serializer.data, status=status.HTTP_200_OK)

    queryset = Job.objects.filter(status='active').order_by('-created_at')

    # Optional filters
    search = request.GET.get('search', '')
    location = request.GET.get('location', '')
    job_type = request.GET.get('job_type', '')
    department = request.GET.get('department', '')
    experience_level = request.GET.get('experience_level', '')
    education = request.GET.get('education', '')
    min_salary = request.GET.get('min_salary', None)
    max_salary = request.GET.get('max_salary', None)
    company_type = request.GET.get('company_type', '')

    # Filter based on user's skills
    if request.user.is_authenticated and request.user.skills:
        user_skills = [skill.strip().lower() for skill in request.user.skills.split(',')]
        skill_query = Q()
        for skill in user_skills:
            skill_query |= Q(skills__icontains=skill)
        queryset = queryset.filter(skill_query)

    # Other filters
    if search:
        queryset = queryset.filter(Q(title__icontains=search) | Q(skills__icontains=search))
    if location:
        queryset = queryset.filter(location__icontains=location)
    if job_type and job_type != 'all':
        queryset = queryset.filter(job_type=job_type)
    if department:
        departments = [d.strip() for d in department.split(',')]
        queryset = queryset.filter(department__in=departments)
    if experience_level:
        levels = [lvl.strip() for lvl in experience_level.split(',')]
        queryset = queryset.filter(experience_level__in=levels)
    if education:
        educations = [ed.strip() for ed in education.split(',')]
        queryset = queryset.filter(education__in=educations)
    if min_salary:
        queryset = queryset.filter(min_salary__gte=min_salary)
    if max_salary:
        queryset = queryset.filter(max_salary__lte=max_salary)
    if company_type:
        company_types = [ct.strip() for ct in company_type.split(',')]
        queryset = queryset.filter(created_by__company_type__in=company_types)

    # Paginate and serialize
    paginator = JobPagination()
    page = paginator.paginate_queryset(queryset, request)
    serializer = JobSerializer(page, many=True)

    return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_applications_view(request):
    user = request.user
    applications = JobApplication.objects.filter(applied_by=user).order_by('-applied_on')
    serializer = JobApplicationSerializer(applications, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)







@api_view(['GET'])
@permission_classes([AllowAnyPermission])  # Change to IsAuthenticated if needed
def company_detail_view(request, pk):
    try:
        company = User.objects.get(id=pk, role='hr')
        serializer = CompanySerializer(company)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({"detail": "Company not found."}, status=status.HTTP_404_NOT_FOUND)


# otp 

User = get_user_model()


def generate_otp():
    return str(random.randint(100000, 999999))




from django.core.mail import EmailMessage
from django.conf import settings

class RequestOTP(APIView):
    permission_classes = [AllowAnyPermission]

    def post(self, request):
        serializer = RequestOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({'error': 'Email not registered.'}, status=404)

            otp = generate_otp()
            cache.set(f'otp_{email}', otp, timeout=600)
            otp_formatted = f"{otp[:3]} - {otp[3:]}"

            subject = 'Verify Your Email - OTP Inside'
            from_email = settings.DEFAULT_FROM_EMAIL
            to_email = [email]

            html_content = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 0; margin: 0;">
              <div style="max-width: 600px; background-color: #ffffff; border-radius: 8px; padding: 20px; margin: 30px auto; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);">
                <div style="text-align: center;">
                  

                  <div style="background: #144fa9db; padding: 30px; border-radius: 4px; color: #fff; font-size: 20px; margin: 20px 0px;">
                    <div style="font-size: 30px; font-weight: 800; margin: 7px 0px;">Incirclejobs</div>
                    <div style="margin-top: 25px; font-size: 25px; letter-spacing: 3px;">Reset Your Password</div>

                    
                  </div>
                  <h2>Hello, {user.first_name or user.email}</h2>
                  <p>Your One-Time Password (OTP) for Password Reset is:</p>
                  <div style="font-size: 24px; font-weight: bold; background-color: #f8f9fa; padding: 15px; text-align: center; border-radius: 8px; border: 1px dashed #007bff; color: #007bff;"> {otp_formatted}</div>
                  <p style="margin-top: 20px;">
                Please use this OTP to complete your verification. The OTP is valid for the next 10 minutes.
                </p>

                </div>
                <div style="color: #6c757d; font-size: 14px; text-align: center; margin-top: 20px;">
                  <p>Thank you,<br>The Incirclejobs Team</p>
                </div>
              </div>
            </body>
            </html>
            """

            email_message = EmailMessage(subject, html_content, from_email, to_email)
            email_message.content_subtype = "html"
            email_message.send()

            return Response({'message': 'OTP sent to email.'})

        return Response(serializer.errors, status=400)

class VerifyOTP(APIView):
    permission_classes = [AllowAnyPermission]  # ✅ Allow unauthenticated access
    
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            cached_otp = cache.get(f'otp_{email}')
            if cached_otp == otp:
                cache.set(f'verified_{email}', True, timeout=600)
                return Response({'message': 'OTP verified.'})
            return Response({'error': 'Invalid or expired OTP.'}, status=400)
        return Response(serializer.errors, status=400)


class ResetPassword(APIView):
    permission_classes = [AllowAnyPermission]  # ✅ Allow unauthenticated access
    def patch(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            new_password = serializer.validated_data['new_password']

            if not cache.get(f'verified_{email}'):
                return Response({'error': 'OTP not verified or expired.'}, status=400)

            try:
                user = User.objects.get(email=email)
                user.set_password(new_password)
                user.save()

                cache.delete(f'otp_{email}')
                cache.delete(f'verified_{email}')

                return Response({'message': 'Password reset successfully.'})
            except User.DoesNotExist:
                return Response({'error': 'User not found.'}, status=404)
        return Response(serializer.errors, status=400)
    
    
   



from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404, render
from .models import Resume 
from .serializers import ResumeSerializer 
from .utils.s3_signed import build_presigned_get_url

class IsOwnerOrStaff(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return request.user.is_staff or obj.user_id == request.user.id
    

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.conf import settings
import requests
import uuid
from datetime import datetime

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_subscription(request):
    user = request.user
    plan_id = request.data.get("plan_id")

    if not plan_id:
        return Response({"error": "Plan ID is required"}, status=400)

    # Fallbacks for customer info
    customer_name = str(user.full_name).strip() if getattr(user, "full_name", None) else "chaitanya"
    customer_email = str(user.email).strip() if getattr(user, "email", None) else "chaitanyakreddysomu@gmail.com"
    customer_phone = str(user.phone).strip() if getattr(user, "phone", None) else "9876543210"

    # Optional: Get these from frontend or settings
    customer_bank_account_number = request.data.get("customer_bank_account_number", "59108290701802")
    customer_bank_ifsc = request.data.get("customer_bank_ifsc", "HDFC0002614")

    subscription_id = f"sub_{uuid.uuid4().hex[:8]}"

    payload = {
        "subscription_id": subscription_id,
        "customer_details": {
            "customer_name": customer_name,
            "customer_email": customer_email,
            "customer_phone": customer_phone,
        },
        "plan_details": {
            "plan_id": plan_id,
        },
        "authorization_details": {
            "authorization_amount": 100,
            "authorization_amount_refund": True,
            "payment_methods": ["enach", "pnach", "upi", "card"]
        },
        "subscription_meta": {
            "return_url": "https://wa.me/9512440440?text=Payment%20Successfull",
            "notification_channel": ["EMAIL", "SMS"]
        },
        "subscription_expiry_time": "2100-01-01T23:00:08+05:30",
        "subscription_first_charge_time": "2025-09-04T23:00:08+05:30",
        "subscription_note": "testSUB",
        "subscription_tags": {
            "psp_note": "Monthly subscription payment",
            "key2": "value2"
        },
    }

    headers = {
        "x-client-id": settings.CASHFREE_APP_ID,
        "x-client-secret": settings.CASHFREE_SECRET_KEY,
        "x-api-version": "2025-01-01",
        "Content-Type": "application/json"
    }

    response = requests.post(
        "https://sandbox.cashfree.com/pg/subscriptions",
        json=payload,
        headers=headers
    )

    data = response.json()

    if response.status_code not in [200, 201]:
        return Response({
            "error": "Failed to create subscription",
            "details": data
        }, status=response.status_code)

    # Extract subscription_session_id for frontend use
    subscription_session_id = data.get("subscription_session_id")
    
    return Response({
        "message": "Subscription created successfully",
        "subscription_id": data.get("subscription_id"),
        "subscription_status": data.get("subscription_status"),
        "subscription_session_id": subscription_session_id,  # Use this with Cashfree JS SDK
        "cf_subscription_id": data.get("cf_subscription_id"),
        "raw": data
    })

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
import uuid
import requests
from django.conf import settings

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def raise_subscription_charge(request):
    user = request.user
    subscription_id = request.data.get("subscription_id")
    amount = request.data.get("amount")
    upi_id = request.data.get("upi_id")  # e.g., "john@upi"

    if not subscription_id:
        return Response({"error": "subscription_id is required"}, status=400)
    if not amount:
        return Response({"error": "amount is required"}, status=400)
    if not upi_id:
        return Response({"error": "upi_id is required"}, status=400)

    # Generate unique payment_id
    payment_id = f"pay_{uuid.uuid4().hex[:10]}"
    
    # Optional: Schedule for current time or a future time
    from datetime import datetime, timedelta
    # schedule_date = (datetime.now() + timedelta(minutes=2)).isoformat()

    payload = {
        "subscription_id": subscription_id,
        "payment_id": payment_id,
        "payment_amount": amount,
        "payment_schedule_date": payment_schedule_date,
        "payment_remarks": "Charge raised via API",
        "payment_type": "CHARGE",
        "payment_method": {
            "upi": {
                "upi_id": upi_id,
                "channel": "collect"
            }
        }
    }

    headers = {
        "x-client-id": settings.CASHFREE_APP_ID,
        "x-client-secret": settings.CASHFREE_SECRET_KEY,
        "x-api-version": "2025-01-01",
        "Content-Type": "application/json"
    }

    response = requests.post(
        "https://sandbox.cashfree.com/pg/subscriptions/pay",
        json=payload,
        headers=headers
    )
    
    data = response.json()

    if response.status_code not in [200, 201] or "cf_payment_id" not in data:
        return Response({
            "error": "Failed to raise subscription charge",
            "details": data
        }, status=response.status_code)

    # Optional: Store charge info in DB if needed

    return Response({
        "message": "Charge raised successfully",
        "cashfree_payment_id": data.get("cf_payment_id"),
        "charge_status": data.get("payment_status"),
        "next_action": data.get("data", {}),
        "raw": data
    })
  

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def cashfree_webhook(request):
    data = request.data
    event_type = data.get("event")
    payload = data.get("data", {})

    subscription_id = payload.get("subscription_id")
    if not subscription_id:
        return Response({"error": "Missing subscription_id"}, status=400)

    # Try to fetch subscription from DB
    try:
        subscription = Subscription.objects.get(subscription_id=subscription_id)
    except Subscription.DoesNotExist:
        subscription = None  # Will be created if needed

    # Try fetching user by email in payload
    user_email = payload.get("customer_details", {}).get("customer_email")
    user = None
    if user_email:
        try:
            user = User.objects.get(email=user_email)
        except User.DoesNotExist:
            pass

    # Event-specific handling
    if event_type == "subscription_status_changed":
        new_status = payload.get("subscription_status")

        if subscription:
            subscription.status = new_status
            subscription.raw_response = data
            subscription.save()
        else:
            if not user:
                return Response({"error": "User not found"}, status=404)

            subscription = Subscription.objects.create(
                user=user,
                subscription_id=subscription_id,
                plan_id=payload.get("plan_details", {}).get("plan_id"),
                plan_name=payload.get("plan_details", {}).get("plan_name"),
                status=new_status,
                raw_response=data
            )

        # Update user's plan and subscribe_date if subscription activated
        if user and new_status == "ACTIVE":
            user.plan = payload.get("plan_details", {}).get("plan_id") or user.plan
            user.subscribe_date = now()
            user.save()

    elif event_type == "subscription_payment_success":
        # Optionally update subscribe_date on payment success
        if user:
            user.subscribe_date = now()
            user.save()

    elif event_type == "subscription_payment_failed":
        if subscription:
            subscription.status = "PAYMENT_FAILED"
            subscription.save()

    elif event_type == "subscription_payment_cancelled":
        if user:
            user.plan = "free"
            user.subscribe_date = None
            user.save()

    elif event_type == "subscription_refund_status":
        print(f"Refund processed or updated for subscription {subscription_id}")

    elif event_type == "subscription_auth_status":
        print(f"Authorization status update for {subscription_id}")
        # You can store mandate info, if needed

    return Response({"message": "Webhook processed"}, status=200)