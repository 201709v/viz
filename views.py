# Create your views here.
import pandas as pd
from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .forms import UserRegistrationForm
from .models import UserRegistrationModel, TokenCountModel
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from datetime import datetime, timedelta
from jose import JWTError, jwt
import os
import json
import random
import hashlib
import socket
import sqlite3

SECRET_KEY = "ce9941882f6e044f9809bcee90a2992b4d9d9c21235ab7c537ad56517050f26b"
ALGORITHM = "HS256"

def compute_hash(data):
    """Compute a SHA-256 hash of the given SCADA data."""
    data_copy = data.copy()
    data_copy.pop("hash", None)  # Remove existing hash before recalculating
    data_str = json.dumps(data_copy, sort_keys=True)
    return hashlib.sha256(data_str.encode()).hexdigest()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=15)  # Token expires in 15 mins
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return HttpResponse(status=204, content="Could not validate credentials")

def UserRegisterActions(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            TokenCountModel.objects.create(loginid=user.loginid, count=0)
            messages.success(request, f'You have been successfully registered. Your key is: {user.key}')
            return render(request, 'UserRegistrations.html', {'form': UserRegistrationForm(), 'key': user.key})
        else:
            messages.error(request, 'Email or Mobile Already Exists')
    return render(request, 'UserRegistrations.html', {'form': UserRegistrationForm()})

def UserLoginCheck(request):
    if request.method == "POST":
        loginid = request.POST.get('loginid')
        pswd = request.POST.get('pswd')
        try:
            check = UserRegistrationModel.objects.get(loginid=loginid, password=pswd)
            if check.status == "activated":
                request.session.update({
                    'id': check.id,
                    'loggeduser': check.name,
                    'loginid': loginid,
                    'email': check.email,
                    'token': create_access_token({'loginid': loginid})
                })
                return redirect('user_key')
            else:
                messages.success(request, 'Your Account is not activated')
        except UserRegistrationModel.DoesNotExist:
            messages.success(request, 'Invalid Login ID or Password')
    return render(request, 'UserLogin.html')

def key_login(request):
    if request.method == 'POST':
        try:
            check = UserRegistrationModel.objects.get(key=request.POST.get('key'))
            messages.success(request, f"Login successful for {check.loginid}")
            return render(request, 'users/UserHomePage.html')
        except UserRegistrationModel.DoesNotExist:
            messages.error(request, "Invalid Key! Please try again.")
    return render(request, 'key_login.html')

def UserHome(request):
    return render(request, 'users/UserHomePage.html')

def sendScadaMessage(request):
    if request.method == "POST":
        msg = {
            "HostName": request.POST.get('hostName'),
            "IP": request.POST.get('ip'),
            "PressureValue": request.POST.get('pressureValue'),
            "Temperature": request.POST.get('temperature'),
            "FlowRate": request.POST.get('flowRate'),
            "SwitchRate": request.POST.get('switchRate'),
            "ValveStatus": request.POST.get('valveStatus'),
            "PumpStatus": request.POST.get('pumpStatus'),
            "FlowIndicator": request.POST.get('flowIndicator'),
            "status": random.choice(['Normal', "Idle"])
        }
        
        # Compute and attach hash before sending
        msg["hash"] = compute_hash(msg)
        
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('localhost', 54321))  # Connect to attacker
            client_socket.sendall(json.dumps(msg).encode())
            client_socket.close()
        except Exception as e:
            print(f"Error sending SCADA message: {e}")
        
        return render(request, 'users/ScadaRes.html', {"data": msg})
    else:
        hostname = socket.gethostname()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        IPAddr = s.getsockname()[0]
        s.close()
        return render(request, "users/sendScadaForm.html", {'hostName': hostname, 'ip': IPAddr})

def cursor_to_dict(cursor):
    """Convert cursor results to a list of dictionaries."""
    return [dict(zip([description[0] for description in cursor.description], row)) for row in cursor.fetchall()]

def MachinesLogs(request):
    conn = sqlite3.connect('attacker.db')
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM ScadaNetwork''')
    result = cursor_to_dict(cursor)
    conn.close()
    return render(request, "users/scadalogs.html", {'data': pd.DataFrame(result).to_html(index=False)})
