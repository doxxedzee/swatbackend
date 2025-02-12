import fastapi
from fastapi import FastAPI, Request, Response, Depends, HTTPException, File, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import jinja2
import pymongo
import os
import json
import uvicorn
from fastapi.templating import Jinja2Templates
import uuid
import bcrypt
from datetime import datetime, timedelta
import aiohttp
import boto3
from botocore.exceptions import NoCredentialsError
from tempfile import NamedTemporaryFile
import urllib.parse  # Add this import

app = FastAPI()

# MongoDB setup for session management, user data, and invite codes
mongo = pymongo.MongoClient("mongodb://localhost:27017/")
db = mongo.discord_bot
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Helper function to check session expiration (30 minutes)
def is_session_expired(session_time: datetime):
    return datetime.utcnow() - session_time > timedelta(minutes=30)

# Cloudflare R2 setup
r2_client = boto3.client('s3',
    endpoint_url='https://b5e7eb471f3b92e466bd5867e7542dc7.r2.cloudflarestorage.com',
    aws_access_key_id='962388237a03c11fbaad1a2bb61cd6ca',
    aws_secret_access_key='4f2b63b55d7b66c788877fbfe1a1986477f6bb0d4ece1e76aaab74aa5eac81fe',
    region_name='auto'
)

R2_BUCKET_NAME = 'swats'

# Function to check if a user is logged in based on the session cookie
def session_check(request: Request):
    session = request.cookies.get('session')
    if session:
        user_session = db.sessions.find_one({"session": session})
        if user_session:
            # Check session expiration
            if is_session_expired(user_session['last_active']):
                db.sessions.delete_one({"session": session})  # Clean up expired session
                return False
            return user_session['username']  # Return username if logged in
    return False  # Return False if no session or expired session

# Function to get the current user from the session
def get_current_user(request: Request):
    username = session_check(request)
    if not username:
        raise HTTPException(status_code=401, detail="You are not logged in, click here to login.")
    user = db.users.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")
    return user

# Register route
@app.get('/register')
def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post('/api/register')
async def register_user(request: Request):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')
    invite_code = data.get('invitecode')

    # Check if username exists
    existing_user = db.users.find_one({"username": username})
    if (existing_user):
        return JSONResponse(content={'success': False, 'message': 'Username already exists.'})

    # Check if invite code exists and is unused
    invite = db.invite_codes.find_one({"code": invite_code, "used": False})
    if not invite:
        return JSONResponse(content={'success': False, 'message': 'Invalid or already used invite code.'})

    # Generate next UID
    latest_user = db.users.find_one(sort=[("uid", -1)])
    next_uid = 1 if not latest_user else (latest_user.get('uid', 0) + 1)

    # Hash password before storing
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Store user data with UID
    new_user = {
        "username": username, 
        "password": hashed_password,
        "uid": next_uid  # Add UID to user document
    }
    db.users.insert_one(new_user)

    # Mark the invite code as used
    db.invite_codes.update_one({"code": invite_code}, {"$set": {"used": True}})

    # Create session
    user_session = uuid.uuid4().hex
    session_data = {
        "username": username,
        "session": user_session,
        "last_active": datetime.utcnow()
    }
    db.sessions.insert_one(session_data)
    
    # Set session cookie
    response = JSONResponse(content={'success': True, 'message': 'User registered successfully.', 'session': user_session})
    response.set_cookie(key='session', value=user_session, max_age=3600)  # Set cookie expiration (30 minutes)
    return response

@app.get("/api/register", response_model=dict)
async def get_stats():
    try:
        user_count = db.users.count_documents({})
        total_views = db.views.count_documents({})
        return {
            "success": True,
            "users": str(user_count),  # Convert to string to ensure proper JSON serialization
            "views": str(total_views)
        }
    except Exception as e:
        print(f"Error getting stats: {str(e)}")
        return {
            "success": False,
            "users": "0",
            "views": "0"
        }

# Login route
@app.get('/login')
def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post('/api/login')
async def login_user(request: Request):
    data = await request.json()
    username = data.get('username')
    password = data.get('password')

    # Retrieve user and compare hashed passwords
    user = db.users.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        session = uuid.uuid4().hex
        session_data = {
            "username": username,
            "session": session,
            "last_active": datetime.utcnow()
        }
        db.sessions.insert_one(session_data)
        response = JSONResponse(content={'success': True, 'message': 'Login successful.', 'session': session})
        response.set_cookie(key='session', value=session, max_age=3600)  # Set cookie expiration (30 minutes)
        return response
    else:
        return JSONResponse(content={'success': False, 'message': 'Invalid username or password.'})

# Add this new function to handle protected routes
def require_auth(request: Request):
    username = session_check(request)
    if not username:
        raise HTTPException(
            status_code=307,  # Temporary redirect
            detail="Authentication required",
            headers={"Location": "/login"}
        )
    return username

# Update protected routes to use require_auth
@app.get('/dashboard')
def dashboard(request: Request):
    try:
        username = require_auth(request)
        user = db.users.find_one({"username": username})
        return templates.TemplateResponse("dashboard.html", {
            "request": request, 
            "username": username,
            "profile_picture": user.get('avatar_url') if user else None
        })
    except HTTPException as e:
        return RedirectResponse(url='/login')

@app.get('/customize')
def customize(request: Request):
    try:
        username = require_auth(request)
        return templates.TemplateResponse("customize.html", {"request": request, "username": username})
    except HTTPException as e:
        return RedirectResponse(url='/login')

@app.get('/premium')
def premium(request: Request):
    try:
        username = require_auth(request)
        return templates.TemplateResponse("premium.html", {"request": request, "username": username})
    except HTTPException as e:
        return RedirectResponse(url='/login')

@app.get('/badges')
def badges(request: Request):
    try:
        username = require_auth(request)
        return templates.TemplateResponse("badges.html", {"request": request, "username": username})
    except HTTPException as e:
        return RedirectResponse(url='/login')

@app.get('/links')
def links(request: Request):
    try:
        username = require_auth(request)
        return templates.TemplateResponse("links.html", {"request": request, "username": username})
    except HTTPException as e:
        return RedirectResponse(url='/login')

# Home route
@app.get("/")
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# API endpoint to upload background image to Cloudflare R2
@app.post("/api/upload-background")
async def upload_background(request: Request):
    user = get_current_user(request)

    form_data = await request.form()
    file = form_data.get('background')

    # If no file is uploaded, return error
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded.")

    # Upload the file to Cloudflare R2
    try:
        upload_response = r2_client.upload_fileobj(
            file.file,
            R2_BUCKET_NAME,
            file.filename,
            ExtraArgs={'ContentType': file.content_type, 'ACL': 'public-read'}
        )
        file_url = f"https://pub-ed272d53e98b4a0cb690106931d3da78.r2.dev/{file.filename}"

        # Save the file URL to the user profile
        db.users.update_one({"username": user['username']}, {"$set": {"background_url": file_url}})

        # Return the uploaded file URL
        return JSONResponse(content={'success': True, 'background_url': file_url})

    except NoCredentialsError:
        raise HTTPException(status_code=403, detail="Cloudflare R2 credentials are missing or incorrect.")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload background: {str(e)}")

# Add this new endpoint for avatar uploads
@app.post("/api/upload-avatar")
async def upload_avatar(request: Request):
    try:
        user = get_current_user(request)
        form_data = await request.form()
        file = form_data.get('avatar')  # Changed from 'pfp' to 'avatar' to match frontend

        if not file:
            raise HTTPException(status_code=400, detail="No file provided")

        # Upload the file to Cloudflare R2
        try:
            upload_response = r2_client.upload_fileobj(
                file.file,
                R2_BUCKET_NAME,
                file.filename,
                ExtraArgs={'ContentType': file.content_type, 'ACL': 'public-read'}
            )
            file_url = f"https://pub-ed272d53e98b4a0cb690106931d3da78.r2.dev/{file.filename}"

            # Save the avatar URL to the user profile
            db.users.update_one(
                {"username": user['username']},
                {"$set": {"avatar_url": file_url}}
            )

            return JSONResponse(content={
                "success": True,
                "avatar_url": file_url,
                "message": "Upload successful"
            })

        except Exception as e:
            print(f"R2 upload error details: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))

    except Exception as e:
        print(f"Error in upload handler: {str(e)}")
        return JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )

# Add this new endpoint for audio uploads
@app.post("/api/upload-audio")
async def upload_audio(request: Request):
    try:
        user = get_current_user(request)
        form_data = await request.form()
        file = form_data.get('audio')

        if not file:
            raise HTTPException(status_code=400, detail="No file provided")

        # Check if file is an audio or video file
        if not (file.content_type.startswith('audio/') or file.content_type.startswith('video/')):
            raise HTTPException(status_code=400, detail="File must be an audio or video file")

        try:
            # Upload file directly to R2
            upload_response = r2_client.upload_fileobj(
                file.file,
                R2_BUCKET_NAME,
                file.filename,
                ExtraArgs={'ContentType': 'audio/mpeg', 'ACL': 'public-read'}
            )
            file_url = f"https://pub-ed272d53e98b4a0cb690106931d3da78.r2.dev/{file.filename}"

            # Save the audio URL to the user profile
            db.users.update_one(
                {"username": user['username']},
                {"$set": {"audio_url": file_url}}
            )

            return JSONResponse(content={
                "success": True,
                "audio_url": file_url,
                "message": "Upload successful"
            })

        except Exception as e:
            print(f"R2 upload error details: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))

    except Exception as e:
        print(f"Error in audio upload handler: {str(e)}")
        return JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )

# Add new endpoint to handle badge updates
@app.post("/api/update-badges")
async def update_badges(request: Request):
    try:
        data = await request.json()
        username = data.get('username')
        badge = data.get('badge')
        
        if not username or not badge:
            raise HTTPException(status_code=400, detail="Missing username or badge")
        
        # Update user's badges in database
        user = db.users.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        badges = user.get('badges', [])
        if badge not in badges:
            badges.append(badge)
            
        db.users.update_one(
            {"username": username},
            {"$set": {"badges": badges}}
        )
        
        return JSONResponse(content={"success": True, "message": "Badge added successfully"})
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )

# Logout route
@app.get('/logout')
def logout(request: Request):
    session = request.cookies.get('session')
    if session:
        db.sessions.delete_one({"session": session})  # Remove session from DB
    response = RedirectResponse(url='/')  # Redirect to home page
    response.delete_cookie('session')  # Delete the session cookie
    return response

# Function to generate a unique invite code
def generate_invite_code():
    return str(uuid.uuid4().hex[:8])  # A unique 8-character invite code

# API to generate invite codes (only for admin or bot use)
@app.post("/api/generate-invite-code")
async def generate_invite_code_api(request: Request):
    code = generate_invite_code()
    db.invite_codes.insert_one({"code": code, "used": False})
    return JSONResponse(content={'success': True, 'message': 'Invite code generated successfully.', 'code': code})

@app.post("/api/update-description")
async def update_description(request: Request):
    try:
        user = get_current_user(request)
        data = await request.json()
        description = data.get('description', '')

        # Always update the description, even if it's the same
        db.users.update_one(
            {"username": user['username']},
            {"$set": {"description": description}}
        )

        return JSONResponse(content={
            "success": True,
            "message": "Description updated successfully"
        })

    except Exception as e:
        print(f"Error updating description: {str(e)}")
        return JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )

# Update the update_discord_presence endpoint:
@app.post("/api/update-discord-presence")
async def update_discord_presence(request: Request):
    try:
        user = get_current_user(request)
        data = await request.json()
        discord_presence = data.get('discord_presence', True)

        # First check if the user exists
        if not user:
            return JSONResponse(
                content={
                    "success": False,
                    "message": "User not found"
                },
                status_code=404
            )

        # Update the setting
        db.users.update_one(
            {"username": user['username']},
            {"$set": {"discord_presence": discord_presence}},
            upsert=True  # Create the field if it doesn't exist
        )

        # Return success response
        return JSONResponse(
            content={
                "success": True,
                "message": "Discord presence setting updated successfully"
            }
        )

    except Exception as e:
        print(f"Error updating discord presence: {str(e)}")
        return JSONResponse(
            content={
                "success": False,
                "message": str(e)
            },
            status_code=500
        )

# Update the get_userbio endpoint:
@app.get("/api/userbio")
async def get_userbio(request: Request):
    try:
        username = require_auth(request)
        user = db.users.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return JSONResponse(content={
            "success": True,
            "user_data": {
                "discord_presence": user.get('discord_presence', True),
                "description": user.get('description', ''),
                "hide_badges": user.get('hide_badges', False),
                "background_url": user.get('background_url', ''),
                "avatar_url": user.get('avatar_url', ''),
                "audio_url": user.get('audio_url', '')
            }
        })
    except HTTPException as e:
        return JSONResponse(
            content={
                "success": False,
                "message": "Authentication required"
            },
            status_code=401
        )

@app.post("/api/update-settings")
async def update_settings(request: Request):
    try:
        user = get_current_user(request)
        data = await request.json()
        hide_badges = data.get('hide_badges', False)

        # Update user settings in database
        db.users.update_one(
            {"username": user['username']},
            {"$set": {"hide_badges": hide_badges}},
            upsert=True
        )

        return JSONResponse(content={
            "success": True,
            "message": "Settings updated successfully"
        })
    except Exception as e:
        print(f"Error updating settings: {str(e)}")
        return JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )

@app.post("/api/add-social")
async def add_social(request: Request):
    try:
        user = get_current_user(request)
        data = await request.json()
        platform = data.get('platform')
        url = data.get('url')

        if not platform or not url:
            raise HTTPException(status_code=400, detail="Missing platform or URL")

        user_socials = user.get('socials', {})
        user_socials[platform] = url

        db.users.update_one(
            {"username": user['username']},
            {"$set": {"socials": user_socials}}
        )

        return JSONResponse(content={
            "success": True,
            "message": "Social link added successfully"
        })
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )

@app.post("/api/remove-social")
async def remove_social(request: Request):
    try:
        user = get_current_user(request)
        data = await request.json()
        platform = data.get('platform')

        if not platform:
            return JSONResponse(
                content={"success": False, "message": "Platform is required"},
                status_code=400
            )

        # Get current socials and clean the platform name
        current_socials = user.get('socials', {})
        platform = platform.strip()  # Remove whitespace

        print(f"Looking for platform: '{platform}' in socials:", current_socials)

        if platform in current_socials:
            # Create new dict without the platform
            new_socials = {k: v for k, v in current_socials.items() if k != platform}
            result = db.users.update_one(
                {"username": user['username']},
                {"$set": {"socials": new_socials}}
            )

            print(f"Update result: {result.modified_count}")

            return JSONResponse(content={
                "success": True,
                "message": "Social link removed successfully"
            })
        else:
            print(f"Platform '{platform}' not found in user's socials")
            return JSONResponse(
                content={"success": False, "message": f"Social link '{platform}' not found"},
                status_code=404
            )
    except Exception as e:
        print(f"Error removing social: {str(e)}")
        return JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )

@app.get("/api/get-socials")
async def get_socials(request: Request):
    try:
        user = get_current_user(request)
        socials = user.get('socials', {})

        return JSONResponse(content={
            "success": True,
            "socials": socials
        })
    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )

@app.post("/api/delete-media")
async def delete_media(request: Request):
    try:
        user = get_current_user(request)
        data = await request.json()
        media_type = data.get('type')

        if media_type not in ['background', 'avatar', 'audio']:
            raise HTTPException(status_code=400, detail="Invalid media type")

        # Create the field name for the media type
        field_name = f"{media_type}_url"

        # Update user document to remove the media URL
        db.users.update_one(
            {"username": user['username']},
            {"$unset": {field_name: ""}}
        )

        return JSONResponse(content={
            "success": True,
            "message": f"{media_type} removed successfully"
        })

    except Exception as e:
        return JSONResponse(
            content={"success": False, "message": str(e)},
            status_code=500
        )

# This will track views with cooldown
def track_view(username, visitor_ip):
    try:
        now = datetime.utcnow()
        cooldown = now - timedelta(hours=12)
        
        # Check if this IP has viewed THIS specific username within cooldown period
        existing_view = db.views.find_one({
            "username": username,
            "visitor_ip": visitor_ip,
            "timestamp": {"$gt": cooldown}
        })
        
        if not existing_view:
            # Add new view since cooldown has expired or first view
            db.views.insert_one({
                "username": username,
                "visitor_ip": visitor_ip,
                "timestamp": now
            })
            
            # Update the view count atomically
            result = db.users.update_one(
                {"username": username},
                {"$inc": {"view_count": 1}},
                upsert=True
            )
            
            print(f"View tracked for {username} from {visitor_ip}")
            print(f"Update result: {result.modified_count}")
            return True
            
        print(f"View skipped - cooldown active for {username} from {visitor_ip}")
        return False
    except Exception as e:
        print(f"Error tracking view: {str(e)}")
        return False

@app.get("/{username}")
def profile(request: Request, username: str):
    try:
        user = db.users.find_one({"username": username})
        if user:
            # Get client IP and track view
            client_ip = request.client.host
            view_tracked = track_view(username, client_ip)
            print(f"View {'tracked' if view_tracked else 'skipped'} for {username}")
            
            # Get current view count directly from database to ensure accuracy
            current_user = db.users.find_one({"username": username})
            view_count = current_user.get('view_count', 0)
            
            # Rest of the code...
            return templates.TemplateResponse("userbio.html", {
                "request": request,
                "username": username,
                "view_count": int(view_count),  # Use the freshly retrieved view count
                "background_url": str(user.get('background_url', '')),
                "profile_picture": str(user.get('avatar_url', '')),
                "audio_url": str(user.get('audio_url', '')),
                "description": str(user.get('description', '')),
                "uid": int(user.get('uid', 1)),
                "hide_badges": bool(user.get('hide_badges', False)),
                "user_badges": list(user.get('badges', [])),
                "discord": {
                    "username": user.get('discord_username', username),
                    "avatar": user.get('discord_avatar', user.get('avatar_url', '')),
                    "connected": bool(user.get('discord_connected', False)),
                    "presence": bool(user.get('discord_presence', True))
                },
                "user_data": {
                    "discord_presence": bool(user.get('discord_presence', True)),
                    "socials": dict(user.get('socials', {}))
                }
            })
        else:
            return templates.TemplateResponse("404.html", {"request": request})
            
    except Exception as e:
        print(f"Profile error: {str(e)}")
        return templates.TemplateResponse("404.html", {
            "request": request,
            "error": str(e)
        })

# Discord OAuth2 Settings
DISCORD_CLIENT_ID = "1329113560474845287"
DISCORD_CLIENT_SECRET = "TMU5IhiMwLJbWyfY5pNTnns7kd0GGLnR"
DISCORD_REDIRECT_URI = "https://swats.lol/discord/callback"  # Make sure this exactly matches what's in Discord Developer Portal
DISCORD_API_ENDPOINT = "https://discord.com/api/v10"

@app.get("/connect/discord")
async def connect_discord(request: Request):
    """Redirect to Discord OAuth2 authorization page"""
    oauth2_url = (
        "https://discord.com/oauth2/authorize"
        "?client_id=1329113560474845287"
        "&response_type=code"
        "&redirect_uri=https%3A%2F%2Fswats.lol%2Fdiscord%2Fcallback"
        "&scope=identify+rpc"
    )
    return RedirectResponse(oauth2_url)

@app.get("/discord/callback")
async def discord_callback(code: str, request: Request):
    """Handle Discord OAuth2 callback"""
    try:
        # Exchange code for access token
        async with aiohttp.ClientSession() as session:
            token_response = await session.post(
                f"{DISCORD_API_ENDPOINT}/oauth2/token",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": DISCORD_REDIRECT_URI
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            token_data = await token_response.json()
            access_token = token_data["access_token"]

            # Get user info from Discord
            user_response = await session.get(
                f"{DISCORD_API_ENDPOINT}/users/@me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            discord_user = await user_response.json()

            # Get current user from session
            username = session_check(request)
            if not username:
                return RedirectResponse(url="/login")

            # Update user's Discord info in database
            db.users.update_one(
                {"username": username},
                {
                    "$set": {
                        "discord_id": discord_user["id"],
                        "discord_username": discord_user["username"],
                        "discord_avatar": f"https://cdn.discordapp.com/avatars/{discord_user['id']}/{discord_user['avatar']}.png",
                        "discord_connected": True
                    }
                }
            )

            return RedirectResponse(url="/dashboard?discord_connected=true")

    except Exception as e:
        print(f"Discord connection error: {str(e)}")
        return RedirectResponse(url="/dashboard?error=discord_connection_failed")

@app.get('/reset-password')
def reset_password(request: Request):
    return templates.TemplateResponse("reset-password.html", {"request": request})

@app.post('/api/reset-password')
async def reset_password_request(request: Request):
    data = await request.json()
    username = data.get('username')
    
    user = db.users.find_one({"username": username})
    if not user:
        return JSONResponse(content={'success': False, 'message': 'User not found'})
    
    # Generate reset token
    reset_token = str(uuid.uuid4())
    expiry = datetime.utcnow() + timedelta(hours=1)
    
    # Store reset token in database
    db.password_resets.insert_one({
        "username": username,
        "token": reset_token,
        "expires": expiry
    })
    
    # The reset URL would be: https://swats.lol/reset-password?token={reset_token}
    return JSONResponse(content={
        'success': True,
        'message': 'Password reset link generated',
        'reset_url': f'https://swats.lol/reset-password?token={reset_token}'
    })

if __name__ == '__main__':
    uvicorn.run(app, host='localhost', port=8000)