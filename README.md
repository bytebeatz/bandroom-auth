## COMMANDS

# Start the authentication service

go run cmd/main.go

# Register a New User

curl -X POST http://localhost:8081/auth/register \
 -H "Content-Type: application/json" \
 -d '{
"email": "user1@bandroom.xyz",
"username": "user1",
"password": "P4ssword!"
}' | jq

### Expected Response

{
"message": "User registered successfully",
"user_id": "generated-uuid-here"
}

# Login & Get Tokens (Access + Refresh)

curl -X POST http://localhost:8081/auth/login \
 -H "Content-Type: application/json" \
 -c cookies.txt \
 -d '{
"email": "user1@bandroom.xyz",
"password": "P4ssword!"
}' | jq

### Expected Response

{
"message": "Login successful",
"access_token": "your-jwt-access-token",
"refresh_token": "your-jwt-refresh-token"
}

# Validate an Access Token

curl -X GET http://localhost:8081/auth/validate \
 -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" | jq

### Expected Response

{
"message": "Token is valid",
"user_id": "your-user-id"
}

# Refresh Access Token

curl -X POST http://localhost:8081/auth/refresh \
 -b cookies.txt | jq

### Expected Response

{
"access_token": "new_access_token_here"
}

# Logout (Invalidate Refresh Token)

curl -X POST http://localhost:8081/auth/logout \
 -b cookies.txt | jq

### Expected Response

{
"message": "Logout successful"
}

# Resend verification code

curl -X POST http://localhost:8081/auth/resend-verification \
 -H "Content-Type: application/json" \
 -d '{ "email": "user2@bandroom.xyz" }' | jq

# Verify token

curl "http://localhost:8081/auth/verify?token=PASTE_TOKEN_HERE" | jq

# Soft delete a user

curl -X DELETE http://localhost:8081/auth/delete \
 -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" | jq

# Promote a user to admin role

go run cmd/cli/promote.go email --confirm

# Demote an admin to a user role

go run cmd/cli/demote/main.go email --confirm

# Reset password

curl -X POST http://localhost:8081/auth/reset-password \
 -H "Content-Type: application/json" \
 -d '{
"token": "<TOKEN>",
"new_password": "NewStr0ngP@ss!"
}' | jq

# Create table for users

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
email TEXT UNIQUE NOT NULL,
username TEXT UNIQUE NOT NULL,
password_hash TEXT NOT NULL,
role TEXT NOT NULL DEFAULT 'user',
refresh_token TEXT,
is_verified BOOLEAN DEFAULT FALSE,
verification_token TEXT,
verification_sent_at TIMESTAMPTZ,
is_active BOOLEAN DEFAULT TRUE,
last_login TIMESTAMPTZ,
last_password_change TIMESTAMPTZ NOT NULL DEFAULT NOW(),
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
deleted_at TIMESTAMPTZ
);

# for frontend dev

"Thanks for signing up! A verification link has been sent to your email. Didn’t get it?"
