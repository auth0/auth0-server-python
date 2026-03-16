# Multi-Factor Authentication (MFA)

The Auth0 MFA API allows you to manage multi-factor authentication for users in server-side applications. This guide covers how to handle MFA requirements, enroll authenticators, and verify MFA challenges.

> [!NOTE]
> Multi-Factor Authentication support for server SDKs is in Early Access. For detailed information, refer to the [Auth0 MFA documentation](https://auth0.com/docs/secure/multi-factor-authentication).

## Table of Contents

- [Multi-Factor Authentication (MFA)](#multi-factor-authentication-mfa)
  - [Table of Contents](#table-of-contents)
  - [Setup](#setup)
  - [Understanding MFA Responses](#understanding-mfa-responses)
    - [Challenge Flow Response](#challenge-flow-response)
    - [Enroll Flow Response](#enroll-flow-response)
  - [Handling MFA Required Errors](#handling-mfa-required-errors)
  - [Getting Authenticators](#getting-authenticators)
    - [Response Structure](#response-structure)
  - [Getting Enrollment Factors](#getting-enrollment-factors)
  - [Enrollment](#enrollment)
    - [Enrolling OTP (Authenticator App)](#enrolling-otp-authenticator-app)
    - [Enrolling SMS](#enrolling-sms)
    - [Enrolling Voice](#enrolling-voice)
    - [Enrolling Email](#enrolling-email)
    - [Enrolling Push Notification (Auth0 Guardian)](#enrolling-push-notification-auth0-guardian)
  - [Challenge](#challenge)
    - [Challenge with SMS](#challenge-with-sms)
    - [Challenge with Email](#challenge-with-email)
    - [Challenge with OTP](#challenge-with-otp)
    - [Challenge with Push Notification](#challenge-with-push-notification)
  - [Verify](#verify)
    - [Verify with OOB (SMS or Email)](#verify-with-oob-sms-or-email)
    - [Verify with OTP](#verify-with-otp)
    - [Verify with Recovery Code](#verify-with-recovery-code)
    - [Verify with Push Notification (Polling)](#verify-with-push-notification-polling)
  - [Session Persistence](#session-persistence)
    - [Automatic Session Update](#automatic-session-update)
    - [Manual Session Update](#manual-session-update)
  - [Complete MFA Flow Examples](#complete-mfa-flow-examples)
    - [Enrollment Flow](#enrollment-flow)
    - [Challenge Flow](#challenge-flow)
    - [Complete Login with MFA](#complete-login-with-mfa)
  - [Error Handling](#error-handling)
    - [Common Error Scenarios](#common-error-scenarios)
  - [Additional Resources](#additional-resources)

## Setup

Before using the MFA API, ensure MFA is configured in your [Auth0 Dashboard](https://manage.auth0.com) under **Security** > **Multi-factor Auth**. For detailed configuration, see the [Auth0 MFA documentation](https://auth0.com/docs/secure/multi-factor-authentication/customize-mfa/customize-mfa-enrollments-universal-login).

## Understanding MFA Responses

When MFA is required during authentication, the error response contains an `mfa_requirements` object that indicates either:

1. **Challenge Flow** (user has enrolled authenticators)
2. **Enroll Flow** (user needs to set up MFA)

### Challenge Flow Response

```json
{
  "error": "mfa_required",
  "error_description": "Multifactor authentication required",
  "mfa_token": "Fe26.2*...",
  "mfa_requirements": {
    "challenge": [
      { "type": "otp" },
      { "type": "sms" },
      { "type": "email" },
      { "type": "auth0" }
    ]
  }
}
```

**Interpretation**: User has enrolled authenticators → proceed with **Get Authenticators → Challenge → Verify** flow

### Enroll Flow Response

```json
{
  "error": "mfa_required",
  "error_description": "Multifactor authentication required",
  "mfa_token": "Fe26.2*...",
  "mfa_requirements": {
    "enroll": [
      { "type": "otp" },
      { "type": "sms" },
      { "type": "email" },
      { "type": "auth0" }
    ]
  }
}
```

**Interpretation**: User needs to set up MFA → proceed with **Get Enrollment Factors → Enroll → Verify** flow

## Handling MFA Required Errors

When `get_access_token()` encounters an MFA requirement, it raises an `MfaRequiredError` with the `mfa_token` context:

```python
from auth0_server_python.error import MfaRequiredError
from auth0_server_python.auth_server import ServerClient

server_client = ServerClient(
    domain="<AUTH0_DOMAIN>",
    client_id="<AUTH0_CLIENT_ID>",
    client_secret="<AUTH0_CLIENT_SECRET>"
)

try:
    access_token = await server_client.get_access_token()
except MfaRequiredError as error:
    mfa_token = error.mfa_token
    print(f"MFA Required: {error.error_description}")
    
    # The MFA context is automatically stored in the client
    # You can now use the MFA methods
```

## Getting Authenticators

Retrieve the list of authenticators the user has already enrolled:

```python
try:
    authenticators = await server_client.mfa.list_authenticators({
        "mfa_token": mfa_token
    })
    
    for auth in authenticators:
        print(f"Authenticator: {auth.id}")
        print(f"  Type: {auth.authenticator_type}")
        print(f"  Created: {auth.created_at}")
        
except Exception as error:
    print(f"Error retrieving authenticators: {error}")
```

### Response Structure

Each authenticator is an `AuthenticatorResponse` object with:
- `id`: Authenticator identifier (e.g., `otp|dev_xxx`)
- `authenticator_type`: Type of authenticator (`otp`, `oob`, `recovery-code`)
- `created_at`: Creation timestamp
- `active`: Boolean indicating if authenticator is active
- `oob_channel`: For OOB authenticators, the channel used (`sms`, `voice`, `email`, `auth0`)
- `phone_number`: For SMS/Voice authenticators, the enrolled phone number
- `last_auth`: Last authentication timestamp (if available)

## Getting Enrollment Factors

Check what MFA factors are available for enrollment:

```python
try:
    factors = await server_client.mfa.list_authenticators({
        "mfa_token": mfa_token
    })
    
    if len(factors) > 0:
        print("Available enrollment factors:")
        for factor in factors:
            print(f"  - {factor.authenticator_type}")
    else:
        print("User already has all available authenticators enrolled")
        
except Exception as error:
    print(f"Error retrieving enrollment factors: {error}")
```

## Enrollment

### Enrolling OTP (Authenticator App)

Enroll an OTP authenticator (Google Authenticator, Microsoft Authenticator, etc.):

```python
try:
    enrollment = await server_client.mfa.enroll_authenticator({
        "mfa_token": mfa_token,
        "factor_type": "otp"
    })
    
    # Display QR code to user
    print(f"QR Code URI: {enrollment.barcode_uri}")  # otpauth://totp/...
    print(f"Secret Key: {enrollment.secret}")  # Base32 secret for manual entry
    
except Exception as error:
    print(f"Enrollment failed: {error}")
```

### Enrolling SMS

Enroll an SMS authenticator:

```python
try:
    enrollment = await server_client.mfa.enroll_authenticator({
        "mfa_token": mfa_token,
        "factor_type": "sms",
        "phone_number": "+12025551234"  # E.164 format
    })
    
    # Save oobCode for enrollment verification
    print(f"OOB Code: {enrollment.oob_code}")
    print("SMS sent to user's phone number")
    
except Exception as error:
    print(f"SMS enrollment failed: {error}")
```

### Enrolling Voice

Enroll a voice call authenticator:

```python
try:
    enrollment = await server_client.mfa.enroll_authenticator({
        "mfa_token": mfa_token,
        "factor_type": "voice",
        "phone_number": "+12025551234"  # E.164 format
    })
    
    print(f"OOB Code: {enrollment.oob_code}")
    print("Voice call initiated to user's phone number")
    
except Exception as error:
    print(f"Voice enrollment failed: {error}")
```

### Enrolling Email

Enroll an email authenticator:

```python
try:
    enrollment = await server_client.mfa.enroll_authenticator({
        "mfa_token": mfa_token,
        "factor_type": "email",
        "email": "user@example.com"
    })
    
    print(f"OOB Code: {enrollment.oob_code}")
    print("Verification email sent to user")
    
except Exception as error:
    print(f"Email enrollment failed: {error}")
```

### Enrolling Push Notification (Auth0 Guardian)

Enroll a push notification authenticator using Auth0 Guardian:

```python
try:
    enrollment = await server_client.mfa.enroll_authenticator({
        "mfa_token": mfa_token,
        "factor_type": "auth0"
    })
    
    # Display Guardian QR code to user — they scan it with the Auth0 Guardian app
    print(f"QR Code URI: {enrollment.barcode_uri}")  # otpauth://... for Guardian app
    print(f"OOB Code: {enrollment.oob_code}")  # Used for polling verification status
    
    # After user scans the QR code, poll for approval (see Verify with Push Notification)
    
except Exception as error:
    print(f"Push enrollment failed: {error}")
```

> [!NOTE]
> The `barcode_uri` is returned in the `OobEnrollmentResponse` and should be rendered as a QR code for the user to scan with the Auth0 Guardian app. After scanning, poll for verification using the `oob_code`.

## Challenge

After enrolling an authenticator, or when the user has existing authenticators, initiate a challenge:

### Challenge with SMS

```python
try:
    challenge = await server_client.mfa.challenge_authenticator({
        "mfa_token": mfa_token,
        "factor_type": "sms",
        "authenticator_id": "sms|dev_xxx"
    })
    
    print(f"OOB Code: {challenge.oob_code}")
    print(f"Challenge Expires In: {challenge.expires_in} seconds")
    print("User will receive SMS with verification code")
    
except Exception as error:
    print(f"Challenge failed: {error}")
```

### Challenge with Email

```python
try:
    challenge = await server_client.mfa.challenge_authenticator({
        "mfa_token": mfa_token,
        "factor_type": "email",
        "authenticator_id": "email|dev_xxx"
    })
    
    print(f"OOB Code: {challenge.oob_code}")
    print("User will receive verification email")
    
except Exception as error:
    print(f"Challenge failed: {error}")
```

### Challenge with OTP

> [!NOTE]
> For OTP authenticators, you do not need to explicitly call challenge. The code is generated automatically by the user's authenticator app. Simply prompt the user to open their app and provide the 6-digit code.

```python
try:
    challenge = await server_client.mfa.challenge_authenticator({
        "mfa_token": mfa_token,
        "factor_type": "otp",
        "authenticator_id": "otp|dev_xxx"
    })
    
    print("User should open their authenticator app and provide the code")
    
except Exception as error:
    print(f"Challenge failed: {error}")
```

### Challenge with Push Notification

```python
try:
    challenge = await server_client.mfa.challenge_authenticator({
        "mfa_token": mfa_token,
        "factor_type": "auth0",
        "authenticator_id": "auth0|dev_xxx"
    })
    
    print(f"OOB Code: {challenge.oob_code}")
    print(f"Challenge Expires In: {challenge.expires_in} seconds")
    print("Push notification sent to user's device — poll for approval")
    
except Exception as error:
    print(f"Challenge failed: {error}")
```

> [!NOTE]
> Push notification challenges do not require a `binding_code` from the user. Instead, the user approves the notification on their device, and you poll the verify endpoint to check if they have approved.

## Verify

Complete MFA verification with the challenge response:

### Verify with OOB (SMS or Email)

```python
try:
    verify_response = await server_client.mfa.verify({
        "mfa_token": mfa_token,
        "oob_code": challenge.oob_code,
        "binding_code": "123456",  # Code user received via SMS/Email
        "persist": True,  # Persist tokens to session store
        "audience": "https://api.example.com",  # Required when persist=True
        "scope": "openid profile email"  # Optional scope
    })
    
    access_token = verify_response.access_token
    id_token = verify_response.id_token
    
    # Check for recovery code (returned on first-time enrollment)
    if verify_response.recovery_code:
        print(f"Recovery Code: {verify_response.recovery_code}")
        print("Save this recovery code securely — it will only be shown once!")
    
    print(f"MFA verification successful!")
    print(f"Access Token: {access_token}")
    print(f"ID Token: {id_token}")
    print("Tokens have been persisted to session store")
    
except Exception as error:
    print(f"Verification failed: {error}")
```

> [!NOTE]
> Setting `persist=True` automatically updates the session store with the new tokens, similar to nextjs-auth0 and auth0-spa-js SDKs. This eliminates the need for manual token management after MFA verification.

> [!TIP]
> The `verify()` response may include a `recovery_code` field. This is returned when a user completes their first MFA enrollment, or when they verify using a recovery code (a new one is generated to replace the used code). Always check for this field and display it to the user.

### Verify with OTP

```python
try:
    verify_response = await server_client.mfa.verify({
        "mfa_token": mfa_token,
        "otp": "123456",  # 6-digit code from authenticator app
        "persist": True,  # Persist tokens to session store
        "audience": "https://api.example.com",  # Required when persist=True
        "scope": "openid profile email"
    })
    
    access_token = verify_response.access_token
    
    print("MFA verification successful!")
    print("Tokens have been persisted to session store")
    
except Exception as error:
    print(f"Invalid OTP code: {error}")
```

### Verify with Recovery Code

Recovery codes can be used to complete MFA verification without initiating a challenge:

```python
try:
    verify_response = await server_client.mfa.verify({
        "mfa_token": mfa_token,
        "recovery_code": "XXXX-XXXX-XXXX",  # One of the recovery codes
        "persist": True,  # Persist tokens to session store
        "audience": "https://api.example.com"  # Required when persist=True
    })
    
    access_token = verify_response.access_token
    
    # A new recovery code is generated after using one
    if verify_response.recovery_code:
        print(f"New Recovery Code: {verify_response.recovery_code}")
        print("Save this new recovery code — the old one has been invalidated!")
    
    print("MFA verification successful using recovery code!")
    print("Tokens have been persisted to session store")
    
except Exception as error:
    print(f"Verification failed: {error}")
```

### Verify with Push Notification (Polling)

Push notification verification uses polling — the user approves on their device, and you repeatedly call `verify()` until approval or timeout:

```python
import asyncio

async def poll_push_verification(server_client, mfa_token, oob_code, timeout=60):
    """Poll for push notification approval."""
    elapsed = 0
    interval = 3  # Poll every 3 seconds
    
    while elapsed < timeout:
        try:
            verify_response = await server_client.mfa.verify({
                "mfa_token": mfa_token,
                "oob_code": oob_code
                # No binding_code needed for push notifications
            })
            
            # Success — user approved on their device
            print("Push notification approved!")
            
            if verify_response.recovery_code:
                print(f"Recovery Code: {verify_response.recovery_code}")
            
            return verify_response
            
        except Exception as error:
            error_msg = str(error)
            if "authorization_pending" in error_msg:
                # User hasn't responded yet — keep polling
                await asyncio.sleep(interval)
                elapsed += interval
            elif "slow_down" in error_msg:
                # Rate limited — increase interval
                interval = min(interval + 2, 10)
                await asyncio.sleep(interval)
                elapsed += interval
            else:
                # Actual error (expired, denied, etc.)
                raise
    
    raise TimeoutError("Push notification timed out")
```

> [!NOTE]
> When polling for push notification approval, the API returns an `authorization_pending` error until the user approves or denies the request. A `slow_down` error indicates you should increase the polling interval.

## Session Persistence

By default, `verify()` returns tokens without persisting them to the session store. However, you can automatically persist tokens by setting `persist=True`, similar to how nextjs-auth0 and auth0-spa-js handle MFA.

### Automatic Session Update

When you set `persist=True`, the SDK will:
1. Update the session's `access_token` for the specified audience
2. Update the session's `id_token` if present
3. Add the token to the `token_sets` array with expiration information

```python
verify_response = await server_client.mfa.verify({
    "mfa_token": mfa_token,
    "otp": "123456",
    "persist": True,  # Enable automatic persistence
    "audience": "https://api.example.com",  # Required when persist=True
    "scope": "openid profile email"  # Optional
})

# Tokens are now available in the session store
# User can call server_client.get_user() to access updated session
user = await server_client.get_user()
```

### Manual Session Update

If you prefer to manage session updates yourself:

```python
verify_response = await server_client.mfa.verify({
    "mfa_token": mfa_token,
    "otp": "123456"
    # persist=False (default)
})

# Handle token storage manually if needed
access_token = verify_response.access_token
id_token = verify_response.id_token

# Store tokens in your application's session management
await my_session_store.update_tokens(access_token, id_token)
```

## Complete MFA Flow Examples

### Enrollment Flow

When a user needs to set up MFA for the first time:

```python
async def handle_mfa_enrollment_flow(server_client, mfa_token):
    try:
        # Get available enrollment factors
        factors = await server_client.mfa.list_authenticators({
            "mfa_token": mfa_token
        })
        
        print("Available MFA options:")
        for factor in factors:
            print(f"  - {factor.authenticator_type}")
        
        # User selects OTP
        enrollment = await server_client.mfa.enroll_authenticator({
            "mfa_token": mfa_token,
            "factor_type": "otp"
        })
        
        # Display QR code to user
        print(f"QR Code: {enrollment.barcode_uri}")
        
        # Wait for user to scan and enter verification code
        user_code = input("Enter 6-digit code from authenticator: ")
        
        # Verify enrollment
        verify_response = await server_client.mfa.verify({
            "mfa_token": mfa_token,
            "otp": user_code,
            "persist": True,
            "audience": "https://api.example.com",
            "scope": "openid profile email"
        })
        
        print("MFA enrollment successful!")
        print("Tokens have been persisted to session store")
        return verify_response.access_token
        
    except Exception as error:
        print(f"Enrollment flow failed: {error}")
        raise
```

### Challenge Flow

When a user with existing authenticators needs to verify:

```python
async def handle_mfa_challenge_flow(server_client, mfa_token):
    try:
        # Get user's enrolled authenticators
        authenticators = await server_client.mfa.list_authenticators({
            "mfa_token": mfa_token
        })
        
        print("Select an authenticator:")
        for i, auth in enumerate(authenticators):
            print(f"  {i + 1}. {auth.authenticator_type} ({auth.id})")
        
        # User selects authenticator
        selected_index = int(input("Selection: ")) - 1
        selected_auth = authenticators[selected_index]
        
        # Determine the correct factor_type for challenge
        # OOB authenticators use their oob_channel as the factor_type
        if selected_auth.authenticator_type == "oob":
            factor_type = selected_auth.oob_channel  # "sms", "email", "voice", "auth0"
        else:
            factor_type = selected_auth.authenticator_type  # "otp", "recovery-code"
        
        # Initiate challenge
        challenge = await server_client.mfa.challenge_authenticator({
            "mfa_token": mfa_token,
            "factor_type": factor_type,
            "authenticator_id": selected_auth.id
        })
        
        # Get verification code from user
        if selected_auth.authenticator_type == "otp":
            user_code = input("Enter 6-digit code from authenticator: ")
            verify_response = await server_client.mfa.verify({
                "mfa_token": mfa_token,
                "otp": user_code,
                "persist": True,
                "audience": "https://api.example.com",
                "scope": "openid profile email"
            })
        elif factor_type == "auth0":
            # Push notification — poll for approval
            verify_response = await poll_push_verification(
                server_client, mfa_token, challenge.oob_code
            )
        else:
            user_code = input(f"Enter code from {factor_type}: ")
            verify_response = await server_client.mfa.verify({
                "mfa_token": mfa_token,
                "oob_code": challenge.oob_code,
                "binding_code": user_code,
                "persist": True,
                "audience": "https://api.example.com",
                "scope": "openid profile email"
            })
        
        print("MFA verification successful!")
        print("Tokens have been persisted to session store")
        return verify_response.access_token
        
    except Exception as error:
        print(f"Challenge flow failed: {error}")
        raise
```

### Complete Login with MFA

```python
from auth0_server_python.error import MfaRequiredError

async def login_with_mfa(server_client):
    try:
        # Attempt to get access token
        access_token = await server_client.get_access_token()
        return access_token
        
    except MfaRequiredError as mfa_error:
        mfa_token = mfa_error.mfa_token
        
        # Determine flow: check if user needs to enroll or has authenticators
        authenticators = await server_client.mfa.list_authenticators({
            "mfa_token": mfa_token
        })
        
        if len(authenticators) == 0:
            # User needs to enroll
            print("MFA enrollment required")
            access_token = await handle_mfa_enrollment_flow(
                server_client, mfa_token
            )
        else:
            # User has authenticators, proceed with challenge
            print("MFA verification required")
            access_token = await handle_mfa_challenge_flow(
                server_client, mfa_token
            )
        
        return access_token
        
    except Exception as error:
        print(f"Login failed: {error}")
        raise
```

## Error Handling

Each MFA operation has specific error handling:

```python
from auth0_server_python.error import MfaRequiredError, ApiError

async def handle_mfa_with_error_handling(server_client):
    try:
        # Attempt token exchange
        access_token = await server_client.get_access_token()
        
    except MfaRequiredError as error:
        print(f"MFA Required: {error.error_description}")
        mfa_token = error.mfa_token
        
        try:
            # Get authenticators
            authenticators = await server_client.mfa.list_authenticators({
                "mfa_token": mfa_token
            })
        except ApiError as list_error:
            print(f"Failed to retrieve authenticators: {list_error}")
            raise
        
        try:
            # Initiate challenge
            challenge = await server_client.mfa.challenge_authenticator({
                "mfa_token": mfa_token,
                "factor_type": "sms",
                "authenticator_id": authenticators[0].id
            })
        except ApiError as challenge_error:
            print(f"Challenge failed: {challenge_error}")
            raise
        
        try:
            # Verify challenge
            verify_response = await server_client.mfa.verify({
                "mfa_token": mfa_token,
                "oob_code": challenge.oob_code,
                "binding_code": "123456"
            })
        except ApiError as verify_error:
            if verify_error.status_code == 403:
                print("Invalid code or challenge expired")
            else:
                print(f"Verification error: {verify_error}")
            raise
    
    except Exception as error:
        print(f"Unexpected error: {error}")
        raise
```

### Common Error Scenarios

- **Invalid OTP Code**: HTTP 403 with error details
- **Expired Challenge**: HTTP 403 with expired_token error
- **MFA Token Expired**: HTTP 400 with context_not_found error
- **Network Issues**: Connection errors with descriptive messages

## Additional Resources

- [Auth0 MFA Documentation](https://auth0.com/docs/secure/multi-factor-authentication)
