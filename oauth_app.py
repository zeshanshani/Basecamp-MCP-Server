"""
Flask application for handling the Basecamp 3 OAuth 2.0 authorization flow.

This application provides endpoints for:
1. Redirecting users to Basecamp for authorization
2. Handling the OAuth callback
3. Using the obtained token to access the Basecamp API
4. Providing a secure token endpoint for the MCP server
"""

import os
import sys
import json
import hmac
import secrets
import logging
from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify, abort, Response
from dotenv import load_dotenv
from basecamp_oauth import BasecampOAuth
from basecamp_client import BasecampClient
from search_utils import BasecampSearch
import token_storage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("oauth_app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Check for required environment variables
required_vars = [
    'BASECAMP_CLIENT_ID',
    'BASECAMP_CLIENT_SECRET',
    'BASECAMP_REDIRECT_URI',
    'USER_AGENT',
    'FLASK_SECRET_KEY',
    'ADMIN_PASSWORD',
]
missing_vars = [var for var in required_vars if not os.getenv(var)]
if missing_vars:
    logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
    logger.error("Please set these variables in your .env file or environment")
    sys.exit(1)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ['FLASK_SECRET_KEY']
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# HTML template for displaying results
RESULTS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Basecamp 3 OAuth Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }
        .button {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        .container { max-width: 1000px; margin: 0 auto; }
        form { margin-top: 20px; }
        input[type="text"] { padding: 8px; width: 300px; }
        button { padding: 8px 15px; background-color: #4CAF50; color: white; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>
        {% if message %}
            <p>{{ message }}</p>
        {% endif %}
        {% if warning %}
            <div class="warning">{{ warning }}</div>
        {% endif %}
        {% if content %}
            <pre>{{ content }}</pre>
        {% endif %}
        {% if auth_url %}
            <a href="{{ auth_url }}" class="button">Log in with Basecamp</a>
        {% endif %}
        {% if token_info %}
            <h2>OAuth Token Information</h2>
            <pre>{{ token_info | tojson(indent=2) }}</pre>
        {% endif %}
        {% if show_logout %}
            <a href="/logout" class="button">Logout</a>
        {% endif %}
        {% if show_home %}
            <a href="/" class="button">Home</a>
        {% endif %}
    </div>
</body>
</html>
"""

@app.template_filter('tojson')
def to_json(value, indent=None):
    return json.dumps(value, indent=indent)

ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')

# Lazily attached by railway_app.py at startup, so the consent screen can
# complete the MCP OAuth flow on the same JSON state file the provider uses.
_mcp_oauth_provider = None


def attach_mcp_oauth_provider(provider) -> None:
    """Wire the OAuth provider into the Flask app for the consent screen."""
    global _mcp_oauth_provider
    _mcp_oauth_provider = provider


def require_admin_auth(view):
    """
    HTTP Basic Auth gate for browser-facing admin routes.

    Used on the routes that expose or destroy token state (/, /logout,
    /token/info). The OAuth callback at /auth/callback stays public because
    Basecamp's redirect cannot send Authorization headers; that route has
    its own state-parameter CSRF protection.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        auth = request.authorization
        expected_user = ADMIN_USERNAME
        expected_pass = os.environ['ADMIN_PASSWORD']
        unauthorized = Response(
            'Authentication required',
            status=401,
            headers={'WWW-Authenticate': 'Basic realm="Basecamp MCP admin"'},
        )
        if not auth or not auth.username or not auth.password:
            return unauthorized
        if not (
            hmac.compare_digest(auth.username, expected_user)
            and hmac.compare_digest(auth.password, expected_pass)
        ):
            return unauthorized
        return view(*args, **kwargs)

    return wrapped

def get_oauth_client():
    """Get a configured OAuth client."""
    try:
        client_id = os.getenv('BASECAMP_CLIENT_ID')
        client_secret = os.getenv('BASECAMP_CLIENT_SECRET')
        redirect_uri = os.getenv('BASECAMP_REDIRECT_URI')
        user_agent = os.getenv('USER_AGENT')

        logger.info("Creating OAuth client with config: %s, %s, %s", client_id, redirect_uri, user_agent)

        return BasecampOAuth(
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            user_agent=user_agent
        )
    except Exception as e:
        logger.error("Error creating OAuth client: %s", str(e))
        raise

def ensure_valid_token():
    """
    Ensure we have a valid, non-expired token. 
    Attempts to refresh if expired.
    
    Returns:
        dict: Valid token data or None if authentication is needed
    """
    token_data = token_storage.get_token()
    
    if not token_data or not token_data.get('access_token'):
        logger.info("No token found")
        return None
    
    # Check if token is expired
    if token_storage.is_token_expired():
        logger.info("Token is expired, attempting to refresh")
        
        refresh_token = token_data.get('refresh_token')
        if not refresh_token:
            logger.warning("No refresh token available, user needs to re-authenticate")
            return None
        
        try:
            oauth_client = get_oauth_client()
            new_token_data = oauth_client.refresh_token(refresh_token)
            
            # Store the new token
            access_token = new_token_data.get('access_token')
            new_refresh_token = new_token_data.get('refresh_token', refresh_token)  # Use old refresh token if new one not provided
            expires_in = new_token_data.get('expires_in')
            account_id = token_data.get('account_id')  # Keep the existing account_id
            
            if access_token:
                token_storage.store_token(
                    access_token=access_token,
                    refresh_token=new_refresh_token,
                    expires_in=expires_in,
                    account_id=account_id
                )
                logger.info("Token refreshed successfully")
                return token_storage.get_token()
            else:
                logger.error("No access token in refresh response")
                return None
                
        except Exception as e:
            logger.error("Failed to refresh token: %s", str(e))
            return None
    
    logger.info("Token is valid")
    return token_data

@app.route('/')
@require_admin_auth
def home():
    """Home page (admin: shows token status and the login-with-Basecamp button)."""
    # Ensure we have a valid token
    token_data = ensure_valid_token()

    if token_data and token_data.get('access_token'):
        # We have a valid token, show token information
        access_token = token_data['access_token']
        # Mask the token for security
        masked_token = f"{access_token[:10]}...{access_token[-10:]}" if len(access_token) > 20 else "***"

        token_info = {
            "access_token": masked_token,
            "account_id": token_data.get('account_id'),
            "has_refresh_token": bool(token_data.get('refresh_token')),
            "expires_at": token_data.get('expires_at'),
            "updated_at": token_data.get('updated_at')
        }

        logger.info("Home page: User is authenticated")

        return render_template_string(
            RESULTS_TEMPLATE,
            title="Basecamp OAuth Status",
            message="You are authenticated with Basecamp!",
            token_info=token_info,
            show_logout=True
        )
    else:
        # No valid token, show login button
        try:
            oauth_client = get_oauth_client()
            state = secrets.token_urlsafe(32)
            session['oauth_state'] = state
            auth_url = oauth_client.get_authorization_url(state=state)

            logger.info("Home page: User not authenticated, showing login button")

            return render_template_string(
                RESULTS_TEMPLATE,
                title="Basecamp OAuth Demo",
                message="Welcome! Please log in with your Basecamp account to continue.",
                auth_url=auth_url
            )
        except Exception as e:
            logger.error("Error getting authorization URL: %s", str(e))
            return render_template_string(
                RESULTS_TEMPLATE,
                title="Error",
                message=f"Error setting up OAuth: {str(e)}",
            )

@app.route('/auth/callback')
def auth_callback():
    """Handle the OAuth callback from Basecamp."""
    logger.info("OAuth callback called (keys=%s)", sorted(request.args.keys()))

    code = request.args.get('code')
    error = request.args.get('error')
    received_state = request.args.get('state')

    if error:
        logger.error("OAuth callback error: %s", error)
        return render_template_string(
            RESULTS_TEMPLATE,
            title="Authentication Error",
            message=f"Basecamp returned an error: {error}",
            show_home=True
        )

    if not code:
        logger.error("OAuth callback: No code provided")
        return render_template_string(
            RESULTS_TEMPLATE,
            title="Error",
            message="No authorization code received.",
            show_home=True
        )

    # CSRF: confirm the state parameter matches the one we generated in /.
    expected_state = session.pop('oauth_state', None)
    if not expected_state or not received_state or not hmac.compare_digest(
        expected_state, received_state
    ):
        logger.error("OAuth callback: state mismatch (possible CSRF)")
        return render_template_string(
            RESULTS_TEMPLATE,
            title="Authentication Error",
            message="OAuth state mismatch. Please start the login again.",
            show_home=True
        )

    try:
        # Exchange the code for an access token
        oauth_client = get_oauth_client()
        logger.info("Exchanging code for token")
        token_data = oauth_client.exchange_code_for_token(code)
        logger.info(
            "Token exchange succeeded: has_access_token=%s has_refresh_token=%s expires_in=%s",
            bool(token_data.get('access_token')),
            bool(token_data.get('refresh_token')),
            token_data.get('expires_in'),
        )

        # Store the token in our secure storage
        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')
        expires_in = token_data.get('expires_in')
        account_id = os.getenv('BASECAMP_ACCOUNT_ID')

        if not access_token:
            logger.error("OAuth exchange: No access token received")
            return render_template_string(
                RESULTS_TEMPLATE,
                title="Authentication Error",
                message="No access token received from Basecamp.",
                show_home=True
            )

        # Try to get identity if account_id is not set
        if not account_id:
            try:
                logger.info("Getting user identity to find account_id")
                identity = oauth_client.get_identity(access_token)
                logger.info(
                    "Identity response received (accounts=%d)",
                    len(identity.get('accounts', []) or []),
                )

                # Find Basecamp 3 account
                if identity.get('accounts'):
                    for account in identity['accounts']:
                        if account.get('product') == 'bc3':  # Basecamp 3
                            account_id = account['id']
                            logger.info("Found account_id: %s", account_id)
                            break
            except Exception as identity_error:
                logger.error("Error getting identity: %s", str(identity_error))
                # Continue with the flow, but log the error

        logger.info("Storing token with account_id: %s", account_id)
        stored = token_storage.store_token(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in,
            account_id=account_id
        )

        if not stored:
            logger.error("Failed to store token")
            return render_template_string(
                RESULTS_TEMPLATE,
                title="Error",
                message="Failed to store token. Please try again.",
                show_home=True
            )

        logger.info("OAuth flow completed successfully")

        return redirect(url_for('home'))
    except Exception as e:
        logger.error("Error in OAuth callback: %s", str(e), exc_info=True)
        return render_template_string(
            RESULTS_TEMPLATE,
            title="Error",
            message=f"Failed to exchange code for token: {str(e)}",
            show_home=True
        )

@app.route('/logout')
@require_admin_auth
def logout():
    """Clear the session and token storage (admin)."""
    logger.info("Logout called")
    session.clear()
    token_storage.clear_tokens()
    return redirect(url_for('home'))

@app.route('/token/info')
@require_admin_auth
def token_info():
    """Display information about the stored token (admin)."""
    logger.info("Token info called")
    token_data = token_storage.get_token()

    if not token_data:
        logger.info("Token info: No token stored")
        return render_template_string(
            RESULTS_TEMPLATE,
            title="Token Information",
            message="No token stored.",
            show_home=True
        )

    # Check if token is expired
    is_expired = token_storage.is_token_expired()
    
    # Mask the tokens for security
    access_token = token_data.get('access_token', '')
    refresh_token = token_data.get('refresh_token', '')

    masked_access = f"{access_token[:10]}...{access_token[-10:]}" if len(access_token) > 20 else "***"
    masked_refresh = f"{refresh_token[:10]}...{refresh_token[-10:]}" if refresh_token and len(refresh_token) > 20 else "***" if refresh_token else None

    display_info = {
        "access_token": masked_access,
        "has_refresh_token": bool(refresh_token),
        "account_id": token_data.get('account_id'),
        "expires_at": token_data.get('expires_at'),
        "updated_at": token_data.get('updated_at'),
        "is_expired": is_expired
    }

    warning_message = None
    if is_expired:
        warning_message = "Warning: Your token is expired! Visit the home page to automatically refresh it, or logout and log back in."

    logger.info("Token info: Returned token info")
    return render_template_string(
        RESULTS_TEMPLATE,
        title="Token Information",
        content=json.dumps(display_info, indent=2),
        warning=warning_message,
        show_home=True
    )

CONSENT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Authorise MCP client</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; max-width: 600px; }
        h1 { color: #333; }
        .meta { background: #f5f5f5; padding: 12px; border-radius: 6px;
                font-family: monospace; font-size: 13px; }
        form { display: inline; }
        button { padding: 10px 20px; margin-right: 10px; border: none;
                 border-radius: 5px; cursor: pointer; font-size: 14px; }
        .approve { background: #4CAF50; color: white; }
        .deny    { background: #ddd; color: #333; }
    </style>
</head>
<body>
    <h1>Authorise this MCP client?</h1>
    <p>An OAuth client is asking to access the Basecamp MCP server on your behalf.</p>
    <div class="meta">
        client_id:    {{ client_id }}<br>
        client_name:  {{ client_name }}<br>
        redirect_uri: {{ redirect_uri }}<br>
        scopes:       {{ scopes }}
    </div>
    <p>Only approve if you initiated this from Claude (or another MCP client you trust).</p>
    <form method="POST" action="/oauth/consent/decide">
        <input type="hidden" name="pending_id" value="{{ pending_id }}">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <button class="approve" name="decision" value="approve">Approve</button>
        <button class="deny"    name="decision" value="deny">Deny</button>
    </form>
</body>
</html>
"""


@app.route('/oauth/consent', methods=['GET'])
@require_admin_auth
def oauth_consent():
    """Render the MCP OAuth consent screen for a pending authorisation."""
    if _mcp_oauth_provider is None:
        return Response('MCP OAuth provider not configured', status=500)

    pending_id = request.args.get('pending_id', '')
    if not pending_id:
        return Response('Missing pending_id', status=400)

    pending = _mcp_oauth_provider.get_pending(pending_id)
    if pending is None:
        return Response('Pending authorisation not found or expired', status=404)

    # Look up the client metadata to display its name. We avoid running the
    # async get_client() here by reading the JSON state directly.
    client_info = _mcp_oauth_provider._read()['clients'].get(pending['client_id'], {})

    csrf = secrets.token_urlsafe(16)
    session['oauth_consent_csrf'] = csrf

    return render_template_string(
        CONSENT_TEMPLATE,
        pending_id=pending_id,
        client_id=pending['client_id'],
        client_name=client_info.get('client_name') or '(unnamed)',
        redirect_uri=pending['redirect_uri'],
        scopes=' '.join(pending.get('scopes') or []) or '(none)',
        csrf=csrf,
    )


@app.route('/oauth/consent/decide', methods=['POST'])
@require_admin_auth
def oauth_consent_decide():
    """Handle approve/deny from the consent screen."""
    if _mcp_oauth_provider is None:
        return Response('MCP OAuth provider not configured', status=500)

    pending_id = request.form.get('pending_id', '')
    decision = request.form.get('decision', '')
    csrf = request.form.get('csrf', '')
    expected_csrf = session.pop('oauth_consent_csrf', None)
    if not expected_csrf or not hmac.compare_digest(csrf, expected_csrf):
        logger.warning("Consent decide: CSRF mismatch")
        return Response('CSRF mismatch', status=400)
    if not pending_id:
        return Response('Missing pending_id', status=400)

    if decision == 'deny':
        pending = _mcp_oauth_provider.discard_pending(pending_id)
        if pending is None:
            return Response('Pending authorisation not found', status=404)
        params = {'error': 'access_denied'}
        if pending.get('state'):
            params['state'] = pending['state']
        target = pending['redirect_uri']
        sep = '&' if ('?' in target) else '?'
        return redirect(f"{target}{sep}{urlencode_form(params)}")

    if decision != 'approve':
        return Response('Invalid decision', status=400)

    result = _mcp_oauth_provider.approve_pending(pending_id)
    if result is None:
        return Response('Pending authorisation not found or expired', status=404)
    code, state, pending = result

    params = {'code': code}
    if state is not None:
        params['state'] = state
    target = pending['redirect_uri']
    sep = '&' if ('?' in target) else '?'
    return redirect(f"{target}{sep}{urlencode_form(params)}")


def urlencode_form(params: dict) -> str:
    from urllib.parse import urlencode
    return urlencode({k: v for k, v in params.items() if v is not None})


@app.route('/health')
def health_check():
    """Health check endpoint."""
    logger.info("Health check called")
    return jsonify({
        "status": "ok",
        "service": "basecamp-oauth-app"
    })

if __name__ == '__main__':
    try:
        logger.info("Starting OAuth app on port %s", os.environ.get('PORT', 8000))
        # Run the Flask app
        port = int(os.environ.get('PORT', 8000))

        # Disable debug and auto-reloader when running in production or background
        is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

        logger.info("Running in %s mode", "debug" if is_debug else "production")
        app.run(host='0.0.0.0', port=port, debug=is_debug, use_reloader=is_debug)
    except Exception as e:
        logger.error("Fatal error: %s", str(e), exc_info=True)
        sys.exit(1)
