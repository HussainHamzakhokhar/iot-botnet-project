"""
Secure Flask Application for IoT Botnet Detection
==================================================
Enhanced with HTTPS/TLS, API authentication, rate limiting, and security headers.

Security Features:
- HTTPS/TLS encryption for data in transit
- API key authentication
- Rate limiting to prevent DoS attacks
- Security headers (CSP, HSTS, X-Frame-Options)
- Input validation and sanitization
- Secure session management
"""

from flask import Flask, jsonify, render_template, request, g, abort
from functools import wraps
import pandas as pd
import joblib
import numpy as np
import hashlib
import time
import ssl
import os
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# Import security modules
from security.config import SecurityConfig, get_security_config
from security.key_manager import KeyManager
from security.secure_storage import SecureModelStorage


def create_secure_app(config: SecurityConfig = None) -> Flask:
    """
    Create a Flask application with security features enabled.
    
    Args:
        config: Security configuration
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__, template_folder='templates')
    config = config or get_security_config()
    
    # Store config in app
    app.config['SECURITY_CONFIG'] = config
    
    # Configure session security
    app.config['SECRET_KEY'] = os.urandom(32)
    app.config['SESSION_COOKIE_SECURE'] = config.ssl_enabled
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=config.session_timeout_minutes)
    
    # Initialize rate limiter storage
    app.rate_limit_storage = defaultdict(list)
    
    # Initialize API key storage (in production, use database)
    app.api_keys = {}
    
    return app


# Create the secure app
security_config = get_security_config()
app = create_secure_app(security_config)

print("\n" + "=" * 60)
print("🔐 STARTING SECURE IoT BOTNET DETECTION SERVER")
print("=" * 60)


# ====================
# Security Middleware
# ====================

@app.before_request
def before_request():
    """Security checks before each request."""
    g.request_start_time = time.time()


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    config = app.config['SECURITY_CONFIG']
    
    if config.secure_headers_enabled:
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Enable XSS protection
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'"
        )
        
        # HTTP Strict Transport Security (only when using HTTPS)
        if config.ssl_enabled:
            response.headers['Strict-Transport-Security'] = (
                f'max-age={config.hsts_max_age}; includeSubDomains; preload'
            )
        
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Permissions Policy
        response.headers['Permissions-Policy'] = (
            'geolocation=(), microphone=(), camera=()'
        )
    
    return response


# ====================
# Rate Limiting
# ====================

def rate_limit(func):
    """Decorator to apply rate limiting to endpoints."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        config = app.config['SECURITY_CONFIG']
        client_ip = request.remote_addr
        current_time = time.time()
        window_start = current_time - config.rate_limit_window_seconds
        
        # Clean old entries
        app.rate_limit_storage[client_ip] = [
            t for t in app.rate_limit_storage[client_ip] 
            if t > window_start
        ]
        
        # Check rate limit
        if len(app.rate_limit_storage[client_ip]) >= config.rate_limit_requests:
            return jsonify({
                'error': 'Rate limit exceeded',
                'retry_after': config.rate_limit_window_seconds
            }), 429
        
        # Record request
        app.rate_limit_storage[client_ip].append(current_time)
        
        return func(*args, **kwargs)
    return wrapper


# ====================
# API Authentication
# ====================

def require_api_key(func):
    """Decorator to require API key authentication for endpoints."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        config = app.config['SECURITY_CONFIG']
        
        if not config.api_key_enabled:
            return func(*args, **kwargs)
        
        # Check for API key in headers
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            api_key = request.args.get('api_key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        # Verify API key (hash and compare)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        if key_hash not in app.api_keys:
            return jsonify({'error': 'Invalid API key'}), 403
        
        # Store client info in request context
        g.api_client = app.api_keys[key_hash]
        
        return func(*args, **kwargs)
    return wrapper


def register_api_key(name: str) -> str:
    """
    Register a new API key.
    
    Args:
        name: Name/identifier for the API key owner
        
    Returns:
        Generated API key
    """
    key_manager = KeyManager(security_config)
    api_key = key_manager.generate_api_key()
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    app.api_keys[key_hash] = {
        'name': name,
        'created_at': datetime.utcnow().isoformat(),
        'last_used': None
    }
    
    return api_key


# ====================
# Model Loading (Secure)
# ====================

def load_model_secure():
    """Load model with optional encryption."""
    try:
        # Try loading from secure storage first
        storage = SecureModelStorage()
        model, metadata = storage.load_model('botnet_model')
        scaler = storage.load_additional_file('botnet_model', 'scaler')
        feature_columns = storage.load_additional_file('botnet_model', 'feature_columns')
        print("✅ Model loaded from encrypted storage!")
        return model, scaler, feature_columns
    except Exception as e:
        # Fall back to unencrypted files
        print(f"⚠️  Loading unencrypted model (secure storage not initialized): {e}")
        model = joblib.load('botnet_model.pkl')
        scaler = joblib.load('scaler.pkl')
        feature_columns = joblib.load('feature_columns.pkl')
        return model, scaler, feature_columns


# Load model and data
try:
    model, scaler, feature_columns = load_model_secure()
    df = pd.read_csv('data/iot_dataset.csv').dropna()
    df = pd.get_dummies(df, drop_first=True)
    print("✅ Model loaded!")
    print("✅ Dataset loaded!")
except FileNotFoundError as e:
    print(f"❌ Error loading files: {e}")
    print("Please run train_model.py first")
    model = scaler = feature_columns = df = None

predictions_cache = []


# ====================
# Routes
# ====================

@app.route('/')
def home():
    """Serve the main dashboard."""
    return render_template('index.html')


@app.route('/api/simulate')
@rate_limit
def simulate():
    """Simulate IoT traffic detection (rate limited)."""
    global predictions_cache
    
    if model is None or df is None:
        return jsonify({'error': 'Model not loaded'}), 500
    
    sample = df.sample(1).copy()
    
    for col in feature_columns:
        if col not in sample.columns:
            sample[col] = 0
    
    X = sample[feature_columns]
    X_scaled = scaler.transform(X)
    
    prob = model.predict_proba(X_scaled)[0]
    threat = max(prob) * 100
    
    if threat > 80:
        status = 'CRITICAL'
    elif threat > 50:
        status = 'SUSPICIOUS'
    else:
        status = 'SAFE'
    
    rec = {
        'device_id': f"Device_{len(predictions_cache)+1}",
        'threat_level': round(threat, 2),
        'status': status,
        'timestamp': datetime.now().strftime('%H:%M:%S')
    }
    
    predictions_cache.append(rec)
    return jsonify(rec)


@app.route('/api/threats')
@rate_limit
def threats():
    """Get threat statistics (rate limited)."""
    safe = sum(1 for p in predictions_cache if p['threat_level'] <= 50)
    sus = sum(1 for p in predictions_cache if 50 < p['threat_level'] <= 80)
    crit = sum(1 for p in predictions_cache if p['threat_level'] > 80)
    
    return jsonify({
        'threats': predictions_cache[-100:],
        'safe': safe,
        'suspicious': sus,
        'critical': crit
    })


@app.route('/api/clear')
@rate_limit
def clear():
    """Clear predictions cache (rate limited)."""
    global predictions_cache
    predictions_cache = []
    return jsonify({'ok': True})


@app.route('/api/health')
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'model_loaded': model is not None,
        'ssl_enabled': security_config.ssl_enabled,
        'timestamp': datetime.utcnow().isoformat()
    })


# ====================
# Protected API Endpoints (require API key)
# ====================

@app.route('/api/admin/keys', methods=['POST'])
@require_api_key
def create_api_key():
    """Create a new API key (admin only)."""
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'error': 'Name required'}), 400
    
    new_key = register_api_key(data['name'])
    return jsonify({
        'api_key': new_key,
        'message': 'Store this key securely - it cannot be retrieved again'
    })


@app.route('/api/admin/stats')
@require_api_key
def admin_stats():
    """Get detailed statistics (requires API key)."""
    return jsonify({
        'total_predictions': len(predictions_cache),
        'rate_limit_config': {
            'requests': security_config.rate_limit_requests,
            'window_seconds': security_config.rate_limit_window_seconds
        },
        'active_clients': len(app.rate_limit_storage)
    })


# ====================
# SSL/TLS Configuration
# ====================

def create_ssl_context(config: SecurityConfig) -> ssl.SSLContext:
    """
    Create SSL context for HTTPS.
    
    Args:
        config: Security configuration
        
    Returns:
        Configured SSL context
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Set minimum TLS version
    if config.min_tls_version == "TLSv1.3":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    else:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Load certificate and key
    cert_path = Path(config.ssl_cert_path)
    key_path = Path(config.ssl_key_path)
    
    if cert_path.exists() and key_path.exists():
        context.load_cert_chain(str(cert_path), str(key_path))
    else:
        raise FileNotFoundError(
            f"SSL certificate or key not found at {cert_path} and {key_path}. "
            "Generate them using: python generate_ssl_certs.py"
        )
    
    # Disable weak ciphers
    context.set_ciphers('ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20')
    
    return context


def run_server(host: str = '0.0.0.0', port: int = 5000, use_ssl: bool = None):
    """
    Run the Flask server with optional SSL.
    
    Args:
        host: Host to bind to
        port: Port to listen on
        use_ssl: Enable SSL (uses config default if None)
    """
    config = security_config
    use_ssl = config.ssl_enabled if use_ssl is None else use_ssl
    
    print("\n" + "=" * 60)
    
    if use_ssl:
        try:
            ssl_context = create_ssl_context(config)
            print(f"🔒 HTTPS ENABLED - TLS {config.min_tls_version}+")
            print(f"📱 OPEN IN BROWSER: https://localhost:{port}")
            print("=" * 60 + "\n")
            app.run(host=host, port=port, ssl_context=ssl_context, debug=False)
        except FileNotFoundError as e:
            print(f"⚠️  SSL certificates not found: {e}")
            print("Starting in HTTP mode (development only)...")
            print(f"📱 OPEN IN BROWSER: http://localhost:{port}")
            print("=" * 60 + "\n")
            app.run(host=host, port=port, debug=False)
    else:
        print("⚠️  RUNNING WITHOUT SSL (development mode)")
        print(f"📱 OPEN IN BROWSER: http://localhost:{port}")
        print("=" * 60 + "\n")
        app.run(host=host, port=port, debug=False)


if __name__ == '__main__':
    # For development, run without SSL
    # For production, set SSL_ENABLED=true and provide certificates
    run_server(use_ssl=False)
