#!/usr/bin/env python3
"""
mIRage DFIR Platform - Main Application
A collaborative incident response and digital forensics platform
"""

import os
import logging
from datetime import datetime
from flask import Flask, jsonify, request, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from celery import Celery
import redis
from prometheus_client import generate_latest, Counter, Histogram, Gauge
import structlog

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
cors = CORS()
cache = Cache()
limiter = Limiter(key_func=get_remote_address)

# Metrics
request_count = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration', ['method', 'endpoint'])
active_users = Gauge('active_users_total', 'Number of active users')

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

def create_app(config_name=None):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Configuration
    app.config.from_object(get_config(config_name))
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    cors.init_app(app, origins=app.config.get('CORS_ORIGINS', ['http://localhost:3000']))
    cache.init_app(app)
    limiter.init_app(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register middleware
    register_middleware(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Initialize Celery
    init_celery(app)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        create_default_admin()
    
    logger.info("mIRage DFIR Platform started", version=app.config.get('VERSION', '2.0.0'))
    
    return app

def get_config(config_name=None):
    """Get configuration class"""
    config_name = config_name or os.environ.get('FLASK_ENV', 'production')
    
    class Config:
        # Database
        SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://mirage:password@localhost/mirage_db')
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        SQLALCHEMY_ENGINE_OPTIONS = {
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'connect_args': {'sslmode': 'prefer'}
        }
        
        # Security
        SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
        JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
        JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get('SESSION_TIMEOUT', 3600))
        SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT', 'salt-change-in-production')
        
        # Cache
        CACHE_TYPE = 'redis'
        CACHE_REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        
        # Celery
        CELERY_BROKER_URL = os.environ.get('RABBITMQ_URL', 'pyamqp://mirage:password@localhost:5672//')
        CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL', 'redis://localhost:6379/1')
        
        # Rate limiting
        RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/2')
        
        # CORS
        CORS_ORIGINS = ['http://localhost:3000', 'https://localhost:443']
        
        # Application
        VERSION = '2.0.0'
        DEBUG = False
        TESTING = False
        
        # Integrations
        MISP_URL = os.environ.get('MISP_URL')
        MISP_API_KEY = os.environ.get('MISP_API_KEY')
        VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
        SENTINELONE_BASE_URL = os.environ.get('SENTINELONE_BASE_URL')
        SENTINELONE_API_TOKEN = os.environ.get('SENTINELONE_API_TOKEN')
        CROWDSTRIKE_CLIENT_ID = os.environ.get('CROWDSTRIKE_CLIENT_ID')
        CROWDSTRIKE_CLIENT_SECRET = os.environ.get('CROWDSTRIKE_CLIENT_SECRET')
    
    class DevelopmentConfig(Config):
        DEBUG = True
        CORS_ORIGINS = ['*']
    
    class ProductionConfig(Config):
        # Production-specific settings
        PREFERRED_URL_SCHEME = 'https'
        SESSION_COOKIE_SECURE = True
        SESSION_COOKIE_HTTPONLY = True
        SESSION_COOKIE_SAMESITE = 'Lax'
    
    config_map = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': Config
    }
    
    return config_map.get(config_name, ProductionConfig)

def register_blueprints(app):
    """Register application blueprints"""
    from app.auth.routes import auth_bp
    from app.cases.routes import cases_bp
    from app.iocs.routes import iocs_bp
    from app.playbooks.routes import playbook_bp
    from app.integrations.routes import integration_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(iocs_bp)
    app.register_blueprint(playbook_bp)
    app.register_blueprint(integration_bp)

def register_middleware(app):
    """Register middleware functions"""
    
    @app.before_request
    def before_request():
        g.start_time = datetime.utcnow()
        
        # Log request
        logger.info("Request started", 
                   method=request.method, 
                   path=request.path, 
                   remote_addr=request.remote_addr)
    
    @app.after_request
    def after_request(response):
        # Calculate request duration
        if hasattr(g, 'start_time'):
            duration = (datetime.utcnow() - g.start_time).total_seconds()
            request_duration.labels(method=request.method, endpoint=request.endpoint or 'unknown').observe(duration)
        
        # Count request
        request_count.labels(method=request.method, endpoint=request.endpoint or 'unknown', status=response.status_code).inc()
        
        # Log response
        logger.info("Request completed", 
                   method=request.method, 
                   path=request.path, 
                   status_code=response.status_code,
                   duration=duration if hasattr(g, 'start_time') else None)
        
        # Security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        return response

def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad request', 'message': str(error)}), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Forbidden', 'message': 'Insufficient permissions'}), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found', 'message': 'Resource not found'}), 404
    
    @app.errorhandler(429)
    def ratelimit_handler(error):
        return jsonify({'error': 'Rate limit exceeded', 'message': 'Too many requests'}), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        logger.error("Internal server error", error=str(error), exc_info=True)
        return jsonify({'error': 'Internal server error', 'message': 'Something went wrong'}), 500

def init_celery(app):
    """Initialize Celery with Flask app context"""
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL'],
        include=['app.workers.tasks']
    )
    
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_time_limit=30 * 60,  # 30 minutes
        task_soft_time_limit=25 * 60,  # 25 minutes
        worker_prefetch_multiplier=1,
        worker_max_tasks_per_child=1000,
    )
    
    class ContextTask(celery.Task):
        """Make celery tasks work with Flask app context."""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    app.celery = celery
    return celery

def create_default_admin():
    """Create default administrator account"""
    from app.auth.models import User, Role
    
    try:
        # Create roles if they don't exist
        roles = ['admin', 'analyst', 'investigator', 'viewer']
        for role_name in roles:
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                role = Role(name=role_name, description=f'{role_name.title()} role')
                db.session.add(role)
        
        # Create admin user if doesn't exist
        admin = User.query.filter_by(username='administrator').first()
        if not admin:
            admin_role = Role.query.filter_by(name='admin').first()
            password = os.environ.get('INITIAL_ADMIN_PASSWORD', 'SecureAdminPassword123!')
            
            admin = User(
                username='administrator',
                email=os.environ.get('ADMIN_EMAIL', 'admin@mirage.local'),
                is_active=True,
                role_id=admin_role.id if admin_role else None
            )
            admin.set_password(password)
            
            db.session.add(admin)
            db.session.commit()
            
            # Log initial password (only on first creation)
            print(f"🔑 Initial admin password: {password}")
            logger.info("Default administrator account created", username='administrator')
        
    except Exception as e:
        logger.error("Error creating default admin", error=str(e))
        db.session.rollback()

# API Routes
@limiter.exempt
def health_check():
    """Health check endpoint for load balancers"""
    try:
        # Check database connection
        db.session.execute('SELECT 1')
        
        # Check Redis connection
        r = redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))
        r.ping()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '2.0.0',
            'database': 'connected',
            'cache': 'connected'
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503

@limiter.exempt
def metrics():
    """Prometheus metrics endpoint"""
    return generate_latest(), 200, {'Content-Type': 'text/plain; charset=utf-8'}

@jwt_required()
def api_info():
    """API information endpoint"""
    return jsonify({
        'name': 'mIRage DFIR Platform API',
        'version': '2.0.0',
        'description': 'Collaborative Digital Forensics & Incident Response Platform',
        'endpoints': {
            'authentication': '/api/auth',
            'cases': '/api/cases',
            'iocs': '/api/iocs',
            'playbooks': '/api/playbooks',
            'integrations': '/api/integrations'
        },
        'user': get_jwt_identity(),
        'timestamp': datetime.utcnow().isoformat()
    })

# Create Flask app
app = create_app()

# Register routes
app.add_url_rule('/api/health', 'health', health_check, methods=['GET'])
app.add_url_rule('/api/metrics', 'metrics', metrics, methods=['GET'])
app.add_url_rule('/api/info', 'info', api_info, methods=['GET'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])
