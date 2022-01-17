import sys
sys.path.insert(0,'/var/www/flask_apps/flask_secure_app')
from project import create_app
application = create_app()