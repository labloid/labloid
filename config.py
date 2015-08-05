import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    SSL_DISABLE = False
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_RECORD_QUERIES = True
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    LABLOID_MAIL_SUBJECT_PREFIX = '[Labloid]'
    LABLOID_MAIL_SENDER = 'Labloid Admin <labloid@bcm.edu>'
    LABLOID_ADMIN = os.environ.get('LABLOID_ADMIN')
    LABLOID_POSTS_PER_PAGE = 20
    LABLOID_FOLLOWERS_PER_PAGE = 50
    LABLOID_COMMENTS_PER_PAGE = 30
    LABLOID_SLOW_DB_QUERY_TIME=0.5

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')



config = {
    'development': DevelopmentConfig,
    'default': DevelopmentConfig
}
