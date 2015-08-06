#!/usr/bin/env python
import os

# --- import environment variables from hidden file
if os.path.exists('.env'):
    print('Importing environment from .env...')
    for line in open('.env'):
        var = line.strip().split('=')
        if len(var) == 2:
            os.environ[var[0]] = var[1]

# --- import extensions and apps
from app import create_app, db
from app.models import User, Feed, Role, Permission, Post, Comment
from flask.ext.script import Manager, Shell
from flask.ext.migrate import Migrate, MigrateCommand

# -- create app and register with extensions
app = create_app(os.getenv('FLASK_CONFIG') or 'default')
manager = Manager(app)
migrate = Migrate(app, db)

# --- shell context
def make_shell_context():
    return dict(app=app, db=db, User=User, Follow=Feed, Role=Role,
                Permission=Permission, Post=Post, Comment=Comment)
manager.add_command("shell", Shell(make_context=make_shell_context))


# --- database and migration
manager.add_command('db', MigrateCommand)


# --- deployment command

@manager.command
def deploy():
    """Run deployment tasks."""
    from flask.ext.migrate import upgrade
    from app.models import Role, User

    # migrate database to latest revision
    upgrade()

    # create user roles
    Role.insert_roles()

    # create self-follows for all users
    User.feed_to_self()


# --- run the application


if __name__ == '__main__':
    manager.run()
