#!/usr/bin/env python
import os
from app import create_app, db
from app.models import User, Role
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
manager = Manager(app)
migrate=Migrate(app,db)

def make_shell_context():
    return dict(app=app, db=db, User=User, Role=Role)

manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)

@manager.command
def deploy():
    from flask_migrate import upgrade
    from app.models import Role,User
    upgrade()
    #create user roles
    Role.insert_roles()
    #create self follow for all users
    User.add_self_follow()


if __name__ == '__main__':
    manager.run()
    db.create_all()