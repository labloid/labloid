from functools import wraps
from flask import abort
from flask.ext.login import current_user
from ..models import Permission, PostGroup, User, GroupMemberShip


def group_permission_required(permission, groupvar):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            group_id = kwargs.get(groupvar, None) or args[f.func_code.co_varnames.index(groupvar)]
            user = current_user
            group = PostGroup.query.filter_by(id=group_id).first_or_404()

            if user.can(Permission.ADMINISTER) or group.user_can(user, permission):
                return f(*args, **kwargs)
            else:
                abort(403)

        return decorated_function
    return decorator

def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)
