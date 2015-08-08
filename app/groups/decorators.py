from functools import wraps
from flask import abort
from flask.ext.login import current_user
from ..models import Permission, PostGroup, User


def group_permission_required(permission, groupvar, uservar=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            group_id = kwargs.get(groupvar, None) or args[f.func_code.co_varnames.index(groupvar)]
            if uservar is None:
                user = current_user
            else:
                user_id = kwargs.get(uservar, None) or args[f.func_code.co_varnames.index(uservar)]
                user = User.query.filter_by(id=user_id).first_or_404()
            group = PostGroup.query.filter_by(id=group_id).first_or_404()


            if not group.user_can(user, permission):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    return permission_required(Permission.ADMINISTER)(f)
