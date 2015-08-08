from flask import Blueprint

groups = Blueprint('groups', __name__)

from . import views
from ..models import Permission


# makes the Permission class available to all templates
@groups.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)
