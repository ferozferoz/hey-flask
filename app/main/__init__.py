from flask import Blueprint
main = Blueprint('main', __name__)
from . import hello
from .. import models

@main.app_context_processor
def inject_permissions():
    return dict(Permission=models.Permission)