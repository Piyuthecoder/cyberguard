from flask import Blueprint, render_template

from .laws import CATEGORIES

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return render_template("index.html", categories=CATEGORIES)


@bp.route("/privacy-policy")
def policy():
    return render_template("policy.html")
