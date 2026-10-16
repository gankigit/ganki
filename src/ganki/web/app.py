"""The Flask application: a read-only view of the scan, reachable only from this machine.

Defences, in order of what they stop:
- The server listens on 127.0.0.1 only (see ``server.py``).
- Every request needs the secret token printed at start-up (kept in an HttpOnly,
  SameSite=Strict cookie afterwards), so another local user or a web page cannot read it.
- The ``Host`` header must be the loopback address, which blocks DNS-rebinding attacks.
- State-changing requests need a custom header plus a same-origin ``Origin`` (no CSRF).
- A strict Content-Security-Policy and other headers; no external resources at all.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable

from flask import Flask, abort, jsonify, make_response, redirect, render_template, request
from werkzeug.wrappers import Response

from ganki import paging
from ganki.service import ScanResult
from ganki.summary import RUNNING_KERNEL
from ganki.tools import OK, OUTDATED, VULNERABLE
from ganki.web import i18n
from ganki.web.jobs import DONE, IDLE, RUNNING, ScanJob

SESSION_COOKIE = "ganki_session"
LANG_COOKIE = "ganki_lang"
FILTERS = ("all", "outdated", "vulnerable")
MAX_QUERY_CHARS = 100
CSP = (
    "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; "
    "img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def uptime_text(seconds: int) -> str:
    """``273600`` -> ``3 d 4 h``."""
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    return f"{days} d {hours} h" if days else f"{hours} h {rest // 60} min"


def create_app(scan: Callable[[], ScanResult], secret: str, port: int) -> Flask:
    """Build the app. ``scan`` produces a ``ScanResult``; ``secret`` is the access token."""
    app = Flask(__name__)
    job = ScanJob(scan)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    app.jinja_env.filters["size"] = paging.human_size
    app.jinja_env.filters["bytes"] = lambda n: paging.human_size(int(n) // 1024)
    app.jinja_env.filters["uptime"] = uptime_text

    def authorized() -> bool:
        cookie = request.cookies.get(SESSION_COOKIE, "")
        return hmac.compare_digest(cookie.encode(), secret.encode())

    @app.before_request
    def guard() -> Response | None:
        if request.host not in allowed_hosts:
            abort(400)
        offered = request.args.get("access", "")
        if offered and hmac.compare_digest(offered.encode(), secret.encode()):
            response = redirect(request.path)  # drop the token from the address bar
            response.set_cookie(
                SESSION_COOKIE, secret, httponly=True, secure=True, samesite="Strict", path="/"
            )
            return response
        if not authorized():
            abort(403)
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("Origin")
            if request.headers.get("X-Ganki") != "1" or (
                origin is not None and origin.split("://", 1)[-1] not in allowed_hosts
            ):
                abort(403)
        return None

    @app.after_request
    def harden(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def current_language() -> str:
        return i18n.pick_language(
            request.cookies.get(LANG_COOKIE), request.headers.get("Accept-Language")
        )

    @app.route("/lang/<code>")
    def set_language(code: str) -> Response:
        if code not in i18n.LANGUAGES:
            abort(404)
        response = redirect("/")
        response.set_cookie(
            LANG_COOKIE, code, httponly=True, secure=True, samesite="Strict", path="/"
        )
        return response

    def tool_view(result: ScanResult) -> dict[str, object]:
        """Everything the tools table needs, taken from the query string."""
        show_all = request.args.get("show") == "all"
        chosen = request.args.get("f", "all")
        chosen = chosen if chosen in FILTERS else "all"
        query = request.args.get("q", "")[:MAX_QUERY_CHARS]
        universe = [t for t in result.tools if t.manual or show_all]
        wanted = {"outdated": OUTDATED, "vulnerable": VULNERABLE}.get(chosen)
        text = query.strip().lower()
        shown = [
            t
            for t in universe
            if (wanted is None or t.state == wanted)
            and (not text or text in t.name.lower() or text in t.description.lower())
        ]
        kernel = [r for r in result.risks if r.kind == RUNNING_KERNEL]
        return {
            "page": paging.paginate(shown, request.args.get("page", 1, type=int)),
            "counts": {
                "all": len(universe),
                "outdated": sum(1 for t in universe if t.state == OUTDATED),
                "vulnerable": sum(1 for t in universe if t.state == VULNERABLE),
                "ok": sum(1 for t in universe if t.state == OK),
            },
            "filter": chosen,
            "filters": FILTERS,
            "q": query,
            "show_all": show_all,
            "kernel": kernel[0] if kernel else None,
        }

    @app.route("/")
    def index() -> str:
        if job.state == IDLE:
            job.start()
        lang = current_language()
        result = job.result
        context: dict[str, object] = {
            "lang": lang,
            "t": lambda key, **values: i18n.translate(lang, key, **values),
            "state": job.state,
            "result": result,
        }
        if result is not None and job.state in (DONE, RUNNING):
            context.update(tool_view(result))
        return render_template("index.html", **context)

    @app.route("/api/status")
    def status() -> Response:
        return jsonify(state=job.state)

    @app.route("/api/rescan", methods=["POST"])
    def rescan() -> Response:
        started = job.start()
        return make_response(jsonify(started=started), 202 if started else 200)

    return app
