from __future__ import annotations

from enum import StrEnum


class SourceKind(StrEnum):
    QUERY = "query"
    BODY = "body"
    HEADERS = "headers"
    COOKIES = "cookies"
    PATH = "path"
    FORM = "form"
    REQUEST_INPUT = "request_input"
    SEARCH_PARAMS = "search_params"
    ROUTE_PARAM = "route_param"
    AUTH_CONTEXT = "auth_context"


AUTH_CONTEXT_SOURCE_MARKERS: tuple[str, ...] = (
    "request.user",
    "req.user",
    "request.auth",
    "request.authentication",
    "authentication",
    "principal",
    "securitycontextholder",
    "auth()->user(",
    "auth::user(",
    "auth.user(",
    "current_user",
)


AUTH_GUARD_MARKERS: tuple[str, ...] = (
    "login_required",
    "permission_required",
    "auth_required",
    "requires_auth",
    "ensureauthenticated",
    "is_authenticated",
    "request.user.is_authenticated",
    "req.user.is_authenticated",
    "auth()->check(",
    "auth::check(",
    "requireauth",
    "authenticate",
    "authmiddleware",
    "middlewareauth",
    "withauth",
    "useauth(",
    "requireauth(",
    "authmiddleware(",
    "middlewareauth(",
    "withauth(",
)


ROLE_GUARD_MARKERS: tuple[str, ...] = (
    "hasrole(",
    "hasroles(",
    "haspermission(",
    "haspermissions(",
    "hasanyrole(",
    "hasanyroles(",
    "can(",
    "authorize(",
    "is_admin",
    "isadministrator",
    "checkrole(",
    "checkpermission(",
    "gate::allows(",
    "gate::denies(",
    "gate::allowsany(",
    "user.has_role(",
    "user.has_roles(",
    "user.has_permission(",
    "user.has_permissions(",
    "roles.includes(",
    "role.includes(",
    "permissions.includes(",
)


COOKIE_SOURCE_MARKERS: tuple[str, ...] = (
    "req.cookies",
    "request.cookies",
    "request.cookies.get(",
    "request.cookie(",
    "request()->cookie(",
    "$request->cookie(",
    "cookies().get(",
    "cookies(",
    "request.cookies[",
    "request.getcookies(",
    "request.getcookie(",
    "request.cookies()",
    "request.cookies['",
    "request.cookies[\"",
    "request.cookie",
    "request.COOKIES",
    "request.get_signed_cookie(",
    "@cookievalue",
    "cookievalue(",
    "getcookies(",
    "getcookie(",
)


BODY_SOURCE_MARKERS: tuple[str, ...] = (
    "req.body",
    "request.body",
    "request.form",
    "request.json",
    "request.get_json(",
    "request.get_data(",
    "request.get_data()",
    "request()->json(",
    "request()->post(",
    "request.getjson(",
    "request()->getjson(",
    "await request.json",
    "await req.json",
    "$request->json(",
    "$request->post(",
    "request.post",
    "@requestbody",
    "requestbody(",
    "getreader(",
    "getinputstream(",
)


QUERY_SOURCE_MARKERS: tuple[str, ...] = (
    "req.query",
    "request.query",
    "request.args",
    "request.get(",
    "request.get_json(",
    "request.querystring",
    "request.params",
    "request()->query(",
    "$request->query(",
    "$request->get(",
    "$request->input(",
    "@requestparam",
    "getparameter(",
    "getquerystring(",
    "searchparams.get(",
)


HEADER_SOURCE_MARKERS: tuple[str, ...] = (
    "request.headers",
    "req.headers",
    "request.meta",
    "request.header(",
    "request()->header(",
    "$request->header(",
    "@requestheader",
    "getheader(",
)


USER_INPUT_SOURCE_KINDS: tuple[SourceKind, ...] = (
    SourceKind.QUERY,
    SourceKind.BODY,
    SourceKind.HEADERS,
    SourceKind.COOKIES,
    SourceKind.PATH,
    SourceKind.FORM,
    SourceKind.REQUEST_INPUT,
    SourceKind.SEARCH_PARAMS,
    SourceKind.ROUTE_PARAM,
)


def is_user_input_source_kind(value: str | SourceKind | None) -> bool:
    if value is None:
        return False
    try:
        return SourceKind(value) in USER_INPUT_SOURCE_KINDS
    except ValueError:
        return False


def is_header_source_reference(value: str | None) -> bool:
    if value is None:
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in HEADER_SOURCE_MARKERS)


def is_query_source_reference(value: str | None) -> bool:
    if value is None:
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in QUERY_SOURCE_MARKERS)


def is_body_source_reference(value: str | None) -> bool:
    if value is None:
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in BODY_SOURCE_MARKERS)


def is_cookie_source_reference(value: str | None) -> bool:
    if value is None:
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in COOKIE_SOURCE_MARKERS)


def is_auth_context_reference(value: str | None) -> bool:
    if value is None:
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in AUTH_CONTEXT_SOURCE_MARKERS)


def is_auth_guard_reference(value: str | None) -> bool:
    if value is None:
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in AUTH_GUARD_MARKERS) or is_role_guard_reference(lowered)


def is_role_guard_reference(value: str | None) -> bool:
    if value is None:
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in ROLE_GUARD_MARKERS)
