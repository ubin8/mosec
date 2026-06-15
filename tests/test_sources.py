from mosec import (
    AUTH_CONTEXT_SOURCE_MARKERS,
    AUTH_GUARD_MARKERS,
    BODY_SOURCE_MARKERS,
    COOKIE_SOURCE_MARKERS,
    HEADER_SOURCE_MARKERS,
    QUERY_SOURCE_MARKERS,
    SourceKind,
    USER_INPUT_SOURCE_KINDS,
    is_auth_context_reference,
    is_auth_guard_reference,
    is_body_source_reference,
    is_cookie_source_reference,
    is_header_source_reference,
    is_query_source_reference,
    is_role_guard_reference,
    is_user_input_source_kind,
)


def test_user_input_source_kinds_are_canonical() -> None:
    values = {kind.value for kind in USER_INPUT_SOURCE_KINDS}

    assert SourceKind.QUERY.value in values
    assert SourceKind.BODY.value in values
    assert SourceKind.HEADERS.value in values
    assert SourceKind.COOKIES.value in values
    assert SourceKind.PATH.value in values
    assert SourceKind.FORM.value in values
    assert SourceKind.REQUEST_INPUT.value in values
    assert SourceKind.SEARCH_PARAMS.value in values
    assert SourceKind.ROUTE_PARAM.value in values
    assert SourceKind.AUTH_CONTEXT.value not in values


def test_is_user_input_source_kind() -> None:
    assert is_user_input_source_kind(SourceKind.QUERY)
    assert is_user_input_source_kind("body")
    assert is_user_input_source_kind("request_input")
    assert is_user_input_source_kind("search_params")
    assert not is_user_input_source_kind("auth_context")
    assert not is_user_input_source_kind(None)


def test_header_source_markers_are_recognized() -> None:
    assert HEADER_SOURCE_MARKERS
    assert is_header_source_reference("req.headers.authorization")
    assert is_header_source_reference("request.headers['x-api-key']")
    assert is_header_source_reference("request()->header('x-forwarded-for')")
    assert is_header_source_reference("$request->header('x-tenant')")
    assert is_header_source_reference("@requestheader('X-Trace-Id')")
    assert is_header_source_reference("getHeader('X-Token')")
    assert not is_header_source_reference("request->input('name')")
    assert not is_header_source_reference(None)


def test_query_source_markers_are_recognized() -> None:
    assert QUERY_SOURCE_MARKERS
    assert is_query_source_reference("req.query.user")
    assert is_query_source_reference("request.args.get('next')")
    assert is_query_source_reference("request()->query('page')")
    assert is_query_source_reference("$request->query('redirect')")
    assert is_query_source_reference("$request->get('token')")
    assert is_query_source_reference("@requestparam('id')")
    assert is_query_source_reference("getParameter('name')")
    assert is_query_source_reference("searchParams.get('next')")
    assert not is_query_source_reference("request->header('x-api-key')")
    assert not is_query_source_reference(None)


def test_body_source_markers_are_recognized() -> None:
    assert BODY_SOURCE_MARKERS
    assert is_body_source_reference("req.body.user")
    assert is_body_source_reference("request.body")
    assert is_body_source_reference("request.form['name']")
    assert is_body_source_reference("request.get_json()['token']")
    assert is_body_source_reference("await request.json()")
    assert is_body_source_reference("$request->post('cmd')")
    assert is_body_source_reference("@RequestBody payload")
    assert is_body_source_reference("getInputStream()")
    assert not is_body_source_reference("request.headers['x-api-key']")
    assert not is_body_source_reference(None)


def test_cookie_source_markers_are_recognized() -> None:
    assert COOKIE_SOURCE_MARKERS
    assert is_cookie_source_reference("req.cookies.session")
    assert is_cookie_source_reference("request.cookies.get('next')")
    assert is_cookie_source_reference("request()->cookie('locale')")
    assert is_cookie_source_reference("$request->cookie('theme')")
    assert is_cookie_source_reference("cookies().get('session')")
    assert is_cookie_source_reference("request.COOKIES['csrftoken']")
    assert is_cookie_source_reference("@CookieValue('session')")
    assert is_cookie_source_reference("getCookie('session')")
    assert is_cookie_source_reference("getCookies()")
    assert not is_cookie_source_reference("request.headers['x-api-key']")
    assert not is_cookie_source_reference(None)


def test_auth_context_and_guard_markers_are_recognized() -> None:
    assert AUTH_CONTEXT_SOURCE_MARKERS
    assert AUTH_GUARD_MARKERS
    assert is_auth_context_reference("request.user")
    assert is_auth_context_reference("req.user")
    assert is_auth_context_reference("authentication")
    assert is_auth_context_reference("principal")
    assert is_auth_context_reference("SecurityContextHolder")
    assert is_auth_context_reference("auth()->user()")
    assert is_auth_context_reference("auth::user()")
    assert is_auth_guard_reference("login_required")
    assert is_auth_guard_reference("requireAuth()")
    assert is_auth_guard_reference("app.use(authMiddleware)")
    assert is_auth_guard_reference("withAuth()")
    assert is_auth_guard_reference("request.user.is_authenticated")
    assert is_auth_guard_reference("auth()->check()")
    assert is_role_guard_reference("hasRole('ADMIN')")
    assert is_role_guard_reference("authorize('admin')")
    assert is_auth_guard_reference("hasRole('ADMIN')")
    assert not is_auth_context_reference("request.headers['x-api-key']")
    assert not is_auth_guard_reference(None)
