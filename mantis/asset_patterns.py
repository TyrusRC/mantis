"""Pattern definitions for the asset map scanner.

Each pattern: (compiled_regex, kind, label, frozenset_of_languages).
Regex named groups ``method``, ``path``, ``name`` are used by the
scanner to build human-readable asset names.
"""
from __future__ import annotations

import re

from mantis.slice import EXT_TO_LANG

_PY = frozenset({"python"})
_JS = frozenset({"javascript", "typescript"})
_JV = frozenset({"java"})
_JK = frozenset({"java", "kotlin"})
_SW = frozenset({"swift"})
_GO = frozenset({"go"})
_RB = frozenset({"ruby"})
_PH = frozenset({"php"})
_CS = frozenset({"csharp"})
_RS = frozenset({"rust"})
_ALL = frozenset(EXT_TO_LANG.values())

EXT_EXTRA: dict[str, str] = {}  # .cs now in EXT_TO_LANG; kept for API compat

PatDef = tuple[re.Pattern, str, str, frozenset[str]]


def _p(pattern: str, kind: str, label: str, langs: frozenset[str],
       flags: int = 0) -> PatDef:
    return (re.compile(pattern, flags), kind, label, langs)


PATTERN_DEFS: list[PatDef] = [
    # ---------------------------------------------------------------
    # ENTRY POINTS
    # ---------------------------------------------------------------

    # Python -- Flask / Quart
    _p(r"@(?:app|bp|blueprint)\s*\.\s*(?P<method>route|get|post|put|delete|patch)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "flask", _PY),
    # Python -- FastAPI / Starlette
    _p(r"@(?:app|router)\s*\.\s*(?P<method>get|post|put|delete|patch|options|head|websocket)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "fastapi", _PY),
    # Python -- Django URL config
    _p(r"^\s*(?:path|re_path|url)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "django-url", _PY),
    # Python -- DRF
    _p(r"@api_view\s*\(\s*\[(?P<method>[^\]]+)\]",
       "entrypoint", "drf", _PY),
    _p(r"class\s+(?P<name>\w+)\s*\(.*(?:APIView|ViewSet|ModelViewSet|GenericAPIView)",
       "entrypoint", "drf-class", _PY),
    # Python -- Tornado
    _p(r"class\s+(?P<name>\w+Handler)\s*\(.*RequestHandler",
       "entrypoint", "tornado", _PY),

    # JS/TS -- Express / Koa / Hono / Fastify
    _p(r"(?:app|router|server)\s*\.\s*(?P<method>get|post|put|delete|patch|all|use)\s*\(\s*['\"](?P<path>/[^'\"]*)['\"]",
       "entrypoint", "express", _JS),
    _p(r"(?:fastify)\s*\.\s*(?P<method>get|post|put|delete|patch)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "fastify", _JS),
    # JS/TS -- Next.js App Router / Pages API
    _p(r"export\s+(?:default\s+)?(?:async\s+)?function\s+(?P<name>GET|POST|PUT|DELETE|PATCH|handler)\b",
       "entrypoint", "nextjs", _JS),

    # Java / Kotlin -- Spring
    _p(r"@(?P<method>GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(\s*['\"](?P<path>[^'\"]+)['\"])?",
       "entrypoint", "spring", _JK),
    _p(r"@RestController", "entrypoint", "spring-controller", _JK),
    # Java -- JAX-RS
    _p(r"@(?P<method>GET|POST|PUT|DELETE|PATCH)\b",
       "entrypoint", "jaxrs", _JV),
    _p(r"@Path\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "jaxrs-path", _JV),
    # Java -- Servlet
    _p(r"(?:void|public)\s+(?P<method>doGet|doPost|doPut|doDelete|service)\s*\(",
       "entrypoint", "servlet", _JV),

    # Swift -- iOS lifecycle / URL handling
    _p(r"(?:override\s+)?func\s+(?P<name>viewDidLoad|viewWillAppear|viewDidAppear|applicationDidFinishLaunching|didFinishLaunchingWithOptions|didReceiveRemoteNotification)\b",
       "entrypoint", "ios-lifecycle", _SW),
    _p(r"func\s+application\s*\(.*open\s+url",
       "entrypoint", "ios-url-scheme", _SW),

    # Go -- net/http, mux, Gin, Echo, Fiber
    _p(r"http\.HandleFunc\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "go-http", _GO),
    _p(r"(?:mux|router|r|e|app|g)\s*\.\s*(?P<method>GET|POST|PUT|DELETE|PATCH|Get|Post|Put|Delete|HandleFunc|Handle)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "go-router", _GO),
    _p(r"func\s+(?P<name>\w+)\s*\(\s*\w+\s+http\.ResponseWriter",
       "entrypoint", "go-handler", _GO),

    # Ruby -- Rails routes / Sinatra
    _p(r"^\s*(?P<method>get|post|put|patch|delete)\s+['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "rails-route", _RB),
    _p(r"^\s*resources?\s+:(?P<name>\w+)",
       "entrypoint", "rails-resource", _RB),

    # PHP -- Laravel
    _p(r"Route\s*::\s*(?P<method>get|post|put|patch|delete)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "laravel", _PH),

    # C# / .NET
    _p(r"\[\s*Http(?P<method>Get|Post|Put|Delete|Patch)",
       "entrypoint", "aspnet", _CS),
    _p(r"\[\s*Route\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "aspnet-route", _CS),
    _p(r"app\.Map(?P<method>Get|Post|Put|Delete|Patch)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "aspnet-minimal", _CS),

    # Rust -- Actix / Axum
    _p(r"#\[(?P<method>get|post|put|delete|patch)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "actix", _RS),
    _p(r"\.(?P<method>get|post|put|delete|patch)\s*\(\s*['\"](?P<path>[^'\"]+)['\"]",
       "entrypoint", "axum", _RS),

    # ---------------------------------------------------------------
    # MIDDLEWARE / TRUST BOUNDARIES
    # ---------------------------------------------------------------

    # Python
    _p(r"@(?P<name>login_required|permission_required|permissions_required|jwt_required|token_required|requires_auth|auth_required)\b",
       "middleware", "py-auth-decorator", _PY),
    _p(r"Depends\s*\(\s*(?P<name>get_current_user|verify_token|authenticate|require_auth)\b",
       "middleware", "fastapi-depends", _PY),
    _p(r"permission_classes\s*=\s*\[(?P<name>[^\]]+)\]",
       "middleware", "drf-permission", _PY),

    # JS/TS
    _p(r"passport\.authenticate\s*\(\s*['\"](?P<name>[^'\"]+)['\"]",
       "middleware", "passport", _JS),
    _p(r"(?:jwt|jsonwebtoken)\s*\.\s*verify\s*\(",
       "middleware", "jwt-verify", _JS),
    _p(r"app\.use\s*\(\s*(?P<name>auth|authenticate|requireAuth|isAuthenticated|protect)\s*[\(,)]",
       "middleware", "express-auth-mw", _JS),
    _p(r"app\.use\s*\(\s*(?:helmet|cors|csurf|rateLimit)\s*\(",
       "middleware", "security-mw", _JS),

    # Java / Kotlin -- Spring Security
    _p(r"@PreAuthorize\s*\(\s*['\"](?P<name>[^'\"]+)['\"]",
       "middleware", "spring-preauth", _JK),
    _p(r"@Secured\s*\(\s*['\"](?P<name>[^'\"]+)['\"]",
       "middleware", "spring-secured", _JK),
    _p(r"@RolesAllowed\s*\(\s*['\"](?P<name>[^'\"]+)['\"]",
       "middleware", "jaxrs-roles", _JK),

    # Go
    _p(r"(?:Auth|Authenticate|RequireAuth|JWTMiddleware|TokenAuth)\s*\(",
       "middleware", "go-auth-mw", _GO),

    # Ruby
    _p(r"before_action\s+:(?P<name>authenticate\w*|require_login|authorize\w*)",
       "middleware", "rails-before-action", _RB),

    # PHP -- Laravel
    _p(r"->middleware\s*\(\s*['\"](?P<name>auth[^'\"]*)['\"]",
       "middleware", "laravel-mw", _PH),

    # C#
    _p(r"\[\s*(?P<name>Authorize|AllowAnonymous)\s*\]",
       "middleware", "aspnet-auth", _CS),

    # ---------------------------------------------------------------
    # DATA STORES
    # ---------------------------------------------------------------

    # Python -- raw SQL, Django ORM, SQLAlchemy
    _p(r"(?:cursor|conn|connection|db)\s*\.\s*(?P<name>execute|executemany|executescript)\s*\(",
       "datastore", "sql-execute", _PY),
    _p(r"(?:session|db)\s*\.\s*(?P<name>query|add|delete|merge|flush|commit)\s*\(",
       "datastore", "sqlalchemy", _PY),
    _p(r"\.objects\s*\.\s*(?P<name>filter|exclude|get|create|update|delete|raw|extra|annotate)\s*\(",
       "datastore", "django-orm", _PY),

    # JS/TS -- Sequelize, Prisma, Knex, mongoose, raw
    _p(r"(?:db|pool|client|connection)\s*\.\s*(?P<name>query|execute)\s*\(",
       "datastore", "sql-query", _JS),
    _p(r"prisma\s*\.\s*\w+\s*\.\s*(?P<name>findMany|findUnique|findFirst|create|update|delete|upsert)\s*\(",
       "datastore", "prisma", _JS),
    _p(r"(?:mongoose|Model|Schema)\s*\.\s*(?P<name>find|findOne|findById|create|updateOne|deleteOne|aggregate)\s*\(",
       "datastore", "mongoose", _JS),

    # Java / Kotlin -- JDBC, JPA, Spring Data
    _p(r"(?:PreparedStatement|Statement)\s*.*\.\s*(?P<name>executeQuery|executeUpdate|execute)\s*\(",
       "datastore", "jdbc", _JK),
    _p(r"(?:entityManager|em)\s*\.\s*(?P<name>createQuery|createNativeQuery|find|persist|merge|remove)\s*\(",
       "datastore", "jpa", _JK),
    _p(r"(?:jdbcTemplate|namedParameterJdbcTemplate)\s*\.\s*(?P<name>query|update|execute|batchUpdate)\s*\(",
       "datastore", "spring-jdbc", _JK),

    # Go -- database/sql, GORM
    _p(r"(?:db|tx)\s*\.\s*(?P<name>Query|QueryRow|Exec|Prepare)\s*\(",
       "datastore", "go-sql", _GO),
    _p(r"(?:db|tx)\s*\.\s*(?P<name>Find|First|Create|Save|Delete|Where|Raw)\s*\(",
       "datastore", "gorm", _GO),

    # Ruby -- ActiveRecord
    _p(r"\.(?P<name>where|find|find_by|create|update|destroy|pluck|select)\s*\(",
       "datastore", "activerecord", _RB),

    # PHP -- Eloquent, DB facade
    _p(r"DB\s*::\s*(?P<name>select|insert|update|delete|statement|raw)\s*\(",
       "datastore", "laravel-db", _PH),
    _p(r"::\s*(?P<name>where|find|findOrFail|create|update|delete|firstOrCreate)\s*\(",
       "datastore", "eloquent", _PH),

    # C# -- EF Core, ADO.NET
    _p(r"(?:context|dbContext|_context|_db)\s*\.\s*\w+\s*\.\s*(?P<name>Add|Remove|Update|Find|FirstOrDefault|Where|ToList)\s*\(",
       "datastore", "ef-core", _CS),
    _p(r"(?:SqlCommand|command)\s*\.\s*(?P<name>ExecuteReader|ExecuteNonQuery|ExecuteScalar)\s*\(",
       "datastore", "ado-net", _CS),

    # Redis / cache (multi-lang)
    _p(r"(?:redis|cache|memcached)\s*\.\s*(?P<name>get|set|del|hget|hset|lpush|rpush|sadd|incr)\s*\(",
       "datastore", "redis", _PY | _JS | _RB | _GO | _PH),

    # ---------------------------------------------------------------
    # EXTERNAL CALLS
    # ---------------------------------------------------------------

    # Python -- requests, httpx, aiohttp, urllib
    _p(r"(?:requests|httpx|aiohttp|session)\s*\.\s*(?P<name>get|post|put|delete|patch|head|request)\s*\(",
       "external", "py-http", _PY),
    _p(r"(?:urllib\.request\.urlopen|urlopen)\s*\(",
       "external", "urllib", _PY),
    _p(r"boto3\s*\.\s*(?P<name>client|resource|Session)\s*\(",
       "external", "aws-sdk", _PY),

    # JS/TS -- fetch, axios, http
    _p(r"\bfetch\s*\(\s*['\"`](?P<path>[^'\"`]+)['\"`]",
       "external", "fetch", _JS),
    _p(r"axios\s*\.\s*(?P<name>get|post|put|delete|patch|request)\s*\(",
       "external", "axios", _JS),

    # Java / Kotlin -- HttpClient, RestTemplate, WebClient
    _p(r"(?:HttpClient|httpClient|client)\s*\.\s*(?P<name>send|sendAsync|newCall)\s*\(",
       "external", "java-http", _JK),
    _p(r"(?:restTemplate|webClient)\s*\.\s*(?P<name>getForObject|getForEntity|postForObject|exchange|retrieve|get|post)\s*\(",
       "external", "spring-http", _JK),

    # Go
    _p(r"http\s*\.\s*(?P<name>Get|Post|PostForm|Head|NewRequest)\s*\(",
       "external", "go-http", _GO),

    # Ruby
    _p(r"(?:Net::HTTP|HTTParty|Faraday|RestClient)\s*\.\s*(?P<name>get|post|put|delete|new)\s*\(?",
       "external", "ruby-http", _RB),

    # PHP
    _p(r"(?:Http|Guzzle|curl_exec|file_get_contents)\s*(?:::|\s*\.\s*|\s*\()",
       "external", "php-http", _PH),

    # C#
    _p(r"(?:HttpClient|httpClient|_client)\s*\.\s*(?P<name>GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync|GetStringAsync)\s*\(",
       "external", "dotnet-http", _CS),

    # ---------------------------------------------------------------
    # SENSITIVE DATA
    # ---------------------------------------------------------------

    _p(r"(?:^|[\s(,{=:])\s*(?P<name>password|passwd|secret|api_key|apikey|api_secret|"
       r"access_token|refresh_token|private_key|client_secret|auth_token|"
       r"session_token|jwt_secret|encryption_key|master_key)\s*[=:,)\]}]",
       "sensitive", "credential-var", _ALL,
       re.IGNORECASE),
    _p(r"(?:^|[\s(,{=:])\s*(?P<name>credit_card|card_number|cvv|ssn|"
       r"social_security|date_of_birth|phone_number|bank_account)\s*[=:,)\]}]",
       "sensitive", "pii-var", _ALL,
       re.IGNORECASE),
]


# Per-language lookup, built once at import time.
LANG_PATTERNS: dict[str, list[tuple[re.Pattern, str, str]]] = {}
for _rx, _kind, _label, _langs in PATTERN_DEFS:
    for _lang in _langs:
        LANG_PATTERNS.setdefault(_lang, []).append((_rx, _kind, _label))
