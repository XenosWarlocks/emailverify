"""Stage 3: the Verimail API client.

Contract (https://verimail.io/docs/v3):

    POST https://api.verimail.io/v3/verify
    Authorization: Bearer <key>
    email=<address>&timeout=<ms>&evidence=<bool>

    200 -> verification ran; read `verdict`. Even a bad address is a 200.
    400 -> malformed parameter       }
    401 -> missing/invalid key       } { "status": "error", "code", "type",
    402 -> monthly limit exhausted   }   "message" }
    403 -> key inactive              }
    500 -> server-side failure       }

Billing matters to the design: `unknown` verdicts and local syntax errors are
NOT billed, `deliverable`/`risky`/most `undeliverable` results are. So 401/402/
403 abort the whole run immediately rather than burning through the remaining
rows, and every answer is cached so a re-run is free.
"""

from __future__ import annotations

import random
import threading
import time
from typing import Any

import requests

from emailverify.cache import ResultCache
from emailverify.config import ApiConfig
from emailverify.models import Action, ApiResult, Flags, REASON_BY_NAME, Verdict
from emailverify.ratelimit import TokenBucket


class VerimailError(Exception):
    """Base class for API failures."""


class VerimailFatalError(VerimailError):
    """Unrecoverable: bad key, exhausted quota, suspended account.

    The pipeline stops calling the API on these; continuing would fail every
    remaining row identically.
    """

    def __init__(self, message: str, status: int, payload: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.payload = payload or {}


class VerimailRequestError(VerimailError):
    """This one address was rejected by the API (HTTP 400). Others may be fine."""


class VerimailTransientError(VerimailError):
    """Temporary failure; retried with backoff."""


_FATAL_STATUSES = {401: "invalid or missing API key",
                   402: "monthly verification limit exhausted",
                   403: "API key inactive (check billing)"}

_RETRY_STATUSES = {408, 425, 429, 500, 502, 503, 504}


class VerimailClient:
    """Single-address verification with pacing, retries and caching."""

    def __init__(
        self,
        cfg: ApiConfig,
        cache: ResultCache | None = None,
        session: requests.Session | None = None,
    ) -> None:
        self.cfg = cfg
        self.cache = cache
        self.session = session or requests.Session()
        self.bucket = TokenBucket(cfg.requests_per_second)
        self.http_requests = 0      # includes retries
        self.addresses_sent = 0     # cache misses that reached the API
        self.calls_billed = 0       # credits actually consumed
        self._fatal: VerimailFatalError | None = None
        # Guards the counters and the budget reservation below. The pipeline
        # calls verify() from a thread pool, so a plain read-then-increment
        # would let one call per worker slip past the budget.
        self._lock = threading.Lock()
        self._reserved = 0          # potentially-billable calls in flight

    # -- public ------------------------------------------------------------- #

    @property
    def endpoint(self) -> str:
        return f"{self.cfg.base_url.rstrip('/')}/verify"

    @property
    def fatal(self) -> VerimailFatalError | None:
        """Set once a fatal error has been seen; callers should stop."""
        return self._fatal

    def preflight(self) -> str:
        """Validate the API key without spending a credit.

        Submitting an empty address returns HTTP 200 with a syntax_error
        verdict, which is explicitly not billed -- so this proves the key works
        for free. A bad key returns 401 instead.
        """
        self.cfg.require_key()
        try:
            resp = self._post({"email": ""})
        except VerimailRequestError as exc:
            # HTTP 400 on an empty address still proves the key authenticated;
            # only the parameter was rejected.
            return f"key accepted (api rejected the empty probe: {exc})"
        # Fatal (401/402/403) and transient (network, 5xx) errors both
        # propagate: a connection failure is NOT a working key, and reporting
        # it as one is worse than reporting nothing.
        verdict = resp.get("verdict") or resp.get("result") or "unknown"
        return f"key accepted (empty-address probe -> {verdict})"

    def verify(self, email: str) -> ApiResult:
        """Verify one address. Never raises for a per-address problem."""
        if self._fatal is not None:
            return ApiResult(email=email, error=f"skipped: {self._fatal}")

        if self.cache is not None:
            cached = self.cache.get_api(email, self.cfg.cache_ttl_hours)
            if cached is not None:
                result = self._parse(email, cached)
                result.from_cache = True
                result.billed = False  # a cache hit costs nothing
                return result

        # The guard rail counts *credits*, not HTTP requests: unknown verdicts
        # and syntax errors come back unbilled and should not eat the budget.
        # Reserve a slot before sending so `billed + in-flight` can never
        # exceed the budget, however many workers are running.
        if not self._reserve():
            return ApiResult(
                email=email,
                error=f"skipped: --max-api-calls budget of {self.cfg.max_calls} credits reached",
            )

        payload: dict[str, Any] = {
            "email": email,
            "timeout": str(self.cfg.verify_timeout_ms),
        }
        if self.cfg.evidence:
            payload["evidence"] = "true"

        with self._lock:
            self.addresses_sent += 1
        try:
            raw = self._post(payload)
        except VerimailFatalError as exc:
            self._fatal = exc
            self._release(billed=False)
            return ApiResult(email=email, error=f"fatal: {exc}")
        except VerimailError as exc:
            self._release(billed=False)
            return ApiResult(email=email, error=str(exc))

        result = self._parse(email, raw)
        self._release(billed=result.billed)
        if self.cache is not None and result.ok:
            self.cache.put_api(email, raw)
        return result

    def _reserve(self) -> bool:
        """Claim one unit of the credit budget. False means the budget is spent."""
        with self._lock:
            if self.cfg.max_calls and self.calls_billed + self._reserved >= self.cfg.max_calls:
                return False
            self._reserved += 1
            return True

    def _release(self, billed: bool) -> None:
        """Convert a reservation into a spent credit, or hand it back."""
        with self._lock:
            self._reserved -= 1
            if billed:
                self.calls_billed += 1

    # -- transport ---------------------------------------------------------- #

    def _post(self, data: dict[str, Any]) -> dict[str, Any]:
        key = self.cfg.require_key()
        headers = {
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
            "User-Agent": "emailverify/0.1 (+hubspot-export-pipeline)",
        }
        last_error: Exception | None = None

        for attempt in range(self.cfg.max_retries + 1):
            self.bucket.acquire()
            try:
                self.http_requests += 1
                resp = self.session.post(
                    self.endpoint, data=data, headers=headers, timeout=self.cfg.http_timeout
                )
            except requests.RequestException as exc:
                last_error = VerimailTransientError(f"network error: {exc}")
                self._sleep_backoff(attempt, None)
                continue

            if resp.status_code in _FATAL_STATUSES:
                raise VerimailFatalError(
                    f"HTTP {resp.status_code}: {_FATAL_STATUSES[resp.status_code]} "
                    f"({self._error_message(resp)})",
                    status=resp.status_code,
                    payload=self._json_or_empty(resp),
                )

            if resp.status_code == 200:
                body = self._json_or_empty(resp)
                if not body:
                    last_error = VerimailTransientError("200 with unparseable body")
                    self._sleep_backoff(attempt, resp)
                    continue
                return body

            if resp.status_code == 400:
                raise VerimailRequestError(f"HTTP 400: {self._error_message(resp)}")

            if resp.status_code in _RETRY_STATUSES:
                last_error = VerimailTransientError(
                    f"HTTP {resp.status_code}: {self._error_message(resp)}"
                )
                self._sleep_backoff(attempt, resp)
                continue

            raise VerimailRequestError(f"HTTP {resp.status_code}: {self._error_message(resp)}")

        raise last_error or VerimailTransientError("exhausted retries")

    def _sleep_backoff(self, attempt: int, resp: requests.Response | None) -> None:
        if attempt >= self.cfg.max_retries:
            return
        # Honour Retry-After when the server sends one; otherwise exponential
        # backoff with jitter so parallel workers do not resynchronise.
        if resp is not None:
            retry_after = resp.headers.get("Retry-After", "").strip()
            if retry_after:
                try:
                    time.sleep(min(60.0, float(retry_after)))
                    return
                except ValueError:
                    pass
        delay = min(30.0, (2.0 ** attempt)) * (0.5 + random.random())
        time.sleep(delay)

    @staticmethod
    def _json_or_empty(resp: requests.Response) -> dict[str, Any]:
        try:
            body = resp.json()
        except ValueError:
            return {}
        return body if isinstance(body, dict) else {}

    @classmethod
    def _error_message(cls, resp: requests.Response) -> str:
        body = cls._json_or_empty(resp)
        msg = body.get("message") or body.get("type") or ""
        if msg:
            return str(msg)
        return (resp.text or "").strip()[:200] or "no message"

    # -- response parsing --------------------------------------------------- #

    @staticmethod
    def _parse(email: str, body: dict[str, Any]) -> ApiResult:
        """Map a v3 response onto ApiResult.

        Reads the modern fields (`verdict`/`reason`/`suggested_action`) and
        falls back to the frozen legacy fields (`result`/`deliverable`/`code`)
        so the client keeps working if an older key is pinned to the legacy
        response shape.
        """
        flags_in = body.get("flags") or {}
        flags = Flags(
            disposable=bool(flags_in.get("disposable")),
            role_account=bool(flags_in.get("role_account")),
            free_provider=bool(flags_in.get("free_provider")),
            catch_all=bool(flags_in.get("catch_all")),
        )

        raw_verdict = str(body.get("verdict") or "").lower()
        label = str(body.get("result") or "")
        if raw_verdict in {v.value for v in Verdict}:
            verdict = Verdict(raw_verdict)
        else:
            # Legacy shape: derive a verdict from `result`.
            verdict = {
                "deliverable": Verdict.DELIVERABLE,
                "catch_all": Verdict.RISKY,
                "inbox_full": Verdict.RISKY,
                "disposable": Verdict.RISKY,
                "hardbounce": Verdict.UNDELIVERABLE,
                "softbounce": Verdict.UNDELIVERABLE,
                "undeliverable": Verdict.UNDELIVERABLE,
                "syntax_error": Verdict.UNDELIVERABLE,
            }.get(label.lower(), Verdict.UNKNOWN)

        raw_action = str(body.get("suggested_action") or "").lower()
        if raw_action in {a.value for a in Action}:
            action = Action(raw_action)
        else:
            action = {
                Verdict.DELIVERABLE: Action.ACCEPT,
                Verdict.UNDELIVERABLE: Action.REJECT,
                Verdict.RISKY: Action.ACCEPT_AND_CONFIRM,
                Verdict.UNKNOWN: Action.ACCEPT_AND_CONFIRM,
            }[verdict]

        reason = str(body.get("reason") or "")
        code = body.get("code")
        try:
            code_int = int(code) if code is not None else REASON_BY_NAME.get(reason)
        except (TypeError, ValueError):
            code_int = REASON_BY_NAME.get(reason)

        return ApiResult(
            email=str(body.get("email") or email),
            verdict=verdict,
            reason=reason,
            code=code_int,
            suggested_action=action,
            did_you_mean=str(body.get("did_you_mean") or ""),
            billed=bool(body.get("billed", verdict is not Verdict.UNKNOWN)),
            provider=str(body.get("provider") or ""),
            latency_ms=int(body.get("latency_ms") or 0),
            flags=flags,
            deliverable=bool(body.get("deliverable", verdict is Verdict.DELIVERABLE)),
            result_label=label,
            evidence=body.get("evidence") or {},
            raw=body,
        )
