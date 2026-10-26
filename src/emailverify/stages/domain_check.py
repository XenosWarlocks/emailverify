"""Stage 2: is the domain alive for mail?

This is the "ping the domain" step. Note that it is deliberately *not* ICMP
ping -- whether a domain answers ICMP says nothing about whether it accepts
mail, and plenty of mail-accepting domains drop ping entirely. The question
that actually matters is the one SMTP asks:

1. MX records? Those name the hosts that accept mail. A single "." MX
   (RFC 7505 null MX) is an explicit declaration that the domain accepts NO
   mail -- that is a definitive dead answer, not a missing one.
2. No MX, but an A/AAAA record? RFC 5321 5.1 says fall back to it as an
   implicit MX. Rarer every year, still real.
3. NXDOMAIN? The domain does not exist. Definitively dead.
4. Timeout / SERVFAIL? Unknown, not dead. The distinction is the whole point:
   a resolver hiccup must never mark a good contact as invalid.

Optionally also: SPF/DMARC presence (a domain that sends real mail almost
always publishes SPF -- useful signal on whether this is a real org) and a TCP
connect to port 25 on the primary MX.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from typing import Callable, Iterable

import dns.exception
import dns.rdatatype
import dns.resolver

from emailverify.cache import ResultCache
from emailverify.config import DnsConfig
from emailverify.models import DomainResult, DomainStatus
from emailverify.rules.classify import registrable_provider


class DomainChecker:
    """Resolves mail-related DNS for domains, with caching and a thread pool."""

    def __init__(
        self,
        cfg: DnsConfig | None = None,
        cache: ResultCache | None = None,
        resolver: dns.resolver.Resolver | None = None,
    ) -> None:
        self.cfg = cfg or DnsConfig()
        self.cache = cache
        self.resolver = resolver or self._build_resolver()

    def _build_resolver(self) -> dns.resolver.Resolver:
        r = dns.resolver.Resolver(configure=True)
        if self.cfg.nameservers:
            r.nameservers = list(self.cfg.nameservers)
        r.timeout = self.cfg.timeout
        r.lifetime = self.cfg.lifetime
        return r

    # -- single domain ------------------------------------------------------ #

    def check(self, domain: str) -> DomainResult:
        domain = domain.lower().rstrip(".")
        if not domain:
            return DomainResult(domain="", status=DomainStatus.NXDOMAIN, error="empty domain")

        if self.cache is not None:
            cached = self.cache.get_domain(domain, self.cfg.cache_ttl_hours)
            if cached is not None:
                return self._from_payload(cached)

        started = time.perf_counter()
        result = self._resolve(domain)
        result.elapsed_ms = int((time.perf_counter() - started) * 1000)

        # Never cache a transient failure -- that would pin a good domain to
        # "unknown" for the whole TTL.
        if self.cache is not None and result.status is not DomainStatus.DNS_ERROR:
            self.cache.put_domain(domain, self._to_payload(result))
        return result

    def _resolve(self, domain: str) -> DomainResult:
        res = DomainResult(domain=domain)

        try:
            answers = self.resolver.resolve(domain, "MX", raise_on_no_answer=False)
            records = sorted(
                ((r.preference, str(r.exchange).rstrip(".")) for r in answers),
                key=lambda t: t[0],
            ) if answers.rrset is not None else []
        except dns.resolver.NXDOMAIN:
            res.status = DomainStatus.NXDOMAIN
            res.error = "domain does not exist"
            return res
        except dns.resolver.NoNameservers as exc:
            res.status = DomainStatus.DNS_ERROR
            res.error = f"no working nameserver: {exc.__class__.__name__}"
            return res
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            res.status = DomainStatus.DNS_ERROR
            res.error = "dns timeout"
            return res
        except dns.exception.DNSException as exc:
            res.status = DomainStatus.DNS_ERROR
            res.error = f"dns error: {exc.__class__.__name__}"
            return res

        # RFC 7505: a lone "." exchange means "this domain accepts no mail".
        if len(records) == 1 and records[0][1] in {"", "."}:
            res.null_mx = True
            res.status = DomainStatus.NO_MAIL_SERVER
            res.error = "null MX (RFC 7505): domain declares it accepts no mail"
            return res

        res.mx_hosts = [host for _, host in records if host not in {"", "."}]
        if res.mx_hosts:
            res.status = DomainStatus.ACTIVE
            res.provider = registrable_provider(res.mx_hosts)
        else:
            # No MX -- fall back to the address record.
            res.has_a_record = self._has_address_record(domain)
            if res.has_a_record:
                res.implicit_mx = True
                res.status = DomainStatus.ACTIVE
                res.provider = domain
            else:
                res.status = DomainStatus.NO_MAIL_SERVER
                res.error = "no MX and no A/AAAA record"
                return res

        if self.cfg.check_spf:
            res.has_spf = self._has_txt_prefix(domain, "v=spf1")
            res.spf_checked = True
        if self.cfg.check_dmarc:
            res.has_dmarc = self._has_txt_prefix(f"_dmarc.{domain}", "v=DMARC1")
            res.dmarc_checked = True
        if self.cfg.smtp_probe and res.mx_hosts:
            res.smtp_reachable, res.smtp_banner = self._probe_smtp(res.mx_hosts[0])

        return res

    def _has_address_record(self, domain: str) -> bool:
        for rtype in ("A", "AAAA"):
            try:
                ans = self.resolver.resolve(domain, rtype, raise_on_no_answer=False)
                if ans.rrset is not None and len(ans.rrset) > 0:
                    return True
            except dns.exception.DNSException:
                continue
        return False

    def _has_txt_prefix(self, name: str, prefix: str) -> bool:
        try:
            ans = self.resolver.resolve(name, "TXT", raise_on_no_answer=False)
        except dns.exception.DNSException:
            return False
        if ans.rrset is None:
            return False
        for rdata in ans:
            # TXT rdata is a tuple of byte strings that must be concatenated
            # before matching -- long records are split at 255 bytes.
            joined = b"".join(rdata.strings).decode("utf-8", "replace")
            if joined.lower().startswith(prefix.lower()):
                return True
        return False

    def _probe_smtp(self, host: str) -> tuple[bool, str]:
        """TCP-connect to port 25 and read the greeting.

        Only ever a positive signal: a failure here usually means the local
        network blocks port 25, not that the server is down. Callers must not
        downgrade a domain on the strength of a failed probe.
        """
        try:
            with socket.create_connection((host, 25), timeout=self.cfg.smtp_probe_timeout) as sock:
                sock.settimeout(self.cfg.smtp_probe_timeout)
                banner = sock.recv(512).decode("utf-8", "replace").strip()
                return True, banner[:200]
        except OSError as exc:
            return False, f"{exc.__class__.__name__}: {exc}"

    # -- batch -------------------------------------------------------------- #

    def check_many(
        self,
        domains: Iterable[str],
        progress: Callable[[str, DomainResult], None] | None = None,
    ) -> dict[str, DomainResult]:
        """Resolve a set of domains concurrently. Deduplicates first."""
        unique = sorted({d.lower().rstrip(".") for d in domains if d})
        if not unique:
            return {}

        results: dict[str, DomainResult] = {}
        workers = max(1, min(self.cfg.workers, len(unique)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dns") as pool:
            for domain, result in zip(unique, pool.map(self.check, unique)):
                results[domain] = result
                if progress is not None:
                    progress(domain, result)
        return results

    # -- cache serialization ------------------------------------------------ #

    @staticmethod
    def _to_payload(result: DomainResult) -> dict:
        payload = asdict(result)
        payload["status"] = result.status.value
        payload.pop("from_cache", None)
        return payload

    @staticmethod
    def _from_payload(payload: dict) -> DomainResult:
        data = dict(payload)
        data["status"] = DomainStatus(data.get("status", "not_checked"))
        data.pop("from_cache", None)
        allowed = {f for f in DomainResult.__slots__}
        result = DomainResult(**{k: v for k, v in data.items() if k in allowed})
        result.from_cache = True
        return result
