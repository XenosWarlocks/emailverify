"""Three-stage email verification for HubSpot contact exports.

Stage 1  rules     -- syntax (RFC 5321/5322 subset), disposable / role / free /
                      relay classification, typo suggestions. Free, offline.
Stage 2  domain    -- MX / A / null-MX resolution: does the domain take mail?
                      Cached per domain. This is what sets the initial status.
Stage 3  verimail  -- SMTP-level mailbox verification via the Verimail v3 API,
                      for addresses that survived stages 1-2. Cached per mailbox.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
