# ADR-0039: Caret has one canonical URL wire spelling

- Status: accepted
- Date: 2026-07-19
- Scope: Go route/publish/serving/verification and shared Cloudflare/EdgeOne request contract

## Context

SOW's frozen route alphabet includes caret (`^`). That byte is not optional:
RPM 4.15 and later permit caret in version strings, and the conventional RPM
filename contains the version. Local repository keys therefore legitimately
contain names such as `tool-1.0^git-1.x86_64.rpm`.

The original edge parser accepted a literal caret but rejected every percent
sign. This was internally consistent only at the string level. The WHATWG URL
path percent-encode set includes U+005E, and standard `URL`/`Request`
serialization turns a literal caret into `%5E`. RFC 3986 normalization likewise
percent-encodes caret. Consequently, a key accepted by Go and emitted by the
repository could be serialized by a normal client into a request that both
edge adapters rejected before origin access.

Accepting general percent-decoding would be worse. Encoded separators, dot
segments, encoded unreserved bytes, case variants and double encoding would
create multiple cache keys or ambiguous origin keys and would violate the
closed route model.

## Decision

The repository-key alphabet remains unchanged. Caret is stored in manifests,
object keys and origin adapter inputs as the literal byte `^`.

At the shared edge request boundary only, `%5E` is the single canonical wire
representation of caret. The parser replaces exact uppercase `%5E` sequences,
then re-encodes every recovered caret and requires byte-for-byte equality with
the original segment. It rejects:

- a raw caret in the serialized request URL;
- lowercase `%5e`;
- every other percent escape, including encoded unreserved bytes and `/`;
- double encoding such as `%255E`; and
- unsafe, empty, trailing-empty, query, fragment and backslash forms that remain
  observable in the serialized `Request.url`.

The decoded segment must still satisfy the exact
`[A-Za-z0-9+._~^:-]+` predicate. Both Cloudflare and EdgeOne call this one
shared parser before authentication, route admission or origin access. Their
origin adapters receive the literal caret key and apply their existing
provider-specific canonical escaping and signing.

Any client-facing URL synthesized by the edge uses the inverse of that same
narrow mapping: validated literal segments remain byte-identical except caret,
which is emitted only as uppercase `%5E`. This includes dynamic Pro mirrorlist
URLs for both token-in-path and Basic Auth routes. General URI component
encoding is not used as an implicit extension of the route alphabet.

Go uses the same closed transform through one shared route URL helper. It
validates a literal relative route, replaces only caret with uppercase `%5E`,
and provides the exact inverse for raw URL-string closure checks. Static
beta/latest mirrorlists, local latest/stable serving, stable transformed
verification digests, runtime token/Basic expectations, compatibility Verify
lookups and purge classification all call this contract. Channel documents,
manifests, remote object keys and filesystem generation paths remain literal.

The generated Nginx include is an origin-facing boundary, not a wire-key
store. Its route validator therefore applies the same frozen literal predicate
to each slash-separated segment, emits literal caret in prefix locations and
filesystem aliases, and quotes caret in regex locations. A normal client sends
`%5E`; Nginx URI normalization selects the literal caret route and alias. The
renderer still excludes whitespace, semicolon, braces, quotes, dollar,
backslash, percent and all other directive-bearing bytes.

`Request.url` is the portable application trust boundary for both adapters.
WHATWG parsing can remove literal/encoded dot segments and normalize
backslashes before shared JavaScript runs, so the handler cannot truthfully
recover or reject those original request-target bytes. It instead re-applies
the closed public route allowlist and token/Basic path scope to the final
canonical path. A normalized target that is unowned remains 404; a normalized
target outside an entitlement remains 403; neither reaches origin. Whether the
provider's pre-Worker cache key also converges those raw spellings must be
proved by the real POC-06 or enforced by a provider raw-request rule.

This decision supersedes only the literal interpretation of the older
"reject every `%`" implementation note. `%5E` is not an alternate object-key
alias or a general decoding fallback; it is the sole standards-required wire
serialization of a byte already admitted by the frozen product alphabet.

## Consequences

- Normal URL clients can fetch RPMs and assets whose canonical keys contain
  caret through anonymous, token and Basic-authenticated routes.
- Dynamic Pro mirrorlists preserve the same canonical spelling when a channel
  root contains caret, so generated client URLs cannot reintroduce raw aliases.
- Go static/local mirrorlists, publish digests and L3/L4 verification use the
  identical spelling; compatibility positive/purge closure decodes only that
  exact wire form before comparing literal ownership.
- Within application-visible `Request.url`, caret has one spelling and every
  other visible percent/trailing alias fails before origin. Pre-Request
  dot/backslash aliases are accepted only as their final canonical path and
  must pass ownership and entitlement again.
- Providers that normalize incoming URLs to RFC 3986 produce the same uppercase
  `%5E` form consumed by the shared parser.
- Literal object keys, manifests, signatures, checkpoints and migration data do
  not change, so no repository rewrite is required.
- A config-valid caret route remains directly hostable by the generated Nginx
  public and Basic-auth includes; real loopback tests bind `%5E` requests to the
  literal tree while retaining default-deny, traversal and symlink guards.
- Contract tests must prove both successful caret routing and origin-free
  rejection of lowercase, double-encoded, encoded-unreserved and
  encoded-separator or trailing-slash aliases for both vendor adapters. They
  must separately prove final-path allowlist and entitlement enforcement after
  WHATWG dot/backslash normalization.

## References

- [WHATWG URL Standard: path percent-encode set](https://url.spec.whatwg.org/#path-percent-encode-set)
- [Cloudflare URL normalization](https://developers.cloudflare.com/rules/normalization/how-it-works/)
- [RPM spec format: version separators](https://rpm.org/docs/4.20.x/manual/spec.html#version)
