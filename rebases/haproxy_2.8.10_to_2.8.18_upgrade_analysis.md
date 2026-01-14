# HAProxy 2.8.10 to 2.8.18 Upgrade Analysis Report

## Executive Summary

This report analyzes bug fixes between HAProxy versions 2.8.10 and 2.8.18 to assist in upgrade risk assessment. The analysis covers **490 total commits** with **337 bug fixes** across 8 patch releases (2.8.11 through 2.8.18).

### Bug Severity Distribution

- **CRITICAL**: 1 bug (CVE-2025-11230)
- **MAJOR**: 7 bugs
- **MEDIUM**: 129 bugs
- **MINOR**: 198 bugs

## CRITICAL Bugs (1)

### CVE-2025-11230: mjson DoS Vulnerability

**Commit**: `444144e4ead6044f4bb53f9b23c80a305da022e6`
**Subsystem**: mjson (Lua integration)
**Version Fixed**: 2.8.16

#### Impact

A denial of service vulnerability exists in the mjson library's number parsing functionality. An attacker can craft JSON numbers with extremely large exponents that cause HAProxy to consume excessive CPU time, potentially hanging the process.

#### Technical Details

The mjson library includes a custom `strtod()` implementation to avoid external dependencies. When processing exponents in JSON numbers, the original implementation used an iterative loop with O(exp) time complexity:

```c
for (i = 0; i < e; i++) d *= 10;
for (i = 0; i < -e; i++) d /= 10;
```

Since the exponent value was unbounded, malicious input like `1e999999999` could cause the loop to execute billions of times, exhausting CPU resources.

#### Fix Applied

The fix replaces the iterative approach with an efficient exponentiation-by-squaring algorithm operating in O(log(exp)) time:

```c
exp = 10;
f = 1;
while (i > 0) {
    if (i & 1) f *= exp;
    exp *= exp;
    i >>= 1;
}
```

This reduces the complexity from billions of operations to approximately 30 operations even for extreme exponents, while avoiding the need for libm dependency.

#### Risk Assessment

- **Severity**: CRITICAL
- **Attack Vector**: Remote, unauthenticated (if Lua endpoints accept untrusted JSON)
- **Exploitability**: Easy (simple crafted JSON payload)
- **Impact**: Denial of Service (CPU exhaustion)
- **Affected Configurations**: Any deployment using Lua scripting with JSON parsing (mjson library)
- **Mitigation**: None available without upgrade
- **Watchdog Protection**: HAProxy's watchdog will eventually terminate runaway processes, but service disruption will occur

#### Who Should Be Concerned

- **HIGH PRIORITY**: Production systems using Lua scripts that parse JSON from untrusted sources (APIs, user input, external webhooks)
- **MEDIUM PRIORITY**: Systems using Lua for internal processing only
- **LOW PRIORITY**: Systems not using Lua functionality

## MAJOR Bugs (7)

### 1. Stream Processing: Channel Analysis Regression

**Commit**: `99eb7ae8917b0d79672d842bcedaef6fcc321b7e`
**Subsystem**: Stream processing / channel handling
**Version Fixed**: 2.8.16

**Impact**: Streams can hang indefinitely when shutdown events occur during synchronous sends, causing connection leaks and resource exhaustion.

**Technical Details**: A previous fix (commit a498e527b) attempted to detect synchronous sends but incorrectly masked write events, potentially hiding shutdown notifications. When an error triggers a shutdown while a write event is pending, the stream never processes the shutdown and remains blocked forever (unless a timeout is configured).

**Affected Configurations**: All deployments, particularly those with:
- High connection churn
- Backend server failures
- Network interruptions

**When to Be Concerned**:
- You observe connection leaks (connections never closing)
- `show sess` shows stuck sessions
- Resource usage grows over time without traffic increase

### 2. Listeners: Connection Accounting Corruption

**Commit**: `27c07abe4290f386ab7e15c2a00e66fcd57d42ad`
**Subsystem**: Listener management
**Version Fixed**: 2.8.14

**Impact**: Per-listener connection counts become incorrect when switching connections between thread groups, potentially causing HAProxy to stop accepting new connections when `maxconn` is configured on `bind` directives.

**Technical Details**: When a bind_conf uses multiple thread groups with shards, connections transferred between groups don't update the source listener's connection count. This causes one listener to report artificially high counts (eventually hitting maxconn limits) while others may show negative counts.

**Affected Configurations**:
- Multi-threaded setups with `nbthread` > 1 and thread groups enabled
- Configurations with `maxconn` set on `bind` directives
- Stats sockets (CLI) with low maxconn limits

**When to Be Concerned**:
- You use thread groups (`thread-groups` directive)
- You have `maxconn` configured on any `bind` line
- HAProxy stops accepting connections despite being under capacity
- High CPU usage in poller trying to accept connections

### 3. OCSP: Reference Counting Corruption

**Commit**: `7a5ca2a36f0317218a9a5292d886a29e67865805`
**Subsystem**: SSL/TLS OCSP stapling
**Version Fixed**: 2.8.13

**Impact**: OCSP responses could be prematurely destroyed when all crt-list entries using a certificate are removed via CLI, even though the certificate remains loaded. This leads to dangling pointers and potential crashes when the OCSP response is accessed.

**Technical Details**: The previous implementation used a single reference counter for OCSP responses. When all `ckch_inst` instances were removed (e.g., via `del ssl crt-list` commands), the OCSP response was destroyed even though the certificate remained in memory. The fix introduces dual reference counting: one for ckch_store references and one for active SSL_CTX instances.

**Affected Configurations**:
- SSL/TLS with OCSP stapling enabled
- Dynamic certificate management via CLI (`set ssl cert`, `add/del ssl crt-list`)

**When to Be Concerned**:
- You use OCSP stapling
- You dynamically manage certificates via CLI
- You observe crashes in SSL/OCSP code paths

### 4. Mux-H1: Zero-Copy Forwarding Deadlock

**Commit**: `1b531863690a36a15c41a3c4b655f2a6c769e3a0`
**Subsystem**: HTTP/1 multiplexer
**Version Fixed**: 2.8.11

**Impact**: H1 connections in CLOSING state with zero-copy forwarding enabled never wake the stream connector to perform the final forwarding, leading to connection leaks. Without shutdown timeouts configured, connections remain indefinitely.

**Technical Details**: When the H1 mux receives I/O events with zero-copy forwarding enabled, it blocks receives and wakes the stream connector to perform the forwarding. However, H1 connections in CLOSING state were not triggering this wakeup, causing the connection closure to be ignored.

**Affected Configurations**:
- All HTTP/1 configurations
- Particularly when zero-copy forwarding is used (Linux with splice support)

**When to Be Concerned**:
- You observe connection leaks
- `show sess all` shows connections stuck in CLOSING state
- Memory usage increases over time

### 5. QUIC: CRYPTO Frame Buffer Overflow Protection

**Commit**: `c090f3418fc5ca896d50cba59260e26e3e599c0e`
**Subsystem**: QUIC protocol
**Version Fixed**: 2.8.14

**Impact**: Missing validation on CRYPTO frame offsets could cause crashes when processing malicious or corrupted QUIC packets.

**Technical Details**: No bounds checking was performed before inserting CRYPTO frames into the ncbuf buffer. An attacker could send frames with extremely large offset values, causing buffer overflows and process crashes. The fix validates that frames fit within the buffer before insertion and closes the connection with `CRYPTO_BUFFER_EXCEEDED` error if they don't.

**Affected Configurations**: QUIC/HTTP3 listeners (USE_QUIC=1)

**When to Be Concerned**:
- QUIC is enabled and exposed to untrusted networks
- You experience unexplained HAProxy crashes
- Security is a primary concern

### 6. QUIC: Packet Building with Acknowledged Frames

**Commit**: `2d1c69de6de756eac342c4f80e116b9f71824800`
**Subsystem**: QUIC protocol
**Version Fixed**: 2.8.11

**Impact**: HAProxy could build empty QUIC packets when probing peers with already-acknowledged frames, violating the QUIC protocol requirement that probe packets must be ACK-eliciting. This could cause connection stalls or failures.

**Technical Details**: When a PTO (Probe Timeout) probe was requested with frames that had just been acknowledged, the frame building process would cancel frame creation but still proceed with packet building, resulting in an empty non-ACK-eliciting packet.

**Affected Configurations**: QUIC/HTTP3 deployments

**When to Be Concerned**:
- QUIC connections stall or timeout intermittently
- High packet loss or network latency environments

### 7. QUIC: CRYPTO Frame Handling Vulnerability

**Commit**: `e78271f988d8e09c0a718a7a06ac160932098d31`
**Subsystem**: QUIC protocol
**Version Fixed**: 2.8.17

**Impact**: QUIC connections fail when clients implement "chaos protection" (aggressive CRYPTO frame fragmentation). Affects latest versions of Chrome, Firefox, and ngtcp2 clients.

**Technical Details**: Chrome and Firefox now fragment TLS handshake messages into very small CRYPTO frames to detect middlebox interference. HAProxy's previous ncbuf storage couldn't handle gaps smaller than 8 bytes between fragments. The fix introduces ncbmbuf (non-contiguous bitmap buffer) with no gap size limitations.

**Affected Configurations**: QUIC/HTTP3 listeners (USE_QUIC=1)

**When to Be Concerned**:
- You have QUIC/HTTP3 enabled in production
- You're experiencing connection failures from Chrome or Firefox browsers
- Clients are updated to recent versions (post-August 2025)

## MEDIUM Bugs (129)

### SSL/TLS (8)

Critical areas addressed:
- **Early data (0-RTT) handling**: Multiple fixes for TLS 1.3 early data on both client and server sides
- **Second ClientHello processing**: Proper handling of TLS renegotiation scenarios
- **Certificate management**: Crashes from dangling ckch_store references, CA file directory mode bugs
- **ECDSA cipher selection**: Correct certificate selection with ssl-max-ver TLSv1.2
- **Build compatibility**: AWS-LC library support

**Key Fixes**:
- `135c87ce`: SSL create the mux immediately on early data
- `324fd5c3`: SSL take care of second client hello
- `1f21378d`: SSL crash from dangling ckch_store reference

**Impact**: SSL/TLS connection failures, crashes during certificate updates, 0-RTT functionality issues, interoperability problems with specific TLS clients.

### HTTP/2 Multiplexer (6)

Critical areas addressed:
- **Connection lifecycle**: Preventing dead connections from being moved to idle pool (fix reverted then re-applied correctly)
- **Header handling**: Proper header count validation in HEADERS frames
- **RST_STREAM transmission**: Not sending RST for streams without assigned IDs
- **Preface handling**: Connection errors during HTTP/2 preface sending
- **Stream termination**: Proper term flag propagation on errors

**Key Fixes**:
- `c18bf84b`: Mux-h2 make sure not to move a dead connection to idle (final fix)
- `BUG/MEDIUM: mux-h2: Check the number of headers in HEADERS frame after decoding`
- `BUG/MEDIUM: mux-h2: Don't send RST_STREAM frame for streams with no ID`

**Impact**: Connection pool corruption, protocol violations, stream handling errors.

### HTTP Client (6)

Critical areas addressed:
- **Data flow control**: HTX_FL_EOM flag checking before buffer commits
- **Notification handling**: Proper reporting of available data until EOM
- **Request draining**: Handling early responses correctly
- **Room negotiation**: Proper xfer space requests
- **Blocked data reporting**: HTX block transfer accounting

**Impact**: HTTP client functionality in Lua scripts, healthchecks, or other internal HTTP client usage.

### Stream Connectors (5)

Critical areas addressed:
- **Timer handling**: Only considering I/O timers for stream expiration
- **Shutdown forwarding**: Not forwarding shutdown in connecting state
- **Error reporting**: Proper error reporting on blocked sends
- **Blocked send detection**: Really reporting blocked sends when errors occur

**Impact**: Connection timeout issues, improper connection state handling.

### Queue Management (5)

Critical areas addressed:
- **Server queue processing**: Correct return value (stream count) from process_srv_queue()
- **pendconn handling**: Not using pendconn_grab_from_px() incorrectly
- **Dequeue timing**: Ensuring process_srv_queue() called when leaving
- **Dequeue flag**: Implementing flag to check for active dequeuing
- **Backend dequeuing**: Always dequeuing backend when redistributing last server
- **Race conditions**: Handling TOCTOU in assign_server_and_queue()

**Impact**: Queue processing errors, stuck connections in queues, server selection issues.

### HTTP Analysis (5)

Critical areas addressed:
- **Tunnel mode**: Not closing server connections on read0 in TUNNEL mode
- **Wait-for-body**: Resetting analyse_exp after wait-for-body action
- **502 reporting**: Only reporting 502 during response forwarding
- **L7 retry**: Resetting request flags about sent data for retries
- **L7 buffer**: Not releasing L7 buffer too early
- **Error reporting**: Proper error reporting on write errors waiting for response

**Impact**: Connection handling in various HTTP scenarios, proper error reporting, retry functionality.

### HTTP/3 Protocol (9)

Critical areas addressed:
- **Interim response handling**: Multiple fixes for 1xx responses (informational) being incorrectly handled, overwritten, or corrupted when followed by final responses
- **QPACK encoding issues**: Whitespace trimming in header values, header field name validation (rejecting 'Z' character)
- **Header limits**: Fixes to properly enforce maximum header counts
- **Pseudo-header validation**: Stricter validation of `:scheme` and `:method` pseudo-headers

**Key Fixes**:
- `b6c8c41e`: H3 do not overwrite interim with final response
- `b527416c`: H3 properly encode response after interim one in same buf
- `7c4f173e`: H3 handle interim response properly on FE side

**Impact**: HTTP/3 clients experiencing header corruption, connection failures, or protocol violations. Particularly important for applications using Server-Sent Events (SSE) or early hints.

### QUIC Protocol (7)

Additional fixes beyond the MAJOR bugs:
- **CRYPTO frame management**: Freeing without eb_delete(), proper parsing error handling
- **Wait-for-handshake support**: Preventing connection freeze on undeciphered 0-RTT content
- **Retransmission handling**: Standalone FIN STREAM retransmit support
- **Race conditions**: DCID exit without unlocking, CID thread assignment

**Key Fixes**:
- `9a069b6d`: QUIC CRYPTO frame freeing without eb_delete()
- `BUG/MEDIUM: quic: prevent crash due to CRYPTO parsing error`
- `BUG/MEDIUM: quic: prevent conn freeze on 0RTT undeciphered content`

**Impact**: Connection stability, race condition crashes, handshake failures.

### Lua Integration (6)

Critical areas addressed:
- **Sample function safety**: Proper error handling in hlua_run_sample_fetch/conv()
- **Context renewal**: Safe hlua_ctx_renew() implementation
- **Socket reporting**: Proper stream connector notification for blocked/consumed data
- **Applet yield regression**: Data loss on TCP/HTTP applet yields
- **CLI UAF**: Use-after-free in hlua_applet_wakeup()
- **Sample fetches**: Forbidding L6/L7 fetches from Lua services

**Key Fixes**:
- `BUG/MEDIUM: hlua: make hlua_ctx_renew() safe`
- `BUG/MEDIUM: hlua: fix hlua_applet_{http,tcp}_fct() yield regression (lost data)`
- `BUG/MEDIUM: hlua/cli: fix cli applet UAF in hlua_applet_wakeup()`

**Impact**: Lua script crashes, data loss, security violations in Lua services.

### Mux-QUIC (5)

Critical areas addressed:
- **Wakeup behavior**: Proper wakeup sequencing
- **Early-data header**: Ensuring header is properly set
- **Timeout handling**: Correct timeout application on pending output
- **Flow control**: Handling low peer initial stream flow control
- **Crash prevention**: Not attaching to already-closed streams
- **Timeout management**: Ensuring server timeout active for short requests

**Impact**: QUIC multiplexing stability, connection management.

### Other Subsystems (67)

**Server Management (3 bugs)**: Healthcheck updates via CLI, FQDN change handling, stuck maintenance state

**Checks/Healthchecks (4 bugs)**: ALPN inheritance, requeuing on I/O events, setting SOCKERR on errors, timeout handling

**Stick Tables (4 bugs)**: Proper session return from stktable_set_entry(), reference counting, string-type key indexing, locking on converters

**H1 Protocol (3 bugs)**: Crash prevention on HTTP/2 upgrade, early data reception, empty Transfer-Encoding header rejection

**H2 Protocol (2 bugs)**: Header field name validation (forbidding 'Z'), early HTX EOM for tunneled streams

**Backend (2 bugs)**: Not overwriting srv dst address on reuse, fixing reuse with set-dst/set-dst-port

**FD Management (2 bugs)**: Using correct tgid in fd_insert(), marking transferred FDs as FD_CLONED

**Clock/Timing (3 bugs)**: Ensuring now_ms != TICK_ETERNITY, detecting time jumps, updating date offset on jumps

**DNS/Resolvers (2 bugs)**: Reconnect tempo reset, FQDN normalization, resolution wait list insertion

**Patterns (2 bugs)**: Preventing uninitialized reads in pat_match_str/beg, preventing UAF on reused pattern expr

**SPOE (2 bugs)**: Not waking idle applets in loop during stopping, creating SPOE applet if none on thread

**Peers (2 bugs)**: Preventing expiration too far in future from unsync nodes

**CLI (2 bugs)**: Deadlock when setting frontend maxconn, releasing back endpoint between mcli commands

**JWT (2 bugs)**: Missing case in switch, clearing SSL error queue on signature check failure

**Debug/Tracing (2 bugs)**: Fix for "show threads" with low thread counts, null deref in lockon mechanism

**Thread Management (2 bugs)**: Using pthread_self() not ha_pthread[tid] in set_affinity, disabling macOS libgcc_s workaround

**Sink (1 bug)**: Retry attempt for sft server

**Filters (1 bug)**: Handling data filters with no payload callback

**HTX (1 bug)**: Wrong count computation in htx_xfer_blks()

**Mailers (1 bug)**: Applying offsets to now_ms in expiration

**Promex (1 bug)**: Wait for request before sending response

**Cache/Stats (1 bug)**: Wait for request before sending response

**Event Handler (1 bug)**: Fix uninitialized value in async mode

**Init (1 bug)**: Fix fd_hard_limit default in compute_ideal_maxconn

**BWLimit (1 bug)**: Never setting analyze expiration in past

**Connection/HTTP Reuse (1 bug)**: Fix address collision on unhandled address families

## MINOR Bugs (198)

### Top Subsystems with MINOR Fixes

**QUIC Protocol (32 bugs)**: The highest concentration of minor fixes, addressing:
- SSL session object freeing
- CID allocation failures
- Congestion window enforcement
- Fragmented CRYPTO frame ordering
- Source address handling on FreeBSD
- Default QUIC curves
- Room checks with padding
- Connection closure edge cases
- Build compatibility issues

**Mux-QUIC (9 bugs)**: Close-spread-time application, output timeout handling, various edge cases

**HTTP/3 (9 bugs)**: Header field name validation, backport error corrections, various protocol conformance issues

**Server Management (7 bugs)**: Healthcheck updates, configuration parsing, DNS resolution handling

**Proxy/Frontend (7 bugs)**: Configuration parsing, fatal error handling, various initialization issues

**HTTP Analysis (7 bugs)**: Request parsing edge cases, header handling, various analysis path fixes

**CLI (7 bugs)**: Command parsing, output formatting, error handling

**SSL/TLS (5 bugs)**: Dead code removal, SSL_CTX_new error handling, global_ssl deinitialization, ClientHello handling

**Lua (5 bugs)**: HTTP applet data accounting, missing case statements, memory leak fixes

**Sink (4 bugs)**: Retry mechanisms, log forwarding edge cases

**Pattern Matching (4 bugs)**: Various pattern matching edge cases and validation

**Mux-H1 (4 bugs)**: Connection state handling, timeout application

**Logging (4 bugs)**: Memory leak fixes, OOM checks, format string handling

**JWT (4 bugs)**: Token parsing, validation edge cases

**Init (4 bugs)**: FD closure, quiet mode handling, startup sequence

**Trace/QUIC (3 bugs)**: Tracing-related fixes specifically for QUIC

**Stream (3 bugs)**: Various stream lifecycle edge cases

**SSL CLI (3 bugs)**: SSL management via CLI commands

**Mux-H2 (3 bugs)**: Additional minor HTTP/2 multiplexing fixes

**H2 Protocol (3 bugs)**: Protocol edge cases

**H1 Protocol (3 bugs)**: HTTP/1 parsing edge cases

**Backend (3 bugs)**: Server selection and connection management

**Additional subsystems** (50+ bugs across 30+ components): Memory allocation OOM checks, stick-table handling, SPOE edge cases, peer protocol, HTTP client, halog utility, DNS, clock handling, and many others.

### Common Themes in MINOR Bugs

1. **Resource Management**: Numerous OOM (Out Of Memory) checks added to calloc/malloc calls across codebase
2. **Memory Leaks**: Plugging potential leaks in error paths
3. **Edge Case Handling**: Proper handling of unusual or rare conditions
4. **Protocol Conformance**: Minor protocol violation corrections
5. **Build System**: Compatibility fixes for various platforms and configurations
6. **Cleanup**: Dead code removal, proper resource deinitialization

## Conclusion

**The upgrade from HAProxy 2.8.10 to 2.8.18 is strongly recommended** for all deployments, with particular urgency for:

1. **Lua-enabled configurations** (CRITICAL security issue)
2. **QUIC/HTTP3 deployments** (multiple MAJOR stability issues)
3. **Multi-threaded configurations with thread groups** (MAJOR connection acceptance bug)
4. **OCSP-enabled deployments with dynamic cert management** (MAJOR crash bug)

The 337 bug fixes across 8 releases represent significant stability and security improvements. While the majority are MINOR fixes, the cumulative effect substantially improves overall reliability.

The HAProxy 2.8.x branch is an LTS (Long Term Support) release supported until approximately Q2 2028. Keeping current with the latest 2.8.x patch release ensures you benefit from all stability improvements while maintaining API compatibility.

## Additional Resources

- HAProxy 2.8 changelog: https://git.haproxy.org/?p=haproxy-2.8.git;a=blob_plain;f=CHANGELOG
- HAProxy bugs overview : https://www.haproxy.org/bugs/bugs-2.8.10.html
