# A malformed peer frame ends the session, not the process

Criterion: a frame this endpoint must reject closes the VOT session under its
registered code and leaves the process running.

This exists because the live receive path used to return
`QUIC_STATUS_ABORTED` from the `MsQuic` stream receive callback on a decoder
fault. `src/core/stream_recv.c` treats a failure status there as an application
bug: `CXPLAT_TEL_ASSERTMSG_ARGS(QUIC_SUCCEEDED(Status), "App failed recv
callback", ...)` aborts a debug-built `MsQuic`, and a release build ignores the
status entirely. Three bytes from any peer were therefore either a process abort
or silently tolerated. The fault now travels only through the close request,
which the driver turns into a registered connection close.

Passing evidence: `a_malformed_peer_frame_ends_the_session_not_the_process`
sends an unregistered critical frame type over a real carrier, proves the
accepted connection reports `Disconnected`, and proves the process is still
running afterwards. `a_decoder_error_keeps_its_registered_code` and
`a_close_request_is_kept_until_the_driver_sends_it` prove the code survives from
the callback to the driver. `a_registered_close_code_reaches_the_peer` proves
the peer reads the registered code back off the wire rather than a bare close.
The msquic-sanitizer job runs the whole live suite under AddressSanitizer and
LeakSanitizer, which is what found a send buffer leaked once per send in the
listener those tests use.

Mutants: return `Err(QUIC_STATUS_ABORTED)` from the receive callback on a frame
fault; return `Err` from `PeerSendShutdown` on a truncated frame; drop the close
request instead of storing it; let a second fault overwrite the first code;
continue parsing the remaining buffers of a coalesced read after a fault.

Observed failure:

```text
process didn't exit successfully: vot_transport_msquic-... (signal: 6, SIGABRT: process abort signal)
the session survived a frame it had to reject
assertion `left == right` failed
  left: None
 right: Some(260)
```

The abort reproduces with `cargo test -p vot-transport-msquic --features live`
against the pinned `MsQuic` revision, which is a debug build. A release build of
the same test passes while silently ignoring the status, so both profiles are
run.

The required `vot-transport-msquic` mutation run reports 72 total, 68 caught, 4
unviable, and 0 missed.
