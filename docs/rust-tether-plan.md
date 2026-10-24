# Rust tether daemon

Status: task 2 code done, access denied. Task 1 done. Tasks 3–8 not started.

The Rust daemon is a new program. It is Ammar's. The C daemon stays as the baseline. This thread orchestrates. For this session the implementer is Grok 4.7 medium, through T3 `delegate_task`, one task at a time. The child does not commit.

Do not replace the C sources until the Rust daemon meets the bar. Do not rewrite the Swift menu bar in this pass.

## Decisions from review

These override the earlier draft.

- `utun` writes in the C daemon are already non-blocking. A full socket makes `utun_write` return 0, and `process_rx_frame` still counts those bytes. The Rust writer counts only bytes `utun` accepted. The third thread exists so the libusb thread never writes the socket. It is not a fix for a blocking write.
- The OUT pool wait is not a 100 ms cap. The C loop waits again every 100 ms until a slot is free or the session stops.
- One OUT transfer carries one Ethernet frame. One IN completion may contain several RNDIS messages. `RNDIS_MAX_PACKETS_PER_TRANSFER` is unused. The Rust unwrap returns every complete message in the buffer.
- The C code learns a MAC from the first inbound Ethernet source whose first byte is not `0xff`. It does not check that the sender is the gateway. Rust does not copy that. After the address is known, send an ARP request for the gateway. Hold unicast IP until a reply names that gateway IP. Allow DHCP and ARP broadcast before that. Retry the request 3 times, 1 second apart, then end the session.
- IPC as implemented, not as the header comment: the UI sends `stop`, `disable`, `enable`. `status` is ignored. The daemon sends `stats` and `state` values `idle`, `watching`, `connected`, `disconnected`. `connecting` is never sent. Watch mode starts in `idle` until `enable`.
- The Swift app hardcodes `/tmp/macostether.sock`. The Rust daemon uses `/tmp/tetherd.sock` until it replaces the C daemon. Only one daemon runs during a comparison. Do not change the Swift path in this pass.
- USB discovery matches the four C filters in `src/usb_device.c`: `E0/01/03`, CDC+ACM+`03`, CDC+vendor+`03`, and vendor class `FF/01/03`, plus a CDC data interface.
- Phone `MaxTransferSize` in INIT_CMPLT is the largest transfer the phone accepts from the host. It caps our OUT size, header included. It is not a reason to reject the phone. Our INIT request advertises a 32 KiB receive buffer.
- DHCP failure does not fall back to `192.168.42.100`. The session ends and watch mode can retry. A phone with no DHCP needs an explicit `--static`, `--gateway`, and `--netmask`. Log timeout and NAK separately.
- Do not delete or replace the existing default route. Add `0.0.0.0/1` and `128.0.0.0/1` via the phone, the same idea as `utun_set_default_route`. Record each route this session actually added (destination, mask, gateway, interface index). On cleanup, delete only a recorded route that still matches. `EEXIST` means we did not add it, so we do not delete it.
- Do not overwrite `State:/Network/Global/DNS`. Publish IPv4, Interface, and DNS with `SCDynamicStoreAddTemporaryValue` on a unique service id so the keys die with the process. SIGTERM runs route cleanup. SIGKILL cannot. On the next start, if our pidfile names a dead process, delete leftover `/1` routes that still match the last saved record.
- Route and DNS code is tested before any session that changes the Mac's routes. The first on-phone bridge uses `--no-route --no-dns`.
- libusb has one owner thread. Other threads push commands (keepalive, ARP send, shutdown) on a bounded queue. The event thread drains that queue between `handle_events` calls. Keepalive is an async control transfer, never a synchronous libusb call inside a completion callback. `clear_halt` is scheduled after the callback returns, and pending transfers on that endpoint are cancelled first. Do not free a transfer, buffer, or context until the completion or cancellation callback has run.
- The ring holds Ethernet frames, at most 2048 bytes each, 256 slots. On IN completion the event thread copies the received bytes out, resubmits that IN slot, then parses the copy and pushes frames. If the ring is full, drop the frame, add to the drop counter, and do not block. Never queue a pointer into a buffer that has already been resubmitted.
- OUT pool: 63 data slots plus 1 ARP slot. If the ARP slot is busy, drop that ARP and count it. The event thread does not wait for it. The free stack is a convenience. Measure it later. Do not make it lock-free in this pass.
- The pass bar is paired runs, not one saved median. Alternate C and Rust on the same phone, cable, and network. Record receiver goodput, CPU seconds, CPU per delivered byte, loss, and a latency sample. A 30 second run is only a smoke test. The pass run lasts 90 seconds so keepalive happens more than once. A daemon that drops frames does not win on a lower CPU number.

## What the C daemon does

One session, in `src/main.c`:

1. Build the RNDIS driver.
2. Find the phone using the four interface filters above and claim the comm and data interfaces.
3. RNDIS init, query the MAC, set the packet filter.
4. DHCP. On failure, fall back to `192.168.42.100`, gateway `192.168.42.129`, DNS `8.8.8.8` and `8.8.4.4`. Rust does not keep this fallback.
5. Open a `utun`, assign the address with `ifconfig`, MTU 1500.
6. Publish a configd service and overwrite global DNS through `scutil`. Sleep 500 ms. Rust does not keep the sleep or the global DNS write. C writes a DNS backup and never reads it back. `utun_restore_dns` deletes global DNS.
7. Add `0.0.0.0/1` and `128.0.0.0/1` via the phone. The normal default route stays.
8. Send a gratuitous ARP. The gateway MAC starts as `ff:ff:ff:ff:ff:ff`.
9. Start two threads.

Phone to Mac: 16 async bulk IN transfers, 32 KiB buffers. The callback parses, may `malloc` an ARP reply, writes `utun`, then resubmits. Stall handling calls `clear_halt` inside the callback and ignores the result.

Mac to phone: poll `utun` every 100 ms, read up to 64 packets, wrap one Ethernet frame per OUT transfer. 64 OUT slots. The mutex scan waits in 100 ms slices until a slot frees. OUT timeout 1000 ms. IN timeout 0.

The main thread calls keepalive every 30 seconds from outside the event thread. Speed uses `time(NULL)` once a second. TX bytes are counted when the OUT transfer is submitted. RX bytes are counted even when `utun_write` returns 0.

`utun` packets are a 4-byte address family in network order plus the IP packet. `src/frame.c` handles IPv4 and IPv6. The session configures IPv4 only.

## Rust shape

16 IN slots, 64 OUT slots (63 data + 1 ARP), 32 KiB USB buffers, no Tokio on the packet path, `rusb` with raw libusb calls for the async pool. A thin wrapper in `pool.rs` owns the context, the transfers, and the buffers until their callbacks run.

Layout:

```
rust/
  Cargo.toml
  src/
    main.rs
    usb.rs
    pool.rs
    ring.rs
    rndis.rs
    frame.rs
    dhcp.rs
    arp.rs
    netcfg.rs
    ipc.rs
    log.rs
```

Flags: `--watch`, `--no-route`, `--no-dns`, `--static`, `--gateway`, `--netmask`, `--verbose`.

## Tasks

1. Done. Pure `rndis`, `frame`, `dhcp`, and `arp`, with unit tests. No USB device and no `utun`. The C files stay untouched.
2. Code done, access denied. USB open and RNDIS handshake on a phone. Print MAC and both transfer sizes. `cargo run --bin handshake` printed `Access denied (insufficient permissions)` and exited 3. No interface classes were readable, so the phone was not claimed.
3. Pending. `netcfg` save and restore, tested without installing a real default route. Then a blocking one-IN one-OUT bridge started with `--no-route --no-dns`.
4. Pending. Pools, frame ring, command queue, keepalive state machine. Stay here until a 90 second paired iperf meets the bar.
5. Pending. Real `/1` routes and temporary DNS service. Prove rollback on SIGTERM, unplug, and a partial setup. Prove SIGKILL leaves no SystemConfiguration keys, and the next start clears leftover `/1` routes.
6. Pending. JSON IPC on `/tmp/tetherd.sock` for `idle`, `watching`, `connected`, `disconnected`, `stats`, `stop`, `disable`, `enable`.
7. Pending. Watch mode, LaunchDaemon, universal binary, static libusb, package.
8. Pending. Paired bench notes in `docs/bench.md`. Needs the phone. Not a blocker for task 1.

## Tests for task 1

- RNDIS init, query, set, keepalive, and data round-trip. A short buffer, a bad length, and a bad data offset return errors.
- Two RNDIS messages in one buffer both parse.
- OUT length is capped by the phone's max transfer size, header included.
- DHCP discover and request contain the magic cookie. An offer yields address, router, and DNS. A NAK is not a lease.
- ARP request for our IP becomes a reply. A request for another IP is ignored. A gateway reply is accepted only when the sender IP is the gateway.
- IPv4 `utun` bytes become Ethernet and back to the same IP bytes. Same for IPv6.

## Out of scope

- Replacing the C files.
- A Rust menu bar, or editing `ui/MenuApp.swift`.
- NCM, ECM, DriverKit.
- Multi-packet OUT aggregation and a lock-free pool.
