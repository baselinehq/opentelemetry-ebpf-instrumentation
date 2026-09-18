// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <pid/pid_helpers.h>
#include <common/large_buffers.h>
#include <common/go_addr_key.h>
#include <common/ringbuf.h>

// A separate event leaves the upstream large-buffer ABI unchanged. Offsets
// advance even when ring-buffer emission fails, so userspace detects loss.
#define COSTGRAPH_TLS_H2_EVENT 250

const volatile bool tls_h2_capture_enabled = false;

typedef struct tls_h2_chunk {
    u8 type;
    u8 direction;
    u16 pad;
    u32 len;
    u64 generation;
    u64 offset;
    pid_info pid;
    connection_info_t conn;
    u8 buf[];
} tls_h2_chunk_t;
_Static_assert(sizeof(tls_h2_chunk_t) == 72, "TLS HTTP2 event layout");

typedef struct tls_h2_connection {
    u64 generation;
    u64 offsets[2];
    connection_info_t conn;
    u32 pad;
} tls_h2_connection_t;

typedef struct tls_h2_io {
    go_addr_key_t key;
    u64 buf;
    u8 direction;
    u8 pad[7];
} tls_h2_io_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // process + TLS connection pointer
    __type(value, tls_h2_connection_t);
    __uint(max_entries, 1024);
} costgraph_h2_connections SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // process + goroutine (Go) or thread (OpenSSL)
    __type(value, tls_h2_io_t);
    __uint(max_entries, 4096);
} costgraph_h2_io SEC(".maps");

static __always_inline bool tls_h2_enter(
    go_addr_key_t *g, void *tls, void *buf, u64 len, connection_info_t *conn, u8 direction) {
    if (!tls_h2_capture_enabled || !http_max_captured_bytes) {
        return false;
    }
    go_addr_key_t key = {.pid = g->pid, .addr = (u64)tls};
    if (direction == TCP_SEND && len >= 24) {
        char preface[24];
        if (!bpf_probe_read_user(preface, sizeof(preface), buf) &&
            !__builtin_memcmp(preface, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24)) {
            tls_h2_connection_t initial = {.generation = bpf_ktime_get_ns(), .conn = *conn};
            bpf_map_update_elem(&costgraph_h2_connections, &key, &initial, BPF_ANY);
        }
    }
    tls_h2_connection_t *state = bpf_map_lookup_elem(&costgraph_h2_connections, &key);
    if (!state) {
        return false;
    }
    if (__builtin_memcmp(&state->conn, conn, sizeof(*conn))) {
        bpf_map_delete_elem(&costgraph_h2_connections, &key);
        return false;
    }
    tls_h2_io_t args = {.key = key, .buf = (u64)buf, .direction = direction};
    bpf_map_update_elem(&costgraph_h2_io, g, &args, BPF_ANY);
    return true;
}

static __always_inline bool tls_h2_return(go_addr_key_t *g, s64 len) {
    tls_h2_io_t *saved = bpf_map_lookup_elem(&costgraph_h2_io, g);
    if (!saved) {
        return false;
    }
    tls_h2_io_t args = *saved;
    bpf_map_delete_elem(&costgraph_h2_io, g);
    tls_h2_connection_t *state = bpf_map_lookup_elem(&costgraph_h2_connections, &args.key);
    if (!state || len <= 0) {
        return true;
    }
    u8 direction = args.direction & 1;
    u64 offset = state->offsets[direction];
    state->offsets[direction] += len;
    tls_h2_chunk_t *event = (tls_h2_chunk_t *)tcp_large_buffers_mem();
    if (!event) {
        return true;
    }
    event->type = COSTGRAPH_TLS_H2_EVENT;
    event->direction = direction;
    event->pad = 0;
    event->generation = state->generation;
    event->conn = state->conn;
    task_pid(&event->pid);
    u32 size = len;
    bpf_clamp_umax(size, 1 << 20);
    for (u32 pos = 0; pos < size; pos += k_large_buf_payload_max_size) {
        u32 n = min(size - pos, k_large_buf_payload_max_size);
        bpf_clamp_umax(n, k_large_buf_payload_max_size);
        event->offset = offset + pos;
        event->len = n;
        if (bpf_probe_read_user(event->buf, n, (void *)(args.buf + pos))) {
            break;
        }
        if (bpf_ringbuf_output(&events, event, sizeof(*event) + n, get_flags())) {
            break;
        }
    }
    return true;
}

static __always_inline void tls_h2_close(go_addr_key_t *key) {
    tls_h2_connection_t *state = bpf_map_lookup_elem(&costgraph_h2_connections, key);
    if (state) {
        tls_h2_chunk_t *event = (tls_h2_chunk_t *)tcp_large_buffers_mem();
        if (event) {
            event->type = COSTGRAPH_TLS_H2_EVENT;
            event->direction = 2;
            event->pad = 0;
            event->len = 0;
            event->generation = state->generation;
            event->offset = 0;
            event->conn = state->conn;
            task_pid(&event->pid);
            bpf_ringbuf_output(&events, event, sizeof(*event), get_flags());
        }
        bpf_map_delete_elem(&costgraph_h2_connections, key);
    }
}
