// Copyright 2022 CFC4N <cfc4n.cs@gmail.com>. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __OPENSSL_ADAPTIVE_H__
#define __OPENSSL_ADAPTIVE_H__

#include "offset_detector.h"

// Forward declarations and required structures
struct active_ssl_buf {
    s32 version;
    u32 fd;
    u32 bio_type;
    const char* buf;
};

// Required BPF maps (declare as extern since they're defined in openssl.h)
extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 2048);
} ssl_st_fd SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct active_ssl_buf);
    __uint(max_entries, 1024);
} active_ssl_write_args_map SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct active_ssl_buf);
    __uint(max_entries, 1024);
} active_ssl_read_args_map SEC(".maps");

// Required globals
#ifndef KERNEL_LESS_5_2
extern const volatile u64 target_pid;
extern const volatile u64 target_uid;
#endif

/***********************************************************
 * Adaptive OpenSSL probing with runtime offset detection
 ***********************************************************/

// Enhanced SSL_write probe with runtime offset detection
SEC("uprobe/SSL_write_adaptive")
int probe_entry_SSL_write_adaptive(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

#ifndef KERNEL_LESS_5_2
    // if target_ppid is 0 then we target all pids
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
    if (target_uid != 0 && target_uid != uid) {
        return 0;
    }
#endif

    debug_bpf_printk("openssl adaptive uprobe/SSL_write pid: %d\n", pid);

    void* ssl = (void*)PT_REGS_PARM1(ctx);

    // Run offset detection on first call
    if (detect_ssl_offsets(ssl) != 0) {
        debug_bpf_printk("SSL offset detection failed, using defaults\n");
    }

    // Use detected offsets (or fallback to defaults)
    u16 version_offset = get_ssl_version_offset();
    u16 wbio_offset = get_ssl_wbio_offset();

    u64 *ssl_ver_ptr, *ssl_wbio_ptr, *ssl_wbio_num_ptr;
    u64 ssl_version, ssl_wbio_addr, ssl_wbio_num_addr;
    int ret;

    // Read SSL version using detected offset
    ssl_ver_ptr = (u64 *)((char *)ssl + version_offset);
    ret = bpf_probe_read_user(&ssl_version, sizeof(u32), ssl_ver_ptr);
    if (ret) {
        debug_bpf_printk("(ADAPTIVE) bpf_probe_read ssl_ver_ptr failed, ret: %d\n", ret);
        return 0;
    }

    // Validate TLS version
    if (!is_valid_tls_version((u32)ssl_version)) {
        debug_bpf_printk("(ADAPTIVE) Invalid TLS version: 0x%x\n", (u32)ssl_version);
        return 0;
    }

    // Read WBIO pointer using detected offset
    ssl_wbio_ptr = (u64 *)((char *)ssl + wbio_offset);
    ret = bpf_probe_read_user(&ssl_wbio_addr, sizeof(ssl_wbio_addr), ssl_wbio_ptr);
    if (ret) {
        debug_bpf_printk("(ADAPTIVE) bpf_probe_read ssl_wbio_addr failed, ret: %d\n", ret);
        return 0;
    }

    if (!is_valid_user_pointer(ssl_wbio_addr)) {
        debug_bpf_printk("(ADAPTIVE) Invalid WBIO pointer: 0x%lx\n", ssl_wbio_addr);
        return 0;
    }

    // Try to detect BIO offsets if not done yet
    u32 bio_key = 0;
    struct bio_offsets *bio_offsets = bpf_map_lookup_elem(&detected_bio_offsets, &bio_key);
    if (!bio_offsets || !bio_offsets->detected) {
        struct bio_offsets new_bio_offsets = {0};

        // Detect BIO fd offset
        if (probe_bio_fd_offset((void *)ssl_wbio_addr, &new_bio_offsets) == 0) {
            // Detect BIO method offset
            if (probe_bio_method_offset((void *)ssl_wbio_addr, &new_bio_offsets) == 0) {
                new_bio_offsets.detected = 1;
                bpf_map_update_elem(&detected_bio_offsets, &bio_key, &new_bio_offsets, BPF_ANY);
            }
        }
    }

    // Get BIO file descriptor using detected offset (or default)
    u16 bio_num_offset = BIO_ST_NUM; // default
    bio_offsets = bpf_map_lookup_elem(&detected_bio_offsets, &bio_key);
    if (bio_offsets && bio_offsets->detected) {
        bio_num_offset = bio_offsets->num_offset;
    }

    ssl_wbio_num_ptr = (u64 *)(ssl_wbio_addr + bio_num_offset);
    ret = bpf_probe_read_user(&ssl_wbio_num_addr, sizeof(ssl_wbio_num_addr), ssl_wbio_num_ptr);
    if (ret) {
        debug_bpf_printk("(ADAPTIVE) bpf_probe_read ssl_wbio_num_ptr failed, ret: %d\n", ret);
        return 0;
    }

    u32 fd = (u32)ssl_wbio_num_addr;
    if (!is_valid_fd(fd)) {
        debug_bpf_printk("(ADAPTIVE) Invalid file descriptor: %d\n", fd);
        // Try fallback mechanism
        u64 ssl_addr = (u64)ssl;
        u64 *fd_ptr = bpf_map_lookup_elem(&ssl_st_fd, &ssl_addr);
        if (fd_ptr) {
            fd = (u32)*fd_ptr;
        } else {
            return 0;
        }
    }

    debug_bpf_printk("(ADAPTIVE) SSL_write: fd=%d, version=0x%x, offsets: ver=0x%x, wbio=0x%x, bio_num=0x%x\n",
                     fd, (u32)ssl_version, version_offset, wbio_offset, bio_num_offset);

    // Store buffer information for SSL_write return probe
    const char* buf = (char*)PT_REGS_PARM2(ctx);
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.fd = fd;
    active_ssl_buf_t.version = (s32)ssl_version;
    active_ssl_buf_t.buf = buf;

    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&active_ssl_write_args_map, &id, &active_ssl_buf_t, BPF_ANY);
    return 0;
}

// Enhanced SSL_read probe with runtime offset detection
SEC("uprobe/SSL_read_adaptive")
int probe_entry_SSL_read_adaptive(struct pt_regs* ctx) {
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();
    u32 uid = current_uid_gid;

#ifndef KERNEL_LESS_5_2
    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }
    if (target_uid != 0 && target_uid != uid) {
        return 0;
    }
#endif

    debug_bpf_printk("openssl adaptive uprobe/SSL_read pid: %d\n", pid);

    void* ssl = (void*)PT_REGS_PARM1(ctx);

    // Run offset detection if not done yet
    if (detect_ssl_offsets(ssl) != 0) {
        debug_bpf_printk("SSL offset detection failed, using defaults\n");
    }

    // Use detected offsets
    u16 version_offset = get_ssl_version_offset();
    u16 rbio_offset = get_ssl_rbio_offset();

    u64 *ssl_ver_ptr, *ssl_rbio_ptr;
    u64 ssl_version, ssl_rbio_addr;
    int ret;

    // Read SSL version using detected offset
    ssl_ver_ptr = (u64 *)((char *)ssl + version_offset);
    ret = bpf_probe_read_user(&ssl_version, sizeof(u32), ssl_ver_ptr);
    if (ret) {
        debug_bpf_printk("(ADAPTIVE) SSL_read: bpf_probe_read ssl_ver_ptr failed, ret: %d\n", ret);
        return 0;
    }

    if (!is_valid_tls_version((u32)ssl_version)) {
        debug_bpf_printk("(ADAPTIVE) SSL_read: Invalid TLS version: 0x%x\n", (u32)ssl_version);
        return 0;
    }

    // Read RBIO pointer using detected offset
    ssl_rbio_ptr = (u64 *)((char *)ssl + rbio_offset);
    ret = bpf_probe_read_user(&ssl_rbio_addr, sizeof(ssl_rbio_addr), ssl_rbio_ptr);
    if (ret) {
        debug_bpf_printk("(ADAPTIVE) SSL_read: bpf_probe_read ssl_rbio_addr failed, ret: %d\n", ret);
        return 0;
    }

    if (!is_valid_user_pointer(ssl_rbio_addr)) {
        debug_bpf_printk("(ADAPTIVE) SSL_read: Invalid RBIO pointer: 0x%lx\n", ssl_rbio_addr);
        return 0;
    }

    // Get file descriptor (same logic as SSL_write)
    u32 bio_key = 0;
    u16 bio_num_offset = BIO_ST_NUM; // default
    struct bio_offsets *bio_offsets = bpf_map_lookup_elem(&detected_bio_offsets, &bio_key);
    if (bio_offsets && bio_offsets->detected) {
        bio_num_offset = bio_offsets->num_offset;
    }

    u64 ssl_rbio_num_addr;
    u64 *ssl_rbio_num_ptr = (u64 *)(ssl_rbio_addr + bio_num_offset);
    ret = bpf_probe_read_user(&ssl_rbio_num_addr, sizeof(ssl_rbio_num_addr), ssl_rbio_num_ptr);
    if (ret) {
        debug_bpf_printk("(ADAPTIVE) SSL_read: bpf_probe_read ssl_rbio_num_ptr failed, ret: %d\n", ret);
        return 0;
    }

    u32 fd = (u32)ssl_rbio_num_addr;
    if (!is_valid_fd(fd)) {
        // Try fallback
        u64 ssl_addr = (u64)ssl;
        u64 *fd_ptr = bpf_map_lookup_elem(&ssl_st_fd, &ssl_addr);
        if (fd_ptr) {
            fd = (u32)*fd_ptr;
        } else {
            return 0;
        }
    }

    debug_bpf_printk("(ADAPTIVE) SSL_read: fd=%d, version=0x%x\n", fd, (u32)ssl_version);

    // Store buffer information for SSL_read return probe
    const char* buf = (char*)PT_REGS_PARM2(ctx);
    struct active_ssl_buf active_ssl_buf_t;
    __builtin_memset(&active_ssl_buf_t, 0, sizeof(active_ssl_buf_t));
    active_ssl_buf_t.fd = fd;
    active_ssl_buf_t.version = (s32)ssl_version;
    active_ssl_buf_t.buf = buf;

    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&active_ssl_read_args_map, &id, &active_ssl_buf_t, BPF_ANY);
    return 0;
}

#endif /* __OPENSSL_ADAPTIVE_H__ */