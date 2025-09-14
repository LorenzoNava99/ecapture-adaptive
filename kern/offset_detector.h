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

#ifndef __OFFSET_DETECTOR_H__
#define __OFFSET_DETECTOR_H__

#include "ecapture.h"

// Maximum search range for structure fields
#define MAX_STRUCT_SIZE 512
#define MAX_PROBE_ATTEMPTS 64

// Valid TLS protocol versions for validation
#define TLS_VERSION_1_0 0x0301
#define TLS_VERSION_1_1 0x0302
#define TLS_VERSION_1_2 0x0303
#define TLS_VERSION_1_3 0x0304
#define DTLS_VERSION_1_0 0xfeff
#define DTLS_VERSION_1_2 0xfefd

// Structure to store detected offsets
struct ssl_offsets {
    u16 version_offset;
    u16 session_offset;
    u16 rbio_offset;
    u16 wbio_offset;
    u16 s3_offset;
    u8 detected;
    u8 ssl_type; // 0=unknown, 1=OpenSSL, 2=BoringSSL
};

struct bio_offsets {
    u16 num_offset;
    u16 method_offset;
    u8 detected;
};

struct bio_method_offsets {
    u16 type_offset;
    u8 detected;
};

// BPF map to store detected offsets
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct ssl_offsets);
    __uint(max_entries, 1);
} detected_ssl_offsets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct bio_offsets);
    __uint(max_entries, 1);
} detected_bio_offsets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct bio_method_offsets);
    __uint(max_entries, 1);
} detected_bio_method_offsets SEC(".maps");

// Helper functions

static __always_inline bool is_valid_tls_version(u32 version) {
    return (version == TLS_VERSION_1_0 ||
            version == TLS_VERSION_1_1 ||
            version == TLS_VERSION_1_2 ||
            version == TLS_VERSION_1_3 ||
            version == DTLS_VERSION_1_0 ||
            version == DTLS_VERSION_1_2);
}

static __always_inline bool is_valid_user_pointer(u64 ptr) {
    // Basic sanity checks for user-space pointers on ARM64 Android
    // User space is typically 0x0000_0000_0000_0000 to 0x0000_7fff_ffff_ffff
    if (ptr == 0) return false;
    if (ptr > 0x7fffffffffff) return false;
    if (ptr < 0x10000) return false; // Avoid null pointer area
    return true;
}

static __always_inline bool is_valid_fd(u32 fd) {
    // File descriptors should be reasonable values
    if (fd == 0) return false; // stdin is not a socket
    if (fd > 65536) return false; // Very high FDs are unlikely
    return true;
}

// Probe SSL structure to find version field offset
static __always_inline int probe_ssl_version_offset(void *ssl_ptr, struct ssl_offsets *offsets) {
    u32 test_version;
    int ret;

    // Try different offsets (8-byte aligned) to find version field
    for (u16 offset = 0; offset < MAX_STRUCT_SIZE; offset += 8) {
        ret = bpf_probe_read_user(&test_version, sizeof(test_version),
                                  (char *)ssl_ptr + offset);
        if (ret != 0) continue;

        if (is_valid_tls_version(test_version)) {
            offsets->version_offset = offset;
            debug_bpf_printk("Found SSL version offset: 0x%x, version: 0x%x\n",
                           offset, test_version);
            return 0;
        }
    }
    return -1;
}

// Probe SSL structure to find BIO pointer offsets
static __always_inline int probe_ssl_bio_offsets(void *ssl_ptr, struct ssl_offsets *offsets) {
    u64 test_bio_ptr;
    int ret;
    int found_count = 0;

    // Try different offsets to find BIO pointers
    for (u16 offset = 8; offset < MAX_STRUCT_SIZE && found_count < 2; offset += 8) {
        ret = bpf_probe_read_user(&test_bio_ptr, sizeof(test_bio_ptr),
                                  (char *)ssl_ptr + offset);
        if (ret != 0) continue;

        if (is_valid_user_pointer(test_bio_ptr)) {
            if (found_count == 0) {
                offsets->rbio_offset = offset;
                debug_bpf_printk("Found SSL rbio offset: 0x%x\n", offset);
                found_count++;
            } else {
                offsets->wbio_offset = offset;
                debug_bpf_printk("Found SSL wbio offset: 0x%x\n", offset);
                found_count++;
            }
        }
    }

    return (found_count >= 2) ? 0 : -1;
}

// Probe BIO structure to find file descriptor
static __always_inline int probe_bio_fd_offset(void *bio_ptr, struct bio_offsets *offsets) {
    u32 test_fd;
    int ret;

    // Try different offsets to find fd field
    for (u16 offset = 0; offset < MAX_STRUCT_SIZE; offset += 4) {
        ret = bpf_probe_read_user(&test_fd, sizeof(test_fd),
                                  (char *)bio_ptr + offset);
        if (ret != 0) continue;

        if (is_valid_fd(test_fd)) {
            offsets->num_offset = offset;
            debug_bpf_printk("Found BIO fd offset: 0x%x, fd: %d\n", offset, test_fd);
            return 0;
        }
    }
    return -1;
}

// Probe BIO structure to find method pointer
static __always_inline int probe_bio_method_offset(void *bio_ptr, struct bio_offsets *offsets) {
    u64 test_method_ptr;
    int ret;

    // Try different offsets to find method pointer
    for (u16 offset = 0; offset < MAX_STRUCT_SIZE; offset += 8) {
        ret = bpf_probe_read_user(&test_method_ptr, sizeof(test_method_ptr),
                                  (char *)bio_ptr + offset);
        if (ret != 0) continue;

        if (is_valid_user_pointer(test_method_ptr)) {
            offsets->method_offset = offset;
            debug_bpf_printk("Found BIO method offset: 0x%x\n", offset);
            return 0;
        }
    }
    return -1;
}

// Main detection function - runs on first SSL_write/SSL_read
static __always_inline int detect_ssl_offsets(void *ssl_ptr) {
    u32 key = 0;
    struct ssl_offsets *cached_offsets;

    // Check if already detected
    cached_offsets = bpf_map_lookup_elem(&detected_ssl_offsets, &key);
    if (cached_offsets && cached_offsets->detected) {
        return 0; // Already detected
    }

    struct ssl_offsets new_offsets = {0};

    // Step 1: Find SSL version offset
    if (probe_ssl_version_offset(ssl_ptr, &new_offsets) != 0) {
        debug_bpf_printk("Failed to detect SSL version offset\n");
        return -1;
    }

    // Step 2: Find BIO pointer offsets
    if (probe_ssl_bio_offsets(ssl_ptr, &new_offsets) != 0) {
        debug_bpf_printk("Failed to detect SSL BIO offsets\n");
        return -1;
    }

    new_offsets.detected = 1;

    // Store detected offsets
    bpf_map_update_elem(&detected_ssl_offsets, &key, &new_offsets, BPF_ANY);

    debug_bpf_printk("SSL offset detection complete: version=0x%x, rbio=0x%x, wbio=0x%x\n",
                     new_offsets.version_offset, new_offsets.rbio_offset, new_offsets.wbio_offset);

    return 0;
}

// Get detected SSL version offset (or fallback to default)
static __always_inline u16 get_ssl_version_offset(void) {
    u32 key = 0;
    struct ssl_offsets *offsets = bpf_map_lookup_elem(&detected_ssl_offsets, &key);
    if (offsets && offsets->detected) {
        return offsets->version_offset;
    }
    return SSL_ST_VERSION; // Fallback to compile-time default
}

// Get detected SSL BIO offsets
static __always_inline u16 get_ssl_wbio_offset(void) {
    u32 key = 0;
    struct ssl_offsets *offsets = bpf_map_lookup_elem(&detected_ssl_offsets, &key);
    if (offsets && offsets->detected) {
        return offsets->wbio_offset;
    }
    return SSL_ST_WBIO; // Fallback to compile-time default
}

static __always_inline u16 get_ssl_rbio_offset(void) {
    u32 key = 0;
    struct ssl_offsets *offsets = bpf_map_lookup_elem(&detected_ssl_offsets, &key);
    if (offsets && offsets->detected) {
        return offsets->rbio_offset;
    }
    return SSL_ST_RBIO; // Fallback to compile-time default
}

#endif /* __OFFSET_DETECTOR_H__ */