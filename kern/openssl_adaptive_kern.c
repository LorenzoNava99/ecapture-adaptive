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

#ifndef ECAPTURE_OPENSSL_ADAPTIVE_KERN_H
#define ECAPTURE_OPENSSL_ADAPTIVE_KERN_H

// Define target architecture for ARM64 Android
#define __TARGET_ARCH_arm64 1

// Adaptive OpenSSL kernel module for runtime offset detection
// Works with any OpenSSL/BoringSSL version without hardcoded offsets

// Default fallback offsets (can be overridden by detection)
// These are reasonable defaults for modern OpenSSL/BoringSSL
#define SSL_ST_VERSION 0x10
#define SSL_ST_SESSION 0x58
#define SSL_ST_RBIO 0x18
#define SSL_ST_WBIO 0x20
#define SSL_ST_S3 0x30

#define BIO_ST_NUM 0x38
#define BIO_ST_METHOD 0x8
#define BIO_METHOD_ST_TYPE 0x0

// Include only what we need to avoid duplicate includes
#include "ecapture.h"
#include "offset_detector.h"
#include "openssl_adaptive.h"

#endif