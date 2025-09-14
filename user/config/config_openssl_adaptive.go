//go:build androidgki
// +build androidgki

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

package config

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/gojue/ecapture/assets"
	"github.com/gojue/ecapture/user/module"
)

type OpensslAdaptiveConfig struct {
	BaseConfig
	eConfig OpensslConfig
}

func NewOpensslAdaptiveConfig() *OpensslAdaptiveConfig {
	config := &OpensslAdaptiveConfig{}
	config.PerCpuMapSize = DefaultMapSizePerCpu
	return config
}

func (oac *OpensslAdaptiveConfig) Check() error {
	// Android GKI specific checks
	if err := oac.checkAndroidEnvironment(); err != nil {
		return err
	}

	// Check if we can find SSL libraries on attached device
	if err := oac.detectSSLLibraries(); err != nil {
		return fmt.Errorf("failed to detect SSL libraries: %v", err)
	}

	return oac.BaseConfig.Check()
}

func (oac *OpensslAdaptiveConfig) checkAndroidEnvironment() error {
	// Check if adb is available
	if _, err := exec.LookPath("adb"); err != nil {
		return fmt.Errorf("adb not found in PATH - required for Android device communication")
	}

	// Check if device is connected
	cmd := exec.Command("adb", "devices")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check adb devices: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	deviceCount := 0
	for _, line := range lines {
		if strings.Contains(line, "\tdevice") {
			deviceCount++
		}
	}

	if deviceCount == 0 {
		return fmt.Errorf("no Android devices connected via adb")
	}

	return nil
}

func (oac *OpensslAdaptiveConfig) detectSSLLibraries() error {
	// Try to find SSL libraries on attached device
	sslPaths := []string{
		"/system/lib64/libssl.so",
		"/system/lib/libssl.so",
		"/vendor/lib64/libssl.so",
		"/vendor/lib/libssl.so",
	}

	found := false
	for _, path := range sslPaths {
		cmd := exec.Command("adb", "shell", "test", "-f", path)
		if err := cmd.Run(); err == nil {
			oac.eConfig.SslLib = path
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("no SSL libraries found on attached Android device")
	}

	return nil
}

func (oac *OpensslAdaptiveConfig) Bytes() []byte {
	return oac.eConfig.Bytes()
}

func (oac *OpensslAdaptiveConfig) IsAndroid() bool {
	return true
}

func (oac *OpensslAdaptiveConfig) GetModules() []module.IModule {
	modules := make([]module.IModule, 0, 1)
	var mod module.IModule
	mod = module.GetModuleByName(module.MODULE_NAME_OPENSSL)
	if mod == nil {
		return modules
	}
	oac.eConfig.BpfFileName = oac.getBPFName()
	oac.eConfig.ConfigName = module.MODULE_NAME_OPENSSL
	mod.Init(context.TODO(), oac, &oac.eConfig)
	modules = append(modules, mod)
	return modules
}

func (oac *OpensslAdaptiveConfig) getBPFName() string {
	return "openssl_adaptive_kern.o"
}

func (oac *OpensslAdaptiveConfig) GetBPFFile() string {
	return oac.getBPFName()
}

func (oac *OpensslAdaptiveConfig) SetBTF(btfFile string) error {
	return oac.eConfig.SetBTF(btfFile)
}

func (oac *OpensslAdaptiveConfig) EnableGlobalVar() error {
	return oac.eConfig.EnableGlobalVar()
}

func (oac *OpensslAdaptiveConfig) SetPid(pid uint64) {
	oac.eConfig.SetPid(pid)
}

func (oac *OpensslAdaptiveConfig) SetUid(uid uint64) {
	oac.eConfig.SetUid(uid)
}

func (oac *OpensslAdaptiveConfig) SetDebug(isDebug bool) {
	oac.eConfig.SetDebug(isDebug)
}

func (oac *OpensslAdaptiveConfig) SetHex(isHex bool) {
	oac.eConfig.SetHex(isHex)
}

func (oac *OpensslAdaptiveConfig) SetBytes(maxBytes uint32) {
	oac.eConfig.SetBytes(maxBytes)
}

func (oac *OpensslAdaptiveConfig) SetPerCpuMapSize(perCpuMapSize int) {
	oac.eConfig.SetPerCpuMapSize(perCpuMapSize)
}

func (oac *OpensslAdaptiveConfig) SetAddrLen(l int) {
	oac.eConfig.SetAddrLen(l)
}

func (oac *OpensslAdaptiveConfig) SetPcapFile(pcapFile string) {
	oac.eConfig.SetPcapFile(pcapFile)
}

func (oac *OpensslAdaptiveConfig) SetKeylogFile(keylogFile string) {
	oac.eConfig.SetKeylogFile(keylogFile)
}

// GetBpfMap returns BPF program as ebpf.CollectionSpec
func (oac *OpensslAdaptiveConfig) GetBpfMap() (*ebpf.CollectionSpec, error) {
	var program string
	switch oac.eConfig.ElfArch {
	case EM_AARCH64:
		program = "openssl_adaptive_kern_noncore.o"
	case EM_X86_64:
		program = "openssl_adaptive_kern_noncore.o"
	default:
		return nil, errors.New(fmt.Sprintf("unsupported arch library. (%s)", oac.eConfig.ElfArch.String()))
	}

	return assets.LoadBpfMap(program)
}