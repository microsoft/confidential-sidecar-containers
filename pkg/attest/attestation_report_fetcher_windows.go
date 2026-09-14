// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows

package attest

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/sirupsen/logrus"
)

// Userland API for the AMD SEV-SNP PSP driver on Windows, exposed by
// amdsnppspapi.dll. See SnpPspApi.h for the definitions mirrored here.
const snpPspApiDllName = "amdsnppspapi.dll"

// SNPPSP_API_STATUS values.
const (
	snpPspApiStatusSuccess            = 0x00000000
	snpPspApiStatusUnsuccessful       = 0x00000001
	snpPspApiStatusDriverUnsuccessful = 0x00000002
	snpPspApiStatusPspUnsuccessful    = 0x00000003
	snpPspApiStatusInvalidParameter   = 0x00000004
	snpPspApiStatusDeviceNotAvailable = 0x00000005
)

// snpPspApiStatusString returns the symbolic name of an SNPPSP_API_STATUS value.
func snpPspApiStatusString(status uintptr) string {
	switch status {
	case snpPspApiStatusSuccess:
		return "SNPPSP_API_STATUS_SUCCESS"
	case snpPspApiStatusUnsuccessful:
		return "SNPPSP_API_STATUS_UNSUCCESSFUL"
	case snpPspApiStatusDriverUnsuccessful:
		return "SNPPSP_API_STATUS_DRIVER_UNSUCCESSFUL"
	case snpPspApiStatusPspUnsuccessful:
		return "SNPPSP_API_STATUS_PSP_UNSUCCESSFUL"
	case snpPspApiStatusInvalidParameter:
		return "SNPPSP_API_STATUS_INVALID_PARAMETER"
	case snpPspApiStatusDeviceNotAvailable:
		return "SNPPSP_API_STATUS_DEVICE_NOT_AVAILABLE"
	default:
		return "???"
	}
}

//		typedef struct _SNPPSP_API_GUEST_REQUEST_RESULT
//		{
//		    DWORD DriverStatus;
//	     // DWORD _pad;
//	     // The next field needs to be 8 byte aligned, hence the above.
//		    SNPPSP_API_PSP_STATUS PspStatus; // UINT64
//		} SNPPSP_API_GUEST_REQUEST_RESULT;
//
// This is safe because Go does not reorder struct fields.
type snpPspApiGuestRequestResult struct {
	DriverStatus uint32
	_            uint32
	PspStatus    uint64
}

func NewAttestationReportFetcher() (AttestationReportFetcher, error) {
	securityContextDir, err := common.GetUvmSecurityCtxDir()
	if err != nil {
		return nil, fmt.Errorf("error finding security context directory: %w", err)
	}

	dllPath := filepath.Join(securityContextDir, snpPspApiDllName)

	if _, err := os.Stat(dllPath); os.IsNotExist(err) {
		logrus.Warnf("%s not found, trying LoadDLL(\"%s\") directly", dllPath, snpPspApiDllName)
		dllPath = snpPspApiDllName
	}

	dll, err := syscall.LoadDLL(dllPath)
	if err != nil {
		return nil, fmt.Errorf("error loading %s: %w", dllPath, err)
	}

	isSnpModeProc, err := dll.FindProc("SnpPspIsSnpMode")
	if err != nil {
		return nil, fmt.Errorf("error finding SnpPspIsSnpMode in %s: %w", dllPath, err)
	}

	fetchReportProc, err := dll.FindProc("SnpPspFetchAttestationReport")
	if err != nil {
		return nil, fmt.Errorf("error finding SnpPspFetchAttestationReport in %s: %w", dllPath, err)
	}

	// Confirm we are running in an SEV-SNP VM before returning a fetcher.
	var isSnp uint8 // BOOLEAN (1 byte)
	status, _, _ := isSnpModeProc.Call(uintptr(unsafe.Pointer(&isSnp)))
	if status != snpPspApiStatusSuccess {
		return nil, fmt.Errorf("SnpPspIsSnpMode failed. status: 0x%x (%s)", status, snpPspApiStatusString(status))
	}
	if isSnp == 0 {
		return nil, fmt.Errorf("not running in an SEV-SNP VM")
	}

	return &windowsAttestationReportFetcher{
		fetchReportProc: fetchReportProc,
	}, nil
}

type windowsAttestationReportFetcher struct {
	fetchReportProc *syscall.Proc
}

func (f *windowsAttestationReportFetcher) FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error) {
	// SNPPSP_API_ATTESTATION_REPORT_SIZE (0x4A0) == ATTESTATION_REPORT_SIZE (1184).
	reportBytes := make([]byte, ATTESTATION_REPORT_SIZE)
	result := snpPspApiGuestRequestResult{}

	// reportData is a local copy of the caller's array, so it is addressable.
	status, _, _ := f.fetchReportProc.Call(
		uintptr(unsafe.Pointer(&reportData[0])),
		uintptr(unsafe.Pointer(&result)),
		uintptr(unsafe.Pointer(&reportBytes[0])),
	)

	if status != snpPspApiStatusSuccess {
		return nil, fmt.Errorf(
			"SnpPspFetchAttestationReport failed. status: 0x%x (%s), driver status: 0x%x, psp status: 0x%x",
			status, snpPspApiStatusString(status), result.DriverStatus, result.PspStatus,
		)
	}

	if common.GenerateTestData {
		if err := os.WriteFile("snp_report.bin", reportBytes, 0644); err != nil {
			return nil, fmt.Errorf("writing snp report failed: %v", err)
		}
	}

	return reportBytes, nil
}

func (f *windowsAttestationReportFetcher) FetchAttestationReportHex(reportData [REPORT_DATA_SIZE]byte) (string, error) {
	report, err := f.FetchAttestationReportByte(reportData)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(report), nil
}
