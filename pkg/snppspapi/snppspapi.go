// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build windows

// Package snppspapi is a pure-Go reimplementation of amdsnppspapi.dll, the
// userland API for the AMD SEV-SNP PSP driver on Windows. It talks to the
// kernel driver directly via DeviceIoControl on the \\.\SnpPsp device.
package snppspapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// =============================================================================
// SnpPspApi.h
// =============================================================================

const (
	// SNPPSP_API_DERIVED_GUEST_KEY_SIZE.
	DerivedGuestKeySize = 32
	// SNPPSP_API_REPORT_DATA_SIZE.
	ReportDataSize = 64
	// SNPPSP_API_ATTESTATION_REPORT_SIZE (0x4A0).
	AttestationReportSize = 0x4A0
)

// Status mirrors SNPPSP_API_STATUS (a DWORD return code).
type Status uint32

// SNPPSP_API_STATUS_* values.
const (
	StatusSuccess            Status = 0x00000000
	StatusUnsuccessful       Status = 0x00000001
	StatusDriverUnsuccessful Status = 0x00000002
	StatusPspUnsuccessful    Status = 0x00000003
	StatusInvalidParameter   Status = 0x00000004
	StatusDeviceNotAvailable Status = 0x00000005
)

// String returns the symbolic name of the status code.
func (s Status) String() string {
	switch s {
	case StatusSuccess:
		return "SNPPSP_API_STATUS_SUCCESS"
	case StatusUnsuccessful:
		return "SNPPSP_API_STATUS_UNSUCCESSFUL"
	case StatusDriverUnsuccessful:
		return "SNPPSP_API_STATUS_DRIVER_UNSUCCESSFUL"
	case StatusPspUnsuccessful:
		return "SNPPSP_API_STATUS_PSP_UNSUCCESSFUL"
	case StatusInvalidParameter:
		return "SNPPSP_API_STATUS_INVALID_PARAMETER"
	case StatusDeviceNotAvailable:
		return "SNPPSP_API_STATUS_DEVICE_NOT_AVAILABLE"
	default:
		return fmt.Sprintf("SNPPSP_API_STATUS(0x%x)", uint32(s))
	}
}

// SNPPSP_API_PSP_STATUS is a UINT64; modeled inline as the PspStatus fields.

// GuestRequestResult mirrors SNPPSP_API_GUEST_REQUEST_RESULT and carries the
// detailed result of a guest request.
type GuestRequestResult struct {
	// DriverStatus is the system error code returned from the PSP driver IOCTL.
	DriverStatus uint32
	// PspStatus is the value returned from the PSP as SW_EXITINFO2.
	PspStatus uint64
}

// =============================================================================
// SnpPspDriverCommon.h
// =============================================================================

// SNP_PSP_DEVICE_FILE_NAME.
const deviceFileName = `\\.\SnpPsp`

// SNP_PSP_SNP_VMPL_DRV. The driver runs as VMPL2 (VTL0); this is the VMPL value
// placed in guest requests.
const vmplDrv = 2

// IOCTL codes, computed from the CTL_CODE macro:
//
//	CTL_CODE(DeviceType, Function, Method, Access) =
//	    (DeviceType<<16) | (Access<<14) | (Function<<2) | Method
//
// with DeviceType=FILE_DEVICE_UNKNOWN(0x22), Method=METHOD_BUFFERED(0) and
// Access=FILE_READ_ACCESS(0x1).
const (
	// IOCTL_SNP_PSP_DEVICE_IS_SNP_MODE: function 0x800. The final
	// "| METHOD_BUFFERED (=0)" term is omitted as it does not affect the value
	// and causes warnings.
	ioctlIsSnpMode = (0x22 << 16) | (0x1 << 14) | (0x800 << 2)
	// IOCTL_SNP_PSP_DEVICE_GUEST_REQUEST: function 0x801.
	ioctlGuestRequest = (0x22 << 16) | (0x1 << 14) | (0x801 << 2)
)

// guestRequestInputHeader is SNPPSP_DRV_GUEST_REQUEST_INPUT_HEADER (8 bytes).
type guestRequestInputHeader struct {
	MessageType    uint8
	MessageVersion uint8
	Reserved       [6]uint8
}

// SNPPSP_PSP_STATUS_SUCCESS.
const pspStatusSuccess = 0

// isSnpModeOut is SNPPSP_DRV_IS_SNP_MODE_OUT (1 byte).
type isSnpModeOut struct {
	IsSnpMode uint8
}

// =============================================================================
// SnpPspApi.cpp
// =============================================================================

// Message types/versions, based on Table 102 of the SNP specification.
const (
	msgKeyReqType = 3
	msgKeyReqVer  = 1

	msgReportReqType = 5
	msgReportReqVer  = 1
)

// The IOCTL message structs below mirror the packed (#pragma pack(1)) C structs
// field-for-field. The C layouts happen to be naturally aligned already, so the
// equivalent Go structs have the same byte layout even though Go does not pack.

// msgKeyReqIoctl is MSG_KEY_REQ_IOCTL (40 bytes).
type msgKeyReqIoctl struct {
	InputHeader guestRequestInputHeader // offset 0

	Flags            uint32 // offset 8
	Reserved         uint32 // offset 12
	GuestFieldSelect uint64 // offset 16
	Vmpl             uint32 // offset 24
	GuestSvn         uint32 // offset 28
	TcbVersion       uint64 // offset 32
}

// msgKeyRespIoctl is MSG_KEY_RESP_IOCTL (72 bytes).
type msgKeyRespIoctl struct {
	PspStatus uint64 // offset 0

	Status     uint32                     // offset 8
	Reserved   [28]uint8                  // offset 12
	DerivedKey [DerivedGuestKeySize]uint8 // offset 40
}

// msgReportReqIoctl is MSG_REPORT_REQ_IOCTL (104 bytes).
type msgReportReqIoctl struct {
	InputHeader guestRequestInputHeader // offset 0

	ReportData [ReportDataSize]uint8 // offset 8
	Vmpl       uint32                // offset 72
	Reserved   [28]uint8             // offset 76
}

// msgReportRespIoctl is MSG_REPORT_RESP_IOCTL (1224 bytes).
type msgReportRespIoctl struct {
	PspStatus uint64 // offset 0

	Status     uint32                       // offset 8
	ReportSize uint32                       // offset 12
	Reserved   [24]uint8                    // offset 16
	Report     [AttestationReportSize]uint8 // offset 40
}

// getPspDevice opens the \\.\SnpPsp device, mirroring GetPspDevice.
func getPspDevice() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(deviceFileName)
	if err != nil {
		return windows.InvalidHandle, err
	}
	h, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return h, nil
}

// FetchAttestationReport returns an attestation report for the given report
// data. It mirrors SnpPspFetchAttestationReport.
func FetchAttestationReport(reportData [ReportDataSize]byte) ([AttestationReportSize]byte, GuestRequestResult, error) {
	const op = "SnpPspFetchAttestationReport"
	var report [AttestationReportSize]byte
	var result GuestRequestResult

	h, err := getPspDevice()
	if err != nil {
		return report, result, &APIError{Op: op, Status: StatusDeviceNotAvailable, Err: err}
	}
	defer windows.CloseHandle(h)

	in := msgReportReqIoctl{
		InputHeader: guestRequestInputHeader{
			MessageType:    msgReportReqType,
			MessageVersion: msgReportReqVer,
		},
		Vmpl: vmplDrv,
	}
	copy(in.ReportData[:], reportData[:])

	var out msgReportRespIoctl
	var bytesReturned uint32
	err = windows.DeviceIoControl(
		h,
		ioctlGuestRequest,
		(*byte)(unsafe.Pointer(&in)),
		uint32(unsafe.Sizeof(in)),
		(*byte)(unsafe.Pointer(&out)),
		uint32(unsafe.Sizeof(out)),
		&bytesReturned,
		nil,
	)
	// The driver returns at least sizeof(SNPPSP_DRV_GUEST_REQUEST_OUTPUT)
	// (the 8-byte PspStatus) on a successful IOCTL.
	if err != nil || uintptr(bytesReturned) < unsafe.Sizeof(out.PspStatus) {
		result.DriverStatus = errno(err)
		return report, result, &APIError{Op: op, Status: StatusDriverUnsuccessful, Result: result, Err: err}
	}
	if out.PspStatus != pspStatusSuccess {
		result.PspStatus = out.PspStatus
		return report, result, &APIError{Op: op, Status: StatusPspUnsuccessful, Result: result}
	}
	if uintptr(bytesReturned) < unsafe.Sizeof(out) {
		return report, result, &APIError{
			Op:     op,
			Status: StatusDriverUnsuccessful,
			Result: result,
			Err:    fmt.Errorf("insufficient bytes returned: got %d, want %d", bytesReturned, unsafe.Sizeof(out)),
		}
	}

	copy(report[:], out.Report[:])
	return report, result, nil
}

// DeriveKey derives a guest key. It mirrors SnpPspDeriveKey.
func DeriveKey(keySel, rootKeySelect uint8, guestFieldSelect uint64, vmpl, guestSvn uint32, tcbVersion uint64) ([DerivedGuestKeySize]byte, GuestRequestResult, error) {
	const op = "SnpPspDeriveKey"
	var key [DerivedGuestKeySize]byte
	var result GuestRequestResult

	const keySelBitCount = 2
	const rootKeySelectBitCount = 1
	if keySel >= (1 << keySelBitCount) {
		return key, result, &APIError{Op: op, Status: StatusInvalidParameter,
			Err: fmt.Errorf("keySel %d is out of range", keySel)}
	}
	if rootKeySelect >= (1 << rootKeySelectBitCount) {
		return key, result, &APIError{Op: op, Status: StatusInvalidParameter,
			Err: fmt.Errorf("rootKeySelect %d is out of range", rootKeySelect)}
	}

	h, err := getPspDevice()
	if err != nil {
		return key, result, &APIError{Op: op, Status: StatusDeviceNotAvailable, Err: err}
	}
	defer windows.CloseHandle(h)

	in := msgKeyReqIoctl{
		InputHeader: guestRequestInputHeader{
			MessageType:    msgKeyReqType,
			MessageVersion: msgKeyReqVer,
		},
		Flags:            uint32(rootKeySelect) | (uint32(keySel) << 1),
		GuestFieldSelect: guestFieldSelect,
		Vmpl:             vmpl,
		GuestSvn:         guestSvn,
		TcbVersion:       tcbVersion,
	}

	var out msgKeyRespIoctl
	var bytesReturned uint32
	err = windows.DeviceIoControl(
		h,
		ioctlGuestRequest,
		(*byte)(unsafe.Pointer(&in)),
		uint32(unsafe.Sizeof(in)),
		(*byte)(unsafe.Pointer(&out)),
		uint32(unsafe.Sizeof(out)),
		&bytesReturned,
		nil,
	)
	if err != nil || uintptr(bytesReturned) < unsafe.Sizeof(out.PspStatus) {
		result.DriverStatus = errno(err)
		return key, result, &APIError{Op: op, Status: StatusDriverUnsuccessful, Result: result, Err: err}
	}
	if out.PspStatus != pspStatusSuccess {
		result.PspStatus = out.PspStatus
		return key, result, &APIError{Op: op, Status: StatusPspUnsuccessful, Result: result}
	}
	if uintptr(bytesReturned) < unsafe.Sizeof(out) {
		return key, result, &APIError{
			Op:     op,
			Status: StatusDriverUnsuccessful,
			Result: result,
			Err:    fmt.Errorf("insufficient bytes returned: got %d, want %d", bytesReturned, unsafe.Sizeof(out)),
		}
	}

	copy(key[:], out.DerivedKey[:])
	return key, result, nil
}

// IsSnpMode reports whether the current environment is running in SNP mode.
// It mirrors SnpPspIsSnpMode.
func IsSnpMode() (bool, error) {
	h, err := getPspDevice()
	if err != nil {
		return false, &APIError{Op: "SnpPspIsSnpMode", Status: StatusDeviceNotAvailable, Err: err}
	}
	defer windows.CloseHandle(h)

	var out isSnpModeOut
	var bytesReturned uint32
	err = windows.DeviceIoControl(
		h,
		ioctlIsSnpMode,
		nil,
		0,
		(*byte)(unsafe.Pointer(&out)),
		uint32(unsafe.Sizeof(out)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return false, &APIError{
			Op:     "SnpPspIsSnpMode",
			Status: StatusDriverUnsuccessful,
			Result: GuestRequestResult{DriverStatus: errno(err)},
			Err:    err,
		}
	}
	return out.IsSnpMode != 0, nil
}

// =============================================================================
// Go-specific helpers
// =============================================================================

// APIError describes a failed snppspapi call. It carries the SNPPSP_API_STATUS
// code, the detailed guest request result, and any underlying syscall error.
type APIError struct {
	Op     string
	Status Status
	Result GuestRequestResult
	Err    error
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("%s failed: status 0x%x (%s), driver status: 0x%x, psp status: 0x%x",
		e.Op, uint32(e.Status), e.Status, e.Result.DriverStatus, e.Result.PspStatus)
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

func (e *APIError) Unwrap() error { return e.Err }

// errno extracts a Windows system error code from err, or 0 if none.
func errno(err error) uint32 {
	if e, ok := err.(windows.Errno); ok {
		return uint32(e)
	}
	return 0
}
