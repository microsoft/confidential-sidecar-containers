// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//go:build linux

package attest

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"unsafe"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"golang.org/x/sys/unix"
)

// Message sizes for the Linux SEV-SNP guest request ioctl interface.
const (
	REPORT_REQ_SIZE = 96   // Size of MSG_REPORT_REQ (Table 20)
	REPORT_RSP_SIZE = 1280 // Size of MSG_REPORT_RSP (Table 23)
	PAYLOAD_SIZE    = 40   // Size of sev_snp_guest_request struct from sev-snp driver include/uapi/linux/psp-sev-guest.h
)

// Message Type Encodings (Table 100)
const (
	MSG_REPORT_REQ = 5
	MSG_REPORT_RSP = 6
)

func NewAttestationReportFetcher() (AttestationReportFetcher, error) {
	switch {
	case IsSNPVM5():
		{
			return NewAttestationReportFetcher5(), nil
		}
	case IsSNPVM6():
		{
			return NewAttestationReportFetcher6(), nil
		}
	default:
		{
			return nil, fmt.Errorf("SEV device is not found")
		}
	}
}

/*
Creates and returns MSG_REPORT_REQ message bytes (SEV-SNP Firmware ABI Specification Table 20)
*/
func createReportReqBytes(reportData [REPORT_DATA_SIZE]byte) [REPORT_REQ_SIZE]byte {
	reportReqBytes := [REPORT_REQ_SIZE]byte{}
	copy(reportReqBytes[0:REPORT_DATA_SIZE], reportData[:])
	return reportReqBytes
}

// ------------ Linux kernel 5.x ------------

const (
	// Value of SEV_SNP_GUEST_MSG_REPORT in sev-snp driver include/uapi/linux/psp-sev-guest.h
	SNP_GET_REPORT_IOCTL_REQ_CODE_5 = 3223868161
)

/*
Creates and returns byte array of the following C struct

// From sev-snp driver include/uapi/linux/psp-sev-guest.h
// struct sev_snp_guest_request {
//   uint8_t req_msg_type;
//   uint8_t rsp_msg_type;
//   uint8_t msg_version;
//   uint16_t request_len;
//   uint64_t request_uaddr;
//   uint16_t response_len;
//   uint64_t response_uaddr;
//   uint32_t error;		// firmware error code on failure (see psp-sev.h)
// };

The padding is based on Section 3.1.2 of System V ABI for AMD64
https://www.uclibc.org/docs/psABI-x86_64.pdf
*/
func createPayloadBytes5(reportReqPtr uintptr, reportRespPtr uintptr) ([PAYLOAD_SIZE]byte, error) {
	payload := [PAYLOAD_SIZE]byte{}
	var buf bytes.Buffer
	// req_msg_type
	if err := binary.Write(&buf, binary.LittleEndian, uint8(MSG_REPORT_REQ)); err != nil {
		return payload, err
	}
	// rsp_msg_type
	if err := binary.Write(&buf, binary.LittleEndian, uint8(MSG_REPORT_RSP)); err != nil {
		return payload, err
	}
	// msg_version
	if err := binary.Write(&buf, binary.LittleEndian, uint8(1)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint8(0)); err != nil {
		return payload, err
	}
	// request_len
	if err := binary.Write(&buf, binary.LittleEndian, uint16(REPORT_REQ_SIZE)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint16(0)); err != nil {
		return payload, err
	}
	// request_uaddr
	if err := binary.Write(&buf, binary.LittleEndian, uint64(reportReqPtr)); err != nil {
		return payload, err
	}
	// response_len
	if err := binary.Write(&buf, binary.LittleEndian, uint16(REPORT_RSP_SIZE)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, [3]uint16{}); err != nil {
		return payload, err
	}
	// response_uaddr
	if err := binary.Write(&buf, binary.LittleEndian, uint64(reportRespPtr)); err != nil {
		return payload, err
	}
	// error
	if err := binary.Write(&buf, binary.LittleEndian, uint32(0)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint32(0)); err != nil {
		return payload, err
	}
	for i, x := range buf.Bytes() {
		payload[i] = x
	}
	return payload, nil
}

func NewAttestationReportFetcher5() AttestationReportFetcher {
	return &realAttestationReportFetcher5{}
}

type realAttestationReportFetcher5 struct {
}

func (f *realAttestationReportFetcher5) FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error) {
	fd, err := unix.Open(SNP_DEVICE_PATH_5, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("error opening SNP device %s: %s", SNP_DEVICE_PATH_5, err)
	}

	reportReqBytes := createReportReqBytes(reportData)
	// MSG_REPORT_RSP message bytes (SEV-SNP Firmware Firmware ABI Specification Table 23)
	reportRspBytes := [REPORT_RSP_SIZE]byte{}
	payload, err := createPayloadBytes5(uintptr(unsafe.Pointer(&reportReqBytes[0])), uintptr(unsafe.Pointer(&reportRspBytes[0])))
	if err != nil {
		return nil, err
	}

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(SNP_GET_REPORT_IOCTL_REQ_CODE_5),
		uintptr(unsafe.Pointer(&payload[0])),
	)

	if errno != 0 {
		return nil, fmt.Errorf("ioctl failed:%v", errno)
	}

	if status := binary.LittleEndian.Uint32(reportRspBytes[0:4]); status != 0 {
		return nil, fmt.Errorf("fetching attestation report failed. status: %v", status)
	}
	const SNP_REPORT_OFFSET = 32
	reportBytes := reportRspBytes[SNP_REPORT_OFFSET : SNP_REPORT_OFFSET+ATTESTATION_REPORT_SIZE]
	if common.GenerateTestData {
		err = os.WriteFile("snp_report.bin", reportBytes, 0644)
		if err != nil {
			return nil, fmt.Errorf("writing snp report failed: %v", err)
		}
	}
	return reportBytes, nil
}

func (f *realAttestationReportFetcher5) FetchAttestationReportHex(reportData [REPORT_DATA_SIZE]byte) (string, error) {
	report, err := f.FetchAttestationReportByte(reportData)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(report), nil
}

// ------------ Linux kernel 6.x ------------

// Linux kernel 6.x specific values
const (
	/*
		Size of the following struct in include/uapi/linux/sev-guest.h.
		It will have the conteints of MSG_REPORT_RSP (Table 23) in the first REPORT_RSP_SIZE bytes.
			typedef struct {
				// response data, see SEV-SNP spec for the format
				uint8_t  data[4000];
			} snp_report_resp;
	*/
	REPORT_RSP_CONTAINER_SIZE_6 = 4000

	// Size of snp_guest_request_ioctl
	PAYLOAD_SIZE_6 = 32
	// Value of SNP_GET_REPORT in sev-snp driver include/uapi/linux/sev-guest.h
	SNP_GET_REPORT_IOCTL_REQ_CODE_6 = 3223343872
)

/*
Creates and returns byte array of the following C struct

	typedef struct {
	    // message version number (must be non-zero)
	    uint8_t msg_version;

	    // Request and response structure address
	    uint64_t req_data;
	    uint64_t resp_data;

	    // firmware error code on failure (see psp-sev.h)
	    uint64_t fw_err;
	} snp_guest_request_ioctl;

The padding is based on Section 3.1.2 of System V ABI for AMD64
https://www.uclibc.org/docs/psABI-x86_64.pdf
*/
func createPayloadBytes6(reportReqPtr uintptr, reportRespPtr uintptr) ([PAYLOAD_SIZE_6]byte, error) {
	payload := [PAYLOAD_SIZE_6]byte{}
	var buf bytes.Buffer
	// msg_version
	if err := binary.Write(&buf, binary.LittleEndian, uint8(1)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, [7]uint8{}); err != nil {
		return payload, err
	}
	// req_data
	if err := binary.Write(&buf, binary.LittleEndian, uint64(reportReqPtr)); err != nil {
		return payload, err
	}
	// resp_data
	if err := binary.Write(&buf, binary.LittleEndian, uint64(reportRespPtr)); err != nil {
		return payload, err
	}
	// fw_err
	if err := binary.Write(&buf, binary.LittleEndian, uint64(0)); err != nil {
		return payload, err
	}
	for i, x := range buf.Bytes() {
		payload[i] = x
	}
	return payload, nil
}

func NewAttestationReportFetcher6() AttestationReportFetcher {
	return &realAttestationReportFetcher6{}
}

type realAttestationReportFetcher6 struct {
}

func (f *realAttestationReportFetcher6) FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error) {
	fd, err := unix.Open(SNP_DEVICE_PATH_6, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("error opening SNP device %s: %s", SNP_DEVICE_PATH_6, err)
	}

	reportReqBytes := createReportReqBytes(reportData)
	// MSG_REPORT_RSP message bytes (SEV-SNP Firmware Firmware ABI Specification Table 23)
	reportRspContainerBytes := [REPORT_RSP_CONTAINER_SIZE_6]byte{}
	payload, err := createPayloadBytes6(uintptr(unsafe.Pointer(&reportReqBytes[0])), uintptr(unsafe.Pointer(&reportRspContainerBytes[0])))
	if err != nil {
		return nil, err
	}

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(SNP_GET_REPORT_IOCTL_REQ_CODE_6),
		uintptr(unsafe.Pointer(&payload[0])),
	)

	if errno != 0 {
		return nil, fmt.Errorf("ioctl failed:%v", errno)
	}

	// It has contents of MSG_REPORT_RSP in SEV-SNP spec
	reportRspBytes := reportRspContainerBytes[0:REPORT_RSP_SIZE]

	if status := binary.LittleEndian.Uint32(reportRspBytes[0:4]); status != 0 {
		return nil, fmt.Errorf("fetching attestation report failed. status: %v", status)
	}

	const SNP_REPORT_OFFSET = 32
	reportBytes := reportRspBytes[SNP_REPORT_OFFSET : SNP_REPORT_OFFSET+ATTESTATION_REPORT_SIZE]
	if common.GenerateTestData {
		err = os.WriteFile("snp_report.bin", reportBytes, 0644)
		if err != nil {
			return nil, fmt.Errorf("writing snp report failed: %v", err)
		}
	}
	return reportBytes, nil
}

func (f *realAttestationReportFetcher6) FetchAttestationReportHex(reportData [REPORT_DATA_SIZE]byte) (string, error) {
	report, err := f.FetchAttestationReportByte(reportData)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(report), nil
}
