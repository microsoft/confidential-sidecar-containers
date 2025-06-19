// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

// Data structures are based on SEV-SNP Firmware ABI Specification
// https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf

const (
	ATTESTATION_REPORT_SIZE = 1184 // Size of ATTESTATION_REPORT (Table 21)
	REPORT_DATA_SIZE        = 64   // Size of REPORT_DATA in ATTESTATION_REPORT
	REPORT_DATA_OFFSET      = 80   // Offset of REPORT_DATA in ATTESTATION_REPORT
	HOST_DATA_SIZE          = 32   // Size of HOST_DATA in ATTESTATION_REPORT
	HOST_DATA_OFFSET        = 192  // Offset of HOST_DATA in ATTESTATION_REPORT
	REPORTED_TCB_OFFSET     = 384
	REPORTED_TCB_SIZE       = 8
	CHIP_ID_OFFSET          = 416
	CHIP_ID_SIZE            = 64
	REPORT_REQ_SIZE         = 96   // Size of MSG_REPORT_REQ (Table 20)
	REPORT_RSP_SIZE         = 1280 // Size of MSG_REPORT_RSP (Table 23)
	PAYLOAD_SIZE            = 40   // Size of sev_snp_guest_request struct from sev-snp driver include/uapi/linux/psp-sev-guest.h
)

// Message Type Encodings (Table 100)
const (
	MSG_REPORT_REQ = 5
	MSG_REPORT_RSP = 6
)

type AttestationReportFetcher interface {
	// Fetches attestation report as []byte.
	// reportData is guest-provided data defined in SEV-SNP Firmware ABI Specification.
	FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error)
	// Fetches attestation report as hex.
	// reportData is guest-provided data defined in SEV-SNP Firmware ABI Specification.
	FetchAttestationReportHex(reportData [REPORT_DATA_SIZE]byte) (string, error)
}

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

// ------------ Fake report ------------

// Not SECURE. It returns fake attestation report.
// hostDataBytes is data provided by the hypervisor at launch defined in SEV-SNP Firmware ABI Specification.
// In real SNP VMs, hostDataBytes is provided by the hypervisor.
func UnsafeNewFakeAttestationReportFetcher(hostDataBytes [HOST_DATA_SIZE]byte) AttestationReportFetcher {
	return &fakeAttestationReportFetcher{
		hostDataBytes: hostDataBytes,
	}
}

type fakeAttestationReportFetcher struct {
	hostDataBytes [HOST_DATA_SIZE]byte
}

func (f *fakeAttestationReportFetcher) FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error) {
	// Fake report data
	fakeReportBytes, err := hex.DecodeString("01000000010000001f00030000000000010000000000000000000000000000000200000000000000000000000000000000000000010000000000000000000031010000000000000000000000000000007ab000a323b3c873f5b81bbe584e7c1a26bcf40dc27e00f8e0d144b1ed2d14f10000000000000000000000000000000000000000000000000000000000000000b579c7d6b89f3914659abe09a004a58a1e77846b65bbdac9e29bd8f2f31b31af445a5dd40f76f71ecdd73117f1d592a38c19f1b6eee8658fbf8ff1b37f603c38929896b1cc813583bbfb21015b7aa66dd188ac79386022aec7aa4e72a7e87b0a8e0e8009183334bb0fe4f97ed89436f360b3644cd8382c7a14531a87b81a8f360000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e880add9a31077e5e8f3568b4c4451f0fea4372f66e3df3c0ca3ba26f447db2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000031000000000000000000000000000000000000000000000000e6c86796cd44b0bc6b7c0d4fdab33e2807e14b5fc4538b3750921169d97bcf4447c7d3ab2a7c25f74c1641e2885c1011d025cc536f5c9a2504713136c7877f48000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000247c7525e84623db9868fccf00faab22229d60aaa380213108f8875011a8f456231c5371277cc706733f4a483338fb59000000000000000000000000000000000000000000000000ed8c62254022f64630ebf97d66254dee04f708ecbe22387baf8018752fadc2b763f64bded65c94a325b6b9f22ebbb0d80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		panic("fake attestation report is broken")
	}
	copy(fakeReportBytes[REPORT_DATA_OFFSET:REPORT_DATA_OFFSET+REPORT_DATA_SIZE], reportData[:])
	copy(fakeReportBytes[HOST_DATA_OFFSET:HOST_DATA_OFFSET+HOST_DATA_SIZE], f.hostDataBytes[:])
	return fakeReportBytes, nil
}

func (f *fakeAttestationReportFetcher) FetchAttestationReportHex(reportData [REPORT_DATA_SIZE]byte) (string, error) {
	report, err := f.FetchAttestationReportByte(reportData)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(report), nil
}
