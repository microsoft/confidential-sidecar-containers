package attest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"unsafe"

	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"golang.org/x/sys/unix"
)

// Data structures are based on SEV-SNP Firmware ABI Specification
// https://www.amd.com/en/support/tech-docs/sev-secure-nested-paging-firmware-abi-specification

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

// From sev-snp driver include/uapi/linux/psp-sev-guest.h
const SEV_SNP_GUEST_MSG_REPORT = 3223868161

const SNP_DEVICE_PATH = "/dev/sev"

/*
Creates and returns MSG_REPORT_REQ message bytes (SEV-SNP Firmware ABI Specification Table 20)
*/
func createReportReqBytes(reportData [REPORT_DATA_SIZE]byte) [REPORT_REQ_SIZE]byte {
	reportReqBytes := [REPORT_REQ_SIZE]byte{}
	copy(reportReqBytes[0:REPORT_DATA_SIZE], reportData[:])
	return reportReqBytes
}

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
func createPayloadBytes(reportReqPtr uintptr, ReportRespPtr uintptr) ([PAYLOAD_SIZE]byte, error) {
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
	if err := binary.Write(&buf, binary.LittleEndian, uint64(ReportRespPtr)); err != nil {
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

type AttestationReportFetcher interface {
	// TODO: Comment about report data
	FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error)
	FetchAttestationReportHex(reportData [REPORT_DATA_SIZE]byte) (string, error)
}

// PR_COMMENT: This interface ('New...' function that returns interface rather than struct) is based on design of
// golang's standard library
// e.g. https://pkg.go.dev/crypto/sha256#New224
// We can provide `UnsafeNewFakeAttestationReportFetcher` which returns fake report in the same way but with `hostData` as parameter.
// With this method we don't have to include `hostData` in functions to fetch real attestation report which don't need it.
// Users of this package can switch between `realAttestationReportFetcher“ and `fakeAttestationReportFetcher`
// easily using dependency injection or similar techniques.
func NewAttestationReportFetcher() AttestationReportFetcher {
	return &realAttestationReportFetcher{}
}

type realAttestationReportFetcher struct {
}

func (_ *realAttestationReportFetcher) FetchAttestationReportByte(reportData [REPORT_DATA_SIZE]byte) ([]byte, error) {
	fd, err := unix.Open(SNP_DEVICE_PATH, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("Error opening SNP device %s: %s", SNP_DEVICE_PATH, err)
	}

	reportReqBytes := createReportReqBytes(reportData)
	// MSG_REPORT_RSP message bytes (SEV-SNP Firmware Firmware ABI Specification Table 23)
	reportRspBytes := [REPORT_RSP_SIZE]byte{}
	payload, err := createPayloadBytes(uintptr(unsafe.Pointer(&reportReqBytes[0])), uintptr(unsafe.Pointer(&reportRspBytes[0])))
	if err != nil {
		return nil, err
	}

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(SEV_SNP_GUEST_MSG_REPORT),
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
		ioutil.WriteFile("snp_report.bin", reportBytes, 0644)
	}
	return reportBytes, nil
}

// PR_COMMENT: Can be used instead of RawAttest
// RawAttest returns the raw attestation report in hex string format
func (f *realAttestationReportFetcher) FetchAttestationReportHex(reportData [REPORT_DATA_SIZE]byte) (string, error) {
	report, err := f.FetchAttestationReportByte(reportData)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(report), nil
}

// Not SECURE. It returns fake attestation report.
// In real SNP VMs, hostDataBytes (TODO: Table ... of ....) is provided by the hypervisor
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

// Takes bytes and generate report data that MAA expects (SHA256 hash of arbitrary data).
// TODO: check if this comment is correct
func GenerateMAAReportData(inputBytes []byte) [REPORT_DATA_SIZE]byte {
	runtimeData := sha256.New()
	if inputBytes != nil {
		runtimeData.Write(inputBytes)
	}
	reportData := [REPORT_DATA_SIZE]byte{}
	runtimeDataBytes := runtimeData.Sum(nil)
	const sha256len = 32
	if len(runtimeDataBytes) != sha256len {
		panic(fmt.Errorf("Length of sha256 hash should be %d bytes, but it is actually %d bytes", sha256len, len(runtimeDataBytes)))
	}
	if sha256len > REPORT_DATA_SIZE {
		panic(fmt.Errorf("Generated hash is too large for report data. hash length: %d bytes, report data size: %d", sha256len, REPORT_DATA_SIZE))
	}
	copy(reportData[:], runtimeDataBytes)
	return reportData
}
