// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.6.1
// source: cmd/attestation-container/protobuf/attestation-container.proto

package protobuf

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// AttestationContainerClient is the client API for AttestationContainer service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AttestationContainerClient interface {
	// Fetches and returns attestation report, platform certificates, and UVM endorsements (UVM reference info).
	// In future it returns Certificate Revocation List (CRL) as well.
	FetchAttestation(ctx context.Context, in *FetchAttestationRequest, opts ...grpc.CallOption) (*FetchAttestationReply, error)
}

type attestationContainerClient struct {
	cc grpc.ClientConnInterface
}

func NewAttestationContainerClient(cc grpc.ClientConnInterface) AttestationContainerClient {
	return &attestationContainerClient{cc}
}

func (c *attestationContainerClient) FetchAttestation(ctx context.Context, in *FetchAttestationRequest, opts ...grpc.CallOption) (*FetchAttestationReply, error) {
	out := new(FetchAttestationReply)
	err := c.cc.Invoke(ctx, "/attestation_container.AttestationContainer/FetchAttestation", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AttestationContainerServer is the server API for AttestationContainer service.
// All implementations must embed UnimplementedAttestationContainerServer
// for forward compatibility
type AttestationContainerServer interface {
	// Fetches and returns attestation report, platform certificates, and UVM endorsements (UVM reference info).
	// In future it returns Certificate Revocation List (CRL) as well.
	FetchAttestation(context.Context, *FetchAttestationRequest) (*FetchAttestationReply, error)
	mustEmbedUnimplementedAttestationContainerServer()
}

// UnimplementedAttestationContainerServer must be embedded to have forward compatible implementations.
type UnimplementedAttestationContainerServer struct {
}

func (UnimplementedAttestationContainerServer) FetchAttestation(context.Context, *FetchAttestationRequest) (*FetchAttestationReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FetchAttestation not implemented")
}
func (UnimplementedAttestationContainerServer) mustEmbedUnimplementedAttestationContainerServer() {}

// UnsafeAttestationContainerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AttestationContainerServer will
// result in compilation errors.
type UnsafeAttestationContainerServer interface {
	mustEmbedUnimplementedAttestationContainerServer()
}

func RegisterAttestationContainerServer(s grpc.ServiceRegistrar, srv AttestationContainerServer) {
	s.RegisterService(&AttestationContainer_ServiceDesc, srv)
}

func _AttestationContainer_FetchAttestation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FetchAttestationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttestationContainerServer).FetchAttestation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attestation_container.AttestationContainer/FetchAttestation",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttestationContainerServer).FetchAttestation(ctx, req.(*FetchAttestationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AttestationContainer_ServiceDesc is the grpc.ServiceDesc for AttestationContainer service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AttestationContainer_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "attestation_container.AttestationContainer",
	HandlerType: (*AttestationContainerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "FetchAttestation",
			Handler:    _AttestationContainer_FetchAttestation_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "cmd/attestation-container/protobuf/attestation-container.proto",
}
