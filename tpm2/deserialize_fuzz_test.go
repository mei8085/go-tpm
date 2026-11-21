package tpm2

import (
	"bytes"
	"reflect"
	"testing"
)

// fuzzDeserializer is the shared body of every Fuzz function in this file. It
// asserts that decoding never panics, that rejected input yields no usable
// value, and that accepted input satisfies the structural-equivalence
// invariant.
func fuzzDeserializer[T Marshallable, P interface {
	*T
	Unmarshallable
}](t *testing.T, data []byte) {
	t.Helper()
	var got *T
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("decoding %x panicked: %v", data, r)
			}
		}()
		got, err = Unmarshal[T, P](data)
	}()
	if err != nil {
		if got != nil {
			t.Fatalf("decoding %x returned non-nil value with error %v", data, err)
		}
		return
	}

	enc := Marshal(any(*got).(Marshallable))
	again, err := Unmarshal[T, P](enc)
	if err != nil {
		t.Fatalf("re-decoding %x (encoded as %x) failed: %v", data, enc, err)
	}
	enc2 := Marshal(any(*again).(Marshallable))
	if !bytes.Equal(enc, enc2) {
		t.Fatalf("marshalling %x was not stable: %x then %x", data, enc, enc2)
	}
	if !reflect.DeepEqual(got, again) {
		t.Fatalf("decoding %x was not idempotent:\nfirst:  %+v\nsecond: %+v", data, got, again)
	}
}

func FuzzUnmarshalTPMTPublic(f *testing.F) {
	for _, v := range nestedPublic() {
		f.Add(Marshal(v))
	}
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x10})             // TPM_ALG_NULL selector
	f.Add([]byte{0x00, 0x06, 0, 0, 0, 0}) // unknown selector
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzDeserializer[TPMTPublic](t, data)
	})
}

func FuzzUnmarshalTPMSAttest(f *testing.F) {
	for _, v := range nestedAttest() {
		f.Add(Marshal(v))
	}
	f.Add([]byte{})
	f.Add([]byte{0xff, 0x54, 0x43, 0x47})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzDeserializer[TPMSAttest](t, data)
	})
}

func FuzzUnmarshalTPM2B(f *testing.F) {
	f.Add(Marshal(&TPM2BData{Buffer: []byte{1, 2, 3}}))
	f.Add(Marshal(&TPM2BData{}))
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzDeserializer[TPM2BData](t, data)
		fuzzDeserializer[TPM2BPublic](t, data)
	})
}

func FuzzUnmarshalTPMSPCRSelection(f *testing.F) {
	f.Add(Marshal(&TPMSPCRSelection{Hash: TPMAlgSHA256, PCRSelect: []byte{1, 2, 3}}))
	f.Add(Marshal(&TPMSPCRSelection{}))
	f.Add([]byte{0x00, 0x0b, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzDeserializer[TPMSPCRSelection](t, data)
	})
}

func FuzzUnmarshalTPMLPCRSelection(f *testing.F) {
	f.Add(Marshal(&TPMLPCRSelection{PCRSelections: []TPMSPCRSelection{
		{Hash: TPMAlgSHA256, PCRSelect: []byte{1}},
		{Hash: TPMAlgSHA1, PCRSelect: []byte{0xff, 0xff}},
	}}))
	f.Add(Marshal(&TPMLPCRSelection{}))
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzDeserializer[TPMLPCRSelection](t, data)
	})
}

func FuzzUnmarshalTPMSNVPublic(f *testing.F) {
	f.Add(Marshal(&TPMSNVPublic{NVIndex: TPMRHOwner, NameAlg: TPMAlgSHA256, DataSize: 64}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzDeserializer[TPMSNVPublic](t, data)
	})
}

// FuzzUnmarshalCommand checks that a truncated or malformed command preimage
// never yields a partially populated command.
func FuzzUnmarshalCommand(f *testing.F) {
	enc, err := MarshalCommand(GetCapability{Capability: TPMCapAlgs, Property: 1, PropertyCount: 2})
	if err != nil {
		f.Fatalf("MarshalCommand: %v", err)
	}
	f.Add(enc)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00, 0x01, 0x7a})
	f.Fuzz(func(t *testing.T, data []byte) {
		var got GetCapability
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decoding %x panicked: %v", data, r)
				}
			}()
			got, err = UnmarshalCommand[GetCapability](data)
		}()
		if err != nil && !reflect.DeepEqual(got, GetCapability{}) {
			t.Fatalf("rejected input %x left partial command %+v (err %v)", data, got, err)
		}
	})
}

// FuzzUnmarshalResponse checks the same invariant for response preimages.
func FuzzUnmarshalResponse(f *testing.F) {
	enc, err := MarshalResponse(GetCapability{}, &GetCapabilityResponse{
		CapabilityData: TPMSCapabilityData{
			Capability: TPMCapAlgs,
			Data:       NewTPMUCapabilities(TPMCapAlgs, &TPMLAlgProperty{}),
		},
	})
	if err != nil {
		f.Fatalf("MarshalResponse: %v", err)
	}
	f.Add(enc)
	f.Add([]byte{})
	f.Add(make([]byte, 8))
	f.Fuzz(func(t *testing.T, data []byte) {
		var got *GetCapabilityResponse
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("decoding %x panicked: %v", data, r)
				}
			}()
			got, err = UnmarshalResponse[GetCapabilityResponse](data)
		}()
		if err != nil {
			if got != nil {
				t.Fatalf("rejected input %x returned a non-nil response %+v (err %v)", data, got, err)
			}
			return
		}
		// An accepted response must be encodable, and the encoding must decode
		// back to a deeply equal response.
		reenc, err := MarshalResponse(GetCapability{}, got)
		if err != nil {
			t.Fatalf("re-marshalling response decoded from %x (%+v) failed: %v", data, got, err)
		}
		again, err := UnmarshalResponse[GetCapabilityResponse](reenc)
		if err != nil {
			t.Fatalf("re-decoding response encoding %x (original input %x) failed: %v", reenc, data, err)
		}
		if !reflect.DeepEqual(got, again) {
			t.Fatalf("response from %x was not structurally stable:\nfirst:  %+v\nsecond: %+v", data, got, again)
		}
	})
}
