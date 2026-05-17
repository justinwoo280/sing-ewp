package ewp

import "testing"

func BenchmarkPaddingPolicy_PadToBucket_Steady(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = padToBucket(800, steadyBuckets)
	}
}

func BenchmarkPaddingPolicy_PadToBucket_Handshake(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = padToBucket(800, handshakeBuckets)
	}
}

func BenchmarkPaddingPolicy_SuggestStreamPad(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = suggestStreamPad(800, i)
	}
}

func BenchmarkPaddingPolicy_SecureRandIntn(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = secureRandIntn(10000)
	}
}
