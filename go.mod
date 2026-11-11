module github.com/pgsty/sow

go 1.27.4

require (
	github.com/ProtonMail/go-crypto v1.5.2
	github.com/aws/aws-sdk-go-v2 v1.48.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.10
	github.com/aws/smithy-go v1.28.9
	github.com/cavaliergopher/rpm v1.3.0
	github.com/kjk/lzma v0.0.0-20161016003348-3fd93898850d
	github.com/klauspost/compress v1.20.4
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8
	go.yaml.in/yaml/v4 v4.0.0
	golang.org/x/sys v0.50.0
	modernc.org/libc v1.81.0
	modernc.org/sqlite v1.62.0
	pault.ag/go/debian v0.21.3
)

// cavaliergopher/rpm v1.3.0 otherwise links its unused GPGCheck helpers to the
// abandoned golang.org/x/crypto/openpgp package (GO-2026-5932). The local copy
// preserves SOW's RPM parser API and removes that unused verification surface;
// repository metadata signatures use ProtonMail go-crypto in SOW proper.
replace github.com/cavaliergopher/rpm => ./third_party/cavaliergopher-rpm

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.12 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20261110164715-8bb1ee682bd8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	modernc.org/gc/v3 v3.2.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	pault.ag/go/topsort v0.1.1 // indirect
)
