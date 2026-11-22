module github.com/pgsty/sow

go 1.27.4

require (
	github.com/ProtonMail/go-crypto v1.5.2
	github.com/aws/aws-sdk-go-v2 v1.48.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.116.0
	github.com/aws/smithy-go v1.28.9
	github.com/cavaliergopher/rpm v1.3.0
	github.com/klauspost/compress v1.20.5
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8
	go.yaml.in/yaml/v4 v4.0.0
	golang.org/x/sys v0.50.0
	modernc.org/libc v1.82.12
	modernc.org/sqlite v1.63.0
	pault.ag/go/debian v0.21.4
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
	github.com/google/pprof v0.0.0-20261118010117-084b33a85f63 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/tools v0.53.0 // indirect
	modernc.org/gc/v3 v3.2.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.13.0 // indirect
	pault.ag/go/topsort v0.1.1 // indirect
)
