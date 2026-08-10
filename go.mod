module github.com/pgsty/sow

go 1.26.5

require (
	github.com/ProtonMail/go-crypto v1.4.1
	github.com/aws/aws-sdk-go-v2 v1.42.1
	github.com/aws/aws-sdk-go-v2/service/s3 v1.105.0
	github.com/aws/smithy-go v1.27.3
	github.com/cavaliergopher/rpm v1.3.0
	github.com/kjk/lzma v0.0.0-20161016003348-3fd93898850d
	github.com/klauspost/compress v1.19.0
	github.com/ulikunitz/xz v0.5.15
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8
	golang.org/x/sys v0.45.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.53.0
	pault.ag/go/debian v0.21.0
)

// cavaliergopher/rpm v1.3.0 otherwise links its unused GPGCheck helpers to the
// abandoned golang.org/x/crypto/openpgp package (GO-2026-5932). The local copy
// preserves SOW's RPM parser API and removes that unused verification surface;
// repository metadata signatures use ProtonMail go-crypto in SOW proper.
replace github.com/cavaliergopher/rpm => ./third_party/cavaliergopher-rpm

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.14 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.31 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.31 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	modernc.org/libc v1.73.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	pault.ag/go/topsort v0.1.1 // indirect
)
