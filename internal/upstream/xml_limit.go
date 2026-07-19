package upstream

import "io"

// xmlTokenLimitReader bounds every XML tag and character-data run before
// encoding/xml can allocate a token-sized buffer. Directives, comments, DTDs,
// and CDATA are rejected at the byte boundary; repository metadata does not
// need them and encoding/xml would otherwise buffer a malicious directive.
type xmlTokenLimitReader struct {
	r       io.Reader
	max     int
	count   int
	inTag   bool
	quote   byte
	pending error
}

func newXMLTokenLimitReader(reader io.Reader, max int) io.Reader {
	return &xmlTokenLimitReader{r: reader, max: max}
}

func (r *xmlTokenLimitReader) Read(p []byte) (int, error) {
	if r.pending != nil {
		err := r.pending
		r.pending = nil
		return 0, err
	}
	n, readErr := r.r.Read(p)
	for i := 0; i < n; i++ {
		current := p[i]
		if !r.inTag {
			if current == '<' {
				r.inTag = true
				r.quote = 0
				r.count = 1
			} else {
				r.count++
			}
		} else {
			r.count++
			if r.count == 2 && current == '!' {
				return r.failAfter(p, i, ErrInvalidMetadata)
			}
			if r.quote != 0 {
				if current == r.quote {
					r.quote = 0
				}
			} else {
				switch current {
				case '\'', '"':
					r.quote = current
				case '>':
					r.inTag = false
					r.count = 0
				}
			}
		}
		if r.count > r.max {
			return r.failAfter(p, i, ErrMetadataTooLarge)
		}
	}
	return n, readErr
}

func (r *xmlTokenLimitReader) failAfter(_ []byte, index int, err error) (int, error) {
	// Return the safe prefix first when one exists, then surface the terminal
	// error on the next Read. This obeys io.Reader semantics while ensuring the
	// XML decoder never receives the byte that crosses the configured bound.
	if index > 0 {
		r.pending = err
		return index, nil
	}
	return 0, err
}
