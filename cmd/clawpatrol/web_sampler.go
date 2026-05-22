package main

// Body sampler used by mitmHTTPS to capture a hash + size + prefix of
// each request / response stream without buffering the full payload.
// The TeeReader writes through to the original consumer; the sampler
// keeps a sha256 hash and a capped byte buffer for the audit log.
// maybeDecode handles the common HTTP Content-Encoding cases so a
// gzip'd JSON response renders as readable text in the dashboard.
//
// The header helpers (unmarshalHeaders, flatHeaders) sit here because
// they share the same audit-log purpose: render the request/response
// headers for the dashboard while masking known credential-bearing
// names so a copy-paste of a sample doesn't leak secrets.

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

type sampler struct {
	hash hash.Hash
	cap  int
	buf  bytes.Buffer
	n    int64
}

func unmarshalHeaders(s string, dst *map[string]string) {
	if s != "" {
		_ = json.Unmarshal([]byte(s), dst)
	}
}

var sensitiveHeader = regexp.MustCompile(
	`(?i)auth|token|secret|key|password|cookie`,
)

func flatHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if sensitiveHeader.MatchString(k) {
			out[k] = "***"
		} else {
			out[k] = strings.Join(v, ", ")
		}
	}
	return out
}

func newSampler(capBytes int) *sampler {
	return &sampler{hash: sha256.New(), cap: capBytes}
}

func (s *sampler) Write(p []byte) (int, error) {
	s.hash.Write(p)
	s.n += int64(len(p))
	if remain := s.cap - s.buf.Len(); remain > 0 {
		take := len(p)
		if take > remain {
			take = remain
		}
		s.buf.Write(p[:take])
	}
	return len(p), nil
}

func (s *sampler) sha() string {
	if s.n == 0 {
		return ""
	}
	return hex.EncodeToString(s.hash.Sum(nil))
}

// sample returns the audit-log preview of the captured body. When
// encoding names a compression we know how to decode (gzip, br,
// deflate, zstd), the buffered prefix is decompressed first so a
// JSON response doesn't get rendered as "binary:<hex>" just because
// it's still on the wire compressed.
func (s *sampler) sample(encoding string) string {
	if s.buf.Len() == 0 {
		return ""
	}
	raw := s.buf.Bytes()
	body := maybeDecode(raw, encoding)
	if isPrintable(body) {
		return string(body)
	}
	return "binary:" + hex.EncodeToString(raw[:min(64, len(raw))])
}

const (
	decodedSampleCap             = 4096
	decodedSampleTruncatedMarker = "\n[decoded response sample truncated]"
)

// maybeDecode returns the decompressed prefix of buf when encoding
// is a compression scheme we recognise, or buf unchanged otherwise.
// The sampler captures at most cap bytes, so the stream is almost
// always truncated mid-block — decoders return whatever they managed
// before hitting EOF, which is what we want for a preview. Decoded
// output is capped separately because tiny compressed inputs can expand
// far beyond the sampled wire bytes.
func maybeDecode(buf []byte, encoding string) []byte {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(bytes.NewReader(buf))
		if err != nil {
			return buf
		}
		defer func() { _ = zr.Close() }()
		r = zr
	case "br":
		r = brotli.NewReader(bytes.NewReader(buf))
	case "deflate":
		// RFC 7230 says "deflate" is zlib-wrapped deflate, but some
		// servers send raw deflate. Try zlib first, fall back to raw.
		if zr, err := zlib.NewReader(bytes.NewReader(buf)); err == nil {
			defer func() { _ = zr.Close() }()
			r = zr
		} else {
			fr := flate.NewReader(bytes.NewReader(buf))
			defer func() { _ = fr.Close() }()
			r = fr
		}
	case "zstd":
		zd, err := zstd.NewReader(bytes.NewReader(buf))
		if err != nil {
			return buf
		}
		defer zd.Close()
		r = zd
	default:
		return buf
	}
	out, _ := io.ReadAll(io.LimitReader(r, decodedSampleCap+1))
	if len(out) == 0 {
		return buf
	}
	if len(out) > decodedSampleCap {
		out = append(out[:decodedSampleCap:decodedSampleCap], decodedSampleTruncatedMarker...)
	}
	return out
}

func isPrintable(b []byte) bool {
	for _, x := range b {
		if x == 0 || (x < 0x20 && x != '\n' && x != '\r' && x != '\t') {
			return false
		}
	}
	return true
}

type teeReadCloser struct {
	r io.Reader
	c io.Closer
}

func (t teeReadCloser) Read(p []byte) (int, error) { return t.r.Read(p) }
func (t teeReadCloser) Close() error               { return t.c.Close() }

func wrapBodySampler(rc io.ReadCloser, s *sampler) io.ReadCloser {
	if rc == nil {
		return nil
	}
	return teeReadCloser{r: io.TeeReader(rc, s), c: rc}
}
