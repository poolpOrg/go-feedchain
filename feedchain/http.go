package feedchain

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type HTTPReader struct {
	client *http.Client
	url    string
	offset int64
	size   int64
}

func NewHTTPReader(url string) (*HTTPReader, error) {
	var resp *http.Response
	var err error

	if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "https://") {
		resp, err = http.Head(url)
		if err != nil {
			return nil, err
		}
	} else {
		// first try https://, then http://
		scheme := "https://"
		resp, err = http.Head(scheme + url)
		if err != nil {
			scheme = "http://"
			resp, err = http.Head(scheme + url)
			if err != nil {
				return nil, err
			}
		}
		url = scheme + url
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("could not track feed: %s", resp.Status)
	}

	contentLength, err := strconv.Atoi(resp.Header.Get("Content-Length"))
	if err != nil {
		return nil, err
	}

	hr := HTTPReader{
		client: &http.Client{},
		url:    url,
		offset: 0,
		size:   int64(contentLength),
	}
	return &hr, nil
}

func (hr *HTTPReader) Read(buf []byte) (int, error) {
	req, err := http.NewRequest("GET", hr.url, nil)
	if err != nil {
		return 0, err
	}

	req.Header.Add("Range", fmt.Sprintf("bytes=%d-%d", hr.offset, hr.offset+int64(len(buf))))
	resp, err := hr.client.Do(req)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("NOT OK")
	}

	n, err := resp.Body.Read(buf)
	hr.offset += int64(n)
	return n, err
}

func (hr *HTTPReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		if offset >= hr.size {
			return 0, io.EOF
		}
		hr.offset = offset
	case io.SeekCurrent:
		if hr.offset+offset >= hr.size {
			return 0, io.EOF
		}
		hr.offset += offset
	case io.SeekEnd:
		if offset > hr.size {
			return 0, io.EOF
		}
		hr.offset = hr.size - offset
	}
	return hr.offset, nil
}

func (hr *HTTPReader) Close() error {
	return nil
}
