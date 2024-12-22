// Package web 网络处理相关
package web

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

var (
	// 如果 CipherSuites 为 nil，将使用一个安全的默认列表。默认的密码套件可能会随时间变化。
	// 在 Go 1.22 中，RSA 密钥交换相关的密码套件已从默认列表中移除，但可以通过 GODEBUG 设置 tlsrsakex=1 重新添加。
	tlsSuites = []uint16{
		// TLS 1.0 - 1.2 cipher suites.
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		// TLS 1.3 cipher suites. 实际无法配置，没用
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
	defaultClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				CipherSuites: tlsSuites,
			},
		},
	}
	clientWithoutTLSVerify = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				CipherSuites:       tlsSuites,
				InsecureSkipVerify: true,
			},
		},
	}
)

// NewDefaultClient ...
func NewDefaultClient() *http.Client {
	return clientWithoutTLSVerify
}

// NewTLS12Client ...
func NewTLS12Client() *http.Client {
	return clientWithoutTLSVerify
}

// NewPixivClient P站特殊客户端
func NewPixivClient() *http.Client {
	return NewTLS12Client()
}

// RequestDataWith 使用自定义请求头获取数据
func RequestDataWith(client *http.Client, url, method, referer, ua string, body io.Reader) (data []byte, err error) {
	// 提交请求
	var request *http.Request
	request, err = http.NewRequest(method, url, body)
	if err == nil {
		// 增加header选项
		if referer != "" {
			request.Header.Add("Referer", referer)
		}
		if ua != "" {
			request.Header.Add("User-Agent", ua)
		}
		var response *http.Response
		response, err = client.Do(request)
		if err == nil {
			if response.StatusCode != http.StatusOK {
				s := fmt.Sprintf("status code: %d", response.StatusCode)
				err = errors.New(s)
				return
			}
			data, err = io.ReadAll(response.Body)
			response.Body.Close()
		}
	}
	return
}

// RequestDataWithHeaders 使用自定义请求头获取数据
func RequestDataWithHeaders(client *http.Client, url, method string, setheaders func(*http.Request) error, body io.Reader) (data []byte, err error) {
	// 提交请求
	var request *http.Request
	request, err = http.NewRequest(method, url, body)
	if err == nil {
		// 增加header选项
		err = setheaders(request)
		if err != nil {
			return
		}
		var response *http.Response
		response, err = client.Do(request)
		if err != nil {
			return
		}
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
			s := fmt.Sprintf("status code: %d", response.StatusCode)
			err = errors.New(s)
			return
		}
		data, err = io.ReadAll(response.Body)
		response.Body.Close()
	}
	return
}

// GetData 获取数据
func GetData(url string) (data []byte, err error) {
	var response *http.Response
	response, err = defaultClient.Get(url)
	if err == nil {
		if response.StatusCode != http.StatusOK {
			s := fmt.Sprintf("status code: %d", response.StatusCode)
			err = errors.New(s)
			return
		}
		data, err = io.ReadAll(response.Body)
		response.Body.Close()
	}
	return
}

// PostData 获取数据
func PostData(url, contentType string, body io.Reader) (data []byte, err error) {
	var response *http.Response
	response, err = defaultClient.Post(url, contentType, body)
	if err == nil {
		if response.StatusCode != http.StatusOK {
			s := fmt.Sprintf("status code: %d", response.StatusCode)
			err = errors.New(s)
			return
		}
		data, err = io.ReadAll(response.Body)
		response.Body.Close()
	}
	return
}

// HeadRequestURL 获取跳转后的链接
func HeadRequestURL(u string) (newu string, err error) {
	var data *http.Response
	data, err = defaultClient.Head(u)
	if err != nil {
		return "", err
	}
	_ = data.Body.Close()
	return data.Request.URL.String(), nil
}
