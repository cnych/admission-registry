package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cnych/admission-registry/pkg"
	"k8s.io/klog"
)

func main() {
	var param pkg.WhSvrParam
	// webhook http server（tls）
	// 命令行参数
	flag.IntVar(&param.Port, "port", 443, "Webhook Server Port.")
	flag.StringVar(&param.CertFile, "tlsCertFile", "/etc/webhook/certs/tls.crt", "x509 certification file")
	flag.StringVar(&param.KeyFile, "tlsKeyFile", "/etc/webhook/certs/tls.key", "x509 private key file")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(param.CertFile, param.KeyFile)
	if err != nil {
		klog.Errorf("Failed to load key pair: %v", err)
		return
	}

	// 实例化一个Webhook Server
	whsrv := pkg.WebhookServer{
		Server: &http.Server{
			Addr: fmt.Sprintf(":%d", param.Port),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		},
		WhiteListRegistries: strings.Split(os.Getenv("WHITELIST_REGISTRIES"), ","),
	}

	// 定义 http server handler
	mux := http.NewServeMux()
	mux.HandleFunc("/validate", whsrv.Handler)
	mux.HandleFunc("/mutate", whsrv.Handler)
	whsrv.Server.Handler = mux

	// 在一个新的 goroutine 里面去启动 webhook server
	go func() {
		if err := whsrv.Server.ListenAndServeTLS("", ""); err != nil {
			klog.Errorf("Failed to listen and serve webhook: %v", err)
		}
	}()

	klog.Info("Server started")

	// 监听 OS 的关闭信号
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<- signalChan

	klog.Infof("Got OS shutdown signal, gracefully shutting down...")
	if err := whsrv.Server.Shutdown(context.Background()); err != nil {
		klog.Errorf("HTTP Server Shutdown error: %v", err)
	}

}
