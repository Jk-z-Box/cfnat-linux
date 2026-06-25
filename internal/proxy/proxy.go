package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfnat-linux/cfnat-linux/internal/scanner"
)

type Server struct {
	listen     string
	targetPort int
	timeout    time.Duration
	logger     *slog.Logger
	pool       atomic.Value
	next       atomic.Uint64
}

func New(listen string, targetPort int, timeout time.Duration, logger *slog.Logger) *Server {
	s := &Server{listen: listen, targetPort: targetPort, timeout: timeout, logger: logger}
	s.pool.Store([]scanner.Result{})
	return s
}

func (s *Server) Update(results []scanner.Result) {
	copyOf := append([]scanner.Result(nil), results...)
	s.pool.Store(copyOf)
	s.logger.Info("转发池已更新", "targets", len(copyOf))
}

func (s *Server) Serve(ctx context.Context) error {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", s.listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	s.logger.Info("TCP 转发服务已启动", "listen", s.listen, "target_port", s.targetPort)
	var connections sync.WaitGroup
	defer connections.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logger.Warn("接受连接失败", "error", err)
			continue
		}
		connections.Add(1)
		go func() { defer connections.Done(); s.handle(ctx, conn) }()
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	pool := s.pool.Load().([]scanner.Result)
	if len(pool) == 0 {
		return
	}
	start := int(s.next.Add(1)-1) % len(pool)
	var upstream net.Conn
	var target string
	var err error
	dialer := net.Dialer{Timeout: s.timeout}
	for i := 0; i < len(pool); i++ {
		selected := pool[(start+i)%len(pool)]
		target = net.JoinHostPort(selected.IP.String(), fmt.Sprint(s.targetPort))
		upstream, err = dialer.DialContext(ctx, "tcp", target)
		if err == nil {
			break
		}
	}
	if err != nil {
		s.logger.Warn("所有上游连接失败", "remote", client.RemoteAddr(), "error", err)
		return
	}
	defer upstream.Close()
	s.logger.Debug("连接已转发", "remote", client.RemoteAddr(), "target", target)
	pipe(client, upstream)
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
}
