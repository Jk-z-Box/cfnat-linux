package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cfnat-linux/cfnat-linux/internal/app"
	"github.com/cfnat-linux/cfnat-linux/internal/config"
	"github.com/cfnat-linux/cfnat-linux/internal/scanner"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "/etc/cfnat/config.json", "配置文件路径")
	flag.Parse()
	command := "run"
	if flag.NArg() > 0 {
		command = flag.Arg(0)
	}

	if command == "version" {
		fmt.Println(version)
		return 0
	}
	if command == "migrate-config" {
		changed, err := config.Migrate(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "配置迁移失败: %v\n", err)
			return 2
		}
		if changed {
			fmt.Println("配置已迁移到当前版本")
		} else {
			fmt.Println("配置无需迁移")
		}
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置错误: %v\n", err)
		return 2
	}
	if command == "check-config" {
		fmt.Println("配置检查通过")
		return 0
	}
	if command == "status" {
		app.PrintStatus(os.Stdout, cfg)
		return 0
	}
	if command == "config-set" {
		if flag.NArg() != 3 {
			fmt.Fprintln(os.Stderr, "用法: cfnat -config <路径> config-set <配置项> <值>")
			return 2
		}
		if err := config.Set(*configPath, flag.Arg(1), flag.Arg(2)); err != nil {
			fmt.Fprintf(os.Stderr, "配置修改失败: %v\n", err)
			return 2
		}
		fmt.Println("配置修改成功")
		return 0
	}

	level := slog.LevelInfo
	if cfg.LogLevel == "debug" {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	s := scanner.New(cfg, logger)
	if command == "scan" {
		results, err := s.Scan(ctx)
		if err != nil {
			logger.Error("扫描失败", "error", err)
			return 1
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return 0
	}
	if command != "run" {
		fmt.Fprintf(os.Stderr, "未知命令 %q，可用命令: run, scan, status, config-set, check-config, migrate-config, version\n", command)
		return 2
	}

	if err := app.New(cfg, logger, s).Run(ctx); err != nil {
		logger.Error("服务退出", "error", err)
		return 1
	}
	return 0
}
