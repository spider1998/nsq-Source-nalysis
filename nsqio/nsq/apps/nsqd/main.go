package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/judwhite/go-svc/svc"
	"github.com/mreiferson/go-options"
	"github.com/nsqio/nsq/internal/lg"
	"github.com/nsqio/nsq/internal/version"
	"github.com/nsqio/nsq/nsqd"
)

type program struct {
	once sync.Once
	nsqd *nsqd.NSQD
}

func main() {
	prg := &program{}
	//通过go-svc启动nsqd
	if err := svc.Run(prg, syscall.SIGINT, syscall.SIGTERM); err != nil {
		logFatal("%s", err)
	}
}

func (p *program) Init(env svc.Environment) error {
	//判断服务环境指定工作目录
	if env.IsWindowsService() {
		dir := filepath.Dir(os.Args[0])
		return os.Chdir(dir)
	}
	return nil
}

//Start()执行后返回svc中监听信号，如果进程停掉，则执行Stop()
func (p *program) Start() error {
	opts := nsqd.NewOptions()

	//通过命令行修改默认配置
	flagSet := nsqdFlagSet(opts)
	flagSet.Parse(os.Args[1:])	//指定解析参数，解析配置

	rand.Seed(time.Now().UTC().UnixNano())	//设置随机种子，为后续随机数准备

	if flagSet.Lookup("version").Value.(flag.Getter).Get().(bool) {	//验证版本参数
		fmt.Println(version.String("nsqd"))
		os.Exit(0)
	}

	//判断config参数是否存在，若存在的话还进行配置文件的读取
	var cfg config
	configFile := flagSet.Lookup("config").Value.String()
	if configFile != "" {
		_, err := toml.DecodeFile(configFile, &cfg)
		if err != nil {
			logFatal("failed to load config file %s - %s", configFile, err)
		}
	}
	//检查配置文件是否合法（主要用于验证tls配置）
	cfg.Validate()

	//配置文件检查通过后，创建默认配置opts，并于命令行参数和配置文件进行合并
	options.Resolve(opts, flagSet, cfg)
	//根据启动选项配置创建实例化nsqd
	nsqd, err := nsqd.New(opts)
	if err != nil {
		logFatal("failed to instantiate nsqd - %s", err)
	}
	p.nsqd = nsqd	//赋值给进程

	//加载元数据文件
	err = p.nsqd.LoadMetadata()
	if err != nil {
		logFatal("failed to load metadata - %s", err)
	}
	//将当前的topic和channel信息写入nsqd.%d.dat文件中,
	//用于在 nsqd 实例意外 exit 的时候存储 nsqd 实例的元数据
	err = p.nsqd.PersistMetadata()
	if err != nil {
		logFatal("failed to persist metadata - %s", err)
	}

	//开始运行
	go func() {
		err := p.nsqd.Main()
		if err != nil {
			p.Stop()
			os.Exit(1)
		}
	}()

	return nil
}

func (p *program) Stop() error {
	p.once.Do(func() {
		p.nsqd.Exit()
	})
	return nil
}

func logFatal(f string, args ...interface{}) {
	lg.LogFatal("[nsqd] ", f, args...)
}
