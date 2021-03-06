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

//运行实例
type program struct {
	once sync.Once	//保证只执行一次
	nsqd *nsqd.NSQD	//nsqd实例
}

func main() {
	prg := &program{}
	//通过go-svc启动nsqd
	//通过第三方 svc 包进行优雅的后台进程管理，svc.Run() -> svc.Init() -> svc.Start()，启动 nsqd 实例
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
	/*-------------------------------------------初始化配置项---------------------------------------------------------*/
	opts := nsqd.NewOptions()	//新建启动项
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
	p.nsqd = nsqd	//赋值给运行实例

	/*-------------------------------------------加载历史数据---------------------------------------------------------*/
	//加载元数据文件
	err = p.nsqd.LoadMetadata()
	if err != nil {
		logFatal("failed to load metadata - %s", err)
	}
	/*-------------------------------------------持久化最新数据---------------------------------------------------------*/
	//将当前的topic和channel信息写入nsqd.%d.dat文件中,
	//用于在 nsqd 实例意外 exit 的时候存储 nsqd 实例的元数据
	err = p.nsqd.PersistMetadata()
	if err != nil {
		logFatal("failed to persist metadata - %s", err)
	}

	/*-------------------------------------------开启协程运行---------------------------------------------------------*/
	go func() {
		err := p.nsqd.Main()
		if err != nil {
			p.Stop()
			os.Exit(1)
		}
	}()

	return nil
}

//关闭nsqd进程
func (p *program) Stop() error {
	p.once.Do(func() {	//保证执行一次
		p.nsqd.Exit()	//关闭nsqd进程（包括http\tcp\数据处理）
	})
	return nil
}

//错误日志处理
func logFatal(f string, args ...interface{}) {
	lg.LogFatal("[nsqd] ", f, args...)
}
