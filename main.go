package main

import (
	"bufio"
	"fmt"
	"os"
	"port-scanner/scanner"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	// 获取 IP 范围输入
	fmt.Print("请输入 IP 范围 (如 10.0.0.*\n10.0.0.1-10\n10.0.0.1, 10.0.0.5-10, 192.168.1.*, 192.168.10.0/24): ")

	iplist, err := reader.ReadString('\n')
	iplist = strings.TrimSpace(iplist)
	ips, err := scanner.GetIpList(iplist)
	if err != nil {
		fmt.Println("IP 地址范围解析错误:", err)
		return
	}

	// 获取端口范围输入
	fmt.Print("请输入端口范围 (如 20-100): ")
	portRange, _ := reader.ReadString('\n')
	portRange = strings.TrimSpace(portRange)

	portParts := strings.Split(portRange, "-")
	if len(portParts) != 2 {
		fmt.Println("端口范围格式错误")
		return
	}

	startPort, _ := strconv.Atoi(strings.TrimSpace(portParts[0]))
	endPort, _ := strconv.Atoi(strings.TrimSpace(portParts[1]))

	// 设置超时时间
	timeout := 2 * time.Second

	taskChan := make(chan map[string]int, 100) // 任务通道，容量 100
	var wg sync.WaitGroup

	// 启动扫描任务的工作协程
	go func() {
		for task := range taskChan {
			for ip, port := range task {
				wg.Add(1)
				go scanner.ScanTcpPortAndservice(ip, port, timeout, &wg)
			}
		}
	}()

	// 生产任务，等待通道有空间
	for _, ip := range ips {
		for port := startPort; port <= endPort; port++ {
			task := map[string]int{ip.String(): port}
			taskChan <- task
		}
	}

	close(taskChan) // 任务全部推送完毕后关闭通道
	wg.Wait()
	fmt.Println("扫描完成")
}
