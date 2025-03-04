package scanner

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"
)

// 过滤 banner，移除不可见字符
func cleanBanner(banner string) string {
	re := regexp.MustCompile(`[^\x20-\x7E]`) // 仅保留 ASCII 可见字符
	return re.ReplaceAllString(banner, "")
}

// 扫描端口的函数
func ScanTcpPortAndservice(ip string, port int, timeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return // 端口未开放
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) // 设置读取超时

	// 针对不同端口发送特定请求
	var request []byte
	switch port {
	case 21: // FTP
		request = []byte("USER anonymous\r\n")
	case 22: // SSH (一般连接后会自动返回版本信息)
		request = nil
	case 25: // SMTP
		request = []byte("HELO example.com\r\n")
	case 53: // DNS (发送简单的查询请求)
		request = []byte("\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01")
	case 80, 8080: // HTTP/HTTPS
		request = []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	case 3306: // MySQL (发送握手包)
		request = []byte("\x00\x00\x00\x04\x03\x00\x00\x01")
	case 6379: // Redis (PING)
		request = []byte("PING\r\n")
	case 3389: // RDP (Remote Desktop Protocol)
		request = []byte("\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00")
	}

	if request != nil {
		conn.Write([]byte(request))
	}

	// 读取 banner 信息
	reader := bufio.NewReader(conn)
	banner, _ := reader.ReadString('\n')
	banner = cleanBanner(banner) // 过滤掉乱码

	// 显示探测结果
	if banner == "" {
		banner = "未知服务"
	}
	fmt.Printf("[TCP开放] %s:%d - 服务: %s\n", ip, port, banner)
}
