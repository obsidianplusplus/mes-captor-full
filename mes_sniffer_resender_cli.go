// mes_sniffer_resender_cli.go
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"

	bolt "go.etcd.io/bbolt"
)

const (
	defaultMESURL = "http://192.168.111.239:9888/eam/snTest/PostInsertTest"
	bucketName    = "spool"
	cfgFileName   = "config.json"
)

type Config struct {
	Iface     string `json:"iface"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	MESURL    string `json:"mes_url"`
	DBPath    string `json:"db_path"`
	UIAddr    string `json:"ui_addr"`
	BPFFilter string `json:"bpf_filter"`
	Timeout   int    `json:"timeout_sec"`
}

func (c *Config) ensureDefaults() {
	if c.Host == "" {
		c.Host = "192.168.111.239"
	}
	if c.Port == 0 {
		c.Port = 9888
	}
	if c.MESURL == "" {
		c.MESURL = defaultMESURL
	}
	if c.DBPath == "" {
		c.DBPath = "spool.db"
	}
	if c.UIAddr == "" {
		c.UIAddr = ":8080"
	}
	if c.Timeout == 0 {
		c.Timeout = 10
	}
}

type SpoolItem struct {
	ID         string              `json:"id"`
	CapturedAt time.Time           `json:"captured_at"`
	Method     string              `json:"method"`
	URL        string              `json:"url"`
	Host       string              `json:"host"`
	Path       string              `json:"path"`
	Headers    map[string][]string `json:"headers"`
	BodyB64    string              `json:"body_b64"`
	Status     string              `json:"status"` // captured|sent|failed
	Attempts   int                 `json:"attempts"`
	LastTried  *time.Time          `json:"last_tried,omitempty"`
	LastError  string              `json:"last_error,omitempty"`
	Summary    map[string]string   `json:"summary,omitempty"`
	Peer       string              `json:"peer,omitempty"`
}

// ------- 全局状态 -------
var (
	cfg     Config
	cfgPath string

	db   *bolt.DB
	dbMu sync.RWMutex

	capMu      sync.Mutex
	capRunning bool
	cancelCap  context.CancelFunc

	startWebOnce sync.Once
)

// ------- 配置文件 -------
func loadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	c.ensureDefaults()
	return c, nil
}

func saveConfig(path string, c Config) error {
	c.ensureDefaults()
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(path, b, 0644)
}

// ------- 数据库 -------
func openDB(path string) (*bolt.DB, error) {
	d, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	err = d.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists([]byte(bucketName))
		return e
	})
	return d, err
}

func putItem(it *SpoolItem) error {
	dbMu.Lock()
	defer dbMu.Unlock()
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		j, _ := json.Marshal(it)
		return b.Put([]byte(it.ID), j)
	})
}

func getAll(limit int) ([]*SpoolItem, error) {
	dbMu.RLock()
	defer dbMu.RUnlock()
	var items []*SpoolItem
	err := db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte(bucketName)).Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var it SpoolItem
			if err := json.Unmarshal(v, &it); err == nil {
				items = append(items, &it)
			}
			if limit > 0 && len(items) >= limit {
				break
			}
		}
		return nil
	})
	return items, err
}

func getByID(id string) (*SpoolItem, error) {
	dbMu.RLock()
	defer dbMu.RUnlock()
	var it SpoolItem
	err := db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(bucketName)).Get([]byte(id))
		if v == nil {
			return fmt.Errorf("not found")
		}
		return json.Unmarshal(v, &it)
	})
	if err != nil {
		return nil, err
	}
	return &it, nil
}

// ------- 抓包（tcpassembly 旁路重组 + http.ReadRequest）-------
type httpStreamFactory struct{}

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (f *httpStreamFactory) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
	hs := &httpStream{
		net:       netFlow,
		transport: transportFlow,
		r:         tcpreader.NewReaderStream(),
	}
	go hs.run()
	return hs
}

func (h *httpStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	h.r.Reassembled(reassemblies)
}

func (h *httpStream) ReassemblyComplete() {
	h.r.ReassemblyComplete()
}

func (h *httpStream) run() {
	br := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(br)
		if err == io.EOF {
			return
		}
		if err != nil {
			// 不是完整HTTP头，继续尝试
			continue
		}
		ct := strings.ToLower(req.Header.Get("Content-Type"))
		if req.Method != http.MethodPost || !strings.Contains(ct, "application/json") {
			_ = req.Body.Close()
			continue
		}
		body, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()

		host := req.Host
		if host == "" {
			host = cfg.Host
			if cfg.Port != 80 && cfg.Port != 0 {
				host = fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
			}
		}
		uri := req.URL.RequestURI()
		url := "http://" + host + uri

		item := &SpoolItem{
			ID:         uuid.NewString(),
			CapturedAt: time.Now(),
			Method:     req.Method,
			URL:        url,
			Host:       host,
			Path:       uri,
			Headers:    pickHeaders(req.Header),
			BodyB64:    base64.StdEncoding.EncodeToString(body),
			Status:     "captured",
			Peer:       fmt.Sprintf("%s:%s", h.net.Dst().String(), h.transport.Dst().String()),
			Summary:    quickSumm(body),
		}
		if err := putItem(item); err != nil {
			log.Printf("DB write error: %v", err)
		} else {
			log.Printf("Captured %s %s (SN=%s)", item.Method, item.URL, item.Summary["sn"])
		}
	}
}

func pickHeaders(hdr http.Header) map[string][]string {
	out := make(map[string][]string)
	for _, k := range []string{"Content-Type", "Authorization", "Cookie"} {
		if v := hdr.Values(k); len(v) > 0 {
			out[k] = v
		}
	}
	return out
}

func quickSumm(body []byte) map[string]string {
	sum := map[string]string{}
	type minimal struct {
		SN         string `json:"sn"`
		TestResult string `json:"testResult"`
	}
	var m minimal
	_ = json.Unmarshal(body, &m)
	if m.SN != "" {
		sum["sn"] = m.SN
	}
	if m.TestResult != "" {
		sum["testResult"] = m.TestResult
	}
	return sum
}

func buildBPF() string {
	if cfg.BPFFilter != "" {
		return cfg.BPFFilter
	}
	return fmt.Sprintf("tcp and dst host %s and dst port %d", cfg.Host, cfg.Port)
}

func runCapture(ctx context.Context) error {
	if cfg.Iface == "" {
		return fmt.Errorf("未配置网卡，请在 CLI 输入： set iface \"网卡名\" 或执行 wizard")
	}
	handle, err := pcap.OpenLive(cfg.Iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("打开网卡失败: %w", err)
	}
	defer handle.Close()
	// 便于停止：收到 cancel 时关闭 handle
	go func() {
		<-ctx.Done()
		// 关闭句柄以打断读循环
		handle.Close()
	}()

	filter := buildBPF()
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("设置 BPF 失败: %w", err)
	}
	log.Printf("开始抓包 iface=%s filter=%q", cfg.Iface, filter)

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)
	defer assembler.FlushAll()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case pkt := <-src.Packets():
			if pkt == nil {
				return nil // 句柄关闭
			}
			netl := pkt.NetworkLayer()
			tl := pkt.TransportLayer()
			if netl == nil || tl == nil {
				continue
			}
			tcp, ok := tl.(*layers.TCP)
			if !ok {
				continue
			}
			assembler.AssembleWithTimestamp(netl.NetworkFlow(), tcp, pkt.Metadata().Timestamp)
		case <-ticker.C:
			// gopacket/tcpassembly v1.1.19 使用 FlushOlderThan
			assembler.FlushOlderThan(time.Now().Add(-2 * time.Minute))
		case <-ctx.Done():
			return nil
		}
	}
}

// ------- 重传 -------
func resendOne(it *SpoolItem, targetURL string) (*http.Response, []byte, error) {
	body, err := base64.StdEncoding.DecodeString(it.BodyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode body: %w", err)
	}
	url := strings.TrimSpace(targetURL)
	if url == "" {
		url = it.URL
	}
	req, err := http.NewRequest(it.Method, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	for k, vals := range it.Headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: time.Duration(cfg.Timeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return resp, respBody, fmt.Errorf("non-2xx: %s", resp.Status)
	}
	return resp, respBody, nil
}

// ------- Web 界面 -------
var pageTmpl = template.Must(template.New("index").Parse(`
<!doctype html>
<html><head><meta charset="utf-8"><title>MES 抓包与重传</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:20px}
table{border-collapse:collapse;width:100%}th,td{padding:8px 10px;border-bottom:1px solid #eee;text-align:left}
code{background:#f6f8fa;padding:2px 4px;border-radius:4px}
input,button{padding:6px 10px}.badge{padding:2px 6px;border-radius:4px;font-size:12px}
.badge.captured{background:#eef;color:#224}.badge.sent{background:#efe;color:#242}.badge.failed{background:#fee;color:#422}
</style></head><body>
<h2>MES 抓包与重传</h2>
<p>默认重传 URL：<code>{{.DefaultURL}}</code></p>
<form method="GET" action="/">
  <input type="text" name="sn" placeholder="按 SN 过滤" value="{{.SN}}">
  <button type="submit">筛选</button>
  <a href="/">清除</a>
</form>
<p>
<form method="POST" action="/retry-all" style="display:inline" onsubmit="return confirm('重传所有 captured/failed 项？');">
  <input type="hidden" name="sn" value="{{.SN}}">
  <button type="submit">批量重传</button>
</form>
</p>
<table><thead><tr><th>时间</th><th>SN</th><th>结果</th><th>状态</th><th>URL</th><th>尝试</th><th>操作</th></tr></thead>
<tbody>
{{range .Items}}
<tr>
  <td title="{{.CapturedAt}}">{{.CapturedAt.Format "01-02 15:04:05"}}</td>
  <td>{{index .Summary "sn"}}</td>
  <td>{{index .Summary "testResult"}}</td>
  <td><span class="badge {{.Status}}">{{.Status}}</span></td>
  <td title="{{.URL}}">{{.Path}}</td>
  <td>{{.Attempts}}</td>
  <td>
    <form method="POST" action="/retry" style="display:inline">
      <input type="hidden" name="id" value="{{.ID}}">
      <button type="submit">重传</button>
    </form>
    <form method="GET" action="/view" style="display:inline">
      <input type="hidden" name="id" value="{{.ID}}">
      <button type="submit">查看</button>
    </form>
  </td>
</tr>
{{end}}
</tbody></table>
</body></html>
`))

func indexHandler(w http.ResponseWriter, r *http.Request) {
	sn := strings.TrimSpace(r.URL.Query().Get("sn"))
	items, _ := getAll(1000)
	filtered := items[:0]
	for _, it := range items {
		if sn == "" {
			filtered = append(filtered, it)
		} else {
			body := mustBase64(it.BodyB64)
			if strings.Contains(strings.ToLower(body), strings.ToLower(sn)) ||
				strings.Contains(strings.ToLower(it.Summary["sn"]), strings.ToLower(sn)) {
				filtered = append(filtered, it)
			}
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].CapturedAt.After(filtered[j].CapturedAt)
	})
	_ = pageTmpl.Execute(w, map[string]interface{}{
		"Items":      filtered,
		"DefaultURL": cfg.MESURL,
		"SN":         sn,
	})
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	it, err := getByID(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	fmt.Fprintf(w, "<pre>%s</pre>", htmlEscape(mustBase64(it.BodyB64)))
}

func retryHandler(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id := r.Form.Get("id")
	it, err := getByID(id)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	now := time.Now()
	resp, body, err := resendOne(it, cfg.MESURL)
	it.Attempts++
	it.LastTried = &now
	if err != nil {
		it.Status = "failed"
		if resp != nil {
			it.LastError = fmt.Sprintf("%v; status=%s; body=%s", err, resp.Status, string(body))
		} else {
			it.LastError = err.Error()
		}
	} else {
		it.Status = "sent"
		it.LastError = ""
	}
	_ = putItem(it)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func retryAllHandler(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	items, _ := getAll(10000)
	sn := strings.TrimSpace(r.Form.Get("sn"))
	for _, it := range items {
		if it.Status == "sent" {
			continue
		}
		if sn != "" {
			body := strings.ToLower(mustBase64(it.BodyB64))
			if !strings.Contains(body, strings.ToLower(sn)) &&
				strings.ToLower(it.Summary["sn"]) != strings.ToLower(sn) {
				continue
			}
		}
		now := time.Now()
		_, _, err := resendOne(it, cfg.MESURL)
		it.Attempts++
		it.LastTried = &now
		if err != nil {
			it.Status = "failed"
			it.LastError = err.Error()
		} else {
			it.Status = "sent"
			it.LastError = ""
		}
		_ = putItem(it)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ------- CLI（交互式命令配置/控制）-------
func printHelp() {
	fmt.Println(`
可用命令：
  help                       显示帮助
  wizard                     交互向导填写配置（网卡、MES、端口等）并保存
  show                       查看当前配置
  save                       保存当前配置到 config.json
  list-ifaces                列出可用网卡
  start                      启动抓包
  stop                       停止抓包
  status                     查看抓包状态
  set iface "<网卡名>"       设置网卡
  set host 192.168.111.239   设置 MES IP
  set port 9888              设置 MES 端口
  set mes-url http://...     设置默认重传 URL（会写入配置）
  set timeout 10             设置重传超时秒
  set bpf "tcp and dst host 192.168.111.239 and dst port 9888" 自定义 BPF 过滤
  resend id=<ID> [url=<URL>] 立刻重传某条记录（可临时覆盖 URL）
  retry-all [sn=<SN>]        批量重传 captured/failed（可按 SN 过滤）
  exit                       退出程序
`)
}

func runCLI() {
	sc := bufio.NewScanner(os.Stdin)
	printHelp()
	for {
		fmt.Print("> ")
		if !sc.Scan() {
			return
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		args := splitArgs(line)
		cmd := strings.ToLower(args[0])

		switch cmd {
		case "help":
			printHelp()
		case "wizard":
			runWizard()
			_ = saveConfig(cfgPath, cfg)
			fmt.Println("已保存到", cfgPath)
		case "show":
			showConfig()
		case "save":
			if err := saveConfig(cfgPath, cfg); err != nil {
				fmt.Println("保存失败：", err)
			} else {
				fmt.Println("已保存到", cfgPath)
			}
		case "list-ifaces":
			listIfaces()
		case "set":
			if len(args) < 3 {
				fmt.Println("用法示例： set mes-url http://192.168.111.239:9888/xxx")
				continue
			}
			key := strings.ToLower(args[1])
			val := strings.Join(args[2:], " ")
			val = strings.Trim(val, "\"'")
			switch key {
			case "iface":
				cfg.Iface = val
			case "host":
				cfg.Host = val
			case "port":
				var p int
				fmt.Sscanf(val, "%d", &p)
				if p > 0 && p < 65536 {
					cfg.Port = p
				} else {
					fmt.Println("端口非法")
				}
			case "mes-url":
				cfg.MESURL = val
			case "timeout":
				var t int
				fmt.Sscanf(val, "%d", &t)
				if t > 0 {
					cfg.Timeout = t
				}
			case "bpf":
				cfg.BPFFilter = val
			default:
				fmt.Println("未知配置项：", key)
			}
			fmt.Println("OK。输入 save 落盘，或 start 生效。")
		case "start":
			startCapture()
		case "stop":
			stopCapture()
		case "status":
			capMu.Lock()
			r := capRunning
			capMu.Unlock()
			if r {
				fmt.Println("抓包：运行中")
			} else {
				fmt.Println("抓包：已停止")
			}
		case "resend":
			if len(args) < 2 {
				fmt.Println(`用法：resend id=<ID> [url=<URL>]`)
				continue
			}
			id := ""
			url := ""
			for _, a := range args[1:] {
				if strings.HasPrefix(a, "id=") {
					id = strings.TrimPrefix(a, "id=")
				} else if strings.HasPrefix(a, "url=") {
					url = strings.TrimPrefix(a, "url=")
				}
			}
			if id == "" {
				fmt.Println("缺少 id")
				continue
			}
			it, err := getByID(id)
			if err != nil {
				fmt.Println("未找到记录：", err)
				continue
			}
			now := time.Now()
			resp, body, err := resendOne(it, choose(url, cfg.MESURL))
			it.Attempts++
			it.LastTried = &now
			if err != nil {
				it.Status = "failed"
				if resp != nil {
					it.LastError = fmt.Sprintf("%v; status=%s; body=%s", err, resp.Status, string(body))
				} else {
					it.LastError = err.Error()
				}
			} else {
				it.Status = "sent"
				it.LastError = ""
			}
			_ = putItem(it)
			fmt.Println("重传完成：", it.Status, it.LastError)
		case "retry-all":
			var sn string
			for _, a := range args[1:] {
				if strings.HasPrefix(a, "sn=") {
					sn = strings.TrimPrefix(a, "sn=")
				}
			}
			items, _ := getAll(100000)
			count := 0
			for _, it := range items {
				if it.Status == "sent" {
					continue
				}
				if sn != "" {
					body := strings.ToLower(mustBase64(it.BodyB64))
					if !strings.Contains(body, strings.ToLower(sn)) &&
						strings.ToLower(it.Summary["sn"]) != strings.ToLower(sn) {
						continue
					}
				}
				now := time.Now()
				_, _, err := resendOne(it, cfg.MESURL)
				it.Attempts++
				it.LastTried = &now
				if err != nil {
					it.Status = "failed"
					it.LastError = err.Error()
				} else {
					it.Status = "sent"
					it.LastError = ""
				}
				_ = putItem(it)
				count++
			}
			fmt.Printf("批量重传完成，共处理 %d 条。\n", count)
		case "exit", "quit":
			stopCapture()
			return
		default:
			fmt.Println("未知命令，输入 help 查看帮助。")
		}
	}
}

func startCapture() {
	capMu.Lock()
	defer capMu.Unlock()
	if capRunning {
		fmt.Println("已在运行。先 stop 再 start 可重启。")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancelCap = cancel

	// 启动 Web 界面（若尚未启动）
	startWebOnce.Do(func() {
		http.HandleFunc("/", indexHandler)
		http.HandleFunc("/view", viewHandler)
		http.HandleFunc("/retry", retryHandler)
		http.HandleFunc("/retry-all", retryAllHandler)
		go func() {
			log.Printf("Web 界面: http://127.0.0.1%s", cfg.UIAddr)
			if err := http.ListenAndServe(cfg.UIAddr, nil); err != nil {
				log.Fatal(err)
			}
		}()
	})

	go func() {
		if err := runCapture(ctx); err != nil {
			log.Println("抓包退出：", err)
		}
		capMu.Lock()
		capRunning = false
		capMu.Unlock()
	}()
	capRunning = true
	fmt.Println("抓包已启动。")
}

func stopCapture() {
	capMu.Lock()
	defer capMu.Unlock()
	if !capRunning {
		fmt.Println("抓包本已停止。")
		return
	}
	cancelCap()
	capRunning = false
	fmt.Println("抓包已停止。")
}

// ------- 工具 -------
func listIfaces() {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Println("获取网卡失败：", err)
		return
	}
	fmt.Println("可用网卡：")
	for _, d := range ifs {
		fmt.Printf("- %s\t(%s)\n", d.Name, d.Description)
		for _, a := range d.Addresses {
			fmt.Printf("    %s\n", a.IP)
		}
	}
}

func runWizard() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("—— 配置向导 ——（直接回车采用括号中默认值）")

	// 网卡
	listIfaces()
	cfg.Iface = ask(reader, "网卡名", cfg.Iface)

	// MES 相关
	cfg.Host = ask(reader, "MES IP", cfg.Host)
	cfg.Port = atoiDefault(ask(reader, "MES 端口", fmt.Sprintf("%d", cfg.Port)), cfg.Port)
	cfg.MESURL = ask(reader, "MES 重传URL", cfg.MESURL)

	// 可选
	cfg.Timeout = atoiDefault(ask(reader, "HTTP 超时(秒)", fmt.Sprintf("%d", cfg.Timeout)), cfg.Timeout)
	if strings.TrimSpace(cfg.BPFFilter) == "" {
		fmt.Printf("自动 BPF: %q\n", buildBPF())
	}
	manualBPF := ask(reader, "自定义BPF(留空自动)", cfg.BPFFilter)
	if strings.TrimSpace(manualBPF) != "" {
		cfg.BPFFilter = manualBPF
	}
	fmt.Println("—— 向导结束 ——")
}

func showConfig() {
	b, _ := json.MarshalIndent(cfg, "", "  ")
	fmt.Println(string(b))
}

func splitArgs(s string) []string {
	// 简单分词：空格为主，支持引号括起
	var out []string
	var cur strings.Builder
	inQuote := false
	quoteChar := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				cur.WriteByte(c)
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = true
			quoteChar = c
			continue
		}
		if c == ' ' || c == '\t' {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func ask(r *bufio.Reader, label string, def string) string {
	if def != "" {
		fmt.Printf("%s (%s): ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	text, _ := r.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return def
	}
	return text
}

func atoiDefault(s string, d int) int {
	var v int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &v)
	if err != nil || v <= 0 {
		return d
	}
	return v
}

func choose(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func htmlEscape(s string) string {
	repl := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;")
	return repl.Replace(s)
}

func mustBase64(b64 string) string {
	b, _ := base64.StdEncoding.DecodeString(b64)
	return string(b)
}

// ------- main -------
func main() {
	// 可选：通过 -config 指定配置路径
	var configCLI string
	flag.StringVar(&configCLI, "config", "", "配置文件路径（默认程序同目录 config.json）")
	flag.Parse()

	exeDir, _ := os.Getwd()
	if configCLI != "" {
		cfgPath = configCLI
	} else {
		cfgPath = filepath.Join(exeDir, cfgFileName)
	}

	// 加载配置或首次生成默认配置
	if c, err := loadConfig(cfgPath); err == nil {
		cfg = c
	} else {
		cfg = Config{
			Iface:   "",
			Host:    "192.168.111.239",
			Port:    9888,
			MESURL:  defaultMESURL,
			DBPath:  "spool.db",
			UIAddr:  ":8080",
			Timeout: 10,
		}
		_ = saveConfig(cfgPath, cfg)
	}

	var err error
	db, err = openDB(cfg.DBPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 启动 CLI
	fmt.Println("配置文件：", cfgPath)
	fmt.Println("Web 界面：", "http://127.0.0.1"+cfg.UIAddr)
	runCLI()
}
