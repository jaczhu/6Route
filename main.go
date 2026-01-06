package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net"
	_ "net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/willf/bloom"
	"golang.org/x/sys/unix"
)

const maxScanTokenSize = 10 * 1024 * 1024 // 10MB

// 补充缺失的IPMap基础类型定义
type IPMap map[string]bool

func (ipMap IPMap) AddIPv6(ip string) {
	if _, exists := ipMap[ip]; !exists {
		ipMap[ip] = true
	}
}

func (ipMap IPMap) HasIPv6(ip string) bool {
	_, exists := ipMap[ip]
	return exists
}

// 新增：存储待扫描的目标地址及对应的TTL值
type Target struct {
	IP  net.IP
	TTL uint8
}

var (
	output    *os.File
	log       *os.File
	eth       = layers.Ethernet{EthernetType: layers.EthernetTypeIPv6}
	ip6       = layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 255}
	icmp6     = layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)}
	icmp6echo = layers.ICMPv6Echo{}
	payload   = gopacket.Payload([]byte{0x00, 0x00, 0x00})
	fd        int

	// BPF过滤器：仅捕获ICMPv6超时/不可达响应
	bpf = []unix.SockFilter{
		{0x28, 0, 0, 0x0000000c},
		{0x15, 0, 6, 0x000086dd},
		{0x30, 0, 0, 0x00000014},
		{0x15, 3, 0, 0x0000003a},
		{0x15, 0, 3, 0x0000002c},
		{0x30, 0, 0, 0x00000036},
		{0x15, 0, 1, 0x0000003a},
		{0x06, 0, 0, 0x00040000},
		{0x06, 0, 0, 0x00000000},
	}
	bpf_prog = unix.SockFprog{Len: uint16(len(bpf)), Filter: &bpf[0]}

	// 全局统计变量
	packetSent uint64 = 0
	initialTTL uint8  = 32

	// 响应路由器存储（去重）
	respondersBackward      = make(IPMap)
	respondersBackwardMutex sync.RWMutex

	// 输入/64前缀集合
	inputPrefix64Set   = make(map[string]bool)
	inputPrefix64Mutex sync.RWMutex

	// 聚类核心变量
	clusters             []*Cluster
	clusterMutex         sync.RWMutex
	clusterIndex         int = 0
	clusterIndexMap      map[int]*Cluster
	clusterIndexMapMutex sync.RWMutex

	// 论文超参数
	alpha          float64 = 1.0
	beta           float64 = 1.0
	epsilon        float64 = 0.05
	Budget         uint64  = 10000000
	iteration      int     = 10
	rate           uint64  = 10000
	minClusterSize int     = 10
	maxWildcard    int     = 2

	// 当前扫描轮次
	currentRound int = 0

	// 布隆过滤器相关
	bloomFilter       *bloom.BloomFilter
	bloomFilterMutex  sync.RWMutex
	expectedElements  uint    = 100000000
	falsePositiveRate float64 = 0.001

	// 新增：每轮待扫描的目标列表（按簇索引存储）
	pendingTargets      map[int][]Target // key: 簇索引, value: 待扫描目标列表
	pendingTargetsMutex sync.RWMutex
)

// 聚类簇结构
type Cluster struct {
	Index       int
	Pattern     string
	Prefixes    []string
	P_i         uint64
	A_i         uint64
	smoothedR_i float64
	budget_i    uint64
	mutex       sync.Mutex
}

// 初始化函数
func init() {
	inputPrefix64Set = make(map[string]bool)
	clusters = make([]*Cluster, 0)
	clusterIndexMap = make(map[int]*Cluster)
	rand.Seed(time.Now().UnixNano())
	bloomFilter = bloom.NewWithEstimates(expectedElements, falsePositiveRate)
	// 初始化待扫描目标映射
	pendingTargets = make(map[int][]Target)
}

// 清理文件名中的非法字符
func sanitizeFilename(filename string) string {
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	filename = strings.ReplaceAll(filename, ":", "-")
	filename = strings.ReplaceAll(filename, "*", "_")
	filename = strings.ReplaceAll(filename, "?", "_")
	filename = strings.ReplaceAll(filename, "\"", "_")
	filename = strings.ReplaceAll(filename, "<", "_")
	filename = strings.ReplaceAll(filename, ">", "_")
	filename = strings.ReplaceAll(filename, "|", "_")
	return filename
}

// 提取IPv6地址的/64前缀
func extractIPv6Prefix64(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To16() == nil {
		return "", fmt.Errorf("无效IPv6地址: %s", ipStr)
	}
	prefixBytes := ip.To16()[:8]
	prefixStr := ""
	for _, b := range prefixBytes {
		prefixStr += fmt.Sprintf("%02x", b)
	}
	return prefixStr, nil
}

// 检查并添加/64前缀到布隆过滤器
func checkAndAddBloomFilter(prefix64 string) bool {
	bloomFilterMutex.Lock()
	defer bloomFilterMutex.Unlock()
	if bloomFilter.TestString(prefix64) {
		return false
	}
	bloomFilter.AddString(prefix64)
	return true
}

// 批量添加/64前缀到布隆过滤器
func batchAddToBloomFilter(prefixes []string) {
	bloomFilterMutex.Lock()
	defer bloomFilterMutex.Unlock()
	addedCount := 0
	for _, prefix := range prefixes {
		if !bloomFilter.TestString(prefix) {
			bloomFilter.AddString(prefix)
			addedCount++
		}
	}
	fmt.Printf("已将%d个/64前缀添加到布隆过滤器（新增%d个）\n", len(prefixes), addedCount)
	fmt.Fprintf(log, "已将%d个/64前缀添加到布隆过滤器（新增%d个）\n", len(prefixes), addedCount)
}

// 层次聚类核心方法
func hierarchicalCluster(prefixes []string, maxWildcard int) []*Cluster {
	fmt.Printf("开始层次聚类 | 最小簇大小：%d | 最大通配符数：%d | 输入前缀数：%d\n",
		minClusterSize, maxWildcard, len(prefixes))
	fmt.Fprintf(log, "开始层次聚类 | 最小簇大小：%d | 最大通配符数：%d | 输入前缀数：%d\n",
		minClusterSize, maxWildcard, len(prefixes))

	clusterMap := make(map[string][]string)
	initialPattern := strings.Repeat("*", 16)
	clusterMap[initialPattern] = prefixes

	for pos := 0; pos < 16; pos++ {
		newClusterMap := make(map[string][]string)
		for pattern, prefixList := range clusterMap {
			if len(prefixList) < minClusterSize {
				newClusterMap[pattern] = prefixList
				continue
			}
			wildcardCount := strings.Count(pattern, "*")
			if wildcardCount <= maxWildcard {
				newClusterMap[pattern] = prefixList
				continue
			}
			if pattern[pos] != '*' {
				newClusterMap[pattern] = prefixList
				continue
			}

			posGroups := make(map[rune][]string)
			for _, prefix := range prefixList {
				if len(prefix) != 16 {
					continue
				}
				char := rune(prefix[pos])
				posGroups[char] = append(posGroups[char], prefix)
			}

			for char, group := range posGroups {
				newPattern := []rune(pattern)
				newPattern[pos] = char
				newPatternStr := string(newPattern)
				newClusterMap[newPatternStr] = append(newClusterMap[newPatternStr], group...)
			}
		}
		clusterMap = newClusterMap
	}

	var clusterList []*Cluster
	for pattern, prefixes := range clusterMap {
		cluster := &Cluster{
			Index:    clusterIndex,
			Pattern:  pattern,
			Prefixes: prefixes,
			P_i:      0,
			A_i:      0,
		}
		clusterList = append(clusterList, cluster)
		clusterIndexMap[clusterIndex] = cluster
		clusterIndex++
	}

	fmt.Printf("聚类完成 | 生成簇数：%d | 最小簇大小：%d | 最大通配符数：%d\n",
		len(clusterList), minClusterSize, maxWildcard)
	fmt.Fprintf(log, "聚类完成 | 生成簇数：%d | 最小簇大小：%d | 最大通配符数：%d\n",
		len(clusterList), minClusterSize, maxWildcard)

	return clusterList
}

// 保存聚类结果到文件
func saveClustersToFile(clusters []*Cluster, filename string) error {
	if err := os.MkdirAll("output", 0755); err != nil {
		return fmt.Errorf("创建output目录失败: %v", err)
	}

	fullPath := fmt.Sprintf("output/clusters_%s_%s", sanitizeFilename(filename), time.Now().Format("20060102-150405"))
	file, err := os.Create(fullPath)
	if err != nil {
		return fmt.Errorf("创建聚类文件失败: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	if _, err := writer.WriteString("簇索引,前缀模式,簇内/64前缀数量,/64前缀列表\n"); err != nil {
		return fmt.Errorf("写入表头失败: %v", err)
	}

	for _, cluster := range clusters {
		prefixList := strings.Join(cluster.Prefixes, ",")
		line := fmt.Sprintf("%d,%s,%d,%s\n", cluster.Index, cluster.Pattern, len(cluster.Prefixes), prefixList)
		if _, err := writer.WriteString(line); err != nil {
			return fmt.Errorf("写入簇%d失败: %v", cluster.Index, err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("刷新缓冲区失败: %v", err)
	}

	fmt.Printf("聚类结果已保存至: %s\n", fullPath)
	fmt.Fprintf(log, "聚类结果已保存至: %s\n", fullPath)
	return nil
}

// 从簇文件加载簇信息
func loadClustersFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("打开簇文件失败: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	lineNum := 0
	var clusterList []*Cluster
	var allPrefixes []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNum++
		if line == "" || strings.HasPrefix(line, "簇索引") {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 4 {
			fmt.Printf("第%d行格式错误，跳过: %s\n", lineNum, line)
			fmt.Fprintf(log, "第%d行格式错误，跳过: %s\n", lineNum, line)
			continue
		}

		var clusterIdx int
		if _, err := fmt.Sscanf(parts[0], "%d", &clusterIdx); err != nil {
			fmt.Printf("第%d行簇索引解析失败，跳过: %s | 错误: %v\n", lineNum, line, err)
			fmt.Fprintf(log, "第%d行簇索引解析失败，跳过: %s | 错误: %v\n", lineNum, line, err)
			continue
		}

		pattern := parts[1]
		prefixes := parts[3:]
		validPrefixes := make([]string, 0, len(prefixes))
		for _, p := range prefixes {
			p = strings.TrimSpace(p)
			if len(p) == 16 {
				validPrefixes = append(validPrefixes, p)
				allPrefixes = append(allPrefixes, p)
			} else if p != "" {
				fmt.Printf("第%d行无效前缀格式，跳过: %s\n", lineNum, p)
				fmt.Fprintf(log, "第%d行无效前缀格式，跳过: %s\n", lineNum, p)
			}
		}

		cluster := &Cluster{
			Index:    clusterIdx,
			Pattern:  pattern,
			Prefixes: validPrefixes,
			P_i:      0,
			A_i:      0,
		}
		clusterList = append(clusterList, cluster)

		clusterIndexMapMutex.Lock()
		clusterIndexMap[clusterIdx] = cluster
		clusterIndexMapMutex.Unlock()

		if clusterIdx >= clusterIndex {
			clusterIndex = clusterIdx + 1
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取簇文件失败: %v", err)
	}

	clusterMutex.Lock()
	clusters = clusterList
	clusterMutex.Unlock()

	batchAddToBloomFilter(allPrefixes)

	fmt.Printf("成功加载簇文件: %s | 加载簇数: %d | 加载/64前缀总数: %d\n",
		filename, len(clusterList), len(allPrefixes))
	fmt.Fprintf(log, "成功加载簇文件: %s | 加载簇数: %d | 加载/64前缀总数: %d\n",
		filename, len(clusterList), len(allPrefixes))

	return nil
}

// 读取IPv6地址文件，提取/64前缀并执行聚类
func readIPv6AddressesFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("打开地址文件失败: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		prefix64, err := extractIPv6Prefix64(line)
		if err != nil {
			fmt.Printf("跳过无效IPv6地址: %s | 错误: %v\n", line, err)
			fmt.Fprintf(log, "跳过无效IPv6地址: %s | 错误: %v\n", line, err)
			continue
		}

		inputPrefix64Mutex.Lock()
		inputPrefix64Set[prefix64] = true
		inputPrefix64Mutex.Unlock()
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取地址文件失败: %v", err)
	}

	inputPrefix64Mutex.RLock()
	prefixList := make([]string, 0, len(inputPrefix64Set))
	for p := range inputPrefix64Set {
		prefixList = append(prefixList, p)
	}
	inputPrefix64Mutex.RUnlock()

	batchAddToBloomFilter(prefixList)

	clusterList := hierarchicalCluster(prefixList, maxWildcard)
	clusterMutex.Lock()
	clusters = clusterList
	clusterMutex.Unlock()

	clusterIndexMapMutex.Lock()
	for _, c := range clusterList {
		clusterIndexMap[c.Index] = c
	}
	clusterIndexMapMutex.Unlock()

	if err := saveClustersToFile(clusterList, filename); err != nil {
		fmt.Printf("保存聚类结果失败: %v\n", err)
		fmt.Fprintf(log, "保存聚类结果失败: %v\n", err)
	}

	fmt.Printf("%s | 提取/64前缀数：%d | 生成簇数：%d\n",
		time.Now().Format("2006-01-02 15:04:05"), len(prefixList), len(clusterList))
	fmt.Fprintf(log, "%s | 提取/64前缀数：%d | 生成簇数：%d\n",
		time.Now().Format("2006-01-02 15:04:05"), len(prefixList), len(clusterList))

	return nil
}

// 簇级预算分配
func allocateClusterBudget() {
	clusterMutex.Lock()
	defer clusterMutex.Unlock()

	n := len(clusters)
	if n == 0 {
		fmt.Println("无可用簇，跳过预算分配")
		fmt.Fprintln(log, "无可用簇，跳过预算分配")
		return
	}

	var sumSmoothedR float64 = 0.0
	for _, cluster := range clusters {
		denominator := alpha + beta + float64(cluster.P_i)
		if denominator == 0 {
			cluster.smoothedR_i = 0.5
		} else {
			cluster.smoothedR_i = (alpha + float64(cluster.A_i)) / denominator
		}
		sumSmoothedR += cluster.smoothedR_i
	}

	budgetExplore := uint64(math.Ceil(float64(Budget) * epsilon))
	budgetExploit := Budget - budgetExplore

	totalMinExplore := uint64(n)
	if budgetExplore < totalMinExplore {
		budgetExplore = totalMinExplore
		budgetExploit = Budget - budgetExplore
		if budgetExploit < 0 {
			budgetExploit = 0
		}
	}
	budgetPerExplore := (budgetExplore - totalMinExplore) / uint64(n)
	remainingExplore := (budgetExplore - totalMinExplore) % uint64(n)

	exploreCount := 0
	for _, cluster := range clusters {
		cluster.budget_i = budgetPerExplore + 1
		if exploreCount < int(remainingExplore) {
			cluster.budget_i += 1
			exploreCount++
		}

		if sumSmoothedR > 0 && budgetExploit > 0 {
			exploit := uint64(math.Floor(float64(budgetExploit) * (cluster.smoothedR_i / sumSmoothedR)))
			cluster.budget_i += exploit
		} else if budgetExploit > 0 {
			cluster.budget_i += budgetExploit / uint64(n)
		}
	}

	fmt.Printf("\n第 %d 轮预算分配完成 | 总预算：%d | 探索预算：%d | 利用预算：%d\n",
		currentRound, Budget, budgetExplore, budgetExploit)
	fmt.Fprintf(log, "\n第 %d 轮预算分配完成 | 总预算：%d | 探索预算：%d | 利用预算：%d\n",
		currentRound, Budget, budgetExplore, budgetExploit)
}

// 从目标IP解析簇索引
func parseClusterIdxFromTarget(targetIPStr string) int {
	ip := net.ParseIP(targetIPStr)
	if ip == nil || ip.To16() == nil {
		return -1
	}

	if ip[8] != 0x00 || ip[9] != 0x00 || ip[10] != 0x00 || ip[11] != 0x00 || ip[12] != 0x00 {
		return -1
	}

	idx := int(ip[13])<<16 + int(ip[14])<<8 + int(ip[15])

	clusterIndexMapMutex.RLock()
	_, exists := clusterIndexMap[idx]
	clusterIndexMapMutex.RUnlock()
	if !exists {
		return -1
	}

	return idx
}

// 生成目标地址并发送扫描包（核心修改：优先扫描待处理目标）
func generateAndScanTargets() uint64 {
	var roundPacketSent uint64 = 0
	var duplicatePrefixCount uint64 = 0

	// 第一步：扫描上一轮留存的待处理目标
	pendingTargetsMutex.RLock()
	// 复制待处理目标，避免锁持有时间过长
	pendingTargetsCopy := make(map[int][]Target)
	for idx, targets := range pendingTargets {
		pendingTargetsCopy[idx] = append([]Target{}, targets...)
	}
	pendingTargetsMutex.RUnlock()

	// 清空本轮待处理目标（准备存储新的）
	pendingTargetsMutex.Lock()
	pendingTargets = make(map[int][]Target)
	pendingTargetsMutex.Unlock()

	// 扫描待处理目标
	for clusterIdx, targets := range pendingTargetsCopy {
		clusterIndexMapMutex.RLock()
		cluster, exists := clusterIndexMap[clusterIdx]
		clusterIndexMapMutex.RUnlock()
		if !exists {
			continue
		}

		// 检查簇预算
		cluster.mutex.Lock()
		budget := cluster.budget_i
		cluster.mutex.Unlock()
		if budget == 0 && currentRound > 1 {
			continue
		}

		for _, target := range targets {
			// 第二轮及以后需要消耗预算
			if currentRound > 1 {
				cluster.mutex.Lock()
				if cluster.budget_i <= 0 {
					cluster.mutex.Unlock()
					break
				}
				cluster.budget_i--
				cluster.mutex.Unlock()
			}

			// 发送扫描包（使用目标自带的TTL）
			Scan(target.IP, target.TTL)
			roundPacketSent++
			packetSent++

			cluster.mutex.Lock()
			cluster.P_i++
			cluster.mutex.Unlock()

			// 控制发包速率
			if roundPacketSent%rate == 0 {
				time.Sleep(200 * time.Millisecond)
			}
		}
	}

	// 第二步：第一轮扫描簇内原有前缀（兼容原有逻辑）
	if currentRound == 1 && roundPacketSent == 0 {
		clusterMutex.RLock()
		clusterCopy := make([]*Cluster, len(clusters))
		copy(clusterCopy, clusters)
		clusterMutex.RUnlock()

		for _, cluster := range clusterCopy {
			cluster.mutex.Lock()
			prefixes := append([]string{}, cluster.Prefixes...)
			cluster.mutex.Unlock()

			for _, prefix64 := range prefixes {
				prefixBytes := make([]byte, 8)
				valid := true
				for i := 0; i < 8; i++ {
					hexStr := prefix64[i*2 : (i+1)*2]
					var b byte
					_, err := fmt.Sscanf(hexStr, "%02x", &b)
					if err != nil {
						valid = false
						break
					}
					prefixBytes[i] = b
				}
				if !valid {
					continue
				}

				if cluster.Index > 0xFFFFFF {
					continue
				}

				targetIP := make(net.IP, 16)
				copy(targetIP[:8], prefixBytes[:8])
				targetIP[8] = 0x00
				targetIP[9] = 0x00
				targetIP[10] = 0x00
				targetIP[11] = 0x00
				targetIP[12] = 0x00
				targetIP[13] = uint8((cluster.Index >> 16) & 0xFF)
				targetIP[14] = uint8((cluster.Index >> 8) & 0xFF)
				targetIP[15] = uint8(cluster.Index & 0xFF)

				Scan(targetIP, initialTTL)
				roundPacketSent++
				packetSent++

				cluster.mutex.Lock()
				cluster.P_i++
				cluster.mutex.Unlock()

				if roundPacketSent%rate == 0 {
					time.Sleep(200 * time.Millisecond)
				}
			}
		}
	}

	// 第三步：第二轮及以后生成新前缀（使用剩余预算）
	if currentRound >= 2 && roundPacketSent < Budget {
		clusterMutex.RLock()
		clusterCopy := make([]*Cluster, len(clusters))
		copy(clusterCopy, clusters)
		clusterMutex.RUnlock()

		for _, cluster := range clusterCopy {
			cluster.mutex.Lock()
			budget := cluster.budget_i
			pattern := cluster.Pattern
			cluster.mutex.Unlock()

			if budget == 0 {
				continue
			}

			generated := uint64(0)
			attempts := uint64(0)
			maxAttempts := budget * 2

			for generated < budget && attempts < maxAttempts {
				attempts++
				newPrefix64 := []rune(pattern)
				for pos, char := range newPrefix64 {
					if char == '*' {
						randHex := "0123456789abcdef"[rand.Intn(16)]
						newPrefix64[pos] = rune(randHex)
					}
				}
				prefix64Str := string(newPrefix64)

				if !checkAndAddBloomFilter(prefix64Str) {
					duplicatePrefixCount++
					continue
				}

				prefixBytes := make([]byte, 8)
				valid := true
				for i := 0; i < 8; i++ {
					hexStr := prefix64Str[i*2 : (i+1)*2]
					var b byte
					_, err := fmt.Sscanf(hexStr, "%02x", &b)
					if err != nil {
						valid = false
						break
					}
					prefixBytes[i] = b
				}
				if !valid {
					continue
				}

				if cluster.Index > 0xFFFFFF {
					continue
				}

				targetIP := make(net.IP, 16)
				copy(targetIP[:8], prefixBytes[:8])
				targetIP[8] = 0x00
				targetIP[9] = 0x00
				targetIP[10] = 0x00
				targetIP[11] = 0x00
				targetIP[12] = 0x00
				targetIP[13] = uint8((cluster.Index >> 16) & 0xFF)
				targetIP[14] = uint8((cluster.Index >> 8) & 0xFF)
				targetIP[15] = uint8(cluster.Index & 0xFF)

				Scan(targetIP, initialTTL)
				roundPacketSent++
				packetSent++
				generated++

				cluster.mutex.Lock()
				cluster.P_i++
				cluster.mutex.Unlock()

				if roundPacketSent%rate == 0 {
					time.Sleep(200 * time.Millisecond)
				}
			}
		}
	}

	fmt.Printf("第 %d 轮 | 发送包数：%d | 预算利用率：%.2f%% | 重复/64前缀数：%d\n",
		currentRound, roundPacketSent, float64(roundPacketSent)/float64(Budget)*100, duplicatePrefixCount)
	fmt.Fprintf(log, "第 %d 轮 | 发送包数：%d | 预算利用率：%.2f%% | 重复/64前缀数：%d\n",
		currentRound, roundPacketSent, float64(roundPacketSent)/float64(Budget)*100, duplicatePrefixCount)

	return roundPacketSent
}

// 安全关闭通道
func safeCloseChan(ch chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("通道关闭警告: %v\n", r)
			fmt.Fprintf(log, "通道关闭警告: %v\n", r)
		}
	}()
	close(ch)
}

// 发送ICMPv6 Echo Request包
func Scan(ipv6Addr net.IP, ttl uint8) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ip6.HopLimit = ttl
	ip6.DstIP = ipv6Addr
	icmp6.SetNetworkLayerForChecksum(&ip6)
	icmp6echo.Identifier = 0
	icmp6echo.SeqNumber = 0

	payloadBytes := make([]byte, 1)
	payloadBytes[0] = byte(ttl)
	payload = gopacket.Payload(payloadBytes)

	err := gopacket.SerializeLayers(buffer, opts, &eth, &ip6, &icmp6, &icmp6echo, &payload)
	if err != nil {
		fmt.Printf("序列化数据包失败: %v\n", err)
		fmt.Fprintf(log, "序列化数据包失败: %v\n", err)
		return
	}

	unix.Send(fd, buffer.Bytes(), unix.MSG_WAITALL)
}

// 接收响应包（核心修改：保存待扫描目标并计算新TTL）
func preRecv(stopChan chan struct{}) {
	buf := make([]byte, 1000)
	running := true

	origFlags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		fmt.Printf("获取FD模式失败: %v\n", err)
		fmt.Fprintf(log, "获取FD模式失败: %v\n", err)
		return
	}
	defer func() {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, origFlags); err != nil {
			fmt.Printf("恢复FD模式失败: %v\n", err)
			fmt.Fprintf(log, "恢复FD模式失败: %v\n", err)
		}
		fmt.Println("收包协程退出，已恢复FD模式")
		fmt.Fprintln(log, "收包协程退出，已恢复FD模式")
	}()

	for running {
		select {
		case <-stopChan:
			running = false
			fmt.Println("收到停止信号，收包协程退出")
			fmt.Fprintf(log, "收到停止信号，收包协程退出")
			return
		default:
			if err := unix.SetNonblock(fd, true); err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			n, _, err := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				fmt.Printf("收包错误: %v\n", err)
				fmt.Fprintf(log, "收包错误: %v\n", err)
				continue
			}

			if n < 102 {
				continue
			}

			switch buf[54] {
			case 1, 3:
				responder := net.IP(buf[22:38]).To16().String()
				dest := net.IP(buf[86:102])
				destStr := dest.String()

				respondersBackwardMutex.Lock()
				isNew := !respondersBackward.HasIPv6(responder)
				if isNew {
					respondersBackward.AddIPv6(responder)

					// 解析簇索引
					clusterIdx := parseClusterIdxFromTarget(destStr)
					if clusterIdx != -1 {
						clusterIndexMapMutex.RLock()
						cluster, exists := clusterIndexMap[clusterIdx]
						clusterIndexMapMutex.RUnlock()
						if exists {
							cluster.mutex.Lock()
							cluster.A_i++
							cluster.mutex.Unlock()
						}

						// 核心修改：计算新的TTL值并保存待扫描目标
						var newTTL uint8
						// 从payload中获取原始TTL（payload第一个字节存储的是发送时的TTL）
						originalTTL := buf[110] // payload位置在110字节

						if buf[54] == 1 { // 类型1：TTL变为原来的1/2
							newTTL = uint8(math.Floor(float64(originalTTL) / 2))
						} else if buf[54] == 3 { // 类型3：TTL减1
							newTTL = originalTTL - 1
						}

						// 确保TTL最小值为4
						if newTTL < 4 {
							newTTL = uint8(4 + rand.Intn(28))
						}

						// 保存待扫描目标
						pendingTargetsMutex.Lock()
						pendingTargets[clusterIdx] = append(pendingTargets[clusterIdx], Target{
							IP:  dest,
							TTL: newTTL,
						})
						pendingTargetsMutex.Unlock()
					}
				}
				respondersBackwardMutex.Unlock()

				if isNew {
					clusterIdx := parseClusterIdxFromTarget(destStr)
					if _, err := fmt.Fprintf(output, "%s,%d,%d,%s,%d\n",
						responder, buf[54], buf[55], destStr, clusterIdx); err != nil {
						fmt.Printf("写入输出文件失败: %v\n", err)
						fmt.Fprintf(log, "写入输出文件失败: %v\n", err)
					}
				}
			}
		}
	}
}

// 主函数
func main() {
	var (
		iface        int
		src          string
		smac         string
		dmac         string
		address_file string
		cluster_file string
		err          error
	)

	flag.IntVar(&iface, "i", 2, "网络接口索引")
	flag.Uint64Var(&rate, "r", 10000, "发包速率（packets/second）")
	flag.StringVar(&address_file, "a", "", "IPv6地址文件（必填，除非指定-cf）")
	flag.StringVar(&cluster_file, "cf", "", "簇文件路径（可选）")
	flag.StringVar(&dmac, "g", "", "目标MAC地址")
	flag.StringVar(&smac, "m", "", "源MAC地址")
	flag.StringVar(&src, "s", "", "源IPv6地址")
	flag.Uint64Var(&Budget, "b", 10000000, "每轮预算（包数）")
	flag.IntVar(&iteration, "c", 10, "扫描轮数")
	flag.Float64Var(&alpha, "alpha", 1.0, "Beta先验参数α")
	flag.Float64Var(&beta, "beta", 1.0, "Beta先验参数β")
	flag.Float64Var(&epsilon, "epsilon", 0.05, "ε-greedy探索率")
	flag.IntVar(&minClusterSize, "min-cluster", 10, "最小簇大小")
	flag.IntVar(&maxWildcard, "max-wildcard", 2, "最大通配符数")
	flag.Parse()

	if cluster_file == "" && address_file == "" {
		fmt.Println("错误：必须指定IPv6地址文件（-a参数）或簇文件（-cf参数）")
		return
	}

	if eth.SrcMAC, err = net.ParseMAC(smac); err != nil {
		panic(fmt.Sprintf("解析源MAC失败: %v", err))
	}
	if eth.DstMAC, err = net.ParseMAC(dmac); err != nil {
		panic(fmt.Sprintf("解析目标MAC失败: %v", err))
	}
	ip6.SrcIP = net.ParseIP(src)
	if ip6.SrcIP == nil {
		panic("无效的源IPv6地址")
	}

	if fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ((unix.ETH_P_ALL<<8)&0xff00)|unix.ETH_P_ALL>>8); err != nil {
		panic(fmt.Sprintf("创建原始套接字失败: %v", err))
	}
	defer unix.Close(fd)

	if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface}); err != nil {
		panic(fmt.Sprintf("绑定接口失败: %v", err))
	}

	if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &bpf_prog); err != nil {
		panic(fmt.Sprintf("附加BPF过滤器失败: %v", err))
	}

	if err := os.MkdirAll("output", 0755); err != nil {
		panic(fmt.Sprintf("创建output目录失败: %v", err))
	}

	baseFilename := func() string {
		if cluster_file != "" {
			return "cluster_" + sanitizeFilename(cluster_file)
		}
		return sanitizeFilename(address_file)
	}()

	outputPath := fmt.Sprintf("output/output-%s-%s", baseFilename, time.Now().Format("20060102-150405"))
	output, err = os.Create(outputPath)
	if err != nil {
		panic(fmt.Sprintf("创建输出文件失败: %v", err))
	}
	defer output.Close()

	logPath := fmt.Sprintf("output/log-%s-%s", baseFilename, time.Now().Format("20060102-150405"))
	log, err = os.Create(logPath)
	if err != nil {
		panic(fmt.Sprintf("创建日志文件失败: %v", err))
	}
	defer log.Close()

	if cluster_file != "" {
		if err := loadClustersFromFile(cluster_file); err != nil {
			fmt.Printf("加载簇文件失败: %v\n", err)
			fmt.Fprintf(log, "加载簇文件失败: %v\n", err)
			return
		}
		fmt.Println("使用已有簇文件，跳过簇文件保存操作")
		fmt.Fprintln(log, "使用已有簇文件，跳过簇文件保存操作")
	} else {
		if err := readIPv6AddressesFromFile(address_file); err != nil {
			fmt.Printf("读取地址文件失败: %v\n", err)
			fmt.Fprintf(log, "读取地址文件失败: %v\n", err)
			return
		}
	}

	clusterMutex.RLock()
	clusterCount := len(clusters)
	clusterMutex.RUnlock()
	if clusterCount == 0 {
		fmt.Println("错误：未加载到任何簇信息，程序退出")
		fmt.Fprintln(log, "错误：未加载到任何簇信息，程序退出")
		return
	}

	totalStartTime := time.Now()
	for currentRound = 1; currentRound <= iteration; currentRound++ {
		fmt.Printf("\n======= 第 %d 轮扫描开始（共 %d 轮） =======\n", currentRound, iteration)
		fmt.Fprintf(log, "\n======= 第 %d 轮扫描开始（共 %d 轮） =======\n", currentRound, iteration)

		if currentRound >= 2 {
			allocateClusterBudget()
		} else {
			fmt.Println("第1轮：直接使用簇内原有/64前缀，无需预算分配")
			fmt.Fprintln(log, "第1轮：直接使用簇内原有/64前缀，无需预算分配")
		}

		stopChan := make(chan struct{})
		go preRecv(stopChan)

		roundPacketSent := generateAndScanTargets()
		if roundPacketSent == 0 {
			fmt.Printf("第 %d 轮无可用目标，跳过\n", currentRound)
			fmt.Fprintf(log, "第 %d 轮无可用目标，跳过\n", currentRound)
			safeCloseChan(stopChan)
			continue
		}

		fmt.Printf("第 %d 轮发包完成 | 发送包数：%d | 等待10秒响应...\n", currentRound, roundPacketSent)
		fmt.Fprintf(log, "第 %d 轮发包完成 | 发送包数：%d | 等待10秒响应...\n", currentRound, roundPacketSent)
		time.Sleep(10 * time.Second)
		safeCloseChan(stopChan)
		time.Sleep(1 * time.Second)

		respondersBackwardMutex.RLock()
		totalResponders := len(respondersBackward)
		respondersBackwardMutex.RUnlock()

		fmt.Printf("第 %d 轮扫描结束 | 本轮发包：%d | 累计发包：%d | 累计发现路由器接口总数：%d\n",
			currentRound, roundPacketSent, packetSent, totalResponders)
		fmt.Fprintf(log, "第 %d 轮扫描结束 | 本轮发包：%d | 累计发包：%d | 累计发现路由器接口总数：%d\n",
			currentRound, roundPacketSent, packetSent, totalResponders)
	}

	totalDuration := time.Now().Sub(totalStartTime)
	respondersBackwardMutex.RLock()
	totalResponders := len(respondersBackward)
	respondersBackwardMutex.RUnlock()

	fmt.Printf("\n======= 扫描完成 =======\n")
	fmt.Printf("总耗时：%.2f秒 | 总发包：%d | 最终发现路由器接口总数：%d\n",
		totalDuration.Seconds(), packetSent, totalResponders)
	fmt.Fprintf(log, "\n======= 扫描完成 =======\n")
	fmt.Fprintf(log, "总耗时：%.2f秒 | 总发包：%d | 最终发现路由器接口总数：%d\n",
		totalDuration.Seconds(), packetSent, totalResponders)
}
