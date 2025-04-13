package main

import (
  "bufio"
  "flag"
  "fmt"
  "golang.org/x/sys/unix"
  "github.com/google/gopacket"  
  "github.com/google/gopacket/layers"
  "io/ioutil"
  "math"
  //"math/big"
  "math/rand"  
  "net"
  "os"
  "strconv"
  "strings"
  "sync" 
  "time"
  _ "net/http"
  _ "net/http/pprof"
)

var (
  output     *os.File // for output
  log      *os.File // for log
  eth       = layers.Ethernet{EthernetType: layers.EthernetTypeIPv6}
  ip6       = layers.IPv6{Version: 6, NextHeader: layers.IPProtocolICMPv6, HopLimit: 255}
  icmp6     = layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)}
  icmp6echo = layers.ICMPv6Echo{}
  payload   = gopacket.Payload([]byte{0x00, 0x00, 0x00})
  fd       int      // for socket
  bpf       = []unix.SockFilter{
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
  packetSent uint64 = 0
  splitTTL uint8 = 16
  initialTTL uint8 = 32
  //noReponseNum uint8 = 5
  //respondersForward = make(IPMap)
  respondersBackward = make(IPMap)
  respondersBackwardMutex sync.RWMutex
  //respondersForwardMutex sync.RWMutex
  //respondersAll = make(IPMap)
  targetStateBlocks map[string]*targetStateBlock
  targetStateBlocksMutex sync.RWMutex // 为destinationBlocks定义一个读写锁
  //firstResponders = make(map[string]IPMap)
  //firstRespondersMutex sync.RWMutex // 为firstResponders定义一个读写锁
  destResponders = make(map[string]IPMap)
  destRespondersMutex sync.RWMutex 
  prefixMap = make(map[int]string) 
  //SubnetMap = make(map[string]int)
  prefixMapMutex sync.RWMutex // 为prefixLenMap定义一个读写锁
  prefixReward = make(map[string]float64)
  greedy float64 = 0.05
)

// 目的控制块  
type targetStateBlock struct {
	nextBackwardTTL uint8
	stopBackward bool
	preRespond bool
} 
type prefixBlock struct {
	prefix string
	reward int
	//subnet int
}

type IPMap map[string]bool

// 一个128位整数的结构体
type uint128 struct {
	Hi, Lo uint64
}

func (ipMap IPMap) AddIPv6(ip string) {  
  if _, exists := ipMap[ip]; !exists {  
    ipMap[ip] = true  
  }  
}  

  
// HasIPv6 检查一个IPv6地址是否已存在于IPMap中  
func (ipMap IPMap) HasIPv6(ip string) bool {  
  _, exists := ipMap[ip]  
  return exists  
}  

func init() {  
    targetStateBlocks = make(map[string]*targetStateBlock)  
}

// 在修改或读取destControlBlocks之前，先加锁  
func safeGet(key string) (*targetStateBlock, bool) {  
    targetStateBlocksMutex.RLock() // 使用读锁  
    defer targetStateBlocksMutex.RUnlock()   
	
    val, exists := targetStateBlocks[key]
	
    return val, exists  
}  
  
// 在修改destControlBlocks之前，先加锁  
func safeSet(key string, value *targetStateBlock) {  
    targetStateBlocksMutex.Lock() // 使用写锁  
    defer targetStateBlocksMutex.Unlock()  
    targetStateBlocks[key] = value  
}  

func safeLen() int {  
    targetStateBlocksMutex.RLock()  
    defer targetStateBlocksMutex.RUnlock()  
    return len(targetStateBlocks)  
}

// 在删除destControlBlocks中的元素之前，先加锁  
func safeDelete(key string) {  
    targetStateBlocksMutex.Lock()  
    defer targetStateBlocksMutex.Unlock() 
    delete(targetStateBlocks, key)  
}  

// readIPv6AddressesFromFile 读取包含IPv6地址的文件，并对每个地址执行操作  
func readIPv6AddressesFromFile(filename string) error {  
    file, err := os.Open(filename)  
    if err != nil {  
        return err  
    }  
    defer file.Close()  
  
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        // 去除可能的空白字符并检查是否为有效的IPv6地址
        ipv6AddrStr := strings.TrimSpace(line)
		ipv6Addr := net.ParseIP(ipv6AddrStr)
        if ipv6Addr == nil {
            fmt.Printf("Invalid IPv6 address: %s\n", line)
            continue
        } 
	    targetStateBlocks[ipv6AddrStr] = &targetStateBlock{
            nextBackwardTTL: initialTTL,
            stopBackward:    false,
        }
    }  
  
    if err := scanner.Err(); err != nil {  
        return err  
    }  
  
    return nil  
}  

// ReverseBinary 将一个整数的二进制形式逆序排列，并返回逆序后的整数  
func ReverseBinary(n int) int {  
	// 将整数转换为二进制字符串（去掉前缀"0b"）  
	binaryStr := strconv.FormatInt(int64(n), 2)  
	//fmt.Println("binaryStr:", binaryStr)
	// 将二进制字符串逆序  
	reversedBinaryStr := reverseString(binaryStr)  
	//fmt.Println("new binaryStr:", reversedBinaryStr)
	// 将逆序后的二进制字符串转换为整数  
	reversedN, err := strconv.ParseInt(reversedBinaryStr, 2, 64)  
	if err != nil {  
		// 处理转换错误（这里简单地输出错误并返回0）  
		fmt.Println("Error parsing reversed binary string:", err)  
		return 0  
	}  
  
	return int(reversedN)  
}  
  
// reverseString 将字符串逆序排列  
func reverseString(s string) string {  
	bytes := []byte(s) // 将字符串转换为byte切片  
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {  
		bytes[i], bytes[j] = bytes[j], bytes[i]  
	}  
	return string(bytes)  
}  
func main() {
    var iface int
	var iteration int
	//var maxttl uint8
	var minTTL uint8 = 3
	var rate uint64
	var budgetPerIte uint64
    var src string
    var smac string
    var dmac string
    var prefix_file string
    var address_file string
    //var output_file string
    var err error
    var data []byte

    flag.IntVar(&iface, "i", 2, "")
	flag.IntVar(&iteration, "c", 2, "")
	//flag.Uint64Var(&maxttl, "x", 32, "")
	//flag.Uint64Var(&minttl, "k", 1, "")
	flag.Uint64Var(&rate, "r", 10000, "")
	flag.Uint64Var(&budgetPerIte, "d", 10000, "")
    flag.StringVar(&prefix_file, "p", "", "IPv6 prefix filename")
    flag.StringVar(&address_file, "a", "", "IPv6 address filename")
    //flag.StringVar(&output_file, "o", "", "output filename")
    //flag.Uint64Var(&budget, "b", 100000, "")
    flag.StringVar(&dmac, "g", "", "")
    flag.StringVar(&smac, "m", "", "")
    flag.StringVar(&src, "s", "", "")
    flag.Parse()
    // 确保随机数生成器使用不同的种子  
	rand.Seed(time.Now().UnixNano())
    // 检查是否同时提供了-n和-t选项，这可能会导致冲突  
    if prefix_file != "" && address_file != "" {  
		fmt.Println("Error: Both -p and -a options cannot be used together.")  
		return  
    }
	
    if eth.SrcMAC, err = net.ParseMAC(smac); err != nil {
		panic(err)
    }
    if eth.DstMAC, err = net.ParseMAC(dmac); err != nil {
		panic(err)
    }
   ip6.SrcIP = net.ParseIP(src)
    if fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ((unix.ETH_P_ALL<<8)&0xff00)|unix.ETH_P_ALL>>8); err != nil {
		panic(err)
    }
    if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface}); err != nil {
		panic(err)
    }
    if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &bpf_prog); err != nil {
		panic(err)
    }
	//输出
	if prefix_file != "" {
		if output, err = os.Create("output/output-" + prefix_file + time.Now().Format("20060102-150405")); err != nil {
			panic(err)
		}
    } else {
		if output, err = os.Create("output/output-" + address_file + time.Now().Format("20060102-150405")); err != nil {
			panic(err)
		}
	}
	//日志
	if prefix_file != "" {
		if log, err = os.Create("output/log-" + prefix_file + time.Now().Format("20060102-150405")); err != nil {
			panic(err)
		}
    } else {
		if log, err = os.Create("output/log-" + address_file + time.Now().Format("20060102-150405")); err != nil {
			panic(err)
		}
	}
	
    // 记录程序开始时间  
	startTime := time.Now()
	
    if prefix_file != "" {
	    if data, err = ioutil.ReadFile(prefix_file); err != nil {
			panic(err)
	    }
	    index := -1
		
		//var subnets []net.IPNet
	    for _, line := range strings.Fields(string(data)) {
			if _, ip6net, err := net.ParseCIDR(line); err != nil {
				panic(err)
			} else {
				index += 1
				prefixMap[index] = line
				//SubnetMap[line] = 1
				prefixLen, _ := ip6net.Mask.Size()
				byteOffset := prefixLen / 8
				bitOffset := prefixLen % 8
				for i := 0; i < 10; i++ {
					_, ip6net, _ := net.ParseCIDR(line)
					ipBinary := ip6net.IP.To16()
					ipBinary[14] |= uint8(0x12)
					ipBinary[15] |= uint8(0x34)
					for j := byteOffset; j < 8; j++ {
						if j == byteOffset {
							randomByte := rand.Intn(256)
							ipBinary[j] |= uint8(randomByte >> bitOffset)
							//fmt.Println(ipBinary)
						} else{
							randomByte := rand.Intn(256)
							ipBinary[j] |= uint8(randomByte)
							//fmt.Println(ipBinary) 
						}
						//fmt.Println("\n")
					}
					targetStateBlocks[ipBinary.String()] = &targetStateBlock {
					nextBackwardTTL: initialTTL,
					stopBackward:    false,
					preRespond:       false,
					} 
				
				}
				
			}
		}
    } else if address_file != "" {
		err := readIPv6AddressesFromFile(address_file)
		if err != nil {  
			fmt.Printf("Error reading IPv6 addresses from file: %v\n", err)  
		return 
		}
	} else {
		fmt.Println("Error: Neither -p nor -a option was provided.")  
		return
	}

	// 探测逻辑
	if address_file != "" {
		stopChan1 := make(chan struct{}) // 创建一个新的停止通道
		stopChan2 := make(chan struct{})
		//RecvSeed(stopChan)
		preRecv(stopChan1)
		//var rate_control uint64 = 0
		
		for round := 0; ; round++ {
			// 使用safeLen来获取当前map的长度
			currentLength := safeLen()
			fmt.Println("Number of remaining addresses to trace:",currentLength)
			fmt.Fprintf(log, "Number of remaining addresses to trace: %d\n",currentLength)
			//fmt.Println("Current round:",round)
			if currentLength == 0 {  
				break // 如果没有任何元素，则退出循环
			} 
			// 为了避免在遍历过程中修改map，先获取所有的key
			keys := make([]string, 0, currentLength)
			targetStateBlocksMutex.RLock()
			for key := range targetStateBlocks {
				//fmt.Println(key)
				keys = append(keys, key)
			}  
			targetStateBlocksMutex.RUnlock()

			rand.Shuffle(len(keys), func(i, j int) {
				keys[i], keys[j] = keys[j], keys[i]
			})

			if round == 0 {
				// 第一轮使用初始TTL
				//<-packetChannel
				//fmt.Println(net.ParseIP(key))
				//Scan(net.ParseIP(key), block.InitialTTL, block.prefixIndex) 
				for _,key := range keys { 
					//fmt.Println(key, "aa")
					block ,_:= safeGet(key)
					if block == nil {
						continue
					}
					Scan(net.ParseIP(key), initialTTL)
					packetSent +=1
					if packetSent % rate == 0 {
						time.Sleep(1000 * time.Millisecond)
					}
				}
				time.Sleep(2 * time.Second)
				close(stopChan1)
				Recv(stopChan2)
				//time.Sleep(2 * time.Second)
			} else {
				for _,key := range keys { 
					block ,_:= safeGet(key)
					if block == nil {
						continue
					}
					
					if block.nextBackwardTTL >= minTTL && !block.stopBackward {
						//<-packetChannel
						if round == 1 && block.preRespond == false {
							block.nextBackwardTTL = splitTTL
						}
						Scan(net.ParseIP(key), block.nextBackwardTTL)
						block.nextBackwardTTL--
						safeSet(key, block)
						packetSent +=1
						if packetSent % rate == 0 {
							time.Sleep(1000 * time.Millisecond)
						}
					} else {
						safeDelete(key)
						//block.stopBackward = true
					}
				}
			}
			time.Sleep(2 * time.Second)
			fmt.Printf("%s sent packets: %d\n", time.Now().Format("2006-01-02 15:04:05"), packetSent)
			respondersBackwardMutex.RLock()
			fmt.Printf("%s backward responders: %d\n", time.Now().Format("2006-01-02 15:04:05"), len(respondersBackward))
			fmt.Fprintf(log, "backward responders: %d\n", len(respondersBackward))
			respondersBackwardMutex.RUnlock()
		}
		close(stopChan2)
	} else {
		for j:= 0; j<iteration ; j++ {
			// 每次循环开始时重启接收  
			stopChan2 := make(chan struct{})
			fmt.Println("Current iteration:",j)
			
			for round := 0; ; round++ {  
				// 使用safeLen来获取当前map的长度  
				currentLength := safeLen()  
				fmt.Println("Number of remaining addresses to trace:", currentLength)
				fmt.Fprintf(log, "Number of remaining addresses to trace: %d\n", currentLength)
				//fmt.Println("Current round:",round)
				if currentLength == 0 {  
					break // 如果没有任何元素，则退出循环  
				} 
				// 为了避免在遍历过程中修改map，我们先获取所有的key  
				keys := make([]string, 0, currentLength)  
				targetStateBlocksMutex.RLock()  
				for key := range targetStateBlocks {  
					//fmt.Println(key)
					keys = append(keys, key)  
				}  
				targetStateBlocksMutex.RUnlock()
				rand.Shuffle(len(keys), func(i, j int) {
					keys[i], keys[j] = keys[j], keys[i]
				})
				if round == 0 {
					// 第一轮使用初始TTL
					stopChan1 := make(chan struct{}) // 创建一个新的停止通道
					preRecv(stopChan1)
					//<-packetChannel
					//fmt.Println(net.ParseIP(key))
					//Scan(net.ParseIP(key), block.InitialTTL, block.prefixIndex) 
					for _,key := range keys { 
						//fmt.Println(key, "aa")
						block ,_:= safeGet(key)
						if block == nil {
							continue
						}
						Scan(net.ParseIP(key), initialTTL)
						packetSent += 1
						//fmt.Println(packetsent)
						//rate_control += 1
						if packetSent % rate == 0 {
							//rate_control = 0
							time.Sleep(700 * time.Millisecond)
						}
					}
					time.Sleep(2 * time.Second)
					close(stopChan1)
					
					Recv(stopChan2)
					time.Sleep(2 * time.Second)
				} else {
					for _,key := range keys { 
						//fmt.Println(key, "aa")
						block ,_:= safeGet(key)
						if block == nil {
							continue
						}
						block.nextBackwardTTL--
						if block.nextBackwardTTL >= minTTL && !block.stopBackward{
							Scan(net.ParseIP(key), block.nextBackwardTTL)
							packetSent +=1
							if packetSent % rate == 0 {
								time.Sleep(700 * time.Millisecond)
							}
							safeSet(key, block)
						} else {
							safeDelete(key)
						}
					}
					time.Sleep(2 * time.Second)
				}
			}
			
			//停止收包函数
			close(stopChan2)
			time.Sleep(2 * time.Second)
			fmt.Println("backward responders:",len(respondersBackward))
			fmt.Fprintf(log, "backward responders: %d\n",len(respondersBackward))
			fmt.Println("Number of sent packets:", packetSent)
			fmt.Fprintf(log, "Number of sent packets: %d\n", packetSent)
			if j == iteration-1 {
				continue
			}
			var rewardTotal uint64 = 0
			var budgetForPrefix float64

			for _, responders := range destResponders {
				//rewardTotal += math.Exp(float64(len(responders)))
				rewardTotal += uint64(len(responders))
			}
			for key, responders := range destResponders{
				//Probility := math.Exp(float64(len(responders))) / float64(rewardTotal)
				//fmt.Fprintf(log, "%f\n", Probility)
				//budgetForPrefix = ((1 - greedy) * Probility + greedy / float64(len(prefixMap))) * float64(budgetPerIte)
				//fmt.Fprintf(log, "%f\n", budgetForPrefix)
				if budgetPerIte * uint64(len(responders)) < rewardTotal {
					budgetForPrefix = 1.0
				} else {
					budgetForPrefix = float64(budgetPerIte * uint64(len(responders))) / float64(rewardTotal)	
				}
				//fmt.Println(budgetForPrefix)
				//var index int 
				//for prefixIndex, pre := range prefixMap {
				//	if pre == key {
				//		index = prefixIndex
				//		break
				//	}
				//}
				_, ip6net, _ := net.ParseCIDR(key)
				//fmt.Println(ip6net)
				//fmt.Println("network address:", ipBinary)
				prefixLen, _ := ip6net.Mask.Size()
				byteOffset := prefixLen / 8
				bitOffset := prefixLen % 8
				//dcb, exists := safeGet(key)
				for i := 0; i < int(math.Ceil(budgetForPrefix)); i++ {
					_, ip6net, _ := net.ParseCIDR(key)
					ipBinary := ip6net.IP.To16()
					ipBinary[14] |= uint8(0x12)
					ipBinary[15] |= uint8(0x34)
					for j := byteOffset; j < 8; j++ {
						if j == byteOffset {
							randomByte := rand.Intn(256)
							ipBinary[j] |= uint8(randomByte >> bitOffset)
						} else{
							randomByte := rand.Intn(256)
							ipBinary[j] |= uint8(randomByte)
						}
					}
					//fmt.Println(ipBinary)
					targetStateBlocksMutex.Lock()
					targetStateBlocks[ipBinary.String()] = &targetStateBlock {
						nextBackwardTTL: initialTTL,
						stopBackward:    false,
					}
					targetStateBlocksMutex.Unlock()
				}
				//SubnetMap[key] += int(math.Ceil(budgetForPrefix))
			}
			//destResponders = make(map[string]IPMap)
			//prefixRewardMutex.Lock()
			//prefixLenMap = make(map[string]int)
			//prefixRewardMutex.Unlock()
		}
    }
	// 记录程序结束时间  
	endTime := time.Now()  
  
	// 计算程序运行时间  
	duration := endTime.Sub(startTime)  
    //fmt.Printf("Packets sent: %d\n", packetSent)
	//fmt.Fprintf(log, "Packets sent: %d\n", packetSent)
	// 以秒为单位打印程序运行时间  
	fmt.Printf("Scanning time(seconds): %.2f\n", duration.Seconds())
	fmt.Fprintf(log, "Scanning time(seconds): %.2f\n", duration.Seconds())	
	//for key := range respondersForward {  
	//	respondersAll[key] = true  
	//}  
	//添加respondersBackward中的键到并集中  
	//for key := range respondersBackward {  
	//	respondersAll[key] = true  
	//}  
	//输出并集的元素数量  
	//fmt.Println("all responders:", len(respondersAll))
}

func Scan(ipv6Addr net.IP, ttl uint8) {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ip6.HopLimit = ttl
	ip6.DstIP = ipv6Addr
	icmp6.SetNetworkLayerForChecksum(&ip6)
	icmp6echo.Identifier = 0
	icmp6echo.SeqNumber = 0
	  
	// 设置payload的第一个字节为TTL值  
	payloadBytes := make([]byte, 1)  
	payloadBytes[0] = byte(ttl)
	//dcb, _ := safeGet(ipv6Addr.String())
	
	//payloadBytes[1] = byte(ttl)
	//payloadBytes[2] = byte(prefixIndex & 0xff)
	payload = gopacket.Payload(payloadBytes)

	gopacket.SerializeLayers(buffer, opts, &eth, &ip6, &icmp6, &icmp6echo, &payload)
	unix.Send(fd, buffer.Bytes(), unix.MSG_WAITALL)
}

func preRecv(stopChan chan struct{}) {
  buf := make([]byte, 1000)
  running := true
  //var status32 uint32
  go func() {
		for running {
			select {
			case <- stopChan:
				running = false
				fmt.Println("preRecv stopped")
			default:
				if _, _, err := unix.Recvfrom(fd, buf, 0); err != nil {
				  fmt.Println(fd, err)
				  continue
				} 
				// responding addr, icmpv6 type, code, ttl, length, probing addr, prefix idx, probing ttl, send time, recv time, check
				switch buf[54] {
				case 129:
					responder := net.IP(buf[22:38]).String()
					responseTTl := uint8(buf[21])
					//probeTTL := uint8(buf[62])
					var distance uint8  
					if responseTTl < 64 {
						distance = 64 - responseTTl
					}
					if responseTTl >= 64 && responseTTl <= 223 {
						distance = 16
						//continue
					}
					if responseTTl > 223 {
						distance = 255 - responseTTl
					}
					dcb, exists := safeGet(responder)
					if !exists {
						continue
					}
					dcb.preRespond = true
					dcb.nextBackwardTTL = distance - 1
					safeSet(responder, dcb)
					fmt.Fprintf(output, "%s,%d,%d,%d\n", responder, buf[54], buf[55], distance)
				case 3:
					responder := net.IP(buf[22:38]).String()
					//fmt.Printf("get respond from %s",responder)
					dest := net.IP(buf[86:102]).String()
					//destIP := net.IP(buf[86:102])
					//probeTTL := uint8(buf[110])
					//prefixLength := uint8(buf[111])
					respondersBackwardMutex.Lock()
					respondersBackward.AddIPv6(responder)
					respondersBackwardMutex.Unlock()
					dcb, exists := safeGet(dest)
					if !exists {
						continue
					}
					dcb.preRespond = true
					dcb.nextBackwardTTL = initialTTL - 1
					//dcb.initialBackTTL = initialTTL - 1
					safeSet(dest, dcb)
					fmt.Fprintf(output, "%s,%d,%d,%d,%s\n", responder, buf[54], buf[55], buf[110], dest)
				case 1:
					responder := net.IP(buf[22:38]).String()
					//fmt.Printf("get respond from %s",responder)
					dest := net.IP(buf[86:102]).String()
					//destIP := net.IP(buf[86:102])
					remainTTL := uint8(buf[69])
					var distance uint8
					distance = initialTTL - remainTTL
					respondersBackwardMutex.Lock()
					respondersBackward.AddIPv6(responder)
					respondersBackwardMutex.Unlock()
					dcb, exists := safeGet(dest)
					if !exists {
						continue
					}
					dcb.preRespond = true
					dcb.nextBackwardTTL = distance - 1
					//dcb.initialBackTTL = distance - 1
					safeSet(dest, dcb) 
					fmt.Fprintf(output, "%s,%d,%d,%d,%s\n", responder, buf[54], buf[55], buf[110], dest)
				  }
			}
		}
	}()
}

func Recv(stopChan chan struct{}) {
  buf := make([]byte, 1000)
  running := true
  //var status32 uint32
  go func() {
		for running {
			select {
			case <- stopChan:
				running = false
				fmt.Println("Recv stopped")
			default:
				if _, _, err := unix.Recvfrom(fd, buf, 0); err != nil {
				  fmt.Println(fd, err)
				  continue
				}
				// responding addr, icmpv6 type, code, ttl, length, probing addr, prefix idx, probing ttl, send time, recv time, check
				switch buf[54] {
				case 129:
					responder := net.IP(buf[22:38])
					responseTTl := uint8(buf[21])
					//probeTTL := uint8(buf[62])
					var distance uint8  
					if responseTTl < 64 {
						distance = 64 - responseTTl
					}
					if responseTTl >= 64 && responseTTl <= 223 {
						distance = 0
						continue
					}
					if responseTTl > 223 {
						distance = 255 - responseTTl
					}
					fmt.Fprintf(output, "%s,%d,%d,%d\n", responder.To16(), buf[54], buf[55], distance)
				case 3:
					responder := net.IP(buf[22:38]).String()
					//fmt.Printf("get respond from %s",responder)
					dest := net.IP(buf[86:102]).String()
					//distance := uint8(buf[110])
					//prefixLength := uint8(buf[111])
					dcb, exists := safeGet(dest)
					if !respondersBackward.HasIPv6(responder) {
						respondersBackwardMutex.Lock()
						respondersBackward.AddIPv6(responder)
						respondersBackwardMutex.Unlock()
						if !exists {
							continue
						}
						safeSet(dest, dcb)
					} else {
						if !exists {
							continue
						}
						dcb.stopBackward = true
						safeSet(dest, dcb)
					}
					fmt.Fprintf(output, "%s,%d,%d,%d,%s\n", responder, buf[54], buf[55], buf[110], dest)
				case 1:
					responder := net.IP(buf[22:38]).String()
					//fmt.Printf("get respond from %s",responder)
					dest := net.IP(buf[86:102]).String()
					//probeTTL := uint8(buf[110]) 
					//remainTTL := uint8(buf[69])
					//distance := probeTTL - remainTTL
					dcb, exists := safeGet(dest)
					if !respondersBackward.HasIPv6(responder) {
						respondersBackwardMutex.Lock()
						respondersBackward.AddIPv6(responder)
						respondersBackwardMutex.Unlock()
					} else {
						if !exists {  
							continue  
						}
						dcb.stopBackward = true
						safeSet(dest, dcb)
					}
					fmt.Fprintf(output, "%s,%d,%d,%d,%s\n", responder, buf[54], buf[55], buf[110], dest)
				  }
			}
		}
	}()
}
 
