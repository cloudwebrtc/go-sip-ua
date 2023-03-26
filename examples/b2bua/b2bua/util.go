package b2bua

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Map map[string]interface{}

var (
	localIPPrefix = [...]string{"192.168", "10.0", "169.254", "172.16"}
	ErrPort       = errors.New("invalid port")
)

func IsLocalIP(ip string) bool {
	for i := 0; i < len(localIPPrefix); i++ {
		if strings.HasPrefix(ip, localIPPrefix[i]) {
			return true
		}
	}
	return false
}

func GetIntefaceIP() string {
	addrs, _ := net.InterfaceAddrs()

	// get internet ip first
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			if !IsLocalIP(ipnet.IP.String()) {
				return ipnet.IP.String()
			}
		}
	}

	// get internat ip
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}

	return ""
}

func ResolveSelfIP() (net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip, nil
		}
	}
	return nil, errors.New("server not connected to any network")
}

func Recover(flag string) {
	_, _, l, _ := runtime.Caller(1)
	if err := recover(); err != nil {
		logger.Errorf("[%s] Recover panic line => %v", flag, l)
		logger.Errorf("[%s] Recover err => %v", flag, err)
		debug.PrintStack()
	}
}

func Marshal(m map[string]interface{}) string {
	if byt, err := json.Marshal(m); err != nil {
		logger.Errorf("Marshal: err ===> %v", err)
		return ""
	} else {
		return string(byt)
	}
}

// get value from map
func Val(msg map[string]interface{}, key string) string {
	if msg == nil {
		return ""
	}
	val := msg[key]
	if val == nil {
		return ""
	}
	switch val.(type) {
	case string:
		return val.(string)
	case map[string]interface{}:
		return Marshal(val.(map[string]interface{}))
	default:
		return fmt.Sprint(val)
	}
}

func StrToInt(str string) int {
	i, _ := strconv.ParseInt(str, 10, 32)
	//logger.Infof("StrToUint32 str=%v i=%v err=%v", str, i, err)
	return int(i)
}

func StrToInt64(str string) int64 {
	i, _ := strconv.ParseInt(str, 10, 64)
	//logger.Infof("StrToUint32 str=%v i=%v err=%v", str, i, err)
	return int64(i)
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func DialUDPInPortRange(portMin, portMax int, network string, laddr *net.UDPAddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if (laddr.Port != 0) || ((portMin == 0) && (portMax == 0)) {
		return net.DialUDP(network, laddr, raddr)
	}
	var i, j int
	i = portMin
	if i == 0 {
		i = 1
	}
	j = portMax
	if j == 0 {
		j = 0xFFFF
	}
	if i > j {
		return nil, ErrPort
	}

	portStart := rand.Intn(j-i+1) + i
	portCurrent := portStart
	for {
		*laddr = net.UDPAddr{IP: laddr.IP, Port: portCurrent}
		c, e := net.DialUDP(network, laddr, raddr)
		if e == nil {
			return c, e
		}
		logger.Debugf("failed to listen %s: %v", laddr.String(), e)
		portCurrent++
		if portCurrent > j {
			portCurrent = i
		}
		if portCurrent == portStart {
			break
		}
	}
	return nil, ErrPort
}

func ListenUDPInPortRange(portMin, portMax int, network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	if (laddr.Port != 0) || ((portMin == 0) && (portMax == 0)) {
		return net.ListenUDP(network, laddr)
	}
	var i, j int
	i = portMin
	if i == 0 {
		i = 1
	}
	j = portMax
	if j == 0 {
		j = 0xFFFF
	}
	if i > j {
		return nil, ErrPort
	}

	portStart := rand.Intn(j-i+1) + i
	portCurrent := portStart
	for {
		*laddr = net.UDPAddr{IP: laddr.IP, Port: portCurrent}
		c, e := net.ListenUDP(network, laddr)
		if e == nil {
			return c, e
		}
		logger.Errorf("failed to listen %s: %v", laddr.String(), e)
		portCurrent++
		if portCurrent > j {
			portCurrent = i
		}
		if portCurrent == portStart {
			break
		}
	}
	return nil, ErrPort
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func GetAllFiles(pathname string) ([]string, error) {
	files := make([]string, 0)
	rd, err := ioutil.ReadDir(pathname)
	for _, fi := range rd {
		if fi.IsDir() {
			//fmt.Printf("[%s]\n", pathname+"\\"+fi.Name())
			fls, err := GetAllFiles(pathname + fi.Name() + "\\")
			if err != nil {
				continue
			}
			files = append(files, fls...)
		} else {
			files = append(files, fi.Name())
		}
	}
	return files, err
}

func GetUtf8Length(str string) int {
	return utf8.RuneCountInString(str)
}

func JsonEncode(str string) map[string]interface{} {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(str), &data); err != nil {
		panic(err)
	}
	return data
}

func BytesCombine(pBytes ...[]byte) []byte {
	len := len(pBytes)
	s := make([][]byte, len)
	for index := 0; index < len; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}

func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)
	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return int(x)
}

func RandInt64(min, max int64) int64 {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Int63n(max-min) + min
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

func RandomString(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// make kv to map, args should be multiple of 2
func NewMap(args ...interface{}) map[string]interface{} {
	if len(args)%2 != 0 {
		return nil
	}
	msg := make(map[string]interface{})
	for i := 0; i < len(args)/2; i++ {
		msg[args[2*i].(string)] = args[2*i+1]
	}
	return msg
}
