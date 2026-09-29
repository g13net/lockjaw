const std = @import("std");
const crypto = @import("crypto.zig");

// --- Win32 Structures & Constants ---

pub const MAX_PATH: usize = 260;
pub const INVALID_HANDLE_VALUE: ?*anyopaque = @ptrFromInt(std.math.maxInt(usize));

pub const FILETIME = extern struct {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
};

pub const WIN32_FIND_DATAA = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: FILETIME,
    ftLastAccessTime: FILETIME,
    ftLastWriteTime: FILETIME,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    dwReserved0: u32,
    dwReserved1: u32,
    cFileName: [MAX_PATH]u8,
    cAlternateFileName: [14]u8,
};

pub const TH32CS_SNAPPROCESS: u32 = 0x00000002;
pub const TH32CS_SNAPTHREAD: u32 = 0x00000004;
pub const TH32CS_SNAPMODULE: u32 = 0x00000008;
pub const TH32CS_SNAPMODULE32: u32 = 0x00000010;

pub const THREADENTRY32 = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ThreadID: u32,
    th32OwnerProcessID: u32,
    tpBasePri: i32,
    tpDeltaPri: i32,
    dwFlags: u32,
};

pub const PROCESSENTRY32 = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [MAX_PATH]u8,
};

pub const MODULEENTRY32W = extern struct {
    dwSize: u32,
    th32ModuleID: u32,
    th32ProcessID: u32,
    GlblcntUsage: u32,
    ProccntUsage: u32,
    modBaseAddr: ?[*]u8,
    modBaseSize: u32,
    hModule: ?*anyopaque,
    szModule: [256]u16,
    szExePath: [MAX_PATH]u16,
};

pub const MAX_ADAPTER_DESCRIPTION_LENGTH: usize = 128;
pub const MAX_ADAPTER_NAME_LENGTH: usize = 256;
pub const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;

pub const IP_ADDRESS_STRING = extern struct {
    String: [16]u8,
};

pub const IP_ADDR_STRING = extern struct {
    Next: ?*IP_ADDR_STRING,
    IpAddress: IP_ADDRESS_STRING,
    IpMask: IP_ADDRESS_STRING,
    Context: u32,
};

pub const IP_ADAPTER_INFO = extern struct {
    Next: ?*IP_ADAPTER_INFO,
    ComboIndex: u32,
    AdapterName: [MAX_ADAPTER_NAME_LENGTH + 4]u8,
    Description: [MAX_ADAPTER_DESCRIPTION_LENGTH + 4]u8,
    AddressLength: u32,
    Address: [MAX_ADAPTER_ADDRESS_LENGTH]u8,
    Index: u32,
    Type: u32,
    HaveDhcp: u32,
    CurrentIpAddress: ?*IP_ADDR_STRING,
    IpAddressList: IP_ADDR_STRING,
    GatewayList: IP_ADDR_STRING,
    DhcpServer: IP_ADDR_STRING,
    HaveWins: i32,
    PrimaryWinsServer: IP_ADDR_STRING,
    SecondaryWinsServer: IP_ADDR_STRING,
    LeaseObtained: i64,
    LeaseExpires: i64,
};

pub const CONTEXT_CONTROL: u32 = 0x00100001;
pub const CONTEXT_INTEGER: u32 = 0x00100002;
pub const CONTEXT_SEGMENTS: u32 = 0x00100004;
pub const CONTEXT_FLOATING_POINT: u32 = 0x00100008;
pub const CONTEXT_DEBUG_REGISTERS: u32 = 0x00100010;
pub const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
pub const CONTEXT_ALL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS;

pub const CONTEXT = extern struct {
    P1Home: u64 align(16), P2Home: u64, P3Home: u64, P4Home: u64, P5Home: u64, P6Home: u64,
    ContextFlags: u32,
    MxCsr: u32,
    SegCs: u16, SegDs: u16, SegEs: u16, SegFs: u16, SegGs: u16, SegSs: u16,
    EFlags: u32,
    Dr0: u64, Dr1: u64, Dr2: u64, Dr3: u64, Dr6: u64, Dr7: u64,
    Rax: u64, Rcx: u64, Rdx: u64, Rbx: u64, Rsp: u64, Rbp: u64, Rsi: u64, Rdi: u64,
    R8: u64, R9: u64, R10: u64, R11: u64, R12: u64, R13: u64, R14: u64, R15: u64,
    Rip: u64,
    FltSave: [512]u8,
    VectorRegister: [26 * 16]u8,
    VectorControl: u64,
    DebugControl: u64,
    LastBranchToRip: u64,
    LastBranchFromRip: u64,
    LastExceptionToRip: u64,
    LastExceptionFromRip: u64,
};

pub const RtlExitUserThreadFn = *const fn(u32) callconv(.winapi) void;

pub const EXCEPTION_RECORD = extern struct {
    ExceptionCode: u32,
    ExceptionFlags: u32,
    ExceptionRecord: ?*EXCEPTION_RECORD,
    ExceptionAddress: ?*anyopaque,
    NumberParameters: u32,
    ExceptionInformation: [15]usize,
};

pub const EXCEPTION_POINTERS = extern struct {
    ExceptionRecord: *EXCEPTION_RECORD,
    ContextRecord: *CONTEXT,
};

pub const PVECTORED_EXCEPTION_HANDLER = *const fn (*EXCEPTION_POINTERS) callconv(.winapi) i32;

pub const MEMORY_BASIC_INFORMATION = extern struct {
    BaseAddress: ?*anyopaque,
    AllocationBase: ?*anyopaque,
    AllocationProtect: u32,
    PartitionId: u16,
    RegionSize: usize,
    State: u32,
    Protect: u32,
    Type: u32,
};

pub const WAIT_OBJECT_0: u32 = 0x00000000;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_ALL_ACCESS: u32 = 0x1FFFFF;
pub const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

pub const SECTION_MAP_READ: u32 = 0x0004;
pub const SECTION_MAP_WRITE: u32 = 0x0002;
pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
pub const SECTION_ALL_ACCESS: u32 = 0x000F001F;
pub const SEC_COMMIT: u32 = 0x08000000;
pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;

pub const ViewShare: u32 = 1;
pub const ViewUnmap: u32 = 2;

pub const DUPLICATE_CLOSE_SOURCE: u32 = 0x00000001;
pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;

pub const FILE_BEGIN: u32 = 0;
pub const FILE_CURRENT: u32 = 1;
pub const FILE_END: u32 = 2;
pub const OPEN_ALWAYS: u32 = 4;

pub const NTSTATUS = i32;

pub const SYSTEM_INFORMATION_CLASS = u32;
pub const SystemProcessInformation: SYSTEM_INFORMATION_CLASS = 5;
pub const SystemHandleInformation: SYSTEM_INFORMATION_CLASS = 16;
pub const SystemExtendedHandleInformation: SYSTEM_INFORMATION_CLASS = 64;

pub const SYSTEM_HANDLE_TABLE_ENTRY_INFO = extern struct {
    UniqueProcessId: u16,
    CreatorBackTraceIndex: u16,
    ObjectTypeIndex: u8,
    HandleAttributes: u8,
    HandleValue: u16,
    Object: ?*anyopaque,
    GrantedAccess: u32,
};

pub const SYSTEM_HANDLE_INFORMATION = extern struct {
    NumberOfHandles: u32,
    Handles: [1]SYSTEM_HANDLE_TABLE_ENTRY_INFO,
};

pub const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX = extern struct {
    Object: ?*anyopaque,
    UniqueProcessId: usize,
    HandleValue: usize,
    GrantedAccess: u32,
    CreatorBackTraceIndex: u16,
    ObjectTypeIndex: u16,
    HandleAttributes: u32,
    Reserved: u32,
};

pub const SYSTEM_HANDLE_INFORMATION_EX = extern struct {
    NumberOfHandles: usize,
    Reserved: usize,
    Handles: [1]SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
};

pub const OBJECT_INFORMATION_CLASS = u32;
pub const ObjectTypeInformation: OBJECT_INFORMATION_CLASS = 2;

pub const SC_MANAGER_CONNECT: u32 = 0x0001;
pub const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
pub const SERVICE_QUERY_CONFIG: u32 = 0x0001;
pub const SERVICE_QUERY_STATUS: u32 = 0x0004;
pub const SERVICE_WIN32: u32 = 0x00000030;
pub const SERVICE_STATE_ALL: u32 = 0x00000003;

pub const SERVICE_STATUS_PROCESS = extern struct {
    dwServiceType: u32,
    dwCurrentState: u32,
    dwControlsAccepted: u32,
    dwWin32ExitCode: u32,
    dwServiceSpecificExitCode: u32,
    dwCheckPoint: u32,
    dwWaitHint: u32,
    dwProcessId: u32,
    dwServiceFlags: u32,
};

pub const ENUM_SERVICE_STATUS_PROCESSA = extern struct {
    lpServiceName: ?[*]u8,
    lpDisplayName: ?[*]u8,
    ServiceStatusProcess: SERVICE_STATUS_PROCESS,
};

pub const QUERY_SERVICE_CONFIGA = extern struct {
    dwServiceType: u32,
    dwStartType: u32,
    dwErrorControl: u32,
    lpBinaryPathName: ?[*]u8,
    lpLoadOrderGroup: ?[*]u8,
    dwTagId: u32,
    lpDependencies: ?[*]u8,
    lpServiceStartName: ?[*]u8,
    lpDisplayName: ?[*]u8,
};

pub const PUBLIC_OBJECT_TYPE_INFORMATION = extern struct {
    TypeName: UNICODE_STRING,
    Reserved: [22]u32,
};

pub const WORKERFACTORYINFOCLASS = u32;
pub const WorkerFactoryBasicInformation: WORKERFACTORYINFOCLASS = 7;
pub const WorkerFactoryThreadMinimum: WORKERFACTORYINFOCLASS = 8;

pub const WORKER_FACTORY_BASIC_INFORMATION = extern struct {
    Timeout: i64,
    RetryTimeout: i64,
    IdleTimeout: i64,
    Paused: bool,
    TimerSet: bool,
    QueuedToExWorker: bool,
    MayCreate: bool,
    CreateInProgress: bool,
    InsertedIntoQueue: bool,
    Shutdown: bool,
    BindingCount: u32,
    ThreadMinimum: u32,
    ThreadMaximum: u32,
    PendingWorkerCount: u32,
    WaitingWorkerCount: u32,
    TotalWorkerCount: u32,
    ReleaseCount: u32,
    InfiniteWaitGoal: i64,
    StartRoutine: ?*anyopaque,
    StartParameter: ?*anyopaque,
    ProcessId: ?*anyopaque,
    StackReserve: usize,
    StackCommit: usize,
    LastThreadCreationStatus: NTSTATUS,
};

// Let me look up WORKER_FACTORY_BASIC_INFORMATION Windows 10
pub const STATUS_SUCCESS: NTSTATUS = 0;

pub const GENERIC_READ: u32    = 0x80000000;
pub const GENERIC_WRITE: u32   = 0x40000000;
pub const FILE_SHARE_READ: u32 = 0x00000001;
pub const FILE_SHARE_WRITE: u32 = 0x00000002;
pub const CREATE_ALWAYS: u32   = 2;
pub const OPEN_EXISTING: u32   = 3;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;

pub const UNICODE_STRING = extern struct {
    Length: u16,
    MaximumLength: u16,
    Buffer: ?[*]u16,
};

pub const USTRING = extern struct {
    Length: u32,
    MaximumLength: u32,
    Buffer: ?*anyopaque,
};

pub const OBJECT_ATTRIBUTES = extern struct {
    Length: u32,
    RootDirectory: ?*anyopaque,
    ObjectName: ?*UNICODE_STRING,
    Attributes: u32,
    SecurityDescriptor: ?*anyopaque,
    SecurityQualityOfService: ?*anyopaque,
};

pub const PS_ATTRIBUTE = extern struct {
    Attribute: usize,
    Size: usize,
    Value: usize,
    ReturnLength: ?*usize,
};

pub const PS_ATTRIBUTE_LIST = extern struct {
    TotalLength: usize,
    Attributes: [2]PS_ATTRIBUTE, // Adjusted for minimal needs
};

pub const STARTUPINFOW = extern struct {
    cb: u32,
    lpReserved: ?[*]u16,
    lpDesktop: ?[*]u16,
    lpTitle: ?[*]u16,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: ?*u8,
    hStdInput: ?*anyopaque,
    hStdOutput: ?*anyopaque,
    hStdError: ?*anyopaque,
};

pub const PROCESS_INFORMATION = extern struct {
    hProcess: ?*anyopaque,
    hThread: ?*anyopaque,
    dwProcessId: u32,
    dwThreadId: u32,
};

// --- Simplified PE/COFF structures ---

pub const IMAGE_DOS_HEADER = extern struct {
    e_magic: u16,
    e_res: [58]u8,
    e_lfanew: u32,
};

pub const IMAGE_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

pub const IMAGE_DATA_DIRECTORY = extern struct {
    VirtualAddress: u32,
    Size: u32,
};

pub const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: u16,
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32,
    SizeOfInitializedData: u32,
    SizeOfUninitializedData: u32,
    AddressOfEntryPoint: u32,
    BaseOfCode: u32,
    ImageBase: u64,
    SectionAlignment: u32,
    FileAlignment: u32,
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32,
    SizeOfImage: u32,
    SizeOfHeaders: u32,
    CheckSum: u32,
    Subsystem: u16,
    DllCharacteristics: u16,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: u32,
    NumberOfRvaAndSizes: u32,
    DataDirectory: [16]IMAGE_DATA_DIRECTORY,
};

pub const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
};

pub const IMAGE_SECTION_HEADER = extern struct {
    Name: [8]u8,
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
};

pub const IMAGE_EXPORT_DIRECTORY = extern struct {
    Characteristics: u32,
    TimeDateStamp: u32,
    MajorVersion: u16,
    MinorVersion: u16,
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
};

pub const IMAGE_BASE_RELOCATION = extern struct {
    VirtualAddress: u32,
    SizeOfBlock: u32,
};

pub const IMAGE_IMPORT_DESCRIPTOR = extern struct {
    OriginalFirstThunk: u32,
    TimeDateStamp: u32,
    ForwarderChain: u32,
    Name: u32,
    FirstThunk: u32,
};

pub const IMAGE_THUNK_DATA64 = extern struct {
    u1: extern union {
        ForwarderString: u64,
        Function: u64,
        Ordinal: u64,
        AddressOfData: u64,
    },
};

pub const IMAGE_IMPORT_BY_NAME = extern struct {
    Hint: u16,
    Name: [1]u8,
};

// --- PEB Structs ---
pub const LIST_ENTRY = extern struct {
    Flink: ?*LIST_ENTRY,
    Blink: ?*LIST_ENTRY,
};

pub const LDR_DATA_TABLE_ENTRY = extern struct {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: ?*anyopaque,
    EntryPoint: ?*anyopaque,
    SizeOfImage: u32,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Flags: u32,
    LoadCount: u16,
    TlsIndex: u16,
    HashLinks: LIST_ENTRY,
    TimeDateStamp: u32,
};

pub const PEB_LDR_DATA = extern struct {
    Length: u32,
    Initialized: u8,
    SsHandle: ?*anyopaque,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
    EntryInProgress: ?*anyopaque,
    ShutdownInProgress: u8,
    ShutdownThreadId: ?*anyopaque,
};

pub const PEB = extern struct {
    InheritedAddressSpace: u8,
    ReadImageFileExecOptions: u8,
    BeingDebugged: u8,
    BitField: u8,
    Mutant: ?*anyopaque,
    ImageBaseAddress: ?*anyopaque,
    Ldr: *PEB_LDR_DATA,
    ProcessParameters: ?*anyopaque,
    SubSystemData: ?*anyopaque,
    ProcessHeap: ?*anyopaque,
    FastPebLock: ?*anyopaque,
    AtlThunkSListPtr: ?*anyopaque,
    IFEOKey: ?*anyopaque,
    CrossProcessFlags: u32,
    UserSharedInfoPtr: ?*anyopaque,
    SystemReserved: [1]u32,
    AtlThunkSListPtr32: u32,
    ApiSetMap: ?*anyopaque,
    TlsExpansionCounter: u32,
    TlsBitmap: ?*anyopaque,
    TlsBitmapBits: [2]u32,
    ReadOnlySharedMemoryBase: ?*anyopaque,
    HotpatchInformation: ?*anyopaque,
    ReadOnlyStaticServerData: ?*anyopaque,
    AnsiCodePageData: ?*anyopaque,
    OemCodePageData: ?*anyopaque,
    UnicodeCaseTableData: ?*anyopaque,
    NumberOfProcessors: u32,
    NtGlobalFlag: u32,
};

pub const PROCESSINFOCLASS = u32;
pub const ProcessBasicInformation: PROCESSINFOCLASS = 0;

pub const PROCESS_BASIC_INFORMATION = extern struct {
    Reserved1: ?*anyopaque,
    PebBaseAddress: ?*PEB,
    Reserved2: [2]?*anyopaque,
    UniqueProcessId: usize,
    Reserved3: ?*anyopaque,
};


pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const TOKEN_QUERY: u32 = 0x0008;

pub const TOKEN_INFORMATION_CLASS = enum(u32) {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    TokenIsAppContainer,
    TokenCapabilities,
    TokenAppContainerSid,
    TokenAppContainerNumber,
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenRestrictedUserClaimAttributes,
    TokenRestrictedDeviceClaimAttributes,
    TokenDeviceGroups,
    TokenRestrictedDeviceGroups,
    TokenSecurityAttributes,
    TokenIsRestricted,
    TokenProcessTrustLevel,
    TokenPrivateNameSpace,
    TokenSingletonAttributes,
    TokenBannedPrivileges,
    TokenAuditPolicySid,
    TokenIsLessPrivilegedAppContainer,
    TokenIsSandboxed,
    TokenOriginatingProcessSessionId,
    MaxTokenInfoClass
};

pub const TOKEN_ELEVATION = extern struct {
    TokenIsElevated: u32,
};

pub const SID_AND_ATTRIBUTES = extern struct {
    Sid: ?*anyopaque,
    Attributes: u32,
};

pub const TOKEN_USER = extern struct {
    User: SID_AND_ATTRIBUTES,
};

pub const TOKEN_MANDATORY_LABEL = extern struct {
    Label: SID_AND_ATTRIBUTES,
};

pub const SID_NAME_USE = enum(u32) {
    SidTypeUser = 1,
    SidTypeGroup,
    SidTypeDomain,
    SidTypeAlias,
    SidTypeWellKnownGroup,
    SidTypeDeletedAccount,
    SidTypeInvalid,
    SidTypeUnknown,
    SidTypeComputer,
    SidTypeLabel,
    SidTypeLogonSession
};

pub const PROCESS_MITIGATION_POLICY = enum(u32) {
    ProcessDEPPolicy = 0,
    ProcessASLRPolicy = 1,
    ProcessDynamicCodePolicy = 2,
    ProcessStrictControlFlowGuardPolicy = 3,
    ProcessSystemCallDisablePolicy = 4,
    ProcessMitigationOptionsMask = 5,
    ProcessExtensionPointDisablePolicy = 6,
    ProcessControlFlowGuardPolicy = 7,
    ProcessSignaturePolicy = 8,
    ProcessFontDisablePolicy = 9,
    ProcessImageLoadPolicy = 10,
    ProcessSystemCallFilterPolicy = 11,
    ProcessPayloadRestrictionPolicy = 12,
    ProcessChildProcessPolicy = 13,
    ProcessSideChannelIsolationPolicy = 14,
    ProcessUserShadowStackPolicy = 15,
    ProcessRedirectionTrustPolicy = 16,
    ProcessUserPointerAuthPolicy = 17,
    ProcessSEHOPPolicy = 18,
    MaxProcessMitigationPolicy
};

pub const PROCESS_MITIGATION_ASLR_POLICY = extern struct {
    Flags: u32,
};

pub const PROCESS_MITIGATION_DYNAMIC_CODE_POLICY = extern struct {
    Flags: u32,
};

pub const PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY = extern struct {
    Flags: u32,
};

pub const PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = extern struct {
    Flags: u32,
};

pub const PROCESS_MITIGATION_IMAGE_LOAD_POLICY = extern struct {
    Flags: u32,
};

pub const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};

pub const GetLocalTimeFn = *const fn(*SYSTEMTIME) callconv(.winapi) void;

pub const LoadLibraryAFn = *const fn([*c]const u8) callconv(.winapi) ?*anyopaque;
pub const LoadLibraryWFn = *const fn([*c]const u16) callconv(.winapi) ?*anyopaque;
pub const GetProcAddressFn = *const fn(?*anyopaque, [*c]const u8) callconv(.winapi) ?*anyopaque;
pub const LookupAccountSidAFn = *const fn(?*anyopaque, ?*anyopaque, [*]u8, *u32, [*]u8, *u32, *u32) callconv(.winapi) i32;
pub const CreateFileAFn = *const fn([*c]const u8, u32, u32, ?*anyopaque, u32, u32, ?*anyopaque) callconv(.winapi) ?*anyopaque;
pub const WriteFileFn = *const fn(?*anyopaque, ?*const anyopaque, u32, *u32, ?*anyopaque) callconv(.winapi) i32;

pub const OpenSCManagerAFn = *const fn(?[*:0]const u8, ?[*:0]const u8, u32) callconv(.winapi) ?*anyopaque;
pub const OpenServiceAFn = *const fn(?*anyopaque, ?[*:0]const u8, u32) callconv(.winapi) ?*anyopaque;
pub const EnumServicesStatusExAFn = *const fn(?*anyopaque, u32, u32, u32, ?[*]u8, u32, *u32, *u32, ?*u32, ?[*:0]const u8) callconv(.winapi) i32;
pub const QueryServiceConfigAFn = *const fn(?*anyopaque, ?*QUERY_SERVICE_CONFIGA, u32, *u32) callconv(.winapi) i32;
pub const CloseServiceHandleFn = *const fn(?*anyopaque) callconv(.winapi) i32;

pub const OpenProcessFn = *const fn(u32, i32, u32) callconv(.winapi) ?*anyopaque;
pub const IsWow64ProcessFn = *const fn(?*anyopaque, *i32) callconv(.winapi) i32;
pub const OpenProcessTokenFn = *const fn(?*anyopaque, u32, *?*anyopaque) callconv(.winapi) i32;
pub const CloseHandleFn = *const fn(?*anyopaque) callconv(.winapi) i32;
pub const GetTokenInformationFn = *const fn(?*anyopaque, TOKEN_INFORMATION_CLASS, ?*anyopaque, u32, *u32) callconv(.winapi) i32;
pub const GetProcessMitigationPolicyFn = *const fn(?*anyopaque, PROCESS_MITIGATION_POLICY, *anyopaque, usize) callconv(.winapi) i32;
pub const GetSidSubAuthorityCountFn = *const fn(?*anyopaque) callconv(.winapi) ?*u8;
pub const GetSidSubAuthorityFn = *const fn(?*anyopaque, u32) callconv(.winapi) ?*u32;

pub fn getPeb() *PEB {
    return asm volatile ("movq %%gs:0x60, %[ret]"
        : [ret] "=r" (-> *PEB)
    );
}

/// Helper to convert wide char string (UTF-16) to a normal string to hash it (ascii only for modules).
fn djb2_unicode_i(us: UNICODE_STRING) u32 {
    var hash: u32 = 5381;
    var i: u16 = 0;
    while (i < us.Length / 2) : (i += 1) {
        var c: u8 = @intCast(us.Buffer.?[i] & 0xFF);
        if (c >= 'A' and c <= 'Z') {
            c += 32;
        }
        hash = (hash *% 33) +% c;
    }
    return hash;
}

pub fn getModuleHandleByHash(hash: u32) ?*anyopaque {
    const peb = getPeb();
    const ldr = peb.Ldr;
    
    const head = &ldr.InLoadOrderModuleList;
    var current = head.Flink orelse return null;
    
    while (current != head) : (current = current.Flink orelse return null) {
        const entry: *LDR_DATA_TABLE_ENTRY = @ptrCast(current);
        if (entry.DllBase == null) {
            continue;
        }
        const mod_hash = djb2_unicode_i(entry.BaseDllName);
        if (mod_hash == hash) {
            return entry.DllBase;
        }
    }
    return null;
}

pub fn getProcAddressByHash(module_base_: *anyopaque, hash: u32) ?*anyopaque {
    const module_base: [*]u8 = @ptrCast(module_base_);
    
    const dos_header: *IMAGE_DOS_HEADER = @ptrCast(@alignCast(module_base));
    if (dos_header.e_magic != 0x5A4D) return null; // "MZ"
    
    const nt_headers: *IMAGE_NT_HEADERS64 = @ptrCast(@alignCast(module_base + dos_header.e_lfanew));
    if (nt_headers.Signature != 0x00004550) return null; // "PE\0\0"
    
    const export_dir_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
    if (export_dir_rva == 0) return null;
    
    const export_dir: *IMAGE_EXPORT_DIRECTORY = @ptrCast(@alignCast(module_base + export_dir_rva));
    
    const address_of_functions: [*]u32 = @ptrCast(@alignCast(module_base + export_dir.AddressOfFunctions));
    const address_of_names: [*]u32 = @ptrCast(@alignCast(module_base + export_dir.AddressOfNames));
    const address_of_name_ordinals: [*]u16 = @ptrCast(@alignCast(module_base + export_dir.AddressOfNameOrdinals));
    
    var i: u32 = 0;
    while (i < export_dir.NumberOfNames) : (i += 1) {
        const name_ptr: [*]u8 = @ptrCast(module_base + address_of_names[i]);
        var name_len: usize = 0;
        while (name_ptr[name_len] != 0) {
            name_len += 1;
        }
        
        const name_slice = name_ptr[0..name_len];
        const func_hash = crypto.djb2(name_slice);
        
        if (func_hash == hash) {
            const ordinal = address_of_name_ordinals[i];
            const func_rva = address_of_functions[ordinal];
            return @ptrCast(module_base + func_rva);
        }
    }
    
    return null;
}
