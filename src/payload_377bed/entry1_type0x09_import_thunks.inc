//----- (0000000000041040) ----------------------------------------------------
unsigned __int64 comm_page64_base_address()
{
//  uintptr_t capabilitiesStub = (uintptr_t)&real_get_cpu_capabilities;
//#if defined(__arm64e__)
//  __asm__ volatile("paciza %0" : "+r"(capabilitiesStub));
//  __asm__ volatile("xpaci %0" : "+r"(capabilitiesStub));
//#endif
//  return *(unsigned __int64 *)(capabilitiesStub + 12) & 0xFFFFFFFFFFFFFF00LL;
    return 0xFFFFFC000;
}
// 483C0: using guessed type __int64 j___get_cpu_capabilities(void);
#if 0
//----- (000000000004106C) ----------------------------------------------------
int __cdecl CC_SHA1_Final(unsigned __int8 *md, CC_SHA1_CTX *c)
{
  return _CC_SHA1_Final(md, c);
}

//----- (000000000004107C) ----------------------------------------------------
int __cdecl CC_SHA1_Init(CC_SHA1_CTX *c)
{
  return _CC_SHA1_Init(c);
}

//----- (000000000004108C) ----------------------------------------------------
int __cdecl CC_SHA1_Update(CC_SHA1_CTX *c, const void *data, CC_LONG len)
{
  return _CC_SHA1_Update(c, data, len);
}

//----- (000000000004109C) ----------------------------------------------------
int __cdecl CC_SHA256_Final(unsigned __int8 *md, CC_SHA256_CTX *c)
{
  return _CC_SHA256_Final(md, c);
}

//----- (00000000000410AC) ----------------------------------------------------
int __cdecl CC_SHA256_Init(CC_SHA256_CTX *c)
{
  return _CC_SHA256_Init(c);
}

//----- (00000000000410BC) ----------------------------------------------------
int __cdecl CC_SHA256_Update(CC_SHA256_CTX *c, const void *data, CC_LONG len)
{
  return _CC_SHA256_Update(c, data, len);
}

//----- (00000000000410CC) ----------------------------------------------------
int __cdecl CC_SHA384_Final(unsigned __int8 *md, CC_SHA512_CTX *c)
{
  return _CC_SHA384_Final(md, c);
}

//----- (00000000000410DC) ----------------------------------------------------
int __cdecl CC_SHA384_Init(CC_SHA512_CTX *c)
{
  return _CC_SHA384_Init(c);
}

//----- (00000000000410EC) ----------------------------------------------------
int __cdecl CC_SHA384_Update(CC_SHA512_CTX *c, const void *data, CC_LONG len)
{
  return _CC_SHA384_Update(c, data, len);
}

//----- (00000000000410FC) ----------------------------------------------------
void __cdecl CFArrayAppendValue(CFMutableArrayRef theArray, const void *value)
{
  _CFArrayAppendValue(theArray, value);
}

//----- (000000000004110C) ----------------------------------------------------
void __cdecl CFArrayApplyFunction(CFArrayRef theArray, CFRange range, CFArrayApplierFunction applier, void *context)
{
  _CFArrayApplyFunction(theArray, range, applier, context);
}

//----- (000000000004111C) ----------------------------------------------------
Boolean __cdecl CFArrayContainsValue(CFArrayRef theArray, CFRange range, const void *value)
{
  return _CFArrayContainsValue(theArray, range, value);
}

//----- (000000000004112C) ----------------------------------------------------
CFIndex __cdecl CFArrayGetCount(CFArrayRef theArray)
{
  return _CFArrayGetCount(theArray);
}

//----- (000000000004113C) ----------------------------------------------------
CFTypeID CFArrayGetTypeID(void)
{
  return _CFArrayGetTypeID();
}

//----- (000000000004114C) ----------------------------------------------------
CFTypeID CFBooleanGetTypeID(void)
{
  return _CFBooleanGetTypeID();
}

//----- (000000000004115C) ----------------------------------------------------
CFDataRef __cdecl CFDataCreate(CFAllocatorRef allocator, const UInt8 *bytes, CFIndex length)
{
  return _CFDataCreate(allocator, bytes, length);
}

//----- (000000000004116C) ----------------------------------------------------
CFDataRef __cdecl CFDataCreateWithBytesNoCopy(
        CFAllocatorRef allocator,
        const UInt8 *bytes,
        CFIndex length,
        CFAllocatorRef bytesDeallocator)
{
  return _CFDataCreateWithBytesNoCopy(allocator, bytes, length, bytesDeallocator);
}

//----- (000000000004117C) ----------------------------------------------------
const UInt8 *__cdecl CFDataGetBytePtr(CFDataRef theData)
{
  return _CFDataGetBytePtr(theData);
}

//----- (000000000004118C) ----------------------------------------------------
CFIndex __cdecl CFDataGetLength(CFDataRef theData)
{
  return _CFDataGetLength(theData);
}

//----- (000000000004119C) ----------------------------------------------------
CFTypeID CFDataGetTypeID(void)
{
  return _CFDataGetTypeID();
}

//----- (00000000000411AC) ----------------------------------------------------
void __cdecl CFDictionaryAddValue(CFMutableDictionaryRef theDict, const void *key, const void *value)
{
  _CFDictionaryAddValue(theDict, key, value);
}

//----- (00000000000411BC) ----------------------------------------------------
void __cdecl CFDictionaryApplyFunction(CFDictionaryRef theDict, CFDictionaryApplierFunction applier, void *context)
{
  _CFDictionaryApplyFunction(theDict, applier, context);
}

//----- (00000000000411CC) ----------------------------------------------------
CFMutableDictionaryRef __cdecl CFDictionaryCreateMutable(
        CFAllocatorRef allocator,
        CFIndex capacity,
        const CFDictionaryKeyCallBacks *keyCallBacks,
        const CFDictionaryValueCallBacks *valueCallBacks)
{
  return _CFDictionaryCreateMutable(allocator, capacity, keyCallBacks, valueCallBacks);
}

//----- (00000000000411DC) ----------------------------------------------------
CFMutableDictionaryRef __cdecl CFDictionaryCreateMutableCopy(
        CFAllocatorRef allocator,
        CFIndex capacity,
        CFDictionaryRef theDict)
{
  return _CFDictionaryCreateMutableCopy(allocator, capacity, theDict);
}

//----- (00000000000411EC) ----------------------------------------------------
CFTypeID CFDictionaryGetTypeID(void)
{
  return _CFDictionaryGetTypeID();
}

//----- (00000000000411FC) ----------------------------------------------------
Boolean __cdecl CFDictionaryGetValueIfPresent(CFDictionaryRef theDict, const void *key, const void **value)
{
  return _CFDictionaryGetValueIfPresent(theDict, key, value);
}

//----- (000000000004120C) ----------------------------------------------------
void __cdecl CFDictionarySetValue(CFMutableDictionaryRef theDict, const void *key, const void *value)
{
  _CFDictionarySetValue(theDict, key, value);
}

//----- (000000000004121C) ----------------------------------------------------
Boolean __cdecl CFEqual(CFTypeRef cf1, CFTypeRef cf2)
{
  return _CFEqual(cf1, cf2);
}

//----- (000000000004122C) ----------------------------------------------------
CFTypeID __cdecl CFGetTypeID(CFTypeRef cf)
{
  return _CFGetTypeID(cf);
}

//----- (000000000004123C) ----------------------------------------------------
CFNumberRef __cdecl CFNumberCreate(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr)
{
  return _CFNumberCreate(allocator, theType, valuePtr);
}

//----- (000000000004124C) ----------------------------------------------------
CFTypeID CFNumberGetTypeID(void)
{
  return _CFNumberGetTypeID();
}

//----- (000000000004125C) ----------------------------------------------------
Boolean __cdecl CFNumberGetValue(CFNumberRef number, CFNumberType theType, void *valuePtr)
{
  return _CFNumberGetValue(number, theType, valuePtr);
}

//----- (000000000004126C) ----------------------------------------------------
CFDataRef __cdecl CFPropertyListCreateData(
        CFAllocatorRef allocator,
        CFPropertyListRef propertyList,
        CFPropertyListFormat format,
        CFOptionFlags options,
        CFErrorRef *error)
{
  return _CFPropertyListCreateData(allocator, propertyList, format, options, error);
}

//----- (000000000004127C) ----------------------------------------------------
CFPropertyListRef __cdecl CFPropertyListCreateWithData(
        CFAllocatorRef allocator,
        CFDataRef data,
        CFOptionFlags options,
        CFPropertyListFormat *format,
        CFErrorRef *error)
{
  return _CFPropertyListCreateWithData(allocator, data, options, format, error);
}

//----- (000000000004128C) ----------------------------------------------------
CFPropertyListRef __cdecl CFPropertyListCreateWithStream(
        CFAllocatorRef allocator,
        CFReadStreamRef stream,
        CFIndex streamLength,
        CFOptionFlags options,
        CFPropertyListFormat *format,
        CFErrorRef *error)
{
  return _CFPropertyListCreateWithStream(allocator, stream, streamLength, options, format, error);
}

//----- (000000000004129C) ----------------------------------------------------
void __cdecl CFReadStreamClose(CFReadStreamRef stream)
{
  _CFReadStreamClose(stream);
}

//----- (00000000000412AC) ----------------------------------------------------
CFReadStreamRef __cdecl CFReadStreamCreateWithBytesNoCopy(
        CFAllocatorRef alloc,
        const UInt8 *bytes,
        CFIndex length,
        CFAllocatorRef bytesDeallocator)
{
  return _CFReadStreamCreateWithBytesNoCopy(alloc, bytes, length, bytesDeallocator);
}

//----- (00000000000412BC) ----------------------------------------------------
Boolean __cdecl CFReadStreamOpen(CFReadStreamRef stream)
{
  return _CFReadStreamOpen(stream);
}

//----- (00000000000412CC) ----------------------------------------------------
void __cdecl CFRelease(CFTypeRef cf)
{
  _CFRelease(cf);
}

//----- (00000000000412DC) ----------------------------------------------------
void __cdecl CFRunLoopAddSource(CFRunLoopRef rl, CFRunLoopSourceRef source, CFRunLoopMode mode)
{
  _CFRunLoopAddSource(rl, source, mode);
}

//----- (00000000000412EC) ----------------------------------------------------
CFRunLoopRef CFRunLoopGetCurrent(void)
{
  return _CFRunLoopGetCurrent();
}

//----- (00000000000412FC) ----------------------------------------------------
void __cdecl CFRunLoopRemoveSource(CFRunLoopRef rl, CFRunLoopSourceRef source, CFRunLoopMode mode)
{
  _CFRunLoopRemoveSource(rl, source, mode);
}

//----- (000000000004130C) ----------------------------------------------------
CFRunLoopRunResult __cdecl CFRunLoopRunInMode(
        CFRunLoopMode mode,
        CFTimeInterval seconds,
        Boolean returnAfterSourceHandled)
{
  return _CFRunLoopRunInMode(mode, seconds, returnAfterSourceHandled);
}

//----- (000000000004131C) ----------------------------------------------------
CFStringRef __cdecl CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding)
{
  return _CFStringCreateWithCString(alloc, cStr, encoding);
}

//----- (000000000004132C) ----------------------------------------------------
Boolean __cdecl CFStringGetCString(CFStringRef theString, char *buffer, CFIndex bufferSize, CFStringEncoding encoding)
{
  return _CFStringGetCString(theString, buffer, bufferSize, encoding);
}

//----- (000000000004133C) ----------------------------------------------------
CFStringEncoding CFStringGetSystemEncoding(void)
{
  return _CFStringGetSystemEncoding();
}

//----- (000000000004134C) ----------------------------------------------------
CFTypeID CFStringGetTypeID(void)
{
  return _CFStringGetTypeID();
}

//----- (000000000004135C) ----------------------------------------------------
Boolean __cdecl CFStringHasPrefix(CFStringRef theString, CFStringRef prefix)
{
  return _CFStringHasPrefix(theString, prefix);
}

//----- (000000000004136C) ----------------------------------------------------
CFDataRef __cdecl IOCFSerialize(CFTypeRef object, CFOptionFlags options)
{
  return _IOCFSerialize(object, options);
}

//----- (000000000004137C) ----------------------------------------------------
kern_return_t __cdecl IOConnectCallMethod(
        mach_port_t connection,
        uint32_t selector,
        const uint64_t *input,
        uint32_t inputCnt,
        const void *inputStruct,
        size_t inputStructCnt,
        uint64_t *output,
        uint32_t *outputCnt,
        void *outputStruct,
        size_t *outputStructCnt)
{
  return _IOConnectCallMethod(
           connection,
           selector,
           input,
           inputCnt,
           inputStruct,
           inputStructCnt,
           output,
           outputCnt,
           outputStruct,
           outputStructCnt);
}

//----- (000000000004138C) ----------------------------------------------------
kern_return_t __cdecl IOConnectCallScalarMethod(
        mach_port_t connection,
        uint32_t selector,
        const uint64_t *input,
        uint32_t inputCnt,
        uint64_t *output,
        uint32_t *outputCnt)
{
  return _IOConnectCallScalarMethod(connection, selector, input, inputCnt, output, outputCnt);
}

//----- (000000000004139C) ----------------------------------------------------
kern_return_t __cdecl IOConnectCallStructMethod(
        mach_port_t connection,
        uint32_t selector,
        const void *inputStruct,
        size_t inputStructCnt,
        void *outputStruct,
        size_t *outputStructCnt)
{
  return _IOConnectCallStructMethod(connection, selector, inputStruct, inputStructCnt, outputStruct, outputStructCnt);
}

//----- (00000000000413AC) ----------------------------------------------------
kern_return_t __cdecl IOConnectTrap4(
        io_connect_t connect,
        uint32_t index,
        uintptr_t p1,
        uintptr_t p2,
        uintptr_t p3,
        uintptr_t p4)
{
  return _IOConnectTrap4(connect, index, p1, p2, p3, p4);
}

//----- (00000000000413BC) ----------------------------------------------------
kern_return_t __cdecl IOConnectTrap6(
        io_connect_t connect,
        uint32_t index,
        uintptr_t p1,
        uintptr_t p2,
        uintptr_t p3,
        uintptr_t p4,
        uintptr_t p5,
        uintptr_t p6)
{
  return _IOConnectTrap6(connect, index, p1, p2, p3, p4, p5, p6);
}

//----- (00000000000413CC) ----------------------------------------------------
io_object_t __cdecl IOIteratorNext(io_iterator_t iterator)
{
  return _IOIteratorNext(iterator);
}

//----- (00000000000413DC) ----------------------------------------------------
IONotificationPortRef __cdecl IONotificationPortCreate(mach_port_t masterPort)
{
  return _IONotificationPortCreate(masterPort);
}

//----- (00000000000413EC) ----------------------------------------------------
void __cdecl IONotificationPortDestroy(IONotificationPortRef notify)
{
  _IONotificationPortDestroy(notify);
}

//----- (00000000000413FC) ----------------------------------------------------
CFRunLoopSourceRef __cdecl IONotificationPortGetRunLoopSource(IONotificationPortRef notify)
{
  return _IONotificationPortGetRunLoopSource(notify);
}

//----- (000000000004140C) ----------------------------------------------------
kern_return_t __cdecl IOObjectRelease(io_object_t object)
{
  return _IOObjectRelease(object);
}

//----- (000000000004141C) ----------------------------------------------------
kern_return_t __cdecl IORegistryEntryCreateCFProperties(
        io_registry_entry_t entry,
        CFMutableDictionaryRef *properties,
        CFAllocatorRef allocator,
        IOOptionBits options)
{
  return _IORegistryEntryCreateCFProperties(entry, properties, allocator, options);
}

//----- (000000000004142C) ----------------------------------------------------
CFTypeRef __cdecl IORegistryEntryCreateCFProperty(
        io_registry_entry_t entry,
        CFStringRef key,
        CFAllocatorRef allocator,
        IOOptionBits options)
{
  return _IORegistryEntryCreateCFProperty(entry, key, allocator, options);
}

//----- (000000000004143C) ----------------------------------------------------
io_registry_entry_t __cdecl IORegistryEntryFromPath(mach_port_t masterPort, const io_string_t path)
{
  return _IORegistryEntryFromPath(masterPort, path);
}

//----- (000000000004144C) ----------------------------------------------------
kern_return_t __cdecl IORegistryEntryGetChildIterator(
        io_registry_entry_t entry,
        const io_name_t plane,
        io_iterator_t *iterator)
{
  return _IORegistryEntryGetChildIterator(entry, plane, iterator);
}

//----- (000000000004145C) ----------------------------------------------------
CFTypeRef __cdecl IORegistryEntrySearchCFProperty(
        io_registry_entry_t entry,
        const io_name_t plane,
        CFStringRef key,
        CFAllocatorRef allocator,
        IOOptionBits options)
{
  return _IORegistryEntrySearchCFProperty(entry, plane, key, allocator, options);
}

//----- (000000000004146C) ----------------------------------------------------
kern_return_t __cdecl IOServiceAddMatchingNotification(
        IONotificationPortRef notifyPort,
        const io_name_t notificationType,
        CFDictionaryRef matching,
        IOServiceMatchingCallback callback,
        void *refCon,
        io_iterator_t *notification)
{
  return _IOServiceAddMatchingNotification(notifyPort, notificationType, matching, callback, refCon, notification);
}

//----- (000000000004147C) ----------------------------------------------------
kern_return_t __cdecl IOServiceClose(io_connect_t connect)
{
  return _IOServiceClose(connect);
}

//----- (000000000004148C) ----------------------------------------------------
io_service_t __cdecl IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching)
{
  return _IOServiceGetMatchingService(masterPort, matching);
}

//----- (000000000004149C) ----------------------------------------------------
CFMutableDictionaryRef __cdecl IOServiceMatching(const char *name)
{
  return _IOServiceMatching(name);
}

//----- (00000000000414AC) ----------------------------------------------------
kern_return_t __cdecl IOServiceOpen(io_service_t service, task_port_t owningTask, uint32_t type, io_connect_t *connect)
{
  return _IOServiceOpen(service, owningTask, type, connect);
}

//----- (00000000000414BC) ----------------------------------------------------
kern_return_t __cdecl IOServiceWaitQuiet(io_service_t service, mach_timespec_t *waitTime)
{
  return _IOServiceWaitQuiet(service, waitTime);
}

//----- (00000000000414CC) ----------------------------------------------------
__int64 _CFProcessPath()
{
  return __CFProcessPath();
}
// 48238: using guessed type __int64 __CFProcessPath(void);

//----- (00000000000414DC) ----------------------------------------------------
__int64 _IOServiceSetAuthorizationID()
{
  return __IOServiceSetAuthorizationID();
}
// 48328: using guessed type __int64 __IOServiceSetAuthorizationID(void);

//----- (00000000000414EC) ----------------------------------------------------
int *__error(void)
{
  return ___error();
}

//----- (000000000004151C) ----------------------------------------------------
__int64 __semwait_signal()
{
  return ___semwait_signal();
}
// 48398: using guessed type __int64 ___semwait_signal(void);

//----- (000000000004154C) ----------------------------------------------------
int __ulock_wait(unsigned int operation, void *addr, unsigned __int64 value, unsigned int timeout)
{
  return ___ulock_wait(operation, addr, value, timeout);
}
// 483B0: using guessed type int ___ulock_wait(unsigned int, void *, unsigned __int64, unsigned int);

//----- (000000000004155C) ----------------------------------------------------
int __ulock_wake(unsigned int operation, void *addr, unsigned __int64 wake_value)
{
  return ___ulock_wake(operation, addr, wake_value);
}
// 483B8: using guessed type int ___ulock_wake(unsigned int, void *, unsigned __int64);

//----- (000000000004156C) ----------------------------------------------------
__int64 _get_cpu_capabilities()
{
  return j___get_cpu_capabilities();
}
// 483C0: using guessed type __int64 j___get_cpu_capabilities(void);

//----- (000000000004157C) ----------------------------------------------------
void *_os_alloc_once(void *slot, size_t size, void *init)
{
  return __os_alloc_once(slot, size, init);
}
// 483C8: using guessed type void *__os_alloc_once(void *slot, size_t size, void *init);

//----- (000000000004158C) ----------------------------------------------------
void __cdecl arc4random_buf(void *__buf, size_t __nbytes)
{
  _arc4random_buf(__buf, __nbytes);
}

//----- (000000000004159C) ----------------------------------------------------
void __cdecl bzero(void *a1, size_t a2)
{
  _bzero(krwCtx, a2);
}

//----- (00000000000415AC) ----------------------------------------------------
void *__cdecl calloc(size_t __count, size_t __size)
{
  return _calloc(__count, __size);
}

//----- (00000000000415BC) ----------------------------------------------------
int __cdecl chown(const char *a1, uid_t a2, gid_t a3)
{
  return _chown(krwCtx, a2, a3);
}

//----- (00000000000415CC) ----------------------------------------------------
int __cdecl close(int a1)
{
  return _close(a1);
}

//----- (00000000000415DC) ----------------------------------------------------
int __cdecl connect(int a1, const sockaddr *a2, socklen_t a3)
{
  return _connect(krwCtx, a2, a3);
}

//----- (00000000000415EC) ----------------------------------------------------
int __cdecl dlclose(void *__handle)
{
  return _dlclose(__handle);
}

//----- (00000000000415FC) ----------------------------------------------------
void *__cdecl dlopen(const char *__path, int __mode)
{
  return _dlopen(__path, __mode);
}

//----- (000000000004160C) ----------------------------------------------------
void *__cdecl dlsym(void *__handle, const char *__symbol)
{
  return _dlsym(__handle, __symbol);
}

//----- (000000000004161C) ----------------------------------------------------
int fcntl(int a1, int a2, ...)
{
  va_list ap;
  int result;

  switch ( a2 )
  {
    case 2:
    case 4:
    case 5:
    case 6:
    case 50:
    case 59:
    case 61:
    case 73:
      va_start(ap, a2);
      result = _fcntl(a1, a2, va_arg(ap, long));
      va_end(ap);
      return result;
    default:
      return _fcntl(a1, a2);
  }
}

//----- (000000000004162C) ----------------------------------------------------
int __cdecl ffsctl(int a1, unsigned __int64 a2, void *a3, unsigned int a4)
{
  return _ffsctl(krwCtx, a2, a3, a4);
}

//----- (000000000004163C) ----------------------------------------------------
int fileport_makefd(mach_port_t port)
{
  return _fileport_makefd(port);
}
// 48428: using guessed type int _fileport_makefd(mach_port_t port);

//----- (000000000004164C) ----------------------------------------------------
// local variable allocation has failed, the output may be wrong!
__int64 __fastcall fileport_makeport(int a1, mach_port_t *a2)
{
  return _fileport_makeport(*(uint64_t *)&a1, a2);
}
// 4164C: variables would overlap: w0.4 and x0.8
// 48430: using guessed type __int64 __fastcall _fileport_makeport(uint64_t, uint64_t);

//----- (000000000004165C) ----------------------------------------------------
void __cdecl free(void *a1)
{
  _free(a1);
}

//----- (000000000004166C) ----------------------------------------------------
int __cdecl fstat(int a1, stat *a2)
{
  return _fstat(krwCtx, a2);
}

//----- (000000000004167C) ----------------------------------------------------
int __cdecl getattrlist(const char *a1, void *a2, void *a3, size_t a4, unsigned int a5)
{
  return _getattrlist(krwCtx, a2, a3, a4, a5);
}

//----- (000000000004168C) ----------------------------------------------------
int __cdecl getmntinfo(struct statfs **a1, int a2)
{
  return _getmntinfo(krwCtx, a2);
}

//----- (000000000004169C) ----------------------------------------------------
pid_t getpid(void)
{
  return _getpid();
}

//----- (00000000000416AC) ----------------------------------------------------
pid_t getppid(void)
{
  return _getppid();
}

//----- (00000000000416BC) ----------------------------------------------------
uid_t getuid(void)
{
  return _getuid();
}

//----- (00000000000416CC) ----------------------------------------------------
kern_return_t __cdecl host_create_mach_voucher(
        host_t host,
        mach_voucher_attr_raw_recipe_array_t recipes,
        mach_msg_type_number_t recipesCnt,
        ipc_voucher_t *voucher)
{
  return _host_create_mach_voucher(host, recipes, recipesCnt, voucher);
}

//----- (00000000000416DC) ----------------------------------------------------
kern_return_t __cdecl host_get_io_master(host_t host, io_master_t *io_master)
{
  return _host_get_io_master(host, io_master);
}

//----- (00000000000416EC) ----------------------------------------------------
kern_return_t __cdecl host_get_special_port(host_priv_t host_priv, int node, int which, mach_port_t *port)
{
  return _host_get_special_port(host_priv, node, which, port);
}

//----- (00000000000416FC) ----------------------------------------------------
kern_return_t __cdecl host_kernel_version(host_t host, kernel_version_t kernel_version)
{
  return _host_kernel_version(host, kernel_version);
}

//----- (000000000004170C) ----------------------------------------------------
kern_return_t __cdecl host_page_size(host_t a1, vm_size_t *a2)
{
  return _host_page_size(krwCtx, a2);
}

//----- (000000000004171C) ----------------------------------------------------
kern_return_t __cdecl host_processors(
        host_priv_t host_priv,
        processor_array_t *out_processor_list,
        mach_msg_type_number_t *out_processor_listCnt)
{
  return _host_processors(host_priv, out_processor_list, out_processor_listCnt);
}

//----- (000000000004172C) ----------------------------------------------------
kern_return_t __cdecl host_security_set_task_token(
        host_security_t host_security,
        task_t target_task,
        security_token_t sec_token,
        audit_token_t *audit_token,
        host_t host)
{
  return _host_security_set_task_token(host_security, target_task, sec_token, audit_token, host);
}

//----- (000000000004173C) ----------------------------------------------------
int ioctl(int a1, unsigned __int64 a2, ...)
{
  va_list ap;
  void *arg;

  va_start(ap, a2);
  arg = va_arg(ap, void *);
  va_end(ap);
  return _ioctl(krwCtx, a2, arg);
}

//----- (000000000004174C) ----------------------------------------------------
int __cdecl lstat(const char *a1, stat *a2)
{
  return _lstat(krwCtx, a2);
}

//----- (000000000004175C) ----------------------------------------------------
uint64_t mach_absolute_time(void)
{
  return _mach_absolute_time();
}

//----- (000000000004176C) ----------------------------------------------------
mach_port_t mach_host_self(void)
{
  return _mach_host_self();
}

//----- (000000000004177C) ----------------------------------------------------
kern_return_t __cdecl mach_make_memory_entry(
        vm_map_t target_task,
        vm_size_t *size,
        vm_offset_t offset,
        vm_prot_t permission,
        mem_entry_name_port_t *object_handle,
        mem_entry_name_port_t parent_entry)
{
  return _mach_make_memory_entry(target_task, size, offset, permission, object_handle, parent_entry);
}

//----- (000000000004178C) ----------------------------------------------------
kern_return_t __cdecl mach_make_memory_entry_64(
        vm_map_t target_task,
        memory_object_size_t *size,
        memory_object_offset_t offset,
        vm_prot_t permission,
        mach_port_t *object_handle,
        mem_entry_name_port_t parent_entry)
{
  return _mach_make_memory_entry_64(target_task, size, offset, permission, object_handle, parent_entry);
}

//----- (000000000004179C) ----------------------------------------------------
mach_msg_return_t __cdecl mach_msg(
        mach_msg_header_t *msg,
        mach_msg_option_t option,
        mach_msg_size_t send_size,
        mach_msg_size_t rcv_size,
        mach_port_name_t rcv_name,
        mach_msg_timeout_t timeout,
        mach_port_name_t notify)
{
  return _mach_msg(msg, option, send_size, rcv_size, rcv_name, timeout, notify);
}

//----- (00000000000417AC) ----------------------------------------------------
void __cdecl mach_msg_destroy(mach_msg_header_t *a1)
{
  _mach_msg_destroy(a1);
}

//----- (00000000000417BC) ----------------------------------------------------
mach_msg_return_t __cdecl mach_msg_send(mach_msg_header_t *a1)
{
  return _mach_msg_send(a1);
}

//----- (00000000000417CC) ----------------------------------------------------
kern_return_t __cdecl mach_port_allocate(ipc_space_t task, mach_port_right_t right, mach_port_name_t *name)
{
  return _mach_port_allocate(task, right, name);
}

//----- (00000000000417DC) ----------------------------------------------------
kern_return_t __cdecl mach_port_deallocate(ipc_space_t task, mach_port_name_t name)
{
  return _mach_port_deallocate(task, name);
}

//----- (00000000000417EC) ----------------------------------------------------
kern_return_t __cdecl mach_port_destroy(ipc_space_t task, mach_port_name_t name)
{
  return _mach_port_destroy(task, name);
}

//----- (00000000000417FC) ----------------------------------------------------
kern_return_t __cdecl mach_port_get_attributes(
        ipc_space_read_t task,
        mach_port_name_t name,
        mach_port_flavor_t flavor,
        mach_port_info_t port_info_out,
        mach_msg_type_number_t *port_info_outCnt)
{
  return _mach_port_get_attributes(task, name, flavor, port_info_out, port_info_outCnt);
}

//----- (000000000004180C) ----------------------------------------------------
kern_return_t __cdecl mach_port_insert_right(
        ipc_space_t task,
        mach_port_name_t name,
        mach_port_t poly,
        mach_msg_type_name_t polyPoly)
{
  return _mach_port_insert_right(task, name, poly, polyPoly);
}

//----- (000000000004181C) ----------------------------------------------------
kern_return_t __cdecl mach_port_mod_refs(
        ipc_space_t task,
        mach_port_name_t name,
        mach_port_right_t right,
        mach_port_delta_t delta)
{
  return _mach_port_mod_refs(task, name, right, delta);
}

//----- (000000000004182C) ----------------------------------------------------
kern_return_t __cdecl mach_port_request_notification(
        ipc_space_t task,
        mach_port_name_t name,
        mach_msg_id_t msgid,
        mach_port_mscount_t sync,
        mach_port_t notify,
        mach_msg_type_name_t notifyPoly,
        mach_port_t *previous)
{
  return _mach_port_request_notification(task, name, msgid, sync, notify, notifyPoly, previous);
}

//----- (000000000004183C) ----------------------------------------------------
kern_return_t __cdecl mach_port_set_attributes(
        ipc_space_t task,
        mach_port_name_t name,
        mach_port_flavor_t flavor,
        mach_port_info_t port_info,
        mach_msg_type_number_t port_infoCnt)
{
  return _mach_port_set_attributes(task, name, flavor, port_info, port_infoCnt);
}

//----- (000000000004184C) ----------------------------------------------------
kern_return_t __cdecl mach_port_space_info(
        ipc_space_read_t space,
        ipc_info_space_t *space_info,
        ipc_info_name_array_t *table_info,
        mach_msg_type_number_t *table_infoCnt,
        ipc_info_tree_name_array_t *tree_info,
        mach_msg_type_number_t *tree_infoCnt)
{
  return _mach_port_space_info(space, space_info, table_info, table_infoCnt, tree_info, tree_infoCnt);
}

//----- (000000000004185C) ----------------------------------------------------
kern_return_t __cdecl mach_ports_register(
        task_t target_task,
        mach_port_array_t init_port_set,
        mach_msg_type_number_t init_port_setCnt)
{
  return _mach_ports_register(target_task, init_port_set, init_port_setCnt);
}

//----- (000000000004186C) ----------------------------------------------------
__int64 mach_reply_port()
{
  return _mach_reply_port();
}
// 48540: using guessed type __int64 _mach_reply_port(void);

//----- (000000000004187C) ----------------------------------------------------
mach_port_t mach_thread_self(void)
{
  return _mach_thread_self();
}

//----- (000000000004188C) ----------------------------------------------------
kern_return_t __cdecl mach_timebase_info(mach_timebase_info_t info)
{
  return _mach_timebase_info(info);
}

//----- (000000000004189C) ----------------------------------------------------
kern_return_t __cdecl mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags)
{
  return _mach_vm_allocate(target, address, size, flags);
}

//----- (00000000000418AC) ----------------------------------------------------
kern_return_t __cdecl mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size)
{
  return _mach_vm_deallocate(target, address, size);
}

//----- (00000000000418BC) ----------------------------------------------------
kern_return_t __cdecl mach_vm_machine_attribute(
        vm_map_t target_task,
        mach_vm_address_t address,
        mach_vm_size_t size,
        vm_machine_attribute_t attribute,
        vm_machine_attribute_val_t *value)
{
  return _mach_vm_machine_attribute(target_task, address, size, attribute, value);
}

//----- (00000000000418CC) ----------------------------------------------------
kern_return_t __cdecl mach_vm_page_info(
        vm_map_read_t target_task,
        mach_vm_address_t address,
        vm_page_info_flavor_t flavor,
        vm_page_info_t info,
        mach_msg_type_number_t *infoCnt)
{
  return _mach_vm_page_info(target_task, address, flavor, info, infoCnt);
}

//----- (00000000000418DC) ----------------------------------------------------
kern_return_t __cdecl mach_vm_read_overwrite(
        vm_map_read_t target_task,
        mach_vm_address_t address,
        mach_vm_size_t size,
        mach_vm_address_t data,
        mach_vm_size_t *outsize)
{
  return _mach_vm_read_overwrite(target_task, address, size, data, outsize);
}

//----- (00000000000418EC) ----------------------------------------------------
kern_return_t __cdecl mach_vm_wire(
        host_priv_t host_priv,
        vm_map_t task,
        mach_vm_address_t address,
        mach_vm_size_t size,
        vm_prot_t desired_access)
{
  return _mach_vm_wire(host_priv, task, address, size, desired_access);
}

//----- (00000000000418FC) ----------------------------------------------------
kern_return_t __cdecl mach_vm_write(
        vm_map_t target_task,
        mach_vm_address_t address,
        vm_offset_t data,
        mach_msg_type_number_t dataCnt)
{
  return _mach_vm_write(target_task, address, data, dataCnt);
}

//----- (000000000004190C) ----------------------------------------------------
int __cdecl madvise(void *a1, size_t a2, int a3)
{
  return _madvise(krwCtx, a2, a3);
}

//----- (000000000004191C) ----------------------------------------------------
void *__cdecl malloc(size_t __size)
{
  return _malloc(__size);
}

//----- (000000000004192C) ----------------------------------------------------
int __cdecl memcmp(const void *__s1, const void *__s2, size_t __n)
{
  return _memcmp(__s1, __s2, __n);
}

//----- (000000000004193C) ----------------------------------------------------
void *__cdecl memcpy(void *__dst, const void *__src, size_t __n)
{
  return _memcpy(__dst, __src, __n);
}

//----- (000000000004194C) ----------------------------------------------------
void __cdecl mig_dealloc_reply_port(mach_port_t reply_port)
{
  _mig_dealloc_reply_port(reply_port);
}

//----- (000000000004195C) ----------------------------------------------------
mach_port_t mig_get_reply_port(void)
{
  return _mig_get_reply_port();
}

//----- (000000000004196C) ----------------------------------------------------
int __cdecl mkdir(const char *a1, mode_t a2)
{
  return _mkdir(krwCtx, a2);
}

//----- (000000000004197C) ----------------------------------------------------
char *__cdecl mktemp(char *a1)
{
  return _mktemp(a1);
}

//----- (000000000004198C) ----------------------------------------------------
void *j_mmap(void *a1, size_t a2, int a3, int a4, int a5, off_t a6)
{
  return _mmap(krwCtx, a2, a3, a4, a5, a6);
}

//----- (000000000004199C) ----------------------------------------------------
int __cdecl mount(const char *a1, const char *a2, int a3, void *a4)
{
  return _mount(krwCtx, a2, a3, a4);
}

//----- (00000000000419AC) ----------------------------------------------------
int necp_client_action(int fd, uint32_t action, const void *client_id, size_t client_id_len, void *buffer, size_t buffer_size)
{
  return _necp_client_action(fd, action, client_id, client_id_len, buffer, buffer_size);
}
// 485E0: using guessed type int _necp_client_action(int fd, uint32_t action, const void *client_id, size_t client_id_len, void *buffer, size_t buffer_size);

//----- (00000000000419BC) ----------------------------------------------------
int necp_open(int flags)
{
  return _necp_open(flags);
}
// 485E8: using guessed type int _necp_open(int flags);

//----- (00000000000419CC) ----------------------------------------------------
int open(const char *a1, int a2, ...)
{
  va_list ap;
  mode_t mode;

  if ( (a2 & 0x200) == 0 )
    return _open(krwCtx, a2);
  va_start(ap, a2);
  mode = (mode_t)va_arg(ap, int);
  va_end(ap);
  return _open(krwCtx, a2, mode);
}

//----- (00000000000419DC) ----------------------------------------------------
int open_dprotected_np(const char *a1, int a2, int a3, int a4, ...)
{
  va_list ap;
  mode_t mode;

  if ( (a2 & 0x200) == 0 )
    return _open_dprotected_np(krwCtx, a2, a3, a4);
  va_start(ap, a4);
  mode = (mode_t)va_arg(ap, int);
  va_end(ap);
  return _open_dprotected_np(krwCtx, a2, a3, a4, mode);
}

//----- (00000000000419EC) ----------------------------------------------------
kern_return_t __cdecl pid_for_task(mach_port_name_t t, int *x)
{
  return _pid_for_task(t, x);
}

//----- (00000000000419FC) ----------------------------------------------------
int __cdecl pipe(int a1[2])
{
  return _pipe(a1);
}

//----- (0000000000041A0C) ----------------------------------------------------
int __cdecl posix_spawn(
        pid_t *a1,
        const char *a2,
        const posix_spawn_file_actions_t *a3,
        const posix_spawnattr_t *a4,
        char *const __argv[],
        char *const __envp[])
{
  return _posix_spawn(krwCtx, a2, a3, a4, __argv, __envp);
}

//----- (0000000000041A1C) ----------------------------------------------------
int __cdecl posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *a1, int a2, const char *a3, int a4, mode_t a5)
{
  return _posix_spawn_file_actions_addopen(krwCtx, a2, a3, a4, a5);
}

//----- (0000000000041A2C) ----------------------------------------------------
int __cdecl posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *a1)
{
  return _posix_spawn_file_actions_destroy(a1);
}

//----- (0000000000041A3C) ----------------------------------------------------
int __cdecl posix_spawn_file_actions_init(posix_spawn_file_actions_t *a1)
{
  return _posix_spawn_file_actions_init(a1);
}

//----- (0000000000041A4C) ----------------------------------------------------
int __cdecl posix_spawnattr_destroy(posix_spawnattr_t *a1)
{
  return _posix_spawnattr_destroy(a1);
}

//----- (0000000000041A5C) ----------------------------------------------------
int __cdecl posix_spawnattr_init(posix_spawnattr_t *a1)
{
  return _posix_spawnattr_init(a1);
}

//----- (0000000000041A6C) ----------------------------------------------------
int __cdecl posix_spawnattr_setflags(posix_spawnattr_t *a1, __int16 a2)
{
  return _posix_spawnattr_setflags(krwCtx, a2);
}

//----- (0000000000041A7C) ----------------------------------------------------
int __cdecl posix_spawnattr_setpgroup(posix_spawnattr_t *a1, pid_t a2)
{
  return _posix_spawnattr_setpgroup(krwCtx, a2);
}

//----- (0000000000041A8C) ----------------------------------------------------
int __cdecl posix_spawnattr_setsigdefault(posix_spawnattr_t *a1, const sigset_t *a2)
{
  return _posix_spawnattr_setsigdefault(krwCtx, a2);
}

//----- (0000000000041A9C) ----------------------------------------------------
ssize_t __cdecl pread(int __fd, void *__buf, size_t __nbyte, off_t a4)
{
  return _pread(__fd, __buf, __nbyte, a4);
}

//----- (0000000000041AAC) ----------------------------------------------------
int __cdecl proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize)
{
  return _proc_pidinfo(pid, flavor, arg, buffer, buffersize);
}

//----- (0000000000041ABC) ----------------------------------------------------
kern_return_t __cdecl processor_set_default(host_t host, processor_set_name_t *default_set)
{
  return _processor_set_default(host, default_set);
}

//----- (0000000000041ACC) ----------------------------------------------------
kern_return_t __cdecl processor_set_info(
        processor_set_name_t set_name,
        int flavor,
        host_t *host,
        processor_set_info_t info_out,
        mach_msg_type_number_t *info_outCnt)
{
  return _processor_set_info(set_name, flavor, host, info_out, info_outCnt);
}

//----- (0000000000041ADC) ----------------------------------------------------
int __cdecl pthread_attr_destroy(pthread_attr_t *a1)
{
  return _pthread_attr_destroy(a1);
}

//----- (0000000000041AEC) ----------------------------------------------------
int __cdecl pthread_attr_init(pthread_attr_t *a1)
{
  return _pthread_attr_init(a1);
}

//----- (0000000000041AFC) ----------------------------------------------------
int __cdecl pthread_attr_setdetachstate(pthread_attr_t *a1, int a2)
{
  return _pthread_attr_setdetachstate(krwCtx, a2);
}

//----- (0000000000041B0C) ----------------------------------------------------
int __cdecl pthread_create(pthread_t *a1, const pthread_attr_t *a2, void *(__cdecl *a3)(void *), void *a4)
{
  return _pthread_create(krwCtx, a2, a3, a4);
}

//----- (0000000000041B1C) ----------------------------------------------------
int __cdecl pthread_create_suspended_np(pthread_t *a1, const pthread_attr_t *a2, void *(__cdecl *a3)(void *), void *a4)
{
  return _pthread_create_suspended_np(krwCtx, a2, a3, a4);
}

//----- (0000000000041B2C) ----------------------------------------------------
pthread_t __cdecl pthread_from_mach_thread_np(mach_port_t a1)
{
  return _pthread_from_mach_thread_np(a1);
}

//----- (0000000000041B3C) ----------------------------------------------------
int __cdecl pthread_join(pthread_t a1, void **a2)
{
  return _pthread_join(krwCtx, a2);
}

//----- (0000000000041B4C) ----------------------------------------------------
mach_port_t __cdecl pthread_mach_thread_np(pthread_t a1)
{
  return _pthread_mach_thread_np(a1);
}

//----- (0000000000041B5C) ----------------------------------------------------
int __cdecl pthread_mutex_destroy(pthread_mutex_t *a1)
{
  return _pthread_mutex_destroy(a1);
}

//----- (0000000000041B6C) ----------------------------------------------------
int __cdecl pthread_mutex_init(pthread_mutex_t *a1, const pthread_mutexattr_t *a2)
{
  return _pthread_mutex_init(krwCtx, a2);
}

//----- (0000000000041B7C) ----------------------------------------------------
int __cdecl pthread_mutex_lock(pthread_mutex_t *a1)
{
  return _pthread_mutex_lock(a1);
}

//----- (0000000000041B8C) ----------------------------------------------------
int __cdecl pthread_mutex_unlock(pthread_mutex_t *a1)
{
  return _pthread_mutex_unlock(a1);
}

//----- (0000000000041B9C) ----------------------------------------------------
pthread_t pthread_self(void)
{
  return _pthread_self();
}

//----- (0000000000041BAC) ----------------------------------------------------
void __cdecl qsort(void *__base, size_t __nel, size_t __width, int (__cdecl *__compar)(const void *, const void *))
{
  _qsort(__base, __nel, __width, __compar);
}

//----- (0000000000041BBC) ----------------------------------------------------
ssize_t __cdecl read(int a1, void *a2, size_t a3)
{
  return _read(krwCtx, a2, a3);
}

//----- (0000000000041BCC) ----------------------------------------------------
void *__cdecl realloc(void *__ptr, size_t __size)
{
  return _realloc(__ptr, __size);
}

//----- (0000000000041BDC) ----------------------------------------------------
int __cdecl rmdir(const char *a1)
{
  return _rmdir(a1);
}

//----- (0000000000041BFC) ----------------------------------------------------
int sched_yield(void)
{
  return _sched_yield();
}

//----- (0000000000041C0C) ----------------------------------------------------
kern_return_t __cdecl semaphore_create(task_t task, semaphore_t *semaphore, int policy, int value)
{
  return _semaphore_create(task, semaphore, policy, value);
}

//----- (0000000000041C1C) ----------------------------------------------------
kern_return_t __cdecl semaphore_destroy(task_t task, semaphore_t semaphore)
{
  return _semaphore_destroy(task, semaphore);
}

//----- (0000000000041C2C) ----------------------------------------------------
kern_return_t __cdecl semaphore_signal(semaphore_t semaphore)
{
  return _semaphore_signal(semaphore);
}

//----- (0000000000041C3C) ----------------------------------------------------
kern_return_t __cdecl semaphore_timedwait(semaphore_t semaphore, mach_timespec_t wait_time)
{
  return _semaphore_timedwait(semaphore, wait_time);
}

//----- (0000000000041C4C) ----------------------------------------------------
kern_return_t __cdecl semaphore_wait(semaphore_t semaphore)
{
  return _semaphore_wait(semaphore);
}

//----- (0000000000041C5C) ----------------------------------------------------
int __cdecl seteuid(uid_t a1)
{
  return _seteuid(a1);
}

//----- (0000000000041C6C) ----------------------------------------------------
int __cdecl setsockopt(int a1, int a2, int a3, const void *a4, socklen_t a5)
{
  return _setsockopt(krwCtx, a2, a3, a4, a5);
}

//----- (0000000000041C7C) ----------------------------------------------------
int snprintf(char *__str, size_t __size, const char *__format, ...)
{
  va_list ap;
  int result;

  va_start(ap, __format);
  result = vsnprintf(__str, __size, __format, ap);
  va_end(ap);
  return result;
}

//----- (0000000000041C8C) ----------------------------------------------------
int __cdecl socket(int a1, int a2, int a3)
{
  return _socket(krwCtx, a2, a3);
}

//----- (0000000000041CAC) ----------------------------------------------------
int __cdecl stat(const char *a1, stat *a2)
{
  return _stat(krwCtx, a2);
}

//----- (0000000000041CBC) ----------------------------------------------------
int __cdecl statfs(const char *a1, struct statfs *a2)
{
  return _statfs(krwCtx, a2);
}

//----- (0000000000041CCC) ----------------------------------------------------
char *__cdecl strchr(const char *__s, int __c)
{
  return _strchr(__s, __c);
}

//----- (0000000000041CDC) ----------------------------------------------------
int __cdecl strcmp(const char *__s1, const char *__s2)
{
  return _strcmp(__s1, __s2);
}

//----- (0000000000041CEC) ----------------------------------------------------
char *__cdecl strcpy(char *__dst, const char *__src)
{
  return _strcpy(__dst, __src);
}

//----- (0000000000041CFC) ----------------------------------------------------
char *__cdecl strdup(const char *__s1)
{
  return _strdup(__s1);
}

//----- (0000000000041D0C) ----------------------------------------------------
size_t __cdecl strlcpy(char *__dst, const char *__source, size_t __size)
{
  return _strlcpy(__dst, __source, __size);
}

//----- (0000000000041D1C) ----------------------------------------------------
size_t __cdecl strlen(const char *__s)
{
  return _strlen(__s);
}

//----- (0000000000041D2C) ----------------------------------------------------
int __cdecl strncmp(const char *__s1, const char *__s2, size_t __n)
{
  return _strncmp(__s1, __s2, __n);
}

//----- (0000000000041D3C) ----------------------------------------------------
char *__cdecl strsep(char **__stringp, const char *__delim)
{
  return _strsep(__stringp, __delim);
}

//----- (0000000000041D4C) ----------------------------------------------------
char *__cdecl strstr(const char *__big, const char *__little)
{
  return _strstr(__big, __little);
}

//----- (0000000000041D5C) ----------------------------------------------------
__int64 __cdecl strtol(const char *__str, char **__endptr, int __base)
{
  return _strtol(__str, __endptr, __base);
}

//----- (0000000000041D6C) ----------------------------------------------------
int syscall(int a1, ...)
{
  va_list ap;
  __int64 a2;
  __int64 a3;
  __int64 a4;
  __int64 a5;
  __int64 a6;
  __int64 a7;

  va_start(ap, a1);
  a2 = va_arg(ap, __int64);
  a3 = va_arg(ap, __int64);
  a4 = va_arg(ap, __int64);
  a5 = va_arg(ap, __int64);
  a6 = va_arg(ap, __int64);
  a7 = va_arg(ap, __int64);
  va_end(ap);
  return _syscall(krwCtx, a2, a3, a4, a5, a6, a7);
}

//----- (0000000000041D7C) ----------------------------------------------------
int __cdecl sysctl(int *a1, u_int a2, void *a3, size_t *a4, void *a5, size_t a6)
{
  return _sysctl(krwCtx, a2, a3, a4, a5, a6);
}

//----- (0000000000041D8C) ----------------------------------------------------
int __cdecl sysctlbyname(const char *a1, void *a2, size_t *a3, void *a4, size_t a5)
{
  return _sysctlbyname(krwCtx, a2, a3, a4, a5);
}

//----- (0000000000041D9C) ----------------------------------------------------
kern_return_t __cdecl task_get_special_port(task_inspect_t task, int which_port, mach_port_t *special_port)
{
  return _task_get_special_port(task, which_port, special_port);
}

//----- (0000000000041DAC) ----------------------------------------------------
kern_return_t __cdecl task_info(
        task_name_t target_task,
        task_flavor_t flavor,
        task_info_t task_info_out,
        mach_msg_type_number_t *task_info_outCnt)
{
  return _task_info(target_task, flavor, task_info_out, task_info_outCnt);
}

//----- (0000000000041DBC) ----------------------------------------------------
kern_return_t __cdecl task_map_corpse_info_64(
        task_t task,
        task_read_t corspe_task,
        mach_vm_address_t *kcd_addr_begin,
        mach_vm_size_t *kcd_size)
{
  return _task_map_corpse_info_64(task, corspe_task, kcd_addr_begin, kcd_size);
}

//----- (0000000000041DCC) ----------------------------------------------------
kern_return_t __cdecl task_resume2(task_suspension_token_t suspend_token)
{
  return _task_resume2(suspend_token);
}

//----- (0000000000041DDC) ----------------------------------------------------
kern_return_t __cdecl task_set_special_port(task_t task, int which_port, mach_port_t special_port)
{
  return _task_set_special_port(task, which_port, special_port);
}

//----- (0000000000041DEC) ----------------------------------------------------
kern_return_t __cdecl task_suspend2(task_t target_task, task_suspension_token_t *suspend_token)
{
  return _task_suspend2(target_task, suspend_token);
}

//----- (0000000000041DFC) ----------------------------------------------------
kern_return_t __cdecl task_threads(
        task_inspect_t target_task,
        thread_act_array_t *act_list,
        mach_msg_type_number_t *act_listCnt)
{
  return _task_threads(target_task, act_list, act_listCnt);
}

//----- (0000000000041E0C) ----------------------------------------------------
kern_return_t __cdecl thread_create(task_t parent_task, thread_act_t *child_act)
{
  return _thread_create(parent_task, child_act);
}

//----- (0000000000041E1C) ----------------------------------------------------
kern_return_t __cdecl thread_get_state(
        thread_read_t target_act,
        thread_state_flavor_t flavor,
        thread_state_t old_state,
        mach_msg_type_number_t *old_stateCnt)
{
  return _thread_get_state(target_act, flavor, old_state, old_stateCnt);
}

//----- (0000000000041E2C) ----------------------------------------------------
kern_return_t __cdecl thread_policy_set(
        thread_act_t thread,
        thread_policy_flavor_t flavor,
        thread_policy_t policy_info,
        mach_msg_type_number_t policy_infoCnt)
{
  return _thread_policy_set(thread, flavor, policy_info, policy_infoCnt);
}

//----- (0000000000041E3C) ----------------------------------------------------
kern_return_t __cdecl thread_resume(thread_act_t target_act)
{
  return _thread_resume(target_act);
}

//----- (0000000000041E4C) ----------------------------------------------------
kern_return_t __cdecl thread_set_exception_ports(
        thread_act_t thread,
        exception_mask_t exception_mask,
        mach_port_t new_port,
        exception_behavior_t behavior,
        thread_state_flavor_t new_flavor)
{
  return _thread_set_exception_ports(thread, exception_mask, new_port, behavior, new_flavor);
}

//----- (0000000000041E5C) ----------------------------------------------------
kern_return_t __cdecl thread_set_state(
        thread_act_t target_act,
        thread_state_flavor_t flavor,
        thread_state_t new_state,
        mach_msg_type_number_t new_stateCnt)
{
  return _thread_set_state(target_act, flavor, new_state, new_stateCnt);
}

//----- (0000000000041E6C) ----------------------------------------------------
kern_return_t __cdecl thread_suspend(thread_act_t target_act)
{
  return _thread_suspend(target_act);
}

//----- (0000000000041E7C) ----------------------------------------------------
kern_return_t __cdecl thread_switch(mach_port_name_t thread_name, int option, mach_msg_timeout_t option_time)
{
  return _thread_switch(thread_name, option, option_time);
}

//----- (0000000000041E8C) ----------------------------------------------------
kern_return_t __cdecl thread_terminate(thread_act_t target_act)
{
  return _thread_terminate(target_act);
}

//----- (0000000000041E9C) ----------------------------------------------------
int __cdecl uname(utsname *a1)
{
  return _uname(a1);
}

//----- (0000000000041EAC) ----------------------------------------------------
int __cdecl unlink(const char *a1)
{
  return _unlink(a1);
}

//----- (0000000000041EBC) ----------------------------------------------------
int __cdecl unmount(const char *a1, int a2)
{
  return _unmount(krwCtx, a2);
}

//----- (0000000000041ECC) ----------------------------------------------------
int __cdecl usleep(useconds_t a1)
{
  return _usleep(a1);
}

//----- (0000000000041EDC) ----------------------------------------------------
int __cdecl uuid_is_null(const uuid_t uu)
{
  return _uuid_is_null(uu);
}

//----- (0000000000041EEC) ----------------------------------------------------
kern_return_t __cdecl vm_allocate(vm_map_t target_task, vm_address_t *address, vm_size_t size, int flags)
{
  return _vm_allocate(target_task, address, size, flags);
}

//----- (0000000000041EFC) ----------------------------------------------------
kern_return_t __cdecl vm_copy(
        vm_map_t target_task,
        vm_address_t source_address,
        vm_size_t size,
        vm_address_t dest_address)
{
  return _vm_copy(target_task, source_address, size, dest_address);
}

//----- (0000000000041F0C) ----------------------------------------------------
kern_return_t __cdecl vm_deallocate(vm_map_t target_task, vm_address_t address, vm_size_t size)
{
  return _vm_deallocate(target_task, address, size);
}

//----- (0000000000041F1C) ----------------------------------------------------
kern_return_t __cdecl vm_map(
        vm_map_t target_task,
        vm_address_t *address,
        vm_size_t size,
        vm_address_t mask,
        int flags,
        mem_entry_name_port_t object,
        vm_offset_t offset,
        boolean_t copy,
        vm_prot_t cur_protection,
        vm_prot_t max_protection,
        vm_inherit_t inheritance)
{
  return _vm_map(
           target_task,
           address,
           size,
           mask,
           flags,
           object,
           offset,
           copy,
           cur_protection,
           max_protection,
           inheritance);
}

//----- (0000000000041F2C) ----------------------------------------------------
kern_return_t __cdecl vm_protect(
        vm_map_t target_task,
        vm_address_t address,
        vm_size_t size,
        boolean_t set_maximum,
        vm_prot_t new_protection)
{
  return _vm_protect(target_task, address, size, set_maximum, new_protection);
}

//----- (0000000000041F3C) ----------------------------------------------------
kern_return_t __cdecl vm_read_overwrite(
        vm_map_t target_task,
        vm_address_t address,
        vm_size_t size,
        vm_address_t data,
        vm_size_t *outsize)
{
  return _vm_read_overwrite(target_task, address, size, data, outsize);
}

//----- (0000000000041F4C) ----------------------------------------------------
kern_return_t __cdecl vm_region_64(
        vm_map_t target_task,
        vm_address_t *address,
        vm_size_t *size,
        vm_region_flavor_t flavor,
        vm_region_info_t info,
        mach_msg_type_number_t *infoCnt,
        mach_port_t *object_name)
{
  return _vm_region_64(target_task, address, size, flavor, info, infoCnt, object_name);
}

//----- (0000000000041F5C) ----------------------------------------------------
kern_return_t __cdecl vm_region_recurse_64(
        vm_map_t target_task,
        vm_address_t *address,
        vm_size_t *size,
        natural_t *nesting_depth,
        vm_region_recurse_info_t info,
        mach_msg_type_number_t *infoCnt)
{
  return _vm_region_recurse_64(target_task, address, size, nesting_depth, info, infoCnt);
}

//----- (0000000000041F6C) ----------------------------------------------------
kern_return_t __cdecl vm_remap(
        vm_map_t target_task,
        vm_address_t *target_address,
        vm_size_t size,
        vm_address_t mask,
        int flags,
        vm_map_t src_task,
        vm_address_t src_address,
        boolean_t copy,
        vm_prot_t *cur_protection,
        vm_prot_t *max_protection,
        vm_inherit_t inheritance)
{
  return _vm_remap(
           target_task,
           target_address,
           size,
           mask,
           flags,
           src_task,
           src_address,
           copy,
           cur_protection,
           max_protection,
           inheritance);
}

//----- (0000000000041F7C) ----------------------------------------------------
kern_return_t __cdecl vm_write(
        vm_map_t target_task,
        vm_address_t address,
        vm_offset_t data,
        mach_msg_type_number_t dataCnt)
{
  return _vm_write(target_task, address, data, dataCnt);
}

//----- (0000000000041F8C) ----------------------------------------------------
pid_t __cdecl waitpid(pid_t a1, int *a2, int a3)
{
  return _waitpid(krwCtx, a2, a3);
}

//----- (0000000000041F9C) ----------------------------------------------------
ssize_t __cdecl write(int __fd, const void *__buf, size_t __nbyte)
{
  return _write(__fd, __buf, __nbyte);
}
#endif

