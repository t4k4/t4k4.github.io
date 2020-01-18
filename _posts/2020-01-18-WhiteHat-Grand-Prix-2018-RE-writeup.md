---
layout:     post
title:      WhiteHat 2018 WP
date:       2020-01-18 16:27:34
summary:    WhiteHat 2018 WP.
categories: RE
thumbnail: RE
tags:
 - CTF
 - reverse engineering
 - WriteUp
---

[TOC]

#### re01

> No hint.

> WriteUp: This challenge is pretty straight forward asks for a key and gives us a flag.


直接运行WhiteHat.exe，没有任何提示
于是丢到OD里，对`GetWindowTextA`下断，可以找到函数`sub_40199B`：

```c++
void sub_40199B()
{
  int v0; // eax@1
  int v1; // eax@2
  int v2; // [sp+8h] [bp-11Ch]@1
  char v3; // [sp+Ch] [bp-118h]@1
  char v4; // [sp+Dh] [bp-117h]@1
  int v5; // [sp+120h] [bp-4h]@1

  v0 = sub_406250();
  unknown_libname_52(v0);
  v5 = 0;
  v3 = 0;
  memset(&v4, 0, 0xF9u);
  CWnd::GetWindowTextA(&v2);                    // bp here
  if ( *(_DWORD *)(v2 - 12) == 16 )             // string length is 16
  {
    v1 = ATL::CSimpleStringT<char,0>::GetBuffer(&v2);// v1指向输入字符串
    sub_40138F(v1, &v3);                        // 如果字符串长度等于16，则进入字符串处理函数sub_40138F
  }
  ATL::CStringData::Release((ATL::CStringData *)(v2 - 16));
}
```
根据函数`sub_40138F`可以得到正确的输入:
```c++
signed int __fastcall sub_40138F(int a1, int a2)
{
  unsigned __int8 v27[16] = {0x83u,0xF9u,0x81u,0xE8u,0x87u,0xE9u,0x85u,0xAAu,
        0x8Bu,0xFAu,0x8Eu,0xC4u,0x8Du,0xF3u,0x93u,0xF2u}; // [sp+4Ch] [bp-14h]@1

  v2 = a1;
  input = a1;
  v3 = a2;

  GetNativeSystemInfo(&SystemInfo);
  GetLocalTime(&SystemTime);                    // SystemTime: Sat. 8.18.2018
  GetLocaleInfoA(0x400u, 0x20001009u, &LCData, 4);
  v4 = 11;
  while ( *(_BYTE *)(v2 + v4) == 'K' )          // input[11] == 'K'
  {                                             // 实际上只有一次循环
    v4 += 7;
    v26 = v4;
    if ( v4 >= 16 )
    {
      *(_DWORD *)v3 = byte_438A0C[0];
      *(_DWORD *)(v3 + 4) = byte_438A0C[1];
      *(_DWORD *)(v3 + 8) = byte_438A0C[2];
      *(_DWORD *)(v3 + 12) = byte_438A0C[3];
      *(_BYTE *)(v3 + 16) = byte_438A0C[4];     // v3 = "abcdefghiklmopqx"
      v5 = input;
      v6 = (_BYTE *)(v3 + 1);
      v7 = input - v3;                          // v7为两个字符串(v3和input)地址的差值
                                                // index based on v7, 实际上是input
      v8 = 8;
      do
      {
        *v6 ^= v6[v7];
        v6 += 2;
        --v8;
      }
      while ( v8 );                             // 两个字符为一组，将v3每组第二个字符与input每组第二个字符异或
      v9 = (_BYTE *)v3;
      v10 = 16;
      do
      {
        v9[v7] = LOBYTE(SystemTime.wDay) ^ (*v9 + v9[v7]);// 
                                                // input[i] = LOBYTE(SystemTime.wDay) ^ (v3[i] + input[i]);
                                                // or 
                                                // input[i] = 0x12 ^ (v3[i] + input[i]);
        *v9++ ^= LOBYTE(SystemTime.wYear);      // 
                                                // v3[i] ^= LOBYTE(SystemTime.wYear);
                                                // or 
                                                // v3[i] ^= 0xe2;
        --v10;                                  // ++i;
      }
      while ( v10 );                            // while(i<16)
      *(_BYTE *)(v5 + 16) += LOBYTE(SystemTime.wDayOfWeek);// 
                                                // input[16] += LOBYTE(SystemTime.wDayOfWeek)
                                                // or 
                                                // input[16] += 0x6
      i = 0;
      while ( *(&v27[i] + v3 - (signed int)v27) == v27[i] )// 字符判断: v27[i] == v3[i]
      {
        if ( ++i >= 16 )                        // length: 16
        {
          v12 = 0;
          do
          {
            v26 += *(_BYTE *)(v3 + v12);
            v12 += 4;
          }
          while ( v12 < 16 );
          v13 = FindResourceA(0, (LPCSTR)0x86, "EXE");// a HTML document
          GetLastError();
          v14 = LoadResource(0, v13);
          v15 = LockResource(v14);
          v16 = SizeofResource(0, v13);
          v17 = v16;
          v18 = sub_4010FC(v16);                // 使(v16+x)能被3整除(x取0, 1, 2)
                                                // 返回(v16+x)*4/3
          v19 = malloc(v18 + 50);
          v20 = v19;
          if ( !v19 || (sub_401000(v19, (int)v15, v17), (result = sub_40111D(v26 / 2 + v20[350000] + 192)) != 0) )// 
                                                // sub_401000: 输入无关(?)
                                                // 以上这段都可以忽略，重点是函数sub_40111D
                                                // bp here
            result = 1;
          return result;
        }
      }
      return 0;
    }
  }
  return 0;
}
```
脚本：
```python
sec = [0x83,0xF9,0x81,0xE8,0x87,0xE9,0x85,0xAA,0x8B,0xFA,0x8E,0xC4,0x8D,0xF3,0x93,0xF2]
v3 = [ord(c) for c in "abcdefghiklmopqx"]

'''original:

input_str = [ord(c) for c in "asdfasfdasdfasdf"]
for i in range(1, len(v3), 2):
    v3[i] ^= input_str[i]

for i in range(16):
    input_str[i] = (v3[i] + input_str[i]) ^ 0x12
    v3[i] ^= 0xe2
'''

for i in range(len(sec)):
    sec[i] ^= 0xe2
for i in range(1, len(sec), 2):
    sec[i] ^= v3[i]
print(''.join([chr(c) for c in sec]))
```
可以得到key： `aycnemg islKoaqh` (**比赛时做到了这一步**)

> WriteUp: After entering the correct key. The executable drop two files named 2.exe and b.dll in %temp% folder (sub_40111D) and runs the 2.exe using CreateProcessA with "564" as CLA(command line arguments).
> After analyzing 2.exe we see that it checks for the parent process ID and must be named to "WhiteHat" if this so it drops the flag.dll in %temp% folder.
> But wait this flag.dll is not actually a PE file. By seeing it's header we get that it is an PNG file. By changing the extension to .png we get our flag.

函数`sub_40111D`:
```c++
signed int __stdcall sub_40111D(int a1)
{
  HGLOBAL v1; // eax@1
  HRSRC v2; // eax@1
  HRSRC v3; // esi@1
  HGLOBAL v4; // eax@1
  const void *v5; // edi@1
  HANDLE v6; // esi@1
  signed int v7; // ecx@1
  signed int v8; // eax@3
  struct _STARTUPINFOA StartupInfo; // [sp+Ch] [bp-80h]@5
  DWORD v11; // [sp+50h] [bp-3Ch]@1
  DWORD NumberOfBytesWritten; // [sp+54h] [bp-38h]@1
  struct _PROCESS_INFORMATION ProcessInformation; // [sp+58h] [bp-34h]@5
  LPCVOID lpBuffer; // [sp+68h] [bp-24h]@1
  HANDLE hObject; // [sp+6Ch] [bp-20h]@1
  HRSRC hResInfo; // [sp+70h] [bp-1Ch]@1
  char v17; // [sp+74h] [bp-18h]@1
  char v18; // [sp+75h] [bp-17h]@1
  char v19; // [sp+98h] [bp+Ch]@1
  CHAR Buffer; // [sp+178h] [bp+ECh]@1
  char v21; // [sp+179h] [bp+EDh]@1
  CHAR FileName; // [sp+27Ch] [bp+1F0h]@1
  char v23; // [sp+27Dh] [bp+1F1h]@1
  CHAR CommandLine; // [sp+380h] [bp+2F4h]@5
  char v25; // [sp+381h] [bp+2F5h]@5
  int v26; // [sp+3E4h] [bp+358h]@3
  int v27; // [sp+3E8h] [bp+35Ch]@3
  int v28; // [sp+3ECh] [bp+360h]@3

  Buffer = 0;
  memset(&v21, 0, 0x103u);
  FileName = 0;
  memset(&v23, 0, 0x103u);
  memset(&v18, 0, 0x103u);
  GetTempPathA(0x104u, &Buffer);
  GetTempPathA(0x104u, &FileName);
  strcat_s(&Buffer, 0x104u, "b.dll"); // 文件路径
  strcat_s(&FileName, 0x104u, "2.exe"); // 文件路径
  hResInfo = FindResourceA(0, (LPCSTR)0x8D, "SYS");
  GetLastError();
  v1 = LoadResource(0, hResInfo);
  lpBuffer = LockResource(v1);
  hResInfo = (HRSRC)SizeofResource(0, hResInfo);
  hObject = CreateFileA(&FileName, 0x10000000u, 1u, 0, 2u, 0x80u, 0);// create file %TEMP%\2.exe
  WriteFile(hObject, lpBuffer, (DWORD)hResInfo, &NumberOfBytesWritten, 0);
  CloseHandle(hObject);
  v2 = FindResourceA(0, (LPCSTR)0x8E, "SYS");
  v3 = v2;
  v4 = LoadResource(0, v2);
  v5 = LockResource(v4);
  hObject = (HANDLE)SizeofResource(0, v3);
  v6 = CreateFileA(&Buffer, 0x10000000u, 1u, 0, 2u, 0x80u, 0);// create file %TEMP%\b.dll
  WriteFile(v6, v5, (DWORD)hObject, &v11, 0);
  CloseHandle(v6);
  qmemcpy(&v17, "qa\"apgcvg\"Rv\"v{rg?\"dkngq{q\"`klRcvj?\"", 0x24u);
  v7 = 0;
  v19 = aQaApgcvgRvVRg_[36];
  do
  {
    *(&v17 + v7) ^= a1 - 48;
    ++v7;
  }
  while ( v7 < 36 );
  v26 = *(_DWORD *)"p`#pwbqw#Sw";
  v27 = *(_DWORD *)"wbqw#Sw";
  v8 = 0;
  v28 = *(_DWORD *)"#Sw";
  do
    *((_BYTE *)&v26 + v8++) ^= (_BYTE)a1 - 47;
  while ( v8 < 11 );
  CommandLine = 0;
  memset(&v25, 0, 0x63u);
  sprintf(&CommandLine, "%d", a1);
  memset(&StartupInfo, 0, 0x44u);
  StartupInfo.cb = 68;
  if ( CreateProcessA(&FileName, &CommandLine, 0, 0, 0, 0, 0, 0, &StartupInfo, &ProcessInformation) ) // run 2.exe with CommandLine as argument, which is "564"(dumped) according to function sub_40128F
  {
    WaitForSingleObject(ProcessInformation.hProcess, 0xFFFFFFFF);
    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
    DeleteFileA(&Buffer);
    DeleteFileA(&FileName);
  }
  return 1;
}
```

最终在%TEMP%文件夹下可以得到三个文件：`b.dll`，`a.exe`，`flag.dll`。
`file`查看flag.dll文件头，可以发现是个PNG文件。
```shell
$ file flag.dll
flag.dll: PNG image data, 560 x 217, 8-bit/color RGB, non-interlaced
```
更改扩展名，打开图片即可看到flag:
`flag is: today is good day`

---
#### re03 - 380p
> No hint.

直接运行`DebugMe.exe`，发现是输入key然后进行验证。
用OD对`GetWindowText`下断，断在函数`sub_40BFA9`，查看对该函数的引用，可以发现程序大致流程如下：
```shell
+-----+     +------------+     +----------------+      +----------------+
| ... | --> | sub_4029C0 | --> |   sub_40BFA9   | ---> | GetWindowTextW |
+-----+     +------------+     +----------------+  |   +----------------+
              |                                    |
              | validate                           |
              v                                    v
            +------------+             +----------------------+
            | sub_402BB0 |             | GetWindowTextLengthW |
            +------------+             +----------------------+
```

`sub_4029C0`:
```c
int __thiscall sub_4029C0(void *this)
{
  v1 = (const unsigned __int16 *)this;
  v13 = 0;
  sub_404C10(&v13, &word_5AAA50);
  v14 = 0;
  sub_40BFA9((int)(v1 + 0xAC), (int)&v13);      // read window text to v13
  v2 = v13;
  v3 = &word_5AAA50;
  while ( 1 )
  {
    v4 = *v2 < *v3;
    if ( *v2 != *v3 )
      break;
    if ( !*v2 )
      goto LABEL_6;
    v5 = v2[1];
    v4 = v5 < v3[1];
    if ( v5 != v3[1] )
      break;
    v2 += 2;
    v3 += 2;
    if ( !v5 )
    {
LABEL_6:
      v6 = 0;
      goto LABEL_8;
    }
  }
  v6 = -v4 | 1;
LABEL_8:
  if ( v6 == 0 )
  {
    MessageBoxW(0, L"Key is empty!", L"Notify", 0);
  }
  else
  {
    v11 = (int)v3;
    v12 = &v11;
    strcpy(&v11, (int *)&v13);
    if ( sub_402BB0(v1, v7, v11) ) // 显然，该函数为验证函数, v11为输入字符串
      MessageBoxW(0, L"Success: Key is correct!", L"Notify", 0x40u);
    else
      MessageBoxW(0, L"Key is NOT correct!", L"Notify", 0x10u);
  }
  v14 = -1;
  v8 = v13 - 8;
  result = _InterlockedDecrement((volatile signed __int32 *)v13 - 1);
  if ( result <= 0 )
  {
    v10 = *(_DWORD *)v8;
    v11 = (int)v8;
    result = (*(int (__stdcall **)(OLECHAR *))(*(_DWORD *)v10 + 4))(v8);
  }
  return result;
}
```

`sub_402BB0`:
```c
signed int __fastcall sub_402BB0(const unsigned __int16 *a1, int a2, int input)
{
  v82 = (unsigned __int16 *)a1;
  v91 = 0;
  v3 = *(_DWORD *)(input - 12); // input length
  if ( v3 < 10 )  goto fail1;
  if ( v3 <= 10 )  goto LABEL_7;
  strcpy(&v81, &input);         // strcpy
  sub_404010(&sub1, (int)v81);  // 字符串处理
                                // 将"dvfrhtgbPr"的前9位替换为v81前9位对应位置值+3
                                // 伪：
                                // string = "dvfrhtgbPr"
                                // string[i] = v81[i] + 3 for i in range(9)
  strcpy(&v81, (int *)&sub1);   // strcpy
  sub_404010(&sub2, (int)v81);  // 字符串处理，将上一步得到的sub1字符串做相同的处理
                                // 或者说，这两步操作等价于：（伪）
                                // string = "dvfrhtgbPr"
                                // string[i] = v81[i] + 6 for i in range(9)
  a1 = (const unsigned __int16 *)wcscmp(sub2, L"wiergrrrrrrfwefi");
  /* ... */
  if ( !a1 )                    // ******* fail if equal *******
  {
fail7:
    /* ... */
    goto fail1;
  }
LABEL_15:
  /* ... */
  while ( 1 )
  {
    while ( v3 >= 55 ); // 字符串长度>=55, 直接陷入死循环
    strcpy(&v81, &input);
    sub_404010(&sub1, (int)v81); // string = "dvfrhtgbPr"
                                 // string[i] = v81[i] + 3 for i in range(9)
    strcpy(&v81, &input);
    sub_404100(&sub2, (int)v81); // string = "dvfrhtgbPr"
                                 // string[i] = v81[i+10] for i in range(9)
    strcpy(&v81, &input);
    sub_404200(&sub3, (int)v81); // string = "rfdeswe32f"
                                 // string[i] = v81[i+20] for i in range(9)
    v3 += 50;                    
    v14 = wcscmp(sub2, L"wiergrrrrrrfwefi");
    if ( !v14 ) goto fail2;      // ******* fail if equal *******
    a1 = sub1;
    v15 = L"efffffe3f";
    while ( 1 ) // 这里是一个字符串比较
    {
      v16 = *a1 < *v15;
      if ( *a1 != *v15 )
        break;
      if ( !*a1 )
        goto fail5;
      v17 = a1[1];
      v16 = v17 < v15[1];
      if ( v17 != v15[1] )
        break;
      a1 += 2;
      v15 += 2;
      if ( !v17 )
      {
fail5:
        v18 = 0;
        goto fail4;
      }
    }
    v18 = -v16 | 1;
fail4:
    if ( v18 == 0 )
    {
fail2:
      /* ... */
fail3:
      /* ... */
      goto fail7;
    }
    /* ... */
    if ( v3 != 100 )
      break;
LABEL_7:
    if ( (unsigned int)(v3 - 2) <= 52 )
    {
      strcpy(&v81, &input);
      sub_404010(&sub1, (int)v81);
      strcpy(&v81, &input);
      sub_404100(&sub4, (int)v81);
      v3 = 50;
      v8 = wcscmp(sub4, L"wiergrrrrrrfwefi");
      if ( v8 ) // ******** if not equal ****** 
      {
        /* ... */
      }
      LOBYTE(v91) = 3;
      v5 = (int)(sub4 - 8);
      goto fail3;
    }
  }
  // 这里看起来有点靠谱了
  if ( *(_DWORD *)(input - 12) != 40 || *(_WORD *)(input + 78) != 'x' ) // 输入字符串长度不等于40 or 输入的最后一个字符not 'x'
  {
fail1:
    flag = 0; goto LABEL_92;
  }
  strcpy(&v81, &input);
  sub_404010(&sub1, (int)v81);  // string = "dvfrhtgbPr"
                                // string[i] = v81[i] + 3 for i in range(9)
  strcpy(&v81, &input);
  sub_404100(&sub2, (int)v81);  // string = "dvfrhtgbPr"
                                // string[i] = v81[i+10] for i in range(9)
  strcpy(&v81, &input);
  sub_404200(&sub3, (int)v81);  // string = "rfdeswe32f"
                                // string[i] = v81[i+20] + 5 for i in range(9)
  strcpy(&v81, &input);
  sub_404310(&sub4, (int)v81);  // string = "bghtwsqsgr"
                                // string[i] = v81[i+30] + 3 for i in range(9)
  strcpy(&v81, &input);
  sub_404420(&v84, (int)v81);   // string = "bghtwsqbghtwsqsgrsgr"
                                // string[i] = v81[i] + 3 for i in range(19)
  strcpy(&v81, &input);
  sub_404510(&v86, (int)v81);   // string = "bghtwbghtwsqsgrsqsgr"
                                // string[i] = v81[i+20] + 3 for i in range(19)
  strcpy(&v81, &input);
  sub_404620(&v85, (int)v81);   // string = "bghtwsbghtwsqsgrqsgr"
                                // string[i] = v81[10+i] + 2 for i in range(19)
  strcpy(&v81, (int *)&sub1);
  v33 = sub_403420(v82, &v83, (int)v81); // v81[i] = v81[i] + 3 if i&1 else v81[i] + 2
  sub_404810(&sub1, v33); // 最终结果存在sub1中
  /* ... */
  v36 = sub1;
  v37 = L"poskjyrvyr";
  while ( 1 ) // 这是一个字符串比较
  {
    v38 = *v36 < *v37;
    if ( *v36 != *v37 )
      break;
    if ( !*v36 )
      goto LABEL_49;
    v39 = v36[1];
    v38 = v39 < v37[1];
    if ( v39 != v37[1] )
      break;
    v36 += 2;
    v37 += 2;
    if ( !v39 )
    {
LABEL_49:
      v40 = 0;
      goto LABEL_51;
    }
  }
  v40 = -v38 | 1;
  if ( v40 )
    goto fail6;
LABEL_51:
  strcpy(&v81, (int *)&sub2);
  v41 = sub_4035D0(v32, &v83, (int)v81); // v81[i] = v81[i] + 5 if i%5 else v81[i] + 9
  sub_404810(&sub2, v41); // 最终结果存在sub2中
  /* ... */
  if ( strcmp(&sub2, L"j676kn|5nr") ) // 字符串比较
    goto fail6;
  strcpy(&v81, &sub3);
  v45 = sub_403790(v32, &v83, (int)v81); // v81[i] = v81[i] + 1 if i%4 else v81[i] + 3 
  sub_404810(&sub3, v45); // 结果存在sub3中
  /* ... */
  if ( strcmp((const unsigned __int16 **)&sub3, L"uku|nokxqf") ) //字符串比较
    goto fail6;
  strcpy(&v81, (int *)&sub4);
  v49 = sub_403940(v32, &v83, (int)v81); // v81[i] = v81[i] + 1 if i%3 else v91[i] + 2
  sub_404810(&sub4, v49); // 结果存在sub4中
  /* ... */
  if ( strcmp(&sub4, L"dzihggh{er") ) // 字符串比较
    goto fail6;
  strcpy(&v81, &v84);
  v53 = sub_403AF0(v32, &v83, (int)v81); // v81[i] = v81[i] + 6 if i&4 else v81[i] + 34
  sub_404810(&v84, v53); // 结果存在v84中
  if ( strcmp((const unsigned __int16 **)&v84, (const unsigned __int16 *)"\x90") ) // 字符串比较
    goto fail6;
  strcpy(&v81, &v86);
  v55 = sub_403CA0(v32, &v83, (int)v81); // v81[i] = v81[i] + 4 if i%5 else v81[i] + 18
  sub_404810(&v86, v55); // 结果存在v86中
  if ( strcmp((const unsigned __int16 **)&v86, (const unsigned __int16 *)"‚") ) // 字符串比较
    goto fail6;
  strcpy(&v81, &v85);
  v57 = sub_403E60(v32, &v83, (int)v81); // v81[i] = v81[i] if i%4 else  v81[i] + 1
  sub_404810(&v85, v57); // 结果存在v85中
  if ( strcmp((const unsigned __int16 **)&v85, L"d343igy2llogrxhkhtkr") ) // 字符串比较
    goto fail6;
  /* ... */
  if ( *(_WORD *)(v86 + 38) == 114 )
    flag = 1;
  else
fail6:
    flag = 0;
  /* ... */
LABEL_92:
  /* ... */
  return flag;
}
```
仔细查看函数可以发现，前面对字符串比较的处理是`相等则fail`，因此这段可以直接跳过，直接从`if ( *(_DWORD *)(input - 12) != 40 || *(_WORD *)(input + 78) != 'x' )`开始读。

字符串比较共有7处，分别为：
`sub_403420(sub_404010(input[0:10]))` vs `"poskjyrvyr"`
`sub_4035D0(sub_404100(input[10:20]))` vs `"j676kn|5nr"`
`sub_403790(sub_404200(input[20:30]))` vs `"uku|nokxqf"`
`sub_403940(sub_404310(input[30:40]))` vs `"dzihggh{er"`
`sub_403AF0(sub_404420(input[0:20]))` vs `"\x90\x72\x77\x6E\x8A\x7C\x76\x79\x99\x6D\x6A\x3A\x57\x3A\x6F\x6E\x9C\x39\x72\x72"`
`sub_403CA0(sub_404510(input[20:40]))` vs `"\x82\x6C\x76\x7D\x6D\x7E\x6C\x79\x70\x6C\x45\x7D\x6C\x6A\x6A\x78\x6A\x7E\x68\x72"`
`sub_403E60(sub_404620(inpupt[10:30]))` vs `"d343igy2llogrxhkhtkr"`

分别对以上7个过程逆向，可以得到7个字符串`s1-s7`。由于对输入字符串的第一步处理并未利用每段输入的最后一个字符，所以逆向得到的7个字符串的最后一位都是不确定正确的。
容易分析得到，将`s5`和`s6`组合可以得到`key'`，其中第20和40个字符是不确定正确的；根据`s7`可以得到第20个字符；根据程序已知最后一个字符为`'x'`。

脚本：
```python
flag = '' 
string = "\x90\x72\x77\x6E\x8A\x7C\x76\x79\x99\x6D\x6A\x3A\x57\x3A\x6F\x6E\x9C\x39\x72\x72"
for (i, c) in enumerate(string[:19]):
    c = ord(c)
    c = c-6 if i%4 else c-34
    flag += chr(c - 3)
flag += string[19:]

string = "\x82\x6C\x76\x7D\x6D\x7E\x6C\x79\x70\x6C\x45\x7D\x6C\x6A\x6A\x78\x6A\x7E\x68\x72"
for (i, c) in enumerate(string[:19]):
    c = ord(c)
    c = c-4 if i%5 else c-18
    flag += chr(c - 3)
flag += string[19:]

'''
flag_patch = '' # processing bytes[10:29]
string = 'd343igy2llogrxhkhtkr'
for (i, c) in enumerate(string[:19]):
    c = ord(c)
    c = c if i%4 else c-1
    flag_patch += chr(c - 2)
flag_patch += string[19:]

flag = flag[:19] + flag_patch[9] + flag[20:39] + 'x'
'''

string = "d343igy2llogrxhkhtkr"
flag_patch = chr(ord(string[9]) - 2)
flag = flag[:19] + flag_patch + flag[20:39] + 'x'
print("WhiteHat{" + flag + "}")
```


---

#### re06 - 100p
> Note: If you find flag in format WhiteHat{abcdef}, you should submit in form WhiteHat{sha1(abcdef)}

直接打开`reverse.exe`, 是个key checker, 包括一个文本框和一个button
`file`看一下, 是个`.net`逆向
```shell
$ file reverse.exe
reverse.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Window           s
```

用`reflector`打开, 可以看到`MainWindow`包含一个`tb_key(TextBox)`和一个`btn_check(Button)`.
观察函数, 有一个`btn_check_Click`, 看起来是`button`对应事件:
```csharp
private void btn_check_Click(object sender, RoutedEventArgs e)
{
    // 加密结果看起来是个base64
    if (Enc(this.tb_key.Text, 0x23c5, 0xa09d) == "iB6WcuCG3nq+fZkoGgneegMtA5SRRL9yH0vUeN56FgbikZFE1HhTM9R4tZPghhYGFgbUeHB4tEKRRNR4Ymu0OwljQwmRRNR4jWBweOKRRyCRRAljLGQ=")
    {
        MessageBox.Show("Correct!! You found FLAG");
    }
    else
    {
        MessageBox.Show("Try again!");
    }
}
```
程序没坑, 把`Enc`函数逆向就可以得到输入的key.
其他函数:

```csharp
public static string Enc(string s, int e, int n)
{
    int num;
    int[] numArray = new int[s.Length];
    // numArray is s
    for (num = 0; num < s.Length; num++)
    {
        numArray[num] = s[num];
    }
    int[] numArray2 = new int[numArray.Length];
    // 用e和n对输入字符串的每一位应用mod函数
    // 结果是1字节变2字节, 注意字节序
    for (num = 0; num < numArray.Length; num++)
    {
        numArray2[num] = mod(numArray[num], e, n);
    }
    string str = "";
    for (num = 0; num < numArray.Length; num++)
    {
        str = str + ((char) numArray2[num]);
    }
    // 然后convert to base64 string
    return Convert.ToBase64String(Encoding.Unicode.GetBytes(str));
}
```
```csharp
// 这个函数可以不用管具体细节
public static int mod(int m, int e, int n)
{
    int[] numArray = new int[100];
    int index = 0;
    // numArray是e的二进制形式
    do
    {
        numArray[index] = e % 2;
        index++;
        e /= 2;
    }
    while (e > 0);
    int num2 = 1;
    for (int i = index - 1; i >= 0; i--)
    {
        num2 = (num2 * num2) % n;
        if (numArray[i] == 1)
        {
            num2 = (num2 * m) % n;
        }
    }
    return num2;
}
```
脚本:
```python
import base64
import hashlib

# 这里就是用python重写了一下上面的mod函数
def mod(m, e, n):
    numArray = []
    index = 0
    while e > 0:
        numArray.append(e % 2) 
        index += 1
        e //= 2
    num2 = 1
    for i in range(index-1, -1, -1):
        num2 = (num2 * num2) % n
        if numArray[i] == 1:
            num2 = (num2 * m) % n
    return hex(num2)[2:].zfill(4) # 这里需要补足4位

# 爆破字典
dicts = {}
for i in range(ord('0'), ord('}')+1):
    index = mod(i, 0x23c5, 0xa09d)[2:4] + mod(i, 0x23c5, 0xa09d)[:2] # little-endian, 小端存储,所以需要把字节顺序颠倒一下
    # mod后的两个字节对应原始输入的一个字节
    dicts[index] = chr(i)

enc = "iB6WcuCG3nq+fZkoGgneegMtA5SRRL9yH0vUeN56FgbikZFE1HhTM9R4tZPghhYGFgbUeHB4tEKRRNR4Ymu0OwljQwmRRNR4jWBweOKRRyCRRAljLGQ="
# base64解码, 因为解码出来的字节有些没有字符表示, 所以用hex表示
dec = base64.b64decode(enc).hex()
flag = ''
for i in range(0, len(dec), 4):
    flag += dicts[dec[i:i+4]]
# flag: WhiteHat{N3xT_t1m3_I_wi11_Us3_l4rg3_nUmb3r}
# 以SHA-1方式提交flag
print(flag[:9] + hashlib.sha1(flag[9:-1].encode("utf-8")).hexdigest() + flag[-1])
```

