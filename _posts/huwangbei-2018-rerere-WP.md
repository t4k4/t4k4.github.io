比较烦的一道题
先运行看看：
    
    D:\CTF\CTFs\huwangbei\rerere>.\task_huwang-refinal-7.exe
    .\task_huwang-refinal-7.exe hash
    
    D:\CTF\CTFs\huwangbei\rerere>.\task_huwang-refinal-7.exe 12346
    No! You are Wrong

需要在命令行传入一个hash值。
用IDA打开，找到引用字符串`No! You are Wrong`的函数：
```c
int __usercall sub_8216A0@<eax>(int a1@<edi>, void *argc, int argv)
{
  if ( (signed int)argc >= 2 )
  {
    if ( strlen(*(const char **)(argv + 4)) <= 0x30 ) // 字符串长度小于等于0x30
    {
      v4 = a1;
      v5 = alloc_mem(0x28u);   // 内存分配
      Memorya = v5;
      *v5 = &RE::`vftable';
      v6 = alloc_mem(0x24u);   // 内存分配
      /* 一些初始化 */
      v7 = v6;      
      v6[1] = 0;
      v6[2] = 0;
      v6[3] = 0;
      input_hash = alloc_mem2(0x64u); // 这里不用管
      v9 = alloc_mem2(0x50u);         // 这里不用管
      v10 = v9;
      
      argv_1_ = *(_DWORD *)(argv + 4);
      /* 这段是strcpy操作 */
      *input_hash = *(_OWORD *)argv_1_;
      input_hash[1] = *(_OWORD *)(argv_1_ + 16);
      input_hash[2] = *(_OWORD *)(argv_1_ + 32);
      *((_WORD *)input_hash + 24) = *(_WORD *)(argv_1_ + 48);
      
      v7[5] = input_hash;
      v7[6] = v9;
      v7[8] = &unk_824018;     // a big array, 非常重要
      /* 根据vftable调用函数 */
      (*(void (__stdcall **)(_DWORD *, int))(*(_DWORD *)Memorya + 0x68))(v7, v4);// sub_821100,（看汇编，这里参数位置写反了）
      (*(void (**)(void))(*(_DWORD *)Memorya + 0x70))();// sub_821530
      (*(void (__cdecl **)(_DWORD *))(*(_DWORD *)Memorya + 0x6C))(v7);// sub_821150
      v12 = "No! You are Wrong\n";
      if ( !*v7 )           // 结果验证
        v12 = "Great! Add flag{} to hash and submit\n";
      print(v12);
      j_j_free(v10);
      j_j_free(input_hash);
      free_0(v7);
      free_0(Memorya);
    }
    result = 0;
  }
  else
  {
    print("%s hash\n", *(_DWORD *)argv);
    result = 0;
  }
  return result;
}
```
其中，`vftable`长这个样子（后面会用到）：
    
    const RE::`vftable'
        offset sub_8210A0    ; 0
        offset sub_821000
        offset sub_821180
        offset sub_821050
        offset sub_821270    ; 4
        ...
        offset sub_8214E0    ; 25
        offset sub_821100
        offset sub_821150
        offset sub_821530

根据`vftable`可以找到调用的三个函数：
```c
/* 这里实际就是把上面v7的一些值赋给this，基本不用管 */
int __thiscall sub_821100(_DWORD *this, _DWORD *a2)
{
  this[1] = *a2;            // vftable
  this[2] = a2[1];          // 0
  this[3] = a2[2];          // 0
  this[4] = a2[3];          // 0
  this[5] = 0;
  this[6] = a2[5];          // input hash
  this[7] = a2[6];          // not so important     
  this[8] = a2[6] + 40;     // not so important
  this[9] = a2[8];          // the big array
  return 0;
}
```

```c
/* 这个是根据上面的大数组调用函数，进行一些操作，包括函数和参数，后面会说 */
int __thiscall sub_821530(unsigned __int8 **this)
{
  unsigned __int8 **v1; // esi
  int result; // eax

  v1 = this;
  while ( 1 )               // *v1: vftable
  {
    result = *v1[9];        // the big array
    switch ( result )
    {
      case 0x43: return result;
      case 0x44: (*((void (__thiscall **)(unsigned __int8 **))*v1 + 18))(v1); break;
      /* 太多了省略掉一部分 */
      case 0x59: (*((void (__thiscall **)(unsigned __int8 **))*v1 + 6))(v1); break;
      default: (*((void (__thiscall **)(unsigned __int8 **))*v1 + 2))(v1); break;
    }
  }
}
```

```c
/* 这里是把this的一些值赋给v7，重要的是*v7（后面验证要用），别的不用看 */
int __thiscall sub_821150(_DWORD *this, _DWORD *a2)
{
  int result; // eax

  *a2 = this[1];
  a2[1] = this[2];
  a2[2] = this[3];
  a2[3] = this[4];
  result = this[5];
  a2[4] = result;
  return result;
}
```

重点是第二个函数。先看一下大数组`unk_824018`，长这样:

    4F 00 00 00 2F 55 05 54 ...

例如，`0x4F`代表调用函数`sub_821310`：
```c
int *__thiscall sub_821310(_DWORD *this)
{
  v1 = (unsigned __int8 *)this[9];
  v2 = v1[3] + ((v1[2] + (v1[1] << 8)) << 8);
  v3 = v1[4];
  this[8] -= 4;
  v4 = v3 + (v2 << 8);
  result = (int *)this[8];
  *result = v4;
  this[9] += 5;
}
```
用人话解释就是，将`0x4F`后面的4个字节以**大端模式**写成一个4字节的`int`类型，并把这个`int` `push`到`this[8]`的**头部**。`this[8]`可以看做是一个`链表header`（not so important, again）。
接下来就可以读这个大数组了...

把结果在这里贴一下：
```c    
/* array start */
    0x4F,0x0,0x0,0x0,0x2F,      ; this[8].push_front(0x2f)  // string_len = 0x30
    0x55,0x5,                   ; this[9] += 2 cuz this[4] == 0       
    0x54,0x30,                  ; this[4] = this[8].pop_front() = 0x2f   // actual a counter
Label_1:    // read a byte (let say 'ch') from your input then input++
    0x46,0x0,                   ; this[1] = this[6][0]      // remember that this[6] initially points to a copy of your input
    0x47,0x22,                  ; this[3] == 0
    0x48,0x2,                   ; this[5] = 1 cuz this[1]>this[3]
    0x4B,0x33,                  ; this[9] += 2 cuz this[5] != 0
    0x49,                       ; this[6]++, this[9]++          
                // if ch > 0x46 then fail and exit
    0x4F,0x0,0x0,0x0,0x46,      ; this[8].push_front(0x46)  // 'F'
    0x54,0x10,                  ; this[2] = this[8].pop_front()=0x46
    0x48,0x1,                   ; this[5]=1 if this[1]>this[2]
    0x4D,0x27,                  ; goto here:0x29(Label_3) if this[5] == 1
                // if ch < 0x30 then start validation
    0x4F,0x0,0x0,0x0,0x30,      ; this[8].push_front(0x30)  // '0' 
    0x54,0x10,                  ; this[2] = this[8].pop_front() = 0x30    
    0x48,0x1,                   ; this[5]=-1 if this[1] < this[2] 
    0x44,0x16,                  ; goto here:0x18(Label_2) if this[5] == -1 
                // if ch <= 0x39 then next loop starts
    0x4F,0x0,0x0,0x0,0x39,      ; this[8].push_front(0x39)  // '9'
    0x54,0x10,                  ; this[2] = this[8].pop_front()=0x39 
    0x48,0x1,                   ; this[5] == -1 if this[1] < this[2] 
    0x44,0x0B,                  ; goto here:0xd(Label_2) if this[5] == -1
                // else if ch < 0x41 then fail and exit
    0x4F,0x0,0x0,0x0,0x41,      ; this[8].push_front(0x41)  // 'A'
    0x54,0x1,                   ; this[2] = this[8].pop_front() = 0x41
    0x48,0x1,                   ; this[5] = -1 if this[1] < this[2]
    0x44,0x6,                   ; goto here:0x8(Label_3) if this[5] == -1
Label_2:    
    0x47,0x0,                   ; this[1] = 0
    0x48,0x0,                   ; this[5] = 0
    0x4B,0x5,                   ; goto here:0x7(Label_4) cuz this[5] == 0
Label_3:    // fail and exit
    0x47,0x0,                   ; this[1] = 0 
    0x50,0x0,                   ; this[1] = this[1]+1 = 1 
    0x43,                       ; end
Label_4:    // next loop or validation
    0x55,0x40,                  ; goto here:-0x40(Label_1) if this[4] != 0
/* 以上是验证每个字符是否合法: [0-9A-F] */

/******* validation start *******/
validation_1:
    0x4F,0x0,0x0,0x0,0x7,       ; this[8].push_front(0x7)
    0x54,0x30,                  ; this[4] = this[8].pop_front() = 0x7 // 一次验证8个字符
    0x47,0x11,                  ; this[2] = 0
loop_1:     // read a byte
    0x56,                       ; this[6]--     // 注意这里是从最后一个开始读的
    0x46,0x0,                   ; this[1] = this[6][0]
                // ch -= 0x30
    0x4F,0x0,0x0,0x0,0x30,  
    0x54,0x20,                  ; this[3] = this[8].pop_front() = 0x30
    0x59,0x2,                   ; this[1] = this[1] - this[3]
                // if ch in [0-9]
    0x4F,0x0,0x0,0x0,0x0A,      ; this[8].push_front(0xa)
    0x54,0x20,                  ; this[3] = this[8].pop_front()=0xa
    0x48,0x2,                   ; this[5] = -1 if this[1] < this[3] 
    0x44,0x9,                   ; goto here:0xb(to_hex) if this[5] == -1
                // if ch in [A-F]
    0x4F,0x0,0x0,0x0,0x7,       ; this[8].push_front(0x7)
    0x54,0x20,                  ; this[3] = this[8].pop_front()=0x7
    0x59,0x2,                   ; this[1] = this[1] - this[3]
to_hex:      
    0x4F,0x0,0x0,0x0,0x10,      ; this[8].push_front(0x10)
    0x54,0x20,                  ; this[3] = this[8].pop_front() = 0x10
    0x58,0x12,                  ; this[2] = this[2] * this[3]
    0x53,0x10,                  ; this[2] = this[2] + this[1]
    0x55,0x2B,                  ; goto here:-0x2b(loop) if this[4]; != 0
                // 判断结果是否等于0x63b5ea2c
    0x4F,0x63,0x0B5,0x0EA,0x2C, ; this[8].push_front(0x63b5ea2c)
    0x54,0x20,                  ; this[3] = this[8].pop_front() = 0x63b5ea2c
    0x48,0x12,                  ; this[5] = 0 if this[2] == this[3]
    0x47,0x0,                   ; this[1] = 0 
    0x4B,0x3,                   ; goto here:0x5(validation_2) if this[5] == 0
    0x50,0x0,                   ; this[1] = this[1] + 1 = 1
    0x43,                       ; end
/* 很清楚了，这里就是一个str2hex，然后与结果比较 */    
/* 后面的验证和这里一样，只是最后待比较的数字不同 */
validation_2:
    0x4F, ...
    0x4F,0x1F,0x94,0x65,0x56,   // 0x1F946556
    ..., 0x4B,0x3,0x50,0x0,0x43,
    
validation_3:
    0x4F, ...
    0x4F,0x5F,0x4A,0xC6,0x7A,   // 0x5F4AC67A
    ..., 0x4B,0x3,0x50,0x0,0x43,
    
validation_4:
    0x4F, ...
    0x4F,0xAF,0x88,0xCB,0xB2,   // 0xAF88CBB2
    ..., 0x4B,0x3,0x50,0x0,0x43,
    
validation_5:
    0x4F, ...
    0x4F,0x6C,0xA5,0x1C,0x3D,   // 0x6CA51C3D
    ..., 0x4B,0x3,0x50,0x0,0x43,
    
validation_6:
    0x4F, ...
    0x4F,0xF9,0x52,0xFC,0x49,   // 0xF952FC49
    ..., 0x4B,0x2,0x50,0x0,0x43
```
把这个烦人的大数组搞定以后就容易了。
脚本：
```python
flag = ''.join(['63b5ea2c', '1F946556', '5F4AC67A', 'AF88CBB2', '6CA51C3D', 'F952FC49'])
flag = list(flag.upper())
flag.reverse() # 这里要注意一下，str2hex的时候是反着读的，所以这里要reverse
print("flag{%s}" % (''.join(flag)))
```
