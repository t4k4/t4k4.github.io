#### Cool

> (3rd) ELF 64-bit executable

运行./cool提示缺少共享库
于是直接丢到IDA里
可以找到几个关键字符串：
`"Give me your key: "`
`"Wrong~"`
`"Congratulation~~~"`
`"Your flag: ISITDTU{ %s }"`
根据字符串可以找到main函数：

    首先读取输入，存入地址602100
    判断字符串长度是否为28
    以4字符为一组，计算MD5
        "ECFD4245812B86AB2A878CA8CB1200F9" —— "fl4g"
        "88E3E2EDB64D39698A2CC0A08588B5FD" —— "_i5_"
        "BBC86F9D0B90B9B08D1256B4EF76354B" —— "h3r3"
    然后判断第13位是否等于'!'
    接下来从第14位开始，将前(13+i)位字符做异或运算，与目标字符比较

Note: 这里有个问题就是，第二个MD5没搜到结果，本来想写脚本爆破，但是成本太高
    就按flag的套路猜了一下，第二组字符可能是"_is_"
    于是试了"_1s_", "_1S_", "_i5_"(bingo!)
    (这里本来还想是不是个假flag，第二组字符可能包含"not"，后来发现想多了= =)
    
程序逻辑很简单，理清就可以写脚本了

python脚本：
```python
secret=[0x7D,0x4D,0x23,0x44,0x36,0x02,0x76,0x03,0x6F,0x5B,0x2F,0x46,0x76,0x18,0x39]
flag = 'fl4g_i5_h3r3!'
for i in range(len(secret)):
    c = secret[i]
    for j in range(i+13):
        c ^= ord(flag[j])
    flag += chr(c)
    
print("ISITDTU{%s}" % flag)
```
---

#### Inter

> (14th) PE32 executable (console)
> windows named pipe

把inter.exe丢进OD，发现对__stdio_common_vfscanf的调用
在此处下断点，然后运行，提示：
    `"Please give me 5 numbers to get the flag:"`

可以据此找到关键(?)函数1 sub_4015C0

    ...
    CreateFileW("\\.\pipe\LogPipe", ...)
    ...
    while(1){
        sub_401050() // read input
        ...
        wsprintfA
        ...
        WriteFile
        ...
        ReadFile
        ...
        ++i
        if(i >= 5) goto print_flag
    }
    ...
    
再加上对CreateNamedPipeW和CreateThread的调用，
可以发现这是个windows命名管道客户端
向服务端传递5个数字，如果服务端均返回 "1"，验证通过，print flag

对ReadFile下断点，可以找到服务端逻辑在loc_401340
(这部分IDA没识别出来代码，需要手动)
然后就可以读汇编啦(...)

先是根据输入字符串得到v1和v2，v1是对输入做atoi，v2则是每位上的数字之和，
然后验证：

    Five numbers total:
    1st: input ^ 0x1e1e1e1e == 0x672E6B41
    2nd: 0x23除input取余，相当于计算input的0x23进制形式，
         从高位到低位顺序为: 1f, 21, 0c, 0d, 18, 1f
    3rd: (input + 0x21) ^ 0x0CAFEBABE == 0x0A8CAD9EF
    4th: MD5比较: 
         MD5(input) == 'e861a6e17bd11a7cec8b6c8514728d2b'
    5th: (input + 0x2d) ^ 0x0CAFACADA == 0x0FB94F394

(v2只是写脚本的时候拿来验证结果)

print flag的时候就直接 `printf("%s", (char*)&input)`  (注意一下大小端)

总体来说这题简单
主要是没认出来是pipe，中间卡了几个小时……(还是菜 _(:з」∠)_)

python脚本：
```python
num1 = 0x672E6B41 ^ 0x1e1e1e1e

mods = [0x1f, 0x21, 0x0c, 0x04, 0x18, 0x1f]
mods.reverse()
num2 = 0
for i in range(len(mods)):
    num2 *= 0x23
    num2 += mods[i]

num3 = 0x0A8CAD9EF
num3 ^= 0x0CAFEBABE
num3 -= 0x21
num3 &= 0xffffffff
    
# md5(num4) = e861a6e17bd11a7cec8b6c8514728d2b
num4 = 1835360107
    
num5 = 0x0FB94F394
num5 ^= 0x0CAFACADA
num5 -= 0x2d
num5 &= 0xffffffff
    
flag = ''
for num in [num1, num2, num3, num4, num5]:
    num = hex(num)[2:]
    for i in range(0, len(num), 2):
        flag += chr(int(num[i:i+2], 16))
    
print("ISITDTU{%s}" % flag)
```

