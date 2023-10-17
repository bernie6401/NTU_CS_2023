## Source code
:::spoiler IDA Main Function
```cpp=
__int64 main_fn()
{
  __int64 idx; // r15
  int v1; // ebp
  __int64 v2; // rbx
  unsigned __int64 v3; // r14
  int v4; // r9d
  int v5; // r9d
  char v6; // al
  __int64 v7; // rdx
  unsigned int v9; // [rsp+Ch] [rbp-9Ch] BYREF
  char v10[32]; // [rsp+10h] [rbp-98h] BYREF
  __int128 user_input[2]; // [rsp+30h] [rbp-78h] BYREF
  __int64 v12; // [rsp+50h] [rbp-58h]
  char v13; // [rsp+58h] [rbp-50h]
  unsigned __int64 v14; // [rsp+68h] [rbp-40h]

  idx = 10000000000000000LL;
  v1 = 0;
  v14 = __readfsqword(0x28u);
  v2 = sub_40C2B0("/dev/urandom", &unk_498004);
  do
  {
    sub_40C3B0(&v9, 4uLL, 1LL, v2);
    v3 = v9 % 100000000uLL;
    sub_40C3B0(&v9, 4uLL, 1LL, v2);
    v1 -= (v3 * v3 + v9 % 100000000uLL * (v9 % 100000000uLL) > 9999999999999999LL) - 1;
    --idx;
  }
  while ( idx );
  sub_44A050(v10, 1u, 30LL, "%lu", 4 * v1 - 0x4F430000, v4);
  v13 = 0;
  v6 = 0x73;
  v12 = 0LL;
  memset(user_input, 0, sizeof(user_input));
  while ( 1 )
  {
    v7 = idx & 0xF;
    *(user_input + idx++) = v10[v7] ^ v6;
    if ( idx == 40 )
      break;
    v6 = byte_498040[idx];
  }
  if ( LOBYTE(user_input[0]) == 'B' && *(user_input + 1) == 'NSLA' && BYTE5(user_input[0]) == '{' && HIBYTE(v12) == '}' )
    sub_44A130(1, "Lucky! flag is %s\n", user_input, byte_498040, user_input, v5);
  else
    (sub_40C4B0)("Not so lucky ...", 1LL, v7, byte_498040, user_input);
  if ( v14 != __readfsqword(0x28u) )
    (sub_44A220)();
  return 0LL;
}
```
:::
## Recon
這是水題，基本上先用ida逆一下，就會看到上面的main function，不過用動態去看很醜，而且要等很久，估計應該是為了拖時間，反正最關鍵的部分在#36~#43這個while loop，還好這一題沒有把關鍵的code藏在tls這種奇怪的地方，或是像[crectf - ez rev](https://hackmd.io/@SBK6401/BJ4WpKb93)那樣用shell code噁心人，每次看到這種一大堆sub_function心裡都會倒抽一口氣，還好這次出題的人有良心(?)，反正仔細看一下#44驗證的部分就會知道前面6個bytes是`BALSN{`，所以代表它只是針對ciphertext做XOR的操作，也就是和v10這個變數，但是v10是從前面來的，也就是要先跳過那超級長的loop才能得知v10存了啥東西，原本到這邊就卡住了，一直用想說可不可以用動態直接dump解密完的結果，但我發現compiler應該有做一些scramble之類的操作讓動態很難看，反正過程就是一整個超卡，後來經過學長提示才想到可以用推的算回去，太久沒有寫reverse題就是這樣，基操的忘記了，反正可以先看一下XOR後的結果和原本的CT做比較，會發現output是`141592`的字串，看上去很眼熟應該就是圓周率，又觀察#38，它是取index mod 16後的結果，所以只需要取$\pi$的前16個字元，再往後面繼續操作就可以了
```python=
ct = [0x73, 0x75, 0x7D, 0x66, 0x77, 0x49, 0x5A, 0x60, 0x50, 0x7E, 0x67, 0x08, 0x44, 0x66, 0x40, 0x02, 0x5E, 0x7B, 0x01, 0x7A, 0x66, 0x03, 0x5B, 0x65, 0x03, 0x47, 0x0F, 0x0D, 0x59, 0x4D, 0x6C, 0x5B, 0x7F, 0x6B, 0x52, 0x02, 0x7F, 0x13, 0x15, 0x48, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 0x6F, 0xF2, 0x86, 0x23, 0x00, 0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00]


pt = [0x42, 0x41, 0x4c, 0x53, 0x4E, 0x7B]

for i in range(len(pt)):
    print(chr(pt[i] ^ ct[i]), end="")

# $ python exp.py
# 141592
```


## Exploit
```python
ct = [0x73, 0x75, 0x7D, 0x66, 0x77, 0x49, 0x5A, 0x60, 0x50, 0x7E, 0x67, 0x08, 0x44, 0x66, 0x40, 0x02, 0x5E, 0x7B, 0x01, 0x7A, 0x66, 0x03, 0x5B, 0x65, 0x03, 0x47, 0x0F, 0x0D, 0x59, 0x4D, 0x6C, 0x5B, 0x7F, 0x6B, 0x52, 0x02, 0x7F, 0x13, 0x15, 0x48, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC1, 0x6F, 0xF2, 0x86, 0x23, 0x00, 0x00, 0xE1, 0xF5, 0x05, 0x00, 0x00, 0x00, 0x00]


key = "1415926535897932"
pt = ""

for i in range(40):
    pt += chr(ct[i] ^ ord(key[i % 16]))

print(pt)
```

Flag: `BALSN{lUcK_1s_s0oO0O_1mP0r74nt_iN_c7F!#}`
## Reference
[BalsnCTF Reverse - lucky WP - maple](https://blog.maple3142.net/2023/10/09/balsn-ctf-2023-writeups/#lucky)