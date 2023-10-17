## Background
[SDK 和 NDK 差別](https://cg2010studio.com/2022/05/29/sdk-%E5%92%8C-ndk-%E5%B7%AE%E5%88%A5/)
[Android：清晰講解JNI 與 NDK(含實例教學)](https://kknews.cc/zh-tw/code/m9ey9b9.html)
[Android Studio - dumpsys](https://developer.android.com/tools/dumpsys?hl=zh-tw)
[adb shell dumpsys meminfo詳解](https://www.cnblogs.com/helloTerry1987/p/13109971.html)

## Source code
[merger2077 - source code](https://github.com/asef18766/balsn-ctf-2023-merger-2077)
## Recon
這一題沒解出來，但賽後有跟asef聊一下看怎麼解，他說這一題難度是中上，算是要對android debugging和unity很熟才會比較有想法，一開始我看到題目敘述提到flag藏在memory中，所以直覺是想說可以直接用adb把memory dump出來，然後再來分析一下整體的資訊，但貌似adb只能dump一些系統性的資訊，例如目前process的使用情況之類的，我還有嘗試把smali decompiler回java(jadx真的很香)，但source code也沒啥東西，嘗試很久也只能放棄
:::spoiler 嘗試過的過程以及一些好想有用的資訊
```bash
$ adb -s emulator-5554 shell ps | findstr balsn
USER           PID  PPID        VSZ    RSS WCHAN            ADDR S NAME
u0_a182       6725   354   36079108 205032 0                   0 S com.DefaultCompany.balsnctf2023
$ adb -s emulator-5554 shell
emu64xa:/ $ su
emu64xa:/ # cat /proc/6725/maps | grep balsn
...
764366600000-764366984000 rw-p 00000000 fe:27 106552                     /storage/emulated/0/Android/data/com.DefaultCompany.balsnctf2023/files/il2cpp/Metadata/ばかみたい
...
emu64xa:/ # exit
emu64xa:/ $ exit
$ adb -s emulator-5554 pull /storage/emulated/0/Android/data/com.DefaultCompany.balsnctf2023/files/il2cpp/Metadata/ .\
```
看起來ばかみたい就是一個很可疑的東西，搞不好其實沒啥用處
:::

根據asef的說法，在設計unity遊戲的時候，通常會把一些資訊(metadata)放在記憶體中，不是特有的exploit，是主要的設計機制就是這樣，而且通常還沒加密，因為有一些遊戲的global variable會需要access，理所當然的我們可以直接去記憶體中撈這一些東西leak一些資訊，更多的說明可以看[^asef-ppt]

asef:
> 可以查il2cpp或是global-metadata.dat這幾個東西，也可以去讀讀il2cpp的source code應該頗有幫助

## Reference
[^asef-ppt]:[asef PPT](https://hackmd.io/@asef18766/H19LRNSXh#/)
