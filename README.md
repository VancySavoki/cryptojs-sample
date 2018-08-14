## crypto.js

====

基于nodejs的crypto模块，提供AES和RSA两种加密算法示例。  
* AES通常用于前端信息自加密，存储一些非关键信息，起到一定的保密作用。  
* RSA用于与服务器传递核心数据，通常有两组密钥，一组用于前端提交加密数据，服务器公钥解密。另一组用于客户端验证，服务器用私钥签名返回数据，客户端公钥校验数据，例如使用传递访问令牌（bearer token, jwt)。如果服务器使用对称算法签名，则需要客户端携带令牌访问服务器校验地址来验证令牌有效性，采用非对称算法则客户端可自行校验。

### AES对称加密用法
```js
import { aes } from 'crypto'
const storeToLocal = 'some information to be stored';
 // 得到对称加密后的文本内容
const entrypted = aes.cipher(storeToLocal);
aes.decipher(encrypted) === storeToLocal; // true
```
#### API
| 参数名 | 描述 | 类型 |  必须 | 默认 |
| ----- | ----- | ----- | ----- | ----- |
|  buf  | 待加密或解密的Buffer对象 | `Buffer` | `true` | |
|  key  | 对称加密算法的key  | `String` | `false` | x82m#*lx8 |
|  algorithm | 对称加密算法名，需要crypto模块支持，具体参见[crypto.createCipher(algorithm, password)](https://nodejs.org/docs/latest-v7.x/api/crypto.html#crypto_crypto_createcipher_algorithm_password) | `String` | `false` | aes192
-----

#### RSA非对称加密用法
```typescript
import { rsa } from 'crypto'
const storeToLocal: str = 'some information to be posted';
class KeyOption {
    constructor(obj) {
        this.key = obj.key;
        this.padding = obj.padding;
    }
}
 // 得到非对称加密后的buffer
const entryptedBuffer: buffer = rsa.publicEncrypt(
                                    new KeyOption(rsa.encryptPublickey),
                                    new Buffer(storeToLocal)
                                );
// 将buffer转换到十六编码的字符串，传递到后台。这里采用什么编码需要与后端协商，以便解码。
entryptedBuffer.toString('hex');

// 客户端自解密
rsa.privateDecrypt(new KeyOption(rsa.decryptPrivatekey), entryptedBuffer);

```
#### API
| 参数名 | 描述 | 类型 |  必须 | 默认 |
| ----- | ----- | ----- | ----- | ----- |
|  keyOption  | key配置对象,参见[crypto.privateDecrypt](https://nodejs.org/docs/latest-v7.x/api/crypto.html#crypto_crypto_privatedecrypt_private_key_buffer) | `KeyOption` | `true` | |
|  buf  | 要加密的buffer对象  | `Buffer` | `true` | |

### 后台私钥解密Java版示例

```java
/** 
 * DO NOT STARTS WITH '-----BEGIN PRIVATE KEY-----'
 * DO NOT ENDS WITH '-----END PRIVATE KEY-----'
 * keep it clean
 */
import java.security.PrivateKey;
import javax.crypto.Cipher;
import RsaUtil;
String privatekey = ''; 
String encryptedPassword = 'xxxxxxxxxxxxxxxxxx';
PrivateKey rsaPrivateKey = RsaUtil.getPrivateKey(privatekey);

byte[] bytes = RsaUtil.hexStringToBytes(encryptedPassword);
byte[] decryptedBytes;
try{
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
    decryptedBytes= cipher.doFinal(bytes);
} catch (Exception ex){
    throw new BadCredentialsException("invalid password");
}
new String(decryptedBytes);
```