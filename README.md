RSA加密、解密、签名、验签的原理及方法
一、RSA加密简介

　　RSA加密是一种非对称加密。可以在不直接传递密钥的情况下，完成解密。这能够确保信息的安全性，避免了直接传递密钥所造成的被破解的风险。是由一对密钥来进行加解密的过程，分别称为公钥和私钥。两者之间有数学相关，该加密算法的原理就是对一极大整数做因数分解的困难性来保证安全性。通常个人保存私钥，公钥是公开的（可能同时多人持有）。

　　

二、RSA加密、签名区别

　　加密和签名都是为了安全性考虑，但略有不同。常有人问加密和签名是用私钥还是公钥？其实都是对加密和签名的作用有所混淆。简单的说，加密是为了防止信息被泄露，而签名是为了防止信息被篡改。这里举2个例子说明。

第一个场景：战场上，B要给A传递一条消息，内容为某一指令。

RSA的加密过程如下：

（1）A生成一对密钥（公钥和私钥），私钥不公开，A自己保留。公钥为公开的，任何人可以获取。

（2）A传递自己的公钥给B，B用A的公钥对消息进行加密。

（3）A接收到B加密的消息，利用A自己的私钥对消息进行解密。

　　在这个过程中，只有2次传递过程，第一次是A传递公钥给B，第二次是B传递加密消息给A，即使都被敌方截获，也没有危险性，因为只有A的私钥才能对消息进行解密，防止了消息内容的泄露。

 

第二个场景：A收到B发的消息后，需要进行回复“收到”。

RSA签名的过程如下：

（1）A生成一对密钥（公钥和私钥），私钥不公开，A自己保留。公钥为公开的，任何人可以获取。

（2）A用自己的私钥对消息加签，形成签名，并将加签的消息和消息本身一起传递给B。

（3）B收到消息后，在获取A的公钥进行验签，如果验签出来的内容与消息本身一致，证明消息是A回复的。

　　在这个过程中，只有2次传递过程，第一次是A传递加签的消息和消息本身给B，第二次是B获取A的公钥，即使都被敌方截获，也没有危险性，因为只有A的私钥才能对消息进行签名，即使知道了消息内容，也无法伪造带签名的回复给B，防止了消息内容的篡改。

 

　　但是，综合两个场景你会发现，第一个场景虽然被截获的消息没有泄露，但是可以利用截获的公钥，将假指令进行加密，然后传递给A。第二个场景虽然截获的消息不能被篡改，但是消息的内容可以利用公钥验签来获得，并不能防止泄露。所以在实际应用中，要根据情况使用，也可以同时使用加密和签名，比如A和B都有一套自己的公钥和私钥，当A要给B发送消息时，先用B的公钥对消息加密，再对加密的消息使用A的私钥加签名，达到既不泄露也不被篡改，更能保证消息的安全性。

　　总结：公钥加密、私钥解密、私钥签名、公钥验签。

 

三、RSA加密、签名的方法，代码例子如下：

复制代码
  1 import java.io.ByteArrayOutputStream;
  2 import java.security.KeyFactory;
  3 import java.security.KeyPair;
  4 import java.security.KeyPairGenerator;
  5 import java.security.PrivateKey;
  6 import java.security.PublicKey;
  7 import java.security.Signature;
  8 import java.security.spec.PKCS8EncodedKeySpec;
  9 import java.security.spec.X509EncodedKeySpec;
 10 import javax.crypto.Cipher;
 11 import org.apache.commons.codec.binary.Base64;
 12 
 13 public class TestRSA {
 14 
 15     /**
 16      * RSA最大加密明文大小
 17      */
 18     private static final int MAX_ENCRYPT_BLOCK = 117;
 19 
 20     /**
 21      * RSA最大解密密文大小
 22      */
 23     private static final int MAX_DECRYPT_BLOCK = 128;
 24 
 25     /**
 26      * 获取密钥对
 27      * 
 28      * @return 密钥对
 29      */
 30     public static KeyPair getKeyPair() throws Exception {
 31         KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
 32         generator.initialize(1024);
 33         return generator.generateKeyPair();
 34     }
 35 
 36     /**
 37      * 获取私钥
 38      * 
 39      * @param privateKey 私钥字符串
 40      * @return
 41      */
 42     public static PrivateKey getPrivateKey(String privateKey) throws Exception {
 43         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
 44         byte[] decodedKey = Base64.decodeBase64(privateKey.getBytes());
 45         PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
 46         return keyFactory.generatePrivate(keySpec);
 47     }
 48 
 49     /**
 50      * 获取公钥
 51      * 
 52      * @param publicKey 公钥字符串
 53      * @return
 54      */
 55     public static PublicKey getPublicKey(String publicKey) throws Exception {
 56         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
 57         byte[] decodedKey = Base64.decodeBase64(publicKey.getBytes());
 58         X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
 59         return keyFactory.generatePublic(keySpec);
 60     }
 61     
 62     /**
 63      * RSA加密
 64      * 
 65      * @param data 待加密数据
 66      * @param publicKey 公钥
 67      * @return
 68      */
 69     public static String encrypt(String data, PublicKey publicKey) throws Exception {
 70         Cipher cipher = Cipher.getInstance("RSA");
 71         cipher.init(Cipher.ENCRYPT_MODE, publicKey);
 72         int inputLen = data.getBytes().length;
 73         ByteArrayOutputStream out = new ByteArrayOutputStream();
 74         int offset = 0;
 75         byte[] cache;
 76         int i = 0;
 77         // 对数据分段加密
 78         while (inputLen - offset > 0) {
 79             if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
 80                 cache = cipher.doFinal(data.getBytes(), offset, MAX_ENCRYPT_BLOCK);
 81             } else {
 82                 cache = cipher.doFinal(data.getBytes(), offset, inputLen - offset);
 83             }
 84             out.write(cache, 0, cache.length);
 85             i++;
 86             offset = i * MAX_ENCRYPT_BLOCK;
 87         }
 88         byte[] encryptedData = out.toByteArray();
 89         out.close();
 90         // 获取加密内容使用base64进行编码,并以UTF-8为标准转化成字符串
 91         // 加密后的字符串
 92         return new String(Base64.encodeBase64String(encryptedData));
 93     }
 94 
 95     /**
 96      * RSA解密
 97      * 
 98      * @param data 待解密数据
 99      * @param privateKey 私钥
100      * @return
101      */
102     public static String decrypt(String data, PrivateKey privateKey) throws Exception {
103         Cipher cipher = Cipher.getInstance("RSA");
104         cipher.init(Cipher.DECRYPT_MODE, privateKey);
105         byte[] dataBytes = Base64.decodeBase64(data);
106         int inputLen = dataBytes.length;
107         ByteArrayOutputStream out = new ByteArrayOutputStream();
108         int offset = 0;
109         byte[] cache;
110         int i = 0;
111         // 对数据分段解密
112         while (inputLen - offset > 0) {
113             if (inputLen - offset > MAX_DECRYPT_BLOCK) {
114                 cache = cipher.doFinal(dataBytes, offset, MAX_DECRYPT_BLOCK);
115             } else {
116                 cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
117             }
118             out.write(cache, 0, cache.length);
119             i++;
120             offset = i * MAX_DECRYPT_BLOCK;
121         }
122         byte[] decryptedData = out.toByteArray();
123         out.close();
124         // 解密后的内容 
125         return new String(decryptedData, "UTF-8");
126     }
127 
128     /**
129      * 签名
130      * 
131      * @param data 待签名数据
132      * @param privateKey 私钥
133      * @return 签名
134      */
135     public static String sign(String data, PrivateKey privateKey) throws Exception {
136         byte[] keyBytes = privateKey.getEncoded();
137         PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
138         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
139         PrivateKey key = keyFactory.generatePrivate(keySpec);
140         Signature signature = Signature.getInstance("MD5withRSA");
141         signature.initSign(key);
142         signature.update(data.getBytes());
143         return new String(Base64.encodeBase64(signature.sign()));
144     }
145 
146     /**
147      * 验签
148      * 
149      * @param srcData 原始字符串
150      * @param publicKey 公钥
151      * @param sign 签名
152      * @return 是否验签通过
153      */
154     public static boolean verify(String srcData, PublicKey publicKey, String sign) throws Exception {
155         byte[] keyBytes = publicKey.getEncoded();
156         X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
157         KeyFactory keyFactory = KeyFactory.getInstance("RSA");
158         PublicKey key = keyFactory.generatePublic(keySpec);
159         Signature signature = Signature.getInstance("MD5withRSA");
160         signature.initVerify(key);
161         signature.update(srcData.getBytes());
162         return signature.verify(Base64.decodeBase64(sign.getBytes()));
163     }
164 
165     public static void main(String[] args) {
166         try {
167             // 生成密钥对
168             KeyPair keyPair = getKeyPair();
169             String privateKey = new String(Base64.encodeBase64(keyPair.getPrivate().getEncoded()));
170             String publicKey = new String(Base64.encodeBase64(keyPair.getPublic().getEncoded()));
171             System.out.println("私钥:" + privateKey);
172             System.out.println("公钥:" + publicKey);
173             // RSA加密
174             String data = "待加密的文字内容";
175             String encryptData = encrypt(data, getPublicKey(publicKey));
176             System.out.println("加密后内容:" + encryptData);
177             // RSA解密
178             String decryptData = decrypt(encryptData, getPrivateKey(privateKey));
179             System.out.println("解密后内容:" + decryptData);
180             
181             // RSA签名
182             String sign = sign(data, getPrivateKey(privateKey));
183             // RSA验签
184             boolean result = verify(data, getPublicKey(publicKey), sign);
185             System.out.print("验签结果:" + result);
186         } catch (Exception e) {
187             e.printStackTrace();
188             System.out.print("加解密异常");
189         }
190     }
191 }
复制代码
　　PS:RSA加密对明文的长度有所限制，规定需加密的明文最大长度=密钥长度-11（单位是字节，即byte），所以在加密和解密的过程中需要分块进行。而密钥默认是1024位，即1024位/8位-11=128-11=117字节。所以默认加密前的明文最大长度117字节，解密密文最大长度为128字。那么为啥两者相差11字节呢？是因为RSA加密使用到了填充模式（padding），即内容不足117字节时会自动填满，用到填充模式自然会占用一定的字节，而且这部分字节也是参与加密的。

　　密钥长度的设置就是上面例子的第32行。可自行调整，当然非对称加密随着密钥变长，安全性上升的同时性能也会有所下降。
