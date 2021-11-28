/**
 * 简单封装一下
 */

 var rsaUtil = {
    //生成密钥对(公钥和私钥)
    genKeyPair: function (bits) {
        let genKeyPair = {};
        let jse = new JSEncrypt({default_key_size: bits});
        //获取私钥
        genKeyPair.privateKey = jse.getPrivateKey();
        //获取公钥
        genKeyPair.publicKey = jse.getPublicKey();
        return genKeyPair;
    },
    //公钥加密
    encrypt: function (plaintext, publicKey) {
        // if (plaintext instanceof Object) {
        //     //1、JSON.stringify
        //     plaintext = JSON.stringify(plaintext)
        // }
        let jse = new JSEncrypt();
        publicKey && jse.setPublicKey(publicKey);
        return jse.encrypt(plaintext);
    },

    //私钥解密
    decrypt: function (ciphertext, privateKey) {
        let jse = new JSEncrypt();
        privateKey && jse.setPrivateKey(privateKey);
        let decString = jse.decrypt(ciphertext);
        // if(decString.charAt(0) === "{" || decString.charAt(0) === "[" ){
        //     //JSON.parse
        //     decString = JSON.parse(decString);
        // }
        return decString;
    },
    sign : function(prikey,info){
        let sjse = new JSEncrypt();
        sjse.setPrivateKey(prikey);
        let signature = sjse.sign(info, CryptoJS.SHA1, "sha1");
        return signature;
    },
    verify : function(pubkey,info,signature){
        let vjse = new JSEncrypt();
        vjse.setPublicKey(pubkey);
        let verified = vjse.verify(info, signature, CryptoJS.SHA1);
        return verified;
    }
};
var fernetUtils={
    genRndKey:function(){   //32Bytes random int with base64-encoded
        let secretWords=CryptoJS.lib.WordArray.random(32);
        let secretStr=CryptoJS.enc.Base64.stringify(secretWords);
        return secretStr;
    },
    encrypt:function(secretStr,plaintext){
        let salt = CryptoJS.lib.WordArray.random(64);
        let eniv=Array.from(Int8Array.from(salt.words))
        let secret=new fernet.Secret(secretStr)
        let token = new fernet.Token({
            secret: secret,
            time: new Date(),
            iv: eniv 
          });
          let ciphertext=token.encode(plaintext);
          let pp=token.decode()
          return ciphertext
    },
    decrypt:function(secretStr,token){
        let secret=new fernet.Secret(secretStr)
        var token = new fernet.Token({
            secret: secret,
            token: token,
            ttl: 0
          });
          plaintext=token.decode();
          return plaintext;
    }
}
var hybridUtils={
    encrypt:function(pubkey,msg){
        rnd_key=fernetUtils.genRndKey();
        console.log(rnd_key)
        console.log("thisis")
        console.log(pubkey)
        encrypted_key=rsaUtil.encrypt(rnd_key,pubkey);
        console.log(encrypted_key)
        encrypted_msg=fernetUtils.encrypt(rnd_key,msg);
        ret_token={"key": encrypted_key,"msg": encrypted_msg};
        return JSON.stringify(ret_token);
    },
    decrypt:function(prikey,token_json){
        token=JSON.parse(token_json);
        key=rsaUtil.decrypt(token.key,prikey)
        msg=fernetUtils.decrypt(key,token.msg)
        return msg
    }
}
var certUtils={
    getPublickey:async function(cert){
        let pem=0
        const jwkey = await x509.toJwk(cert, 'pem')
        const keyObj = new jsckey.Key('jwk', jwkey)
            pemStr = await keyObj.export('pem')
            console.log(pemStr);
            return pemStr;
    }
}
var keypair=rsaUtil.genKeyPair(2048);
function oldfunc(){
    console.log(keypair.publicKey);
    console.log(keypair.privateKey);
    let plaintext=$("#text").val();
    let ciphertext=rsaUtil.encrypt(plaintext,keypair.publicKey)
    console.log(ciphertext)
    let p=rsaUtil.decrypt(ciphertext,keypair.privateKey)
    console.log(p)
    let info="mynewsign"
    let s=rsaUtil.sign(keypair.privateKey,info)
    let v=rsaUtil.verify(keypair.publicKey,info,s)
    console.log(s)
    console.log(v)
}
function clickfunc(){
    let salt = CryptoJS.lib.WordArray.random(64);
    let iv=Array.from(Int8Array.from(salt.words))
    fernetUtils.myiv=iv
    let secretWords=CryptoJS.lib.WordArray.random(32)
    let secretStr=CryptoJS.enc.Base64.stringify(secretWords)
    let secret=new fernet.Secret(secretStr)
    fernetUtils.secret=secret
    let plaintext=$("#text").val();
    ciphertext=fernetUtils.encrypt(plaintext)
    p=fernetUtils.decrypt(ciphertext)
    console.log("--------------fernet---------")
    console.log(iv)
    console.log(secretStr)
    console.log(ciphertext)
    console.log(p)
}
function newfunc(){
    keypair=rsaUtil.genKeyPair(2048);
    token=hybridUtils.encrypt(keypair.publicKey,"fuck");
    p=hybridUtils.decrypt(keypair.privateKey,token);
    console.log(p)
}