function encrypt(plaintext){
    let secretStr= "Q2Cm1lW95HmteIrluXIbn1jJgoG4iR6SuLWGILV1Jg0=";
    //let plaintext=$("#ibox").val();
    ciphertext=fernetUtils.encrypt(secretStr,plaintext)
    //p=fernetUtils.decrypt(ciphertext);
    return ciphertext;
    /*console.log("--------------fernet---------")
    console.log(iv)
    console.log(secretStr)
    console.log(ciphertext)
    console.log(p)*/
}
function sendHash(challenge){
    var username = document.getElementById("username").value;
    var pwd = document.getElementById("password").value;
    var pwd_hash = CryptoJS.MD5(pwd);
    var mix = pwd_hash + challenge;
    var mix_hash = CryptoJS.MD5(mix);
    var fd = new FormData();
    mix_hash = encrypt(mix_hash.toString());
    //username = encrypt(username);
    alert(username)
    fd.append('hash',mix_hash);
    fd.append('username',username);
    xml2 = new XMLHttpRequest();
    xml2.open('post','/hash_accept',true);
    xml2.send(fd);
    alert('suc');
    xml2.onreadystatechange = function(){
        if(xml2.status==200 && xml2.readyState==4){
            var res = JSON.parse(xml2.responseText);
            alert(res.resul);
            if( res.resul == "right")
            {
                alert("success login in");
                setCookie('token',res.token);
                alert(document.cookie);
            　　 window.location.href="page1";

            }
            if( res.resul == "wrong") alent("fail login in");
        }
    }
}

function sendMsg(){
    //var form = document.getElementById("myform"); 
    //var formData = new FormData(form );
    var username = document.getElementById("username").value;
    username = encrypt(username);
    var fd = new FormData();
    fd.append('username',username);
    
    xml = new XMLHttpRequest();
    xml.open('post', '/challenge_sender',true);
    xml.send(fd);
    xml.onreadystatechange=function(){
        if(xml.status==200 && xml.readyState==4){
            var res = JSON.parse(xml.responseText);
            if(res.resul=="right"){
                sendHash(res.challenge);
            }
            else{
                alert("用户名不存在,请重新输入");                        
            }
        }
    }
}


