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
            　　 window.location.href="http://127.0.0.1:8099/";
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



function certinit(){
var message = "flag=true";
    var xml = new XMLHttpRequest();
    xml.open('post','send_certi','true');
    xml.setRequestHeader('content-type', 'application/x-www-form-urlencoded');
    xml.send(message);
    xml.onreadystatechange = function(){
        if(xml.readyState==4){
            var result = JSON.parse(xml.responseText);
            certi = result.certi;

            certi=certi.replace(/[\r\n]/g,"<br>");
            setCookie('certi',certi);
        }
    }
}

function encryp(){
    var password = document.getElementById('password').value;
    var rpassword = document.getElementById('rpassword').value;
    if(rpassword!=password){return;}
    var certi = getCookie('certi');
    certi=certi.replace(/<br>/g,"\r\n");
    console.log(certi)
    //var publickey = certUtils.getPublickey(certi);
    certUtils.getPublickey(certi).then(publickey=>{
    console.log(publickey);

    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if(xhr.readyState === 4 && xhr.status === 200) {
        var result = JSON.parse(xhr.responseText);
            if(result.flag=='right') alert('success');
            if(result.flag=='wrong') alert('already logon');
        }
    }
    xhr.open('POST', 'process_logon/', true);
    xhr.setRequestHeader('Content-Type', 'application/json;charset=utf-8');
    var username = document.getElementById('username').value;
    var emali = document.getElementById('user_ID').value;
    var phone = document.getElementById('phone').value;

    password = CryptoJS.MD5(password).toString();

    var result = {'username' : username, 'password' : password,
    'emali' : emali, 'phone' : phone};

    var result_str = JSON.stringify(result);
    result_str = hybridUtils.encrypt(publickey, result_str);
    console.log(result_str)
    xhr.send(result_str);
    })
}