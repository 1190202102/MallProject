function download(filename, text) {
    var element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    element.setAttribute('download', filename);
    element.style.display = 'none';
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
}
function generate_key(){
    var keypair=rsaUtil.genKeyPair(2048);
    alert(keypair.publicKey);
    download('私钥文件',keypair.privateKey);
}