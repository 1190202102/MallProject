// First,call init()
// Second,call packToBusi()
var setUtils={
    // paraPI and paraOI are Object, not JSON string
    init:function(paraPI,paraOI,client_prikey){
        PI=JSON.parse(paraPI)
        OI=JSON.parse(paraOI)
        PI['rnd']=Math.random();
        OI['rnd']=Math.random();
        PI=JSON.stringify(PI)
        OI=JSON.stringify(OI)
        let PIMD=CryptoJS.SHA1(PI).toString(CryptoJS.enc.Hex);
        let OIMD=CryptoJS.SHA1(OI).toString(CryptoJS.enc.Hex);
        let POMD=CryptoJS.SHA1(PIMD+OIMD).toString(CryptoJS.enc.Hex);
        let DS=rsaUtil.sign(client_prikey,POMD);
        ret={
            PIMD:PIMD,
            OIMD:OIMD,
            POMD:POMD,
            DS:DS,
            PI:PI,
            OI:OI
        };
        return ret;
    },
    getBankData:function(POdata){
        data={
            DS:POdata.DS,
            PI:POdata.PI,
            OIMD:POdata.OIMD
        };
        return JSON.stringify(data);
    },
    getBusiData:function(POdata){
        data={
            DS:POdata.DS,
            OI:POdata.OI,
            PIMD:POdata.PIMD
        };
        return JSON.stringify(data);
    },
    packToBusi: function(POdata,pubkeyBank){
        pack=JSON.parse(this.getBusiData(POdata))
        pack.toBank=hybridUtils.encrypt(pubkeyBank,this.getBankData(POdata));
        return JSON.stringify(pack)
    }
}

// Format of PI: amount,INaccount,OUTaccount
// Format of OI: shopcart,clientID