var setUtils={
    init:function(PI,OI,client_prikey){
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
    }
}