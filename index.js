const java = require("java");
const fs = require("fs");
const axios = require('axios');
const soap = require('soap');
const { Buffer } = require('buffer');
const xmlbuilder = require('xmlbuilder2');

java.classpath.push(".");
java.classpath.push("/home/chanik/document/saeol/saeolnode/files/libgpkiapi_jni.jar");

const gpkiJni = java.import('com.gpki.gpkiapi_jni')
const Ldap = java.import('com.gpki.gpkiapi.util.Ldap');
const Disk = java.import('com.gpki.gpkiapi.storage.Disk');

const myCertId = 'SVR3940415001'
const ldapServer = '152.99.57.127'
const seumteoId = 'SVR1310505007'

const pathForEnvCert = `./files/${myCertId}_env.cer`
const pathForEnvKey = `./files/${myCertId}_env.key`
const envKeyPw = 'wotks2893*'
const pathForSignCert = `./files/${myCertId}_sig.cer`
const pathForSignKey = `./files/${myCertId}_sig.key`
let encodingData
let times = 0

function getMsgKey() {
    const d = new Date();
    const sdf = new Intl.DateTimeFormat('ko-KR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        fractionalSecondDigits: 3,
    });

    return sdf.format(d) + Math.random().toString().substring(2, 12);
}

function getTxid() {
	 const currentDate = new Date();
	 const sdf = new Intl.DateTimeFormat('ko-KR', {
	       year: 'numeric',
	       month: '2-digit',
	       day: '2-digit',
	       hour: '2-digit',
	       minute: '2-digit',
	       second: '2-digit',
	       fractionalSecondDigits: 3
	 });
	 const cur = sdf.format(currentDate).replace(/[^\d]/g, '');
	 const transactionUniqueId = cur + keyGen(8);
	return transactionUniqueId
}

function keyGen(length) {
	const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	let key = '';
	for (let i = 0; i < length; i++) {
	  const randomIndex = Math.floor(Math.random() * characters.length);
	  key += characters.charAt(randomIndex);
	}
	return key;
}

function makeReqSoap(ifid, srcorgcd, tgtorgcd, msgkey, message) {
    const soapEnvelope = xmlbuilder.create({
        'soapenv:Envelope': {
            '@xmlns:soapenv': 'http://schemas.xmlsoap.org/soap/envelope/',
            'soapenv:Header': '',
            'soapenv:Body': {
                'DOCUMENT': {
                    'IFID': ifid,
                    'SRCORGCD': srcorgcd,
                    'TGTORGCD': tgtorgcd,
                    'RESULTCODE': '000',
                    'MSGKEY': msgkey,
                    'DATA': {
                        '#raw': message,
                    },
                },
            },
        },
    });

    return soapEnvelope.end({ prettyPrint: true });
}

async function sendHttpRequest(addr, reqSoap, soapAction) {
    const headers = {
        'Content-Type': 'text/xml;charset=utf-8',
        'Accept': 'application/soap+xml, application/dime, multipart/related, text/*',
        'SOAPAction': soapAction,
    };

    try {
		console.log('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
        const response = await axios.post(addr, reqSoap, { headers });
        console.log(response)
        return response.data;
    } catch (error) {
        console.log(error)
        throw error;
    }
}

async function sendAPI(encodingData) {
	const charset = 'utf-8';
    const ifID = 'SOINN00001';
    const srcorgcd = '3940017';
    const tgtorgcd = '3940000';
    const msgkey = getMsgKey();

   const message = encodingData
// SOWNN00213
    const addr = 'http://105.10.1.82:3100/stmr/websvc/std/ws?wsdl=SOINN00001';
    const reqSoap = makeReqSoap(ifID, srcorgcd, tgtorgcd, msgkey, message);

    // console.log('reqSoap=>\n', reqSoap);
    
    try {
        const resSoap = await sendHttpRequest(addr, reqSoap, ifID);
        // console.log('resSoap=>\n', resSoap);
    } catch (error) {
        // console.error('Error:', error.message);
    }



	// [6] API 호출
// 	const formattedDateTime = (new Date(Date.now() + 9 * 60 * 60 * 1000)).toISOString().replace(/\D/g, '').slice(0, 14);
// 	data.header.requestDate = formattedDateTime
// 	data.body = encodingData
// 	headers.tx_id = getTxid() // date + 랜덤 string
//     try {
// 	    axios.post(dataSet.apiUrl, data, { headers })
// 	      .then(response => {
// 		      const {data: { header, body = ''} = {}} = response
// 		      console.log(header)
// 		      decrypt(body)
// 	    })
// 	      .catch(error => {
// 	        console.error(error);
// 	    });
//    	} catch (e) {
// //        console.log(e)
//     	}

}

function decrypt(datas) {
	        const gpki = new gpkiJni();

		// [7] BASE64 디코딩
	        gpki.BASE64_DecodeSync(datas);

	        const decoded = java.newArray('byte',JSON.parse(`[${gpki.baReturnArray.toString()}]`))
	        // [8] 전자서명
	        gpki.CMS_ProcessSignedDataSync(decoded);

	        const result = java.newArray('byte',JSON.parse(`[${gpki.baData.toString()}]`))

	        let svrCert = Disk.readCertSync(pathForEnvCert);
	        let svrKmPriKey = Disk.readPriKeySync(pathForEnvKey, envKeyPw);

		const myCert = java.newArray('byte',JSON.parse(`[${svrCert.getCertSync().toString()}]`))
	        const myKey = java.newArray('byte',JSON.parse(`[${svrKmPriKey.getKeySync().toString()}]`))
		// [9] 데이터 복호화
		gpki.CMS_ProcessEnvelopedDataSync(myCert, myKey, result);
		const fin = Buffer.from(gpki.baReturnArray.toString().split(',')).toString()

//		console.log(JSON.parse(Buffer.from(gpki.baReturnArray.toString().split(',')).toString()))

}

function encryptAndVerify(times){
	//  getTxid()
	 // [1] Ldap 서버에서 암호화를 위한 키 가져오기
	 const ldap = new Ldap()
	 ldap.setLdapSync(ldapServer, 389)
	 ldap.searchCNSync(Ldap.DATA_TYPE_KM_CERT, seumteoId)
	 const ldapKey = ldap.getDataSync()

	 const svrCertByteArray = java.newArray('byte',JSON.parse(`[${ldapKey.toString()}]`))

	 // [2] 암호화 시킬 데이터 호출
	
    const message = `
        <message>
            <body>
                <query_id>3940000SOI002</query_id>
                <dataList><data>20230805</data></dataList>
            </body>
        </message>
    `;
    const newJson = {
        "queryId": "3940000SOI002",
        "date": "20230805"
    }
    const buffer = Buffer.from(JSON.stringify(message))
    const bt = Array.from(buffer)
    const targetByteArr = java.newArray('byte',JSON.parse(`[${bt.toString()}]`));
    
	//  let target = Disk.readSync(`./test.xml`);
    //  let target2 = Disk.readSync(`./test.json`);
	// let target = message

	//  const targetByteArr = java.newArray('byte',JSON.parse(`[${target.toString()}]`));
     console.log(targetByteArr)

	 const gpki = new gpkiJni();
	 
	 // [3] 암호화
	 gpki.CMS_MakeEnvelopedData(svrCertByteArray, targetByteArr, gpkiJni.SYM_ALG_NEAT_CBC)

	 let svrCert = Disk.readCertSync(pathForSignCert);
	 let svrKmPriKey = Disk.readPriKeySync(pathForSignKey, envKeyPw);

	 const myCert = java.newArray('byte',JSON.parse(`[${svrCert.getCertSync().toString()}]`))
	 const myKey = java.newArray('byte',JSON.parse(`[${svrKmPriKey.getKeySync().toString()}]`))

	 const encrypted = java.newArray('byte',JSON.parse(`[${gpki.baReturnArray.toString()}]`))

	 // [4] 전자서명
	 gpki.CMS_MakeSignedDataSync(myCert, myKey, encrypted, "")
	 const signed = java.newArray('byte',JSON.parse(`[${gpki.baReturnArray.toString()}]`))

	 // [5] BASE64 인코딩
	 gpki.BASE64_EncodeSync(signed)
	 encodingData = gpki.sReturnString
	        
	 sendAPI(encodingData)
}

encryptAndVerify(times)
