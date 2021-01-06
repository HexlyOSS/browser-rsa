const NodeRSA = require('node-rsa');

class Encryptor {

  constructor(key){
    this.key = key
  }

  encrypt(data){
    return this.key.encrypt(data)
  }

  decrypt(data){
    return this.key.decrypt(data)
  }

  static fromPem(pem){
    const key = new NodeRSA()
    key.importKey(pem)
    return new Encryptor(key)
  }
}


const generateKey = args => NodeRSA(args)

class JwksEncryptor {

  jwks = [];

  refresh(url){
    return fetch(url)
      .then(data =>  data.json())
      .then(data => {
        this.jwks = data || []
        return data
      })
  }
  encryptorByKid(kid){
    const jwk = this.jwks.find(e => e && e.kid === kid)
    if( !jwk ){
      throw new Error(`0 of ${this.jwks.length} JWKs matched kid '${kid}'`)
    }
    if( !jwk.rsaPublicKey ) {
      throw new Error(`JWK of kid '${kid}' must have a 'rsaPublicKey' pem property`)
    }
    const key = new NodeRSA()
    key.importKey(jwk.rsaPublicKey)
    return new Encryptor(key)
  }
}
Object.assign(JwksEncryptor, {
  NodeRSA,
  Encryptor,
  generateKey
})
;(global || window).JwksEncryptor = JwksEncryptor
