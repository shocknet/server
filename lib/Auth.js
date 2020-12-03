
const jwt = require('jsonwebtoken')
const uuid = require('uuid')
const Storage = require('node-persist')


Storage.init({
dir: './.storage'
})

class Auth {
    readSecrets = async () => {
        const secrets = await Storage.getItem('auth/secrets')

        if (secrets) {
            return secrets
        }

        const newSecrets = await Storage.setItem('auth/secrets', {})

        return newSecrets
    }

    async writeSecrets(key, value) {
        const allSecrets = await this.readSecrets()
        const newSecrets = await Storage.setItem('auth/secrets', {
            ...allSecrets,
            [key]: value
        })
        return newSecrets
    }

    async generateToken(subdomain) {
        if(!subdomain){
            throw new Error('no subdomain provided to generate token')
        }
        const timestamp = Date.now()
        const { v1: uuidv1 } = uuid
        const secret = uuidv1()
        //logger.info('Generating new secret...')
        const token = jwt.sign(
            {
                data: { 
                    timestamp,
                    subdomain
                }
            },
            secret,
            { expiresIn: '500h' }
        )
        //logger.info('Saving secret...')
        await this.writeSecrets(timestamp, secret)
        return token
    }

    async validateToken(token,subdomain) {
        if(!subdomain){
            throw new Error('no subdomain provided to validate token')
        }
        const jwtData = jwt.decode(token).data
        const key = jwtData.timestamp
        const tokenSubdomain = jwtData.subdomain
        if(subdomain !== tokenSubdomain){
            throw new Error('unauthorized subdomain')
        }
        const secrets = await this.readSecrets()
        const secret = secrets[key]
        if (!secret) {
            throw Error('invalid token provided')
        }
        await new Promise((resolve, reject) => {
            jwt.verify(token, secret, (err, decoded) => {
            if (err) {
                //logger.info('validateToken err', err)
                reject('invalid token provided')
            } else {
                // logger.info('decoded', decoded)
                resolve()
            }
            })
        })
        return true
        
    }
}

module.exports = new Auth()
