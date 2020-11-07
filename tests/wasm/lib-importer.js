import libPolyRecorder from '../../hcl';

const initLibrary = async (wasmUrl) => {
    const module = await new Promise(resolve => {
        const module = libPolyRecorder({
            noInitialRun: true,
            locateFile: url => {
                if (url.endsWith(".wasm")) {
                    return wasmUrl;
                }
                return url;
            },
            onRuntimeInitialized: () => {
                delete module.then;
                resolve(module);
            }
        })
    })
    window.module = module

    try {
        const password = new module.Password()
        password.InitializeSymmetricCipher()
        password.SetDomain('https://www.google.com/')
        password.SetName('Google')
        password.SetLogin('Neodar')
        password.SetPassword('toto1234')
        const secret = new module.SymmetricKey()
        secret.SetKey('aledoskour')
        let start = Date.now()
        const serialized = password.Serialize('aledoskour')
        console.log('Serialize', Date.now() - start)
        console.log(serialized)
        start = Date.now()
        const outSecret = module.Secret.Deserialize('aledoskour', serialized)
        console.log('Deserialize', Date.now() - start)
        console.log(outSecret.CorrectDecryption())
        console.log(outSecret.GetSecretTypeName())
        if (outSecret.GetSecretTypeName() === 'password') {
            const outPassword = module.CastSecretToPassword(outSecret)
            console.log(outPassword.GetDomain())
            console.log(outPassword.GetName())
            console.log(outPassword.GetLogin())
            console.log(outPassword.GetPassword())
        }
        console.log('### Done Symmetric tests ###')
        // const password2 = new module.Password()
        // password2.InitializeAsymmetricCipher()
        // password2.SetDomain('https://www.facebook.com/')
        // password2.SetName('Facebook')
        // password2.SetLogin('La Bonne Bibe')
        // password2.SetPassword('plopplop')
        // const rsaKeyPair = module.GenerateRSAKeyPair(512)
        // const publicKey = rsaKeyPair.GetPublic()
        // const privateKey = rsaKeyPair.GetPrivate()
        // const serialized2 = password2.SerializeAsymmetric(publicKey.ExtractKey())
        // console.log(serialized2)
        // const outSecret2 = module.Secret.DeserializeAsymmetric(privateKey.ExtractKey(), serialized2)
        // console.log(outSecret2.CorrectDecryption())
        // console.log(outSecret2.GetSecretTypeName())
        // if (outSecret2.GetSecretTypeName() === 'password') {
        //     const outPassword = module.CastSecretToPassword(outSecret)
        //     console.log(outPassword.GetDomain())
        //     console.log(outPassword.GetName())
        //     console.log(outPassword.GetLogin())
        //     console.log(outPassword.GetPassword())
        // }
    } catch (error) {
        console.error(error)
        console.error(module.GetExceptionMessage(error))
    }

}

initLibrary('../../hcl.wasm')
