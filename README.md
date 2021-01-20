# Trusted Platform Module (TPM) and Google Cloud KMS based mTLS auth to HashiCorp Vault

[HashiCorp Vault](https://www.vaultproject.io/) is a flexible secrets engine that can store any number of passwords, keys, tokens you or your application would need.  It can store PKI private keys, perform symmetric encryption, provide "on-demand" access_tokens, and has many other capabilities you can find at [Vault Secrets Engines](https://www.vaultproject.io/docs/secrets/index.html).  This article focuses [TLS Certificates Auth Method](https://www.vaultproject.io/docs/auth/cert.html) is sealed within a [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module) and also as a side-show, within Google Cloud KMS

As an intro of sorts, Vault is a really popular and flexible system to store secrets...but the question comes up how a clients authenticate _to_ Vault itself.  An administrator can configure Vault to allow Alice access to a secret but not Bob...how does Vault identity any given token request is on behalf of Alice?  Well, Vault ofcourse offers numerous [Vault Authentication](https://www.vaultproject.io/docs/concepts/auth.html) mechanism which you can employ depending on your needs.  At the most basic default level, a `VAULT_TOKEN` is given to Alice by an administrator that identifies the caller.  Alice would use that token to authenticate and gain access to a secret as dictated by some policy.  There are many other mechanisms an administrator can employ and you can read about them all in link above or if you are specifically interested in GCP, see [Vault auth and secrets on GCP](https://medium.com/google-cloud/vault-auth-and-secrets-on-gcp-51bd7bbaceb).

The specific advantage to using the `TPM` to save the mTLS key is that you can have assurances the key wasn't exported or used ANYWHERE else.  If done correctly, the key will forever be bound unexportable inside that TPM...What that means is that you can be assured this specific client machine is authenticating to vault (or making an TLS connectin, signing, etc)..that capability is really pretty neat.

anyway,


This article is divided into several steps:

1. Creating public-private keys and x509 certificate.
2. Install Vault and configure for [certificate auth](https://www.vaultproject.io/docs/auth/cert.html).
   - Enable access policy for keypair generated in (1)
3. PEM (optional):
   - Use key files generated in (1) to confirm mTLS auth to Vault 
4. TPM
   - Create GCP VM with a TPM
   - Embed private key in step 1 into the TPM
   - Access Vault using the TPM to sign the mTLS session
5. KMS (optional)
   - Import the keypair to Google Cloud KMS
   - Enable Google Cloud Application Default Credentials on client to access KMS Key
   - Access Vault using KMS key to sign the mTLS session.


>> IMPORTANT: you must use at MOST go1.13 since versions beyond that uses RSA-PSS (ref [32425](https://github.com/golang/go/issues/32425)) and at least KMS 
and TPM only support RSA


>> Note: I'm not covering techniques to scale or productionize any of this...this is just a POC showing this is possible and is NOT supported by google.  _caveat emptor_

If you are interested in this, another variation of using an embedded certificate can be found here:

- [Using TPM-embedded GCP credentials](https://github.com/salrashid123/oauth2#usage-tpmtokensource)
- [Using Trusted Platform Module (TPM) C openssl extensions to sign,decrypt and get Google Cloud credentials](https://medium.com/google-cloud/using-trusted-platform-module-tpm-c-openssl-extensions-to-sign-decrypt-and-get-google-cloud-dec4a46be378)


but this is just about Vault... 


### Setup

Lets get started. Since this is just a POC, we will run Vault on the same system that you will run the 'client' (i know,realistic).


#### Create Certificate authority and keypair

For this demo, we will create a stand-alone CA and a pair of keys:

You can use the certs listed under `certs/` folder but if you wanted to set all this up on your own, see this [receipe](https://github.com/salrashid123/gcegrpc/tree/master/certs)

You can see the details of the client cert by running:

```
openssl x509 -in client.crt -text -noout
```

Also note we need an x509 cert here specifically since we're going to use mTLS (a private key PEM isn't going to be sufficient).


#### TPM

Now create a VM with a TPM chip

- Create Shielded VM:

```bash
gcloud  compute  instances create shielded-5 --zone=us-central1-a --machine-type=n1-standard-1 --subnet=default --network-tier=PREMIUM  --no-service-account --no-scopes --image=ubuntu-1804-bionic-v20191002 --image-project=gce-uefi-images --no-shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring
```

Note, if you intend to use this same VM for KMS flows, add on (replace the YOUR_PROJECT_NUMBER)

```bash
--service-account=$YOUR_PROJECT_NUMBER-compute@developer.gserviceaccount.com --scopes=https://www.googleapis.com/auth/cloud-platform 
```

- Install Vault

SSH to the shielded VM

```
gcloud compute ssh shielded-5

$ sudo su -
$ apt-get update && apt-get install git jq
$ git clone git clone https://github.com/salrashid123/vault-mtls.git
$ cd vault-mtls
```

[Install golang 1.12+](https://golang.org/dl/)


[Install Vault](https://www.vaultproject.io/docs/install/index.html) and unseal:

```bash
export VAULT_ADDR='https://localhost:8200'
export VAULT_CACERT=certs/CA_crt.pem

vault server -config=server.conf &
```

Init vault an unseal (ofcourse your keys will be different!)

```bash
$ vault operator init
    Unseal Key 1: U4FPnoQhEhEuDoe1a+B5vvPMfbSIU7jH290etqrpTgUz
    Unseal Key 2: 7ep4pycGEf6hjd1YAIAAwKknvxtbQvmCj0V4eu8ysjfq
    Unseal Key 3: S5qRG+j4VW2WB/3URQmXnqs3n7RiCdZC6HIfGZRol0BA
    Unseal Key 4: OJM1CXYzHF82v04NRaFsqZPbE+3mZIaUAIujSxv+K1pL
    Unseal Key 5: qG6Sd+/svJen/xtPzUsnyEhnfeuaSQY2lVibxH4loDle

    Initial Root Token: s.kWMwmmLO8TBSOCb3kyh9R9wz

$ export VAULT_TOKEN=s.kWMwmmLO8TBSOCb3kyh9R9wz

$ vault  operator unseal 
```


Enable various other secrets engines and cert auth

```
vault secrets enable -version=2  -path=kv kv
vault secrets enable transit
vault policy write token-policy  hcl/token_policy.hcl
vault policy write secrets-policy  hcl/secrets_policy.hcl
vault write -f transit/keys/foo
```

For [Vautl Cert Auth](https://www.vaultproject.io/docs/auth/cert.html)

```bash
$ vault auth enable cert

$ vault write auth/cert/certs/web   \
        display_name=web         policies=token-policy,secrets-policy         certificate=@certs/client.crt         ttl=3600
```


Verify cert auth works:

```bash
curl \
    -s \
    --request POST \
    --cacert certs/CA_crt.pem \
    --cert certs/client.crt \
    --key certs/client.key \
    --data '{"name": "web"}' \
    https://localhost:8200/v1/auth/cert/login | jq '.'
```

You should see an entry for the VAULT Token..yeah!

Now use it

```
export VAULT_ADDR='https://localhost:8200'
export VAULT_CACERT=certs/CA_crt.pem
export VAULT_TOKEN=...

vault kv put kv/message foo=world
vault kv get kv/message
```

#### PEM (optional)

Ok, all we've done now is setup Vault.  If you want to use golang Vault client to get the same token as above using the PEM **FILES** read on, otherwise skip.

The only reason i've added this section here is simply because in the course of writing the various [crypto.Singer](https://github.com/salrashid123/signer) implementations, I found it useful to _reimplement_ PEM based mTLS using my own custom `crypto.Signer`.  Yes, i know, this step is equivalent to 'just using mTLS' that comes out of the box with golang...

If you're still reading,

in `main.go`, note:

```golang
import (
    salpem "github.com/salrashid123/signer/pem"
)
	caCert, err := ioutil.ReadFile("certs/CA_crt.pem")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r, err := salpem.NewPEMCrypto(&salpem.PEM{
		PublicCertFile: "certs/client.crt",
		PublicPEMFile:  "certs/client.pem",
        PrivatePEMFile: "certs/client.key",
		ExtTLSConfig: &tls.Config{
			RootCAs:        caCertPool,
		},        
	})
```

All that does is use the PEM files we already have there anyway.

```
go run main.go
```

What you should see is just a VAULT token...you'd use that token to get other secrets but were not showing that yet.


#### TPM

This step is involved and at the moment very manual since we need to embed the private key into the TPM.

You can embed the key to the tpm using either

1. [tpm2_tools](https://github.com/tpm2-software/tpm2-tools).   See instructions here
    [Installing TPM2Tools](https://github.com/salrashid123/tpm2#installing-tpm2_tools-golang)
```bash
    	tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx
	    tpm2_import -C primary.ctx -G rsa -i client.key -u key.pub -r key.prv
	    tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
	    tpm2_evictcontrol -C o -c key.ctx 0x81010002
```

2. Using [go-tpm](https://github.com/google/go-tpm) wrapper library.  I've combined all the steps you'd need in the sample below
    [import_gcp_sa.go](https://github.com/salrashid123/tpm2/blob/master/utils/import_gcp_sa.go)

```bash
        go run main.go --pemFile client.key --primaryFileName=primary.bin --keyFileName=key.bin --logtostderr=1 -v 10
```

Either way, the `client.pem` should now be persisted inside the TPM at handle `0x81010002`

As mentioned, that means is the key now exists inside the TPM and the TPM can use it to sign some data you ask it to using the key...the key itself never leaves the coprocessor; you'll never see it or need it..you can safely delete private key file from the filesystem. 

You can also generate a privatekey directly on the TPM (meaning you'll never see the key on rust ever).  That procedure is described [here](https://github.com/salrashid123/tpm2/tree/master/sign_with_rsa).  Basically, you ask the TPM to create the key instead of importing an external one.  From there, just make it peristent. 

```bash
    tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
    tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx
    tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
    tpm2_readpublic -c key.ctx -f PEM -o public.pem
    tpm2_evictcontrol -C o -c key.ctx 0x81010002 
```
Note, if you've already have something persisted at that handle, you need to evict it first: `tpm2_evictcontrol -C o -c 0x81010002` 

 If you choose to use a Key thats on the TPM from the get-go, you need to somehow setup an `x509` cert based off of it.  I haven't found a way to do that with `tpm2_tools`  but I did write the following snippet which uses `go-tpm` to create a canned cert:

- Create x509 cert from PEM file on TPM or KMS: [certgen.go](https://github.com/salrashid123/signer/blob/master/certgen/certgen.go)

Now that the key is persisted, we can run `main.go`  and specify the TPM's handle where we saved the key

```golang
import (
    saltpm "github.com/salrashid123/signer/tpm"
)
	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: "/dev/tpm0",
		TpmHandle: 0x81010002,

		PublicCertFile: "certs/client.crt",
		ExtTLSConfig: &tls.Config{
			RootCAs:        caCertPool,
		},
	})
```

If everthing went ok :), you should see the VAULT token which you can further use to get access to other secrets..yeah

#### KMS (optional)

In this mode, we will import the private key into Google Cloud KMS and use that to sign the mTLS connection.  All crypto operations happen on GCP and you never need to have physical file access to the privatekey.  This is similar to using the TPM except the signing operation is via remote API call.

To use this mode, the VM you you will run the client on will use its own Credentials to gain access to the KSM key to Sign the TLS connection.  You do not have to run the whole setup on a SHielded VM since...we're not using a TPM (this secttion you can run on your laptop...if you do, omit the part about GCE VM below...)

Basically, where the client runs:

1. Import `client.key` to KMS.
2. Allow the VM where you run this access to the Key to `Sign`
3. VM uses Application Default Credentials to access a KMS key and sign the mTLS connection.


Yes, you can ask why not just use [Vault GCP Auth](https://www.vaultproject.io/docs/auth/gcp.html) which itself use the [Application Default Credentials](https://cloud.google.com/docs/authentication/production#finding_credentials_automatically) in the first place...

Anyway, you first need to import the key...i've already done that here so follow these steps to import the key.  

- [mTLS with Google Cloud KMS](https://medium.com/google-cloud/mtls-with-google-cloud-kms-fb17f3ed8219)

You will need to authorize the GCE VM's service account access to the KMS key (if you're )

Anyway, if you've imported the key and authorized either your own credentials or the GCE's default account, uncomment the following section to enable the KMS based mTLS:

```golang
import (
    salkms "github.com/salrashid123/signer/kms"
)
	r, err := salkms.NewKMSCrypto(&salkms.KMS{
		PublicKeyFile: "certs/client.crt",
		ProjectId:     "mineral-minutia-820",
		LocationId:    "us-central1",
		KeyRing:       "mycacerts",
		Key:           "client",
		KeyVersion:    "2",
		ExtTLSConfig: &tls.Config{
			RootCAs:        caCertPool,
		},
	})
```


### Conclusion

This is just a proof of concept...but it shows a powerful capability: you can reasonably assure a given machine+TPM is the _only_ one that can access Vault as an identity...i stated reasonably because we're, you know, allowing the private key to exist on disk and wherever it went on transit.  If you securely provision the key on the TPM (eg, by generating it on TPM) and bind it to the TPM `FIXED_TPM` you've provided some additional assurances on the system making the call...

In a future article,  i'll cover access policies for the TPM:  for example, you can say something like "only allow access to this secret on the TPM if the operating system matches these exact properties i expect or the [PCR](https://docs.microsoft.com/en-us/windows/security/information-protection/tpm/switch-pcr-banks-on-tpm-2-0-devices value) matches what i expect...(eg, make sure the system hasn't been altered, etc)..

- [IMA Policies](https://www.kernel.org/doc/Documentation/ABI/testing/ima_policy)
- [seal-unseal with tpm and PCR value](https://github.com/salrashid123/tpm2/tree/master/seal_to_tpm)


### References
- Various TPM2 procedures in `tpm2_tools` and `go-tpm`:  [salrashid123/tpm2](https://github.com/salrashid123/tpm2)
- Import Google Cloud Service Account to TPM: [import_gcp_sa.go](https://github.com/salrashid123/tpm2/blob/master/utils/import_gcp_sa.go)
- golang [crypto.Signer](https://github.com/salrashid123/signer) for TPM, KMS
- Google Cloud TokenSource using TPM based keys: [salrashid123/oauth2](https://github.com/salrashid123/oauth2)
- OpenSSL EVP for TPM2 [tpm2_evp_helloworld](https://github.com/salrashid123/tpm2_evp_sign_decrypt#usage)
- [mTLS with Google Cloud KMS](https://medium.com/google-cloud/mtls-with-google-cloud-kms-fb17f3ed8219)
- Google Cloud KMS based signer: [kms_golang_signer](https://github.com/salrashid123/kms_golang_signer)

