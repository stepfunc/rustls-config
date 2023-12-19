# Creating test certificates

Use the [step](https://smallstep.com/docs/step-cli/) CLI.

## Self-signed certificate and private key with 30 year validity (262,800 hours)
```
> step certificate create bill bill.crt bill.priv --san other --kty=OKP --profile self-signed --subtle --no-password --insecure --not-after=262800h
``` 

## Single-layer authority w/ a client and server and 30 year cert validity

```
step certificate create --profile=root-ca --kty=OKP TestRootCA ca.crt ca.key --no-password --insecure

step certificate create --csr --san server42 --profile=leaf --kty=OKP myserver server.csr server.key --no-password --insecure
step certificate sign --not-after 262800h .\server.csr .\ca.crt .\ca.key | out-file -encoding ascii server.crt

step certificate create --csr --san client21 --profile=leaf --kty=OKP myclient client.csr client.key --no-password --insecure
step certificate sign --not-after 262800h .\client.csr .\ca.crt .\ca.key | out-file -encoding ascii client.crt
```