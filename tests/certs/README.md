# Creating test certificates

Use the [step](https://smallstep.com/docs/step-cli/) CLI to generate self-signed certs and authority signed certs w/ SAN extension.

## Self-signed certificate and private key with 30 year validity (262,800 hours)
```
> step certificate create bill bill.crt bill.priv --san other --kty=OKP --profile self-signed --subtle --no-password --insecure --not-after=262800h
``` 

## Single-layer authority w/ a client and server and 30 year cert validity

```shell
step certificate create --profile=root-ca --kty=OKP TestRootCA ca.crt ca.key --no-password --insecure

step certificate create --csr --san server42 --profile=leaf --kty=OKP myserver server.csr server.key --no-password --insecure
step certificate sign --not-after 262800h .\server.csr .\ca.crt .\ca.key | out-file -encoding ascii server.crt

step certificate create --csr --san client21 --profile=leaf --kty=OKP myclient client.csr client.key --no-password --insecure
step certificate sign --not-after 262800h .\client.csr .\ca.crt .\ca.key | out-file -encoding ascii client.crt
```

## Use openssl to generate authority signed certs w/o the SAN extension with 30 year validity

```shell
openssl req -x509 -newkey rsa:4096 -keyout ./ca.key -out ./ca.crt -subj "CN=TestRootCA" -nodes -days 10950

openssl req -new -newkey rsa:4096 -keyout ./server.key -out ./server.csr -subj "/CN=myserver" -nodes -days 10950
openssl x509 -req -days 10950 -in ./server.csr -CA ./ca.crt -extfile v3.ext -CAkey ./ca.key -set_serial 1 -out ./server.crt -sha256

openssl req -new -newkey rsa:4096 -keyout ./client.key -out ./client.csr -subj "/CN=myclient" -nodes -days 10950
openssl x509 -req -days 10950 -in ./client.csr -CA ./ca.crt -extfile v3.ext -CAkey ./ca.key -set_serial 1 -out ./client.crt -sha256
```
