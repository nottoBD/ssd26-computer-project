# PKI Integration Verification README

This README lists commands to verify the PKI setup after running `bash/2-pki_setup.sh` and `bash/3-run.sh`. Run these from the project root to ensure the certificate chain is effective and gap-free.

## Inspect Individual Certificates

### Root CA

```bash
openssl x509 -in pki/roots/step-root.pem -noout -text -fingerprint -sha256
```


### Intermediate CA
```bash
openssl x509 -in pki/roots/intermediate_ca.crt -noout -text -fingerprint -sha256
```

### Leaf Certificates 
```bash
for leaf in nginx server logger client; do
  echo "Inspecting $leaf:"
  openssl x509 -in pki/leafs/$leaf/fullchain.crt -noout -text -fingerprint -sha256 | head -n 30
  echo ""
done
```

## Verify Chain of Trust

### With Intermediates as Untrusted

```bash
for leaf in nginx server logger client; do
  echo "Verifying $leaf:"
  openssl verify -verbose -CAfile pki/roots/step-root.pem -untrusted pki/roots/intermediate_ca.crt pki/leafs/$leaf/fullchain.crt
  echo ""
done
```


## Simulate TLS Handshake
### OpenSSL Client
```bash
echo | openssl s_client -connect localhost:3443 -CAfile pki/roots/step-root.pem -showcerts -quiet
```

### Curl Verbose
```bash
curl -v --cacert pki/roots/step-root.pem https://localhost:3443/api/health/
```

## Check Certificate Validity Dates
### Root CA
```bash
openssl x509 -in pki/roots/step-root.pem -noout -dates
```

### Intermediate CA
```bash
openssl x509 -in pki/roots/intermediate_ca.crt -noout -dates
```

### Leaf Certificates
```bash
for leaf in nginx server logger client; do
  echo "Validity dates for $leaf:"
  openssl x509 -in pki/leafs/$leaf/fullchain.crt -noout -dates | head -n 2
  echo ""
done
```


## Check Revocation (OCSP/CRL)
This project uses the free community edition of Smallstep's step-ca, which does not support OCSP responders. For CRL, while passive revocation is available (e.g., via step ca revoke), we have opted not to enable active CRL distribution points or endpoints in certificates to keep the setup minimal and aligned with core project requirements.
### Check Certificate Extensions
```bash
openssl x509 -in pki/leafs/nginx/fullchain.crt -noout -ext crlDistributionPoints,ocsp
```


## Additional Integrity Checks
### No PrivKey in Chain
```bash
grep -q "PRIVATE KEY" pki/leafs/nginx/fullchain.crt && echo "Error: Private key in chain!" || echo "OK: No private keys in chain"
```

### Root PubKey Fingerprint
```bash
openssl x509 -in pki/roots/step-root.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 | awk '{print $2}'
```

## Docker Mount Inspection
```bash
docker inspect nginx | jq '.[0].Mounts[] | select(.Destination | contains("/etc/ssl"))'
```

