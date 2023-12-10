# webapp
## Prerequisites for building
* JVM
* Mysql

## How to depoly

* install JVM
* install Mysql
* compile code
* deploy package

## How to upload certificate
aws iam upload-server-certificate --server-certificate-name certificate_object_name --certificate-body file:///Users/feynman/Downloads/demo.feynman-cloud.online/certificate.crt --private-key file:///Users/feynman/Downloads/demo.feynman-cloud.online/private.key --certificate-chain file:///Users/feynman/Downloads/demo.feynman-cloud.online/ca_bundle.crt --region us-west-2

aws iam list-server-certificates --region us-west-2