# warning: do not use the certificates produced by this tool in production.
# This is for testing purposes only
set -e

script_dir="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
openssl_ext_file="${script_dir}/generate_test_certs.openssl.cnf"

rm -rf "${script_dir}/test_certs"
mkdir "${script_dir}/test_certs"
cd "${script_dir}/test_certs"

echo "GENERATED CERTIFICATES FOR TESTING ONLY." >> ./README.txt
echo "DO NOT USE THESE CERTIFICATES IN PRODUCTION" >> ./README.txt

# certificate authority
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 1826 -extensions "certificate_authority" -key "ca.key" -out "ca.crt" -subj "/C=LS/ST=NA/L=Http Input/O=Logstash/CN=root" -config "${openssl_ext_file}"

# es from ca
openssl genrsa -out "es.key" 4096
openssl req -new -key "es.key" -out "es.csr" -subj "/C=LS/ST=NA/L=Http Input/O=Logstash/CN=server" -config "${openssl_ext_file}"
openssl x509 -req -extensions "elasticsearch_server" -extfile "${openssl_ext_file}" -days 1096 -in "es.csr" -CA "ca.crt" -CAkey "ca.key" -set_serial 03 -sha256 -out "es.crt"
openssl x509 -in "es.crt" -outform der | sha256sum | awk '{print $1}' > "es.der.sha256"

# ls from ca
openssl genrsa -out "ls.key" 4096
openssl req -new -key "ls.key" -out "ls.csr" -subj "/C=LS/ST=NA/L=Http Input/O=Logstash/CN=server" -config "${openssl_ext_file}"
openssl x509 -req -extensions "logstash_client" -extfile "${openssl_ext_file}" -days 1096 -in "ls.csr" -CA "ca.crt" -CAkey "ca.key" -set_serial 03 -sha256 -out "ls.crt"
openssl x509 -in "ls.crt" -outform der | sha256sum | awk '{print $1}' > "ls.der.sha256"

# verify :allthethings
openssl verify -CAfile "ca.crt" "es.crt"
openssl verify -CAfile "ca.crt" "ls.crt"

# create pkcs12 keystores (pass:12345678)
openssl pkcs12 -export -in "ls.crt" -inkey ls.key -out "ls.p12" -name "logstash" -passout 'pass:12345678'

# use java keytool to convert all pkcs12 keystores to jks-format keystores (pass:12345678)
keytool -importkeystore -srckeystore "ls.p12" -srcstoretype "pkcs12" -srcstorepass "12345678" -destkeystore "ls.jks" -deststorepass "12345678" -alias logstash

# cleanup csr, we don't need them
rm -rf *.csr
