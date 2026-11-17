# CryptoProg
cd hash
make
./hash test.txt
cd ../cipher
make
./cipher aes -e ../hash/test.txt encrypted.bin mypassword
./cipher aes -d encrypted.bin decrypted.txt mypassword
diff ../hash/test.txt decrypted.txt
