#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>

using namespace std;
using namespace CryptoPP;

int main(int argc, char* argv[]) {
    if (argc != 5) {
        cerr << "Использование: " << argv[0] << " <-e|-d> <вход> <выход> <пароль>" << endl;
        return 1;
    }

    string mode = argv[1];
    string inFile = argv[2];
    string outFile = argv[3];
    string password = argv[4];

    CryptoPP::byte key[16];
    CryptoPP::byte iv[16];

    PKCS12_PBKDF<SHA256> pbkdf;
    CryptoPP::byte salt[] = "salt"; 
    
    pbkdf.DeriveKey(key, sizeof(key), 0, (CryptoPP::byte*)password.c_str(), password.size(), salt, sizeof(salt)-1, 1000, 0.0);
    pbkdf.DeriveKey(iv, sizeof(iv), 0, (CryptoPP::byte*)password.c_str(), password.size(), salt, sizeof(salt)-1, 1001, 0.0);

    ifstream in(inFile, ios::binary);
    if (!in) {
        cerr << "Ошибка: не удалось открыть " << inFile << endl;
        return 1;
    }
    string data((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();

    string result;

    try {
        if (mode == "-e") {
            CBC_Mode<AES>::Encryption e;
            e.SetKeyWithIV(key, sizeof(key), iv);
            StringSource(data, true, new StreamTransformationFilter(e, new StringSink(result)));
        } 
        else if (mode == "-d") {
            CBC_Mode<AES>::Decryption d;
            d.SetKeyWithIV(key, sizeof(key), iv);
            StringSource(data, true, new StreamTransformationFilter(d, new StringSink(result)));
        } 
        else {
            cerr << "Ошибка: используйте -e или -d" << endl;
            return 1;
        }

        ofstream out(outFile, ios::binary);
        out.write(result.c_str(), result.size());
        out.close();
        cout << "Готово! Файл: " << outFile << endl;

    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }
    return 0;
}