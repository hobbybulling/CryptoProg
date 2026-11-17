#include <iostream>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

using namespace std;
using namespace CryptoPP;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Использование: " << argv[0] << " <файл>" << endl;
        return 1;
    }

    try {
        SHA256 hash;
        string digest;
        
        FileSource fs(argv[1], true, 
            new HashFilter(hash, 
                new HexEncoder(new StringSink(digest))
            )
        );
        
        cout << digest << endl;
    } catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }
    return 0;
}