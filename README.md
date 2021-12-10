# Donut_Injector
This repo gives you an injector that bypasses static and dynamic analysis. The shellcodes that are injected must be encrypted with a key and 
decrypted at runtime to avoid detection.

This is a c# injector that holds an encrypted shellcode and decrypts the shellcode before injecting.
This injector also encrypted the process_name in which shellcode will be injected as further obfuscation.
This encryption/decryption process is used  to bypass static analysis and to some extent dynamic analysis
The injection template has been found and modified from ExcelNtDonut, hence the modified malware name is Donut.
The AES_shellcode_encryptor had been provide in the repository: https://github.com/shaddy43/AES_Shellcode_Encryptor
