using System.Text;
using C_Sharp_Secure_Coding___In_Memory_Encryption;

//Plaintext

String valueToEncrypt = "Hello World";//Value To Be Encrypted

//Encrypt

byte[] plaintext = ASCIIEncoding.ASCII.GetBytes(valueToEncrypt);//Binary Encoded Version Of Value To Be Encrypted
byte[] ciphertext = Windows_DPAPI.Protect(plaintext, true, System.Security.Cryptography.DataProtectionScope.LocalMachine);//Encrypt Data

Console.WriteLine("Plaintext Value (Before Encryption): " + valueToEncrypt);
Console.WriteLine("");
Console.WriteLine("Ciphertext Value (After Encryption): " + System.Convert.ToBase64String(ciphertext));
Console.WriteLine("");

//Remove Plaintext Values From Memory

valueToEncrypt = null;
plaintext = null;
GC.Collect();//Invoke Garbage Collector

//Decrypt

plaintext = Windows_DPAPI.Unprotect(ciphertext, true, System.Security.Cryptography.DataProtectionScope.LocalMachine);//Decrypt Data
String decryptedValue = ASCIIEncoding.ASCII.GetString(plaintext);//Recreate Original Object (String) From Binary Encoded Version
Console.WriteLine("Plaintext Value (After Decryption): " + decryptedValue);