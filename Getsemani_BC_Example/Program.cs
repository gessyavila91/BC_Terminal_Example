using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

public class PgpExample {
    private const string PublicKeyPath = @"C:\Users\getsemani.avila\Desktop\TEST_PASS_0x2B63FC09_public.asc";
    private const string PrivateKeyPath = @"C:\Users\getsemani.avila\Desktop\TEST_PASS_0x2B63FC09_SECRET.asc";
    private const string Password = "password";// Cambia esto por la contraseña de tu llave privada

    public static void Main() {
        var originalMessage = "GETSEMANI";
        Console.WriteLine($"Mensaje Original: {originalMessage}");

        var encryptedMessage = Encrypt(originalMessage, PublicKeyPath);
        Console.WriteLine($"Mensaje Encriptado: {encryptedMessage}");

        var decryptedMessage = Decrypt(encryptedMessage, PrivateKeyPath, Password);
        Console.WriteLine($"Mensaje Desencriptado: {decryptedMessage}");
    }

    public static string Encrypt(string plainText, string publicKeyPath) {
        PgpPublicKey encKey = ReadPublicKey(publicKeyPath);

        using (MemoryStream outputBytes = new MemoryStream()) {
            PgpCompressedDataGenerator compGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            Stream outputStream = compGen.Open(outputBytes);

            PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.TripleDes);

            encGen.AddMethod(encKey);
            Stream encryptedOut = encGen.Open(outputStream, new byte[4096]);

            PgpLiteralDataGenerator litGen = new PgpLiteralDataGenerator();
            Stream litOut = litGen.Open(encryptedOut, PgpLiteralData.Binary, PgpLiteralData.Console, plainText.Length,
                DateTime.UtcNow);

            litOut.Write(System.Text.Encoding.UTF8.GetBytes(plainText), 0, plainText.Length);
            litOut.Close();
            encryptedOut.Close();
            outputStream.Close();
            compGen.Close();

            return Convert.ToBase64String(outputBytes.ToArray());
        }
    }

    public static string Decrypt(string cipherText, string privateKeyPath, string password) {
        // Convertir la cadena cifrada en un flujo de entrada
        using (Stream inputStream = new MemoryStream(Encoding.UTF8.GetBytes(cipherText)))
        using (Stream decodedStream = PgpUtilities.GetDecoderStream(inputStream)) {
            // Inicializar la factoría de objetos PGP
            PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(decodedStream);
            PgpObject pgpObject = pgpObjectFactory.NextPgpObject();

            // Si el objeto es de tipo comprimido, obtener el contenido real
            if (pgpObject is PgpCompressedData) {
                PgpCompressedData compressedData = (PgpCompressedData)pgpObject;
                PgpObjectFactory innerFactory = new PgpObjectFactory(compressedData.GetDataStream());
                pgpObject = innerFactory.NextPgpObject();
            }

            // Asegurarse de que el objeto ahora es una lista de datos encriptados
            if (!(pgpObject is PgpEncryptedDataList)) {
                throw new Exception("El mensaje no es una lista de datos encriptados PGP.");
            }

            PgpEncryptedDataList encryptedDataList = (PgpEncryptedDataList)pgpObject;
            PgpPublicKeyEncryptedData publicKeyEncryptedData = encryptedDataList.GetEncryptedDataObjects()
                .Cast<PgpPublicKeyEncryptedData>().FirstOrDefault();

            if (publicKeyEncryptedData == null) {
                throw new Exception("No se encontró ningún dato encriptado con clave pública PGP.");
            }

            // Leer la clave privada
            PgpPrivateKey privateKey = ReadPrivateKey(privateKeyPath, password);

            // Desencriptar
            using (Stream clear = publicKeyEncryptedData.GetDataStream(privateKey)) {
                PgpObjectFactory plainFact = new PgpObjectFactory(clear);
                PgpObject messageObject = plainFact.NextPgpObject();

                if (messageObject is PgpLiteralData) {
                    PgpLiteralData literalData = (PgpLiteralData)messageObject;
                    using (Stream literalDataStream = literalData.GetInputStream())
                    using (StreamReader reader = new StreamReader(literalDataStream)) {
                        return reader.ReadToEnd();
                    }
                }
                else {
                    throw new Exception("El mensaje no es un dato literal simple.");
                }
            }
        }
    }

    private static PgpPublicKey ReadPublicKey(string publicKeyPath) {
        using (Stream keyIn = File.OpenRead(publicKeyPath)) {
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings()) {
                foreach (PgpPublicKey key in kRing.GetPublicKeys()) {
                    if (key.IsEncryptionKey) {
                        return key;
                    }
                }
            }
        }
        throw new ArgumentException("Can't find encryption key in public key ring.");
    } 
    private static PgpPrivateKey ReadPrivateKey(string privateKeyPath, string password) {
        try {
            using (Stream keyIn = File.OpenRead(privateKeyPath)) {
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

                foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings()) {
                    foreach (PgpSecretKey key in kRing.GetSecretKeys()) {
                        Console.WriteLine("Checking key...");
                        // if (key.IsSigningKey) continue; // Uncomment this if you want to skip signing keys.

                        PgpPrivateKey privateKey = key.ExtractPrivateKey(password.ToCharArray());

                        if (privateKey != null) {
                            Console.WriteLine("Private key found.");
                            return privateKey;
                        }
                        else {
                            Console.WriteLine("Private key extraction returned null.");
                        }
                    }
                }
            }
        }
        catch (Exception ex) {
            Console.WriteLine($"Error: {ex.Message}");
        }

        throw new ArgumentException("Can't find decryption key in private key ring.");
    }

}
