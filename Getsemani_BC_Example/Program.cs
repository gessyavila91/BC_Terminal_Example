/*
 * Desarrollado por Getsemani Avila Quezada.
 * Fecha: 10/08/2023.
 * 
 * Licencia: Software Libre. Se permite la distribución, modificación, y uso de este software
 * con la condición de que el nombre del autor original, Getsemani Avila Quezada, sea reconocido
 * en cualquier versión derivada o uso del software.
 *
 * Descripción:
 * Esta clase proporciona métodos para encriptar y desencriptar mensajes utilizando Bouncy Castle y llaves PGP.
 */
using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

public class PgpExample {
    private const string PublicKeyPath = @"C:\Users\getsemani.avila\Desktop\TEST_NO_PASS_0xE887B525_public.asc";
    private const string PrivateKeyPath = @"C:\Users\getsemani.avila\Desktop\TEST_NO_PASS_0xE887B525_SECRET.asc";
    private const string Password = null;// Cambia esto por la contraseña de tu llave privada

    /// <summary>
    /// Método principal de ejecución.
    /// </summary>
    public static void Main() {
        var originalMessage = "GETSEMANI";
        Console.WriteLine($"Mensaje Original: {originalMessage}");

        var encryptedMessage = Encrypt(originalMessage, PublicKeyPath);
        Console.WriteLine($"Mensaje Encriptado: {encryptedMessage}");

        var decryptedMessage = Decrypt(encryptedMessage, PrivateKeyPath, Password);
        Console.WriteLine($"Mensaje Desencriptado: {decryptedMessage}");
    }

    /// <summary>
    /// Encripta un mensaje usando una clave pública PGP.
    /// </summary>
    /// <param name="plainText">El mensaje a encriptar.</param>
    /// <param name="publicKeyPath">Ruta al archivo de clave pública.</param>
    /// <returns>Mensaje encriptado en formato Base64.</returns>
    public static string Encrypt(string plainText, string publicKeyPath) {
        // Leer la clave pública del archivo especificado
        PgpPublicKey encKey = ReadPublicKey(publicKeyPath);


        using (MemoryStream outputBytes = new MemoryStream()) {
            // Iniciar MemoryStream para almacenar el mensaje encriptado
            PgpCompressedDataGenerator compGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
            Stream outputStream = compGen.Open(outputBytes);

            // Inicializar el generador de datos encriptados y configurar la encriptación Triple DES
            PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.TripleDes);
            encGen.AddMethod(encKey);
            Stream encryptedOut = encGen.Open(outputStream, new byte[4096]);

            // Escribir el texto original en el flujo de datos literales
            PgpLiteralDataGenerator litGen = new PgpLiteralDataGenerator();
            Stream litOut = litGen.Open(encryptedOut, PgpLiteralData.Binary, PgpLiteralData.Console, plainText.Length,
                DateTime.UtcNow);

            // Cerrar todos los flujos para asegurar que todos los datos se hayan escrito correctamente
            litOut.Write(System.Text.Encoding.UTF8.GetBytes(plainText), 0, plainText.Length);
            litOut.Close();
            encryptedOut.Close();
            outputStream.Close();
            compGen.Close();

            return Convert.ToBase64String(outputBytes.ToArray());
        }
    }

    /// <summary>
    /// Desencripta un mensaje usando una clave privada PGP.
    /// </summary>
    /// <param name="cipherText">El mensaje encriptado en formato Base64.</param>
    /// <param name="privateKeyPath">Ruta al archivo de clave privada.</param>
    /// <param name="password">Contraseña para desencriptar la clave privada.</param>
    /// <returns>Mensaje desencriptado.</returns>
    public static string Decrypt(string cipherText, string privateKeyPath, string password) {
        // Convertir la cadena cifrada en un flujo de entrada
        using (Stream inputStream = new MemoryStream(Encoding.UTF8.GetBytes(cipherText)))
        using (Stream decodedStream = PgpUtilities.GetDecoderStream(inputStream)) {
            // Inicializar el generador de objetos PGP a partir del flujo decodificado
            PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(decodedStream);
            PgpObject pgpObject = pgpObjectFactory.NextPgpObject();

            // Si el objeto es de tipo comprimido, descomprimirlo para obtener el contenido real
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

            // Verificar si el objeto es una lista de datos encriptados
            if (publicKeyEncryptedData == null) {
                throw new Exception("No se encontró ningún dato encriptado con clave pública PGP.");
            }

            // Leer la clave privada desde la ruta proporcionada
            PgpPrivateKey privateKey = ReadPrivateKey(privateKeyPath, password);

            // Desencriptar el texto usando la clave privada
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

    /// <summary>
    /// Lee y devuelve una clave pública desde un archivo.
    /// </summary>
    /// <param name="publicKeyPath">Ruta al archivo de clave pública.</param>
    /// <returns>Clave pública PGP.</returns>
    private static PgpPublicKey ReadPublicKey(string publicKeyPath) {
        // Abrir el archivo de la clave pública en modo lectura
        using (Stream keyIn = File.OpenRead(publicKeyPath)) {
            // Decodificar el contenido del archivo y crear un conjunto de anillos de claves públicas
            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

            // Iterar a través de todos los anillos de claves públicas en el conjunto
            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings()) {
                // Iterar a través de todas las claves públicas en el anillo actual
                foreach (PgpPublicKey key in kRing.GetPublicKeys()) {
                    // Verificar si la clave actual es una clave de encriptación
                    if (key.IsEncryptionKey) {
                        // Si es así, devolver esta clave
                        return key;
                    }
                }
            }
        }
        // Si se llega a este punto, no se encontró ninguna clave de encriptación adecuada. Lanzar una excepción.
        throw new ArgumentException("Can't find encryption key in public key ring.");
    }

    /// <summary>
    /// Lee y devuelve una clave privada desde un archivo.
    /// </summary>
    /// <param name="privateKeyPath">Ruta al archivo de clave privada.</param>
    /// <param name="password">Contraseña para desencriptar la clave privada.</param>
    /// <returns>Clave privada PGP.</returns>
    private static PgpPrivateKey ReadPrivateKey(string privateKeyPath, string password) {
        try {
            // Abrir el archivo de la clave privada en modo lectura
            using (Stream keyIn = File.OpenRead(privateKeyPath)) {
                // Decodificar el contenido del archivo y crear un conjunto de anillos de claves secretas
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));

                // Iterar a través de todos los anillos de claves secretas en el conjunto
                foreach (PgpSecretKeyRing kRing in pgpSec.GetKeyRings()) {
                    // Iterar a través de todas las claves secretas en el anillo actual
                    foreach (PgpSecretKey key in kRing.GetSecretKeys()) {
                        Console.WriteLine("Checking key...");
                        // Descomenta esto si quieres omitir las claves de firma.
                        // if (key.IsSigningKey) continue; 

                        // Intentar extraer la clave privada usando la contraseña proporcionada
                        char[] passphrase = string.IsNullOrEmpty(password) ? null : password.ToCharArray();
                        PgpPrivateKey privateKey = key.ExtractPrivateKey(passphrase);

                        // Si se extrajo con éxito, devolver esta clave
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
        // Si se llega a este punto, no se encontró ninguna clave de desencriptación adecuada. Lanzar una excepción.
        throw new ArgumentException("Can't find decryption key in private key ring.");
    }


}
