# 🛡 BC Example cSharp 🛡 - Encriptación con Bouncy Castle y PGP

Desarrollado por **Getsemani Avila Quezada** el 10/08/2023.

## 📜 Licencia

Este software es de Software Libre. Se permite la distribución, modificación y uso con la condición de que el nombre del autor original, **Getsemani Avila Quezada**, sea reconocido en cualquier versión derivada o uso del software.

## 📝 Descripción

El proyecto "BC Example cSharp" proporciona una clase `PgpExample` que ofrece funcionalidades para encriptar y desencriptar mensajes utilizando la biblioteca Bouncy Castle junto con llaves PGP. 🔒🔑 El código hace uso de las llaves almacenadas en rutas específicas y proporciona métodos para:

1. **Encriptar**: 🔐 Utilizando una clave pública PGP para transformar un mensaje claro en uno encriptado.
2. **Desencriptar**: 🔓 Utilizando una clave privada PGP (y potencialmente una contraseña) para revertir el proceso de encriptación y recuperar el mensaje original.

Es importante notar que dependiendo de cómo se generaron las llaves PGP, podría ser necesario proveer una contraseña al utilizar la clave privada. Si las llaves PGP que estás utilizando están protegidas con una contraseña, deberás proporcionarla. De lo contrario, si no tienen contraseña, puedes omitirla.

El flujo principal de la aplicación muestra un ejemplo de cómo usar estos métodos para encriptar un mensaje y luego desencriptarlo, mostrando los resultados en la consola. 💻

## 🚀 Uso

Para usar el programa:

1. Asegúrate de tener las llaves PGP correctas en las rutas definidas en las constantes `PublicKeyPath` y `PrivateKeyPath`.
2. Si tu llave privada está protegida por contraseña, establece la contraseña correcta en la constante `Password`. Si tu llave no requiere contraseña, puedes omitir este paso.
3. Ejecuta el programa para ver el proceso de encriptación y desencriptación en acción.

```csharp
var originalMessage = "TU_MENSAJE_AQUI";
Console.WriteLine($"Mensaje Original: {originalMessage}");

var encryptedMessage = PgpExample.Encrypt(originalMessage, PgpExample.PublicKeyPath);
Console.WriteLine($"Mensaje Encriptado: {encryptedMessage}");

var decryptedMessage = PgpExample.Decrypt(encryptedMessage, PgpExample.PrivateKeyPath, PgpExample.Password);
Console.WriteLine($"Mensaje Desencriptado: {decryptedMessage}");

```

## 🤝 Contribución
Si tienes mejoras o correcciones para el código, no dudes en enviar un Pull Request o abrir un Issue. Tu contribución será apreciada. 👍