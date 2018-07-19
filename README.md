# openpgp-fluentapi
have you ever needed to use OpenPGP encryption decryption in your .net code, have you tired to use BouncyCastle.OpenPgp library and had hard time getting your code to work.

This project introduce a wrapper around Bouncy Castle OpenPgp library, just prepare your files/streams and public/secret keys and get the work done.

Via a fluent API you should be able to pass all parameters required to get your desired action done, this includes

1- Encrypt (and optionally sign) a file/stream

2- Decrypt (and optionally verify signature) of an encrypted file/stream

3- Generate Ascii armored or binary encrypted files.

### here how to get the job done

- ##### Encrypt a stream and sign it 
```
string PlainMessage = "this is a test plain message";
MemoryStream PlainMessageStream = new MemoryStream(Encoding.ASCII.GetBytes(PlainMessage));

string strPublicKey1 = "your PGP public key";
Stream PublicKey1 = new MemoryStream(Encoding.ASCII.GetBytes(strPublicKey1));

string strPrivateKey1 = "ypur pgp secret key";
Stream PrivateKey1 = new MemoryStream(Encoding.ASCII.GetBytes(strPrivateKey1));

string PassPhrase1 = "your pgp secret key password";
		
var encryptionTask = new PgpEncryptionBuilder()
	.Encrypt(PlainMessageStream)
	.WithArmor()
	.WithCompression()
	.WithIntegrityCheck()
	.WithPublicKey(PublicKey1)
	.WithSigning(PrivateKey1, PassPhrase1)
	.Build();

var encryptedStream = encryptionTask.Run().GetEncryptedStream();

var encryptedText = new StreamReader(encryptedStream).ReadToEnd();
```

- #### Decrypt a stream and verify it's signature
```
var encryptedStream = System.IO.File.OpenRead("your encrypted file path");

string strPublicKey1 = "your PGP public key";
Stream PublicKey1 = new MemoryStream(Encoding.ASCII.GetBytes(strPublicKey1));

string strPrivateKey1 = "ypur pgp secret key";
Stream PrivateKey1 = new MemoryStream(Encoding.ASCII.GetBytes(strPrivateKey1));

string PassPhrase1 = "your pgp secret key password";

var decryptionTask = new PgpDecryptionBuilder()
	.Decrypt(encryptedStream)
	.WithPrivateKey(PrivateKey1, PassPhrase1)
	.VerifySignatureUsingKey(PublicKey1)
	.Build();

var decryptedStream = decryptionTask.Run().GetDecryptedStream();
var signatureStatus = decryptionTask.GetSignatureStatus();

var decryptedText = new StreamReader(decryptedStream).ReadToEnd();
if(signatureStatus == SignatureStatus.Valid || signatureStatus == SignatureStatus.NoSignature)
{
	var decryptedText = new StreamReader(decryptedStream).ReadToEnd();
}
```

Enjoy
