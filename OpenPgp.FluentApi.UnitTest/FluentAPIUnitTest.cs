using Org.BouncyCastle.Bcpg.OpenPgp.FluentApi;
using System;
using System.Text;
using System.IO;
using Xunit;

namespace OpenPgp.FluentApi.UnitTest
{
    public class FluentAPIUnitTest
    {
        static string PlainMessage = "this is a test plain message";
        static MemoryStream PlainMessageStream = new MemoryStream(Encoding.ASCII.GetBytes(PlainMessage));

        static string strPublicKey1 = Resource1.PublicKey1;
        static Stream PublicKey1 = new MemoryStream(Encoding.ASCII.GetBytes(strPublicKey1));

        static string strPrivateKey1 = Resource1.PrivateKey1;
        static Stream PrivateKey1 = new MemoryStream(Encoding.ASCII.GetBytes(strPrivateKey1));

        static string PassPhrase1 = "pass123";

        static string strPublicKey2 = Resource1.PublicKey2;
        static Stream PublicKey2 = new MemoryStream(Encoding.ASCII.GetBytes(strPublicKey2));

        static string strPrivateKey2 = Resource1.PrivateKey2;
        static Stream PrivateKey2 = new MemoryStream(Encoding.ASCII.GetBytes(strPrivateKey2));

        static string PassPhrase2 = "pass123";

        [Fact]
        public void TestEncrypt_Decrypt_2KeysAnd2Signatures()
        {
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);
            PublicKey2.Seek(0, SeekOrigin.Begin);
            PrivateKey2.Seek(0, SeekOrigin.Begin);

            var encryptionTask = new PgpEncryptionBuilder()
                .Encrypt(PlainMessageStream)
                .WithArmor()
                .WithCompression()
                .WithIntegrityCheck()
                .WithPublicKey(PublicKey1)
                .WithPublicKey(PublicKey2)
                .WithSigning(PrivateKey1, PassPhrase1)
                .WithSigning(PrivateKey2, PassPhrase2)
                .Build();

            var encryptedStream = encryptionTask.Run().GetEncryptedStream();

            var encryptedText = new StreamReader(encryptedStream).ReadToEnd();


            encryptedStream.Seek(0, SeekOrigin.Begin);
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);
            PublicKey2.Seek(0, SeekOrigin.Begin);
            PrivateKey2.Seek(0, SeekOrigin.Begin);


            var decryptionTask = new PgpDecryptionBuilder()
                .Decrypt(encryptedStream)
                .WithPrivateKey(PrivateKey1, PassPhrase1)
                .WithPrivateKey(PrivateKey2, PassPhrase2)
                .VerifySignatureUsingKey(PublicKey1)
                .VerifySignatureUsingKey(PublicKey2)
                .Build();

            var decryptedStream = decryptionTask.Run().GetDecryptedStream();

            var decryptedText = new StreamReader(decryptedStream).ReadToEnd();

            Assert.Equal(PlainMessage, decryptedText);
        }

        [Fact]
        public void TestEncrypt_Decrypt_2KeysAndNoSignatures()
        {
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);
            PublicKey2.Seek(0, SeekOrigin.Begin);
            PrivateKey2.Seek(0, SeekOrigin.Begin);

            var encryptionTask = new PgpEncryptionBuilder()
                .Encrypt(PlainMessageStream)
                .WithArmor()
                .WithCompression()
                .WithIntegrityCheck()
                .WithPublicKey(PublicKey1)
                .WithPublicKey(PublicKey2)
                .Build();

            var encryptedStream = encryptionTask.Run().GetEncryptedStream();

            var encryptedText = new StreamReader(encryptedStream).ReadToEnd();
            
            encryptedStream.Seek(0, SeekOrigin.Begin);
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);
            PublicKey2.Seek(0, SeekOrigin.Begin);
            PrivateKey2.Seek(0, SeekOrigin.Begin);


            var decryptionTask = new PgpDecryptionBuilder()
                .Decrypt(encryptedStream)
                .WithPrivateKey(PrivateKey1, PassPhrase1)
                .WithPrivateKey(PrivateKey2, PassPhrase2)
                .VerifySignatureUsingKey(PublicKey1)
                .VerifySignatureUsingKey(PublicKey2)
                .Build();

            var decryptedStream = decryptionTask.Run().GetDecryptedStream();
            var signatureStatus = decryptionTask.GetSignatureStatus();

            var decryptedText = new StreamReader(decryptedStream).ReadToEnd();

            Assert.Equal(PlainMessage, decryptedText);
            Assert.True(signatureStatus == SignatureStatus.NoSignature);
        }

        [Fact]
        public void TestEncrypt_Decrypt_2KeysAnd2SignaturesWithoutSignatureCheck()
        {
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);
            PublicKey2.Seek(0, SeekOrigin.Begin);
            PrivateKey2.Seek(0, SeekOrigin.Begin);

            var encryptionTask = new PgpEncryptionBuilder()
                .Encrypt(PlainMessageStream)
                .WithArmor()
                .WithCompression()
                .WithIntegrityCheck()
                .WithPublicKey(PublicKey1)
                .WithPublicKey(PublicKey2)
                .WithSigning(PrivateKey1, PassPhrase1)
                .WithSigning(PrivateKey2, PassPhrase2)
                .Build();

            var encryptedStream = encryptionTask.Run().GetEncryptedStream();

            var encryptedText = new StreamReader(encryptedStream).ReadToEnd();

            encryptedStream.Seek(0, SeekOrigin.Begin);
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);
            PublicKey2.Seek(0, SeekOrigin.Begin);
            PrivateKey2.Seek(0, SeekOrigin.Begin);


            var decryptionTask = new PgpDecryptionBuilder()
                .Decrypt(encryptedStream)
                .WithPrivateKey(PrivateKey1, PassPhrase1)
                .WithPrivateKey(PrivateKey2, PassPhrase2)
                .Build();

            var decryptedStream = decryptionTask.Run().GetDecryptedStream();
            var signatureStatus = decryptionTask.GetSignatureStatus();

            var decryptedText = new StreamReader(decryptedStream).ReadToEnd();

            Assert.Equal(PlainMessage, decryptedText);
            Assert.True(signatureStatus == SignatureStatus.NotChecked);
        }

        [Fact]
        public void TestEncrypt_Decrypt_1KeyAnd1Signature()
        {
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);

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

            encryptedStream.Seek(0, SeekOrigin.Begin);
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);


            var decryptionTask = new PgpDecryptionBuilder()
                .Decrypt(encryptedStream)
                .WithPrivateKey(PrivateKey1, PassPhrase1)
                .VerifySignatureUsingKey(PublicKey1)
                .Build();

            var decryptedStream = decryptionTask.Run().GetDecryptedStream();
            var signatureStatus = decryptionTask.GetSignatureStatus();

            var decryptedText = new StreamReader(decryptedStream).ReadToEnd();

            Assert.Equal(PlainMessage, decryptedText);
            Assert.True(signatureStatus == SignatureStatus.Valid);
        }

        [Fact]
        public void TestEncrypt_Decrypt_1KeyAnd1WrongSignature()
        {
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);

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

            encryptedStream.Seek(0, SeekOrigin.Begin);
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);


            var decryptionTask = new PgpDecryptionBuilder()
                .Decrypt(encryptedStream)
                .WithPrivateKey(PrivateKey1, PassPhrase1)
                .VerifySignatureUsingKey(PublicKey2)
                .Build();

            var decryptedStream = decryptionTask.Run().GetDecryptedStream();
            var signatureStatus = decryptionTask.GetSignatureStatus();

            var decryptedText = new StreamReader(decryptedStream).ReadToEnd();

            Assert.Equal(PlainMessage, decryptedText);
            Assert.True(signatureStatus == SignatureStatus.Invalid);
        }

        [Fact]
        public void TestEncrypt_Decrypt_WrongDecryptionKey()
        {
            PlainMessageStream.Seek(0, SeekOrigin.Begin);
            PublicKey1.Seek(0, SeekOrigin.Begin);
            PrivateKey1.Seek(0, SeekOrigin.Begin);

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

            encryptedStream.Seek(0, SeekOrigin.Begin);
            PlainMessageStream.Seek(0, SeekOrigin.Begin);


            var decryptionTask = new PgpDecryptionBuilder()
                .Decrypt(encryptedStream)
                .WithPrivateKey(PrivateKey2, PassPhrase2)
                .VerifySignatureUsingKey(PublicKey2)
                .Build();

            Assert.Throws<SecretKeyNotFound>(() => decryptionTask.Run());
        }
    }
}
