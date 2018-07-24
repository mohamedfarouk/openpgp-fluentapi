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

        static string strPublicKey1 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nmQENBFtW2NkBCADIVNEroNsaQjrTm2B58D3gX0opffrAq31Rtp6VyRxKZ1sykubP\r\nAtuEMK8aQjqQrnSMRtusQjTazajr8jwInT69fpLe1FU8FlSh+xDLIHeNY9gixCCr\r\n5sM4mPbtSaJDYRUAurkt3sQi7835w/CeLoV0h5z7uVveRr0S3UrT9Tj+NI5VBpKZ\r\nK5q4SJXJOH27ksMjTuav2XueJCMoBMKRVJkswcypVQYiJuUgQFr/b4srFXB0vAEX\r\n1VOj8891XsstsmhVM/n/cCD6eRvv6S2MrWSMkKB94AJM4o8dHaf7LQA2ClVZTB3X\r\nBsOLVNrZT9NBWjsmPTF8rTctGKcrfwtMvNpPABEBAAG0FnRlc3QxIDx0ZXN0MUB0\r\nZXN0LmNvbT6JAU4EEwEIADgWIQRBPafGL3R8wGa1LxOfqOBWv6kkmgUCW1bY2QIb\r\nAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRCfqOBWv6kkmhL6B/9LTxWrLya8\r\n9z0IQzKl1W8hxOAfDk4SZfUgzcyDfsfR/fs9kL4zsVgYZaP8fcblFKWh0WuC0/mZ\r\n/Mi+sw1mCXgpRbOiAeNVwWHkgG9nczTTprvqGPNZ83b5RWjkNs0AfaHo0zdRjAkY\r\n4S72wwO4nJD/inB8EVKMNnb+iReM2TFux9oJ9CvzCrF6rfnZ7aWQlIv7naqQWpH7\r\nGjb91r9H67phYNqBmdRWerVLWAfOF2HkLO03putFYeZMkVMCK3SiR3/lG4KFLJLb\r\nstcbYxC+S/FKYZC3dZLHvRDhDZ6bAEK5R2t4P29FBhKnLiyYZxqzoCkOssH8Hkbm\r\nfGVu/uHJtF6wuQENBFtW2NkBCADmYFAr9m80vv7gPzRyEpdcxRRZMsEMLr1QVNZ8\r\nZWn0zrfPzme8p0JGEPbgJ/fPsfPrVRb/ApK7HtCzg5w+F/NvWSalFznou5yvrvsD\r\n9NXcMbxhfCG1Zi9DyXmGYDHSeQNsgdkFcgh4AvRsWKkqBgnGMohMOQQgqoK2HE3L\r\nhI3ZR9FQJ9xwEFZ4bwqKydl+opg6+Ebery3M7SBLiFZtZOgcrBnQYN2bQX8Up+uX\r\nffmh765QLbizctuQATr8z1NBNXW9L3lQE7Y6tVu/suMIR/aOahpp5XfdIK2lz0nH\r\nY+YUanYr0D/r17KBViTvG9w9zi1CPcBscNNPXoRg7691r5HPABEBAAGJATYEGAEI\r\nACAWIQRBPafGL3R8wGa1LxOfqOBWv6kkmgUCW1bY2QIbDAAKCRCfqOBWv6kkmrus\r\nB/9AOEd11kBbitt+Rl20V3Q4oaWQIH5AO9Gv48GPexY9t1mWdz2cVEi2y2wGt8j2\r\nIslmk03/xBLyTK+jw7wgD2TZEJAslHKRiW/TG5nS970MZQ9NRnWM3agnMH9ghvMh\r\nKQmm9sfF3aNzVz/Av0W1Ml1dgDSWc6mDH59O6iJVCIt8rGlvnmUddB0ni5ZPFf1B\r\nynGhdmyhlCHwHtmn3wppTPKviDHsSnlGGmhsywAv2DdHCf0Dy3/F0Pe4Arg+6oYR\r\nnSIgUT4wEGdIz7FJ1y2a5vS8M18vQzy+QVetrAf7msP1LT4F9sy/q6EUoNBBmrlq\r\nASNzM+Mva+Yq+6t0F4pOCRTl\r\n=8ch+\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n";
        static Stream PublicKey1 = new MemoryStream(Encoding.ASCII.GetBytes(strPublicKey1));

        static string strPrivateKey1 = "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\r\n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\r\nuWoBI3Mz4y9r5ir7q3QXik4JFOU=\r\n=JgBM\r\n-----END PGP PRIVATE KEY BLOCK-----\r\n";
        static Stream PrivateKey1 = new MemoryStream(Encoding.ASCII.GetBytes(strPrivateKey1));

        static string PassPhrase1 = "pass1234";

        static string strPublicKey2 = "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nmQENBFtW2QwBCADbrGpqmMuxLWh3oOwZFP36PWN/QoJuSaanVcCcMH428Hhxy7Qn\r\ndpeZCY8tuUX/r400XYj2vzxFMnjxmbXdz51wQr4qAhN7lm2jFvYZlSYkU1YP6uor\r\nCB10OeY1VxWjP3QuTusrDHVXMwMSUAu37yyjIqDUVMEThqSDf5WOPbcg1xfRiLw8\r\n+AiSga/cP+MTE+HfhP7ekwwuu5JR2lFp7eI6Kn5u70gOvJaNZ22HapU3kbTSCHVt\r\nG9PPDOlfiYP5xBfn44btaDXFTpLL/zPpn4ovK0xGdU/3asWzupsODQjC4mVse0tl\r\niY8LTT5JsKciZTwWSQ0kO1qPW227dg+05dJpABEBAAG0FnRlc3QyIDx0ZXN0MkB0\r\nZXN0LmNvbT6JAU4EEwEIADgWIQRajZc2TFwv1Bumjk7uUXiOFVjKNQUCW1bZDAIb\r\nAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRDuUXiOFVjKNf1SCACGsF71+8LD\r\nKc6d5HEL6uDHGWNaka4dJi8/9mPhg+Cy7uBfVqYMgHtlzVr7rRqq3PgH3+nLC4dC\r\no59YIHhs+BLd1C1Ho2uUhe/U8+oX4qBBKxmmISlGKlUDRhE3u4A6+7bPhpuNyW6j\r\nRvRxBc7RbMpM8LJvkPIGn+Tm7hxTjJzKP+QuDe3BnbJ9ELeWcAFeKisBKGPgFoTF\r\nYwXnpCa5OpD6QQFKtd9UDMlOmU3cD5cjdDj790lMFDgeMzEJBz9Lvkpl4+8iYFZB\r\no1YIkAJLTapeyg3LY034XLIsrF+9mpDS0FrW05HIN4Kk9b/ArayGay3+vz2OzYDb\r\nKnZtaOxlLyNJuQENBFtW2QwBCADD8nD1gqapxUlWWNdJcHNhmFOVcgPPiyHQ4rmt\r\n5D0KVN1hjSEDek64VnaV/X10+CQwvjX+lpg8jeQlRmGMkeEUczvgCVloOXRcRYfe\r\nbDwKq7lsU1w7w7dNvJqZrRApMfs4QSpHZaVHCuJrcm/HpyHAkGLogHJZ/mdNrVfH\r\n7qewiCu1jXq8uGOhrloBIr5ApFjwRP0GScLYZUnLXgztFdrLPAYE4irwNOLdt4Dq\r\n9pcT8WXIGztOVFWQlnT8lQrjmWLJEmeHbKQ0FPY3a51QskChx6kDT58a8BeSXBy7\r\n2USXzvhxv81cdNk9tREr8t3ZZKg9cILVR5umKNL3gvbFtgQnABEBAAGJATYEGAEI\r\nACAWIQRajZc2TFwv1Bumjk7uUXiOFVjKNQUCW1bZDAIbDAAKCRDuUXiOFVjKNZ/t\r\nB/wMPV87PtcdwcCLAX/wTjlIpNStgCMIjjkQH9n2108mdy4sWRUMMnVLeREvMvea\r\nrlpAxHr4vrcRw4Iqogs6kvSRZn6Su7lYaz5lNvF3TgZuPzwP5JE0yQaDONyjaqVa\r\nbun2tQGii7e+lTcz1Q0RLAp+66kb2XNxvrnALIFYC1wc6qDVXV5JmWa4P2mY8Ktg\r\nETp4kHhuCaBdW24k8vcEwgA3xBKR8xG3ZEWtRr73jmblR7GbBXSM79hceEC3AogF\r\nv85WmUZyECVaXMTRYQlgb0wlSZ7MIAWXZApTaaa6yJc6XiFuhM5cgnrBsRaoaWX7\r\nuT6Pyjz84rBVpOUW43QFtpUP\r\n=/PnD\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n";
        static Stream PublicKey2 = new MemoryStream(Encoding.ASCII.GetBytes(strPublicKey2));

        static string strPrivateKey2 = "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\r\n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\r\nZfu5Po/KPPzisFWk5RbjdAW2lQ8=\r\n=q4oH\r\n-----END PGP PRIVATE KEY BLOCK-----\r\n";

        static Stream PrivateKey2 = new MemoryStream(Encoding.ASCII.GetBytes(strPrivateKey2));

        static string PassPhrase2 = "pass1234";

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
