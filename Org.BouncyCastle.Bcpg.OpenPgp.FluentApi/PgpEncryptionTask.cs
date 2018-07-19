using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.FluentApi
{
    public class PgpEncryptionTask
    {
        internal FileInfo InFile;
        internal FileInfo OutFile;

        internal List<Stream> PublicKeys;
        internal List<PrivateKeyInfo> PrivateKeys;

        internal bool Armor;
        internal bool Compress;
        internal bool WithIntegrityCheck;
        internal bool WithSigning;


        public PgpEncryptionTask Run()
        {
            var inFile = InFile;
            if (WithSigning)
            {
                SignAndEncryptFile();
            }
            else
            {
                EncryptFile();
            }

            return this;
        }

        public Stream GetEncryptedStream()
        {
            return OutFile.OpenRead();
        }

        #region PGP Encrypt Function

        void EncryptFile()
        {
            try
            {
                var InStream = InFile.OpenRead();
                var OutStream = OutFile.OpenWrite();

                PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, WithIntegrityCheck, new SecureRandom());

                foreach (var publicKey in PublicKeys)
                {
                    var encKey = ReadPublicKey(publicKey);
                    encGen.AddMethod(encKey);
                }

                MemoryStream bOut = new MemoryStream();
                if (Compress)
                {
                    PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.ZLib);
                    WriteStreamToLiteralData(comData.Open(bOut), PgpLiteralData.Binary, InStream);
                    comData.Close();
                }
                else
                {
                    WriteStreamToLiteralData(bOut, PgpLiteralData.Binary, InStream);
                }

                byte[] bytes = bOut.ToArray();

                if (Armor)
                {
                    using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(OutStream))
                    {
                        using (Stream cOut = encGen.Open(armoredStream, bytes.Length))
                        {
                            cOut.Write(bytes, 0, bytes.Length);
                        }
                    }
                }
                else
                {
                    using (Stream cOut = encGen.Open(OutStream, bytes.Length))
                    {
                        cOut.Write(bytes, 0, bytes.Length);
                    }
                }

                OutStream.Close();
            }
            catch
            {
                throw;
            }
        }

        void SignAndEncryptFile()
        {
            const int BUFFER_SIZE = 1 << 16; // should always be power of 2

            var OutStream = OutFile.OpenWrite();

            PgpEncryptedDataGenerator encryptedDataGenerator = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, WithIntegrityCheck, new SecureRandom());

            foreach (var publicKey in PublicKeys)
            {
                var encKey = ReadPublicKey(publicKey);
                encryptedDataGenerator.AddMethod(encKey);
            }

            Stream outputStream = OutStream;
            if (Armor)
                outputStream = new ArmoredOutputStream(outputStream);

            Stream encryptedOut = encryptedDataGenerator.Open(outputStream, new byte[BUFFER_SIZE]);

            if (Compress)
            {
                // Init compression
                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                encryptedOut = compressedDataGenerator.Open(encryptedOut);
            }

            //signing
            List<PgpSignatureGenerator> pgpSignatureGenerators = new List<PgpSignatureGenerator>();
            foreach (var privateKeyInfo in PrivateKeys)
            {
                PgpSecretKey pgpSecKey = ReadSecretKey(privateKeyInfo.PrivateKeyStream);
                PgpPrivateKey pgpPrivKey = pgpSecKey.ExtractPrivateKey(privateKeyInfo.PrivateKeyPassword.ToCharArray());

                PgpSignatureGenerator signatureGenerator = new PgpSignatureGenerator(pgpSecKey.PublicKey.Algorithm, HashAlgorithmTag.Sha1);
                signatureGenerator.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);

                foreach (string userId in pgpSecKey.PublicKey.GetUserIds())
                {

                    PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();
                    spGen.SetSignerUserId(false, userId);
                    signatureGenerator.SetHashedSubpackets(spGen.Generate());
                    // Just the first one!
                    break;
                }

                signatureGenerator.GenerateOnePassVersion(false).Encode(encryptedOut);

                pgpSignatureGenerators.Add(signatureGenerator);
            }
            // Create the Literal Data generator output stream
            PgpLiteralDataGenerator literalDataGenerator = new PgpLiteralDataGenerator();
            Stream literalOut = literalDataGenerator.Open(encryptedOut, PgpLiteralData.Binary, InFile.Name, InFile.LastWriteTime, new byte[BUFFER_SIZE]);

            // Open the input file
            FileStream inputStream = InFile.OpenRead();

            byte[] buf = new byte[BUFFER_SIZE];
            int len;
            while ((len = inputStream.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, len);
                foreach (var signatureGenerator in pgpSignatureGenerators)
                    signatureGenerator.Update(buf, 0, len);
            }

            literalOut.Close();
            literalDataGenerator.Close();
            foreach (var signatureGenerator in pgpSignatureGenerators)
                signatureGenerator.Generate().Encode(encryptedOut);
            encryptedOut.Close();
            encryptedOut.Close();
            encryptedDataGenerator.Close();
            inputStream.Close();


            if (Armor)
                outputStream.Close();

            OutStream.Close();
        }

        private static void WriteStreamToLiteralData( Stream output, char fileType, Stream input)
        {
            PgpLiteralDataGenerator lData = new PgpLiteralDataGenerator();
            using (Stream pOut = lData.Open(output, fileType, "", input.Length, DateTime.Now))
            {
                byte[] buf = input.ReadFully();
                pOut.Write(buf, 0, buf.Length);
            }
        }

        private static PgpPublicKey ReadPublicKey(Stream publicKeyStream)
        {
            if (publicKeyStream.CanSeek)
                publicKeyStream.Seek(0, SeekOrigin.Begin);

            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
            {
                foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        private static PgpSecretKey ReadSecretKey(Stream input)
        {
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(input));

            //
            // we just loop through the collection till we find a key suitable for encryption, in the real
            // world you would probably want to be a bit smarter about this.
            //

            foreach (PgpSecretKeyRing keyRing in pgpSec.GetKeyRings())
            {
                foreach (PgpSecretKey key in keyRing.GetSecretKeys())
                {
                    if (key.IsSigningKey)
                    {
                        return key;
                    }
                }
            }

            throw new ArgumentException("Can't find signing key in key ring.");
        }


        #endregion
    }
}