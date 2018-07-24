using Org.BouncyCastle.Utilities.IO;
using System;
using System.Linq;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp.FluentApi
{
    public class PgpDecryptionTask
    {
        internal Stream InStream { get; set; }
        internal Stream OutStream { get; set; }
        internal List<PrivateKeyInfo> PrivateKeys { get; set; }
        internal List<Stream> SignatureKeys { get; set; }
        internal bool CheckSignature { get; set; }
        private SignatureStatus SignatureStatus { get; set; }


        public PgpDecryptionTask Run()
        {
            SignatureStatus = DecryptFile();
            return this;
        }

        public Stream GetDecryptedStream()
        {
            OutStream.Seek(0, SeekOrigin.Begin);

            return OutStream;
        }

        public SignatureStatus GetSignatureStatus()
        {
            return SignatureStatus;
        }

        #region PGP Encrypt Function

        private SignatureStatus DecryptFile()
        {
            if (InStream.CanSeek)
                InStream.Seek(0, SeekOrigin.Begin);
            var inputStream = PgpUtilities.GetDecoderStream(InStream);

            try
            {
                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList enc;

                PgpObject o = pgpF.NextPgpObject();
                //
                // the first object might be a PGP marker packet.
                //
                if (o is PgpEncryptedDataList)
                {
                    enc = (PgpEncryptedDataList)o;
                }
                else
                {
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
                }


                var privateKeys = GetAllPrivateKeys();
                //
                // find the secret key
                //
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                
                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = FindPrivateKey(privateKeys, pked.KeyId);

                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                }

                if (sKey == null)
                {
                    throw new SecretKeyNotFound("secret key for message not found.");
                }

                Stream clear = pbe.GetDataStream(sKey);

                PgpLiteralData pgpLiteralData = null;
                PgpOnePassSignatureList onePassSignatureList = null;
                PgpSignatureList signatureList = null;

                PgpObjectFactory pgpObjectFactory = new PgpObjectFactory(clear);
                var pgpObject = pgpObjectFactory.NextPgpObject();
                while (pgpObject != null)
                {
                    if (pgpObject is PgpCompressedData)
                    {
                        var compressedData = (PgpCompressedData)pgpObject;
                        pgpObjectFactory = new PgpObjectFactory(compressedData.GetDataStream());
                        pgpObject = pgpObjectFactory.NextPgpObject();
                    }

                    if (pgpObject is PgpLiteralData)
                    {
                        pgpLiteralData = pgpObject as PgpLiteralData;
                        //must read directly to continue reading next pgp objects
                        Stream unc = pgpLiteralData.GetInputStream();
                        Streams.PipeAll(unc, OutStream);
                    }
                    else if (pgpObject is PgpOnePassSignatureList)
                    {
                        onePassSignatureList = pgpObject as PgpOnePassSignatureList;
                    }
                    else if (pgpObject is PgpSignatureList)
                    {
                        signatureList = pgpObject as PgpSignatureList;
                    }

                    pgpObject = pgpObjectFactory.NextPgpObject();
                }

                if(pgpLiteralData == null)
                    throw new PgpLitralDataNotFound("couldn't find pgp literal data");

                

                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify())
                    {
                        throw new PgpIntegrityCheckFailed("message failed integrity check");
                    }
                }

                if (CheckSignature)
                {
                    if (onePassSignatureList == null || signatureList == null)
                        return SignatureStatus.NoSignature;
                    else
                    {
                        return VerifyFileSignature(OutStream, onePassSignatureList, signatureList);
                    }
                }
                else
                    return SignatureStatus.NotChecked;
            }
            catch
            {
                throw;
            }
        }

        private SignatureStatus VerifyFileSignature(Stream literalDataStream, PgpOnePassSignatureList pgpOnePassSignatureList, PgpSignatureList pgpSignatureList)
        {
            try
            {
                
                const int BUFFER_SIZE = 1 << 16; // should always be power of 2

                SignatureStatus signatureStatus = SignatureStatus.Invalid;

                var signatureKeys = GetAllSignatureKeys();

                if (pgpOnePassSignatureList == null)
                    return SignatureStatus.NoSignature;

                for (int i = 0; i < pgpOnePassSignatureList.Count; i++)
                {
                    if (literalDataStream.CanSeek)
                        literalDataStream.Seek(0, SeekOrigin.Begin);

                    PgpOnePassSignature pgpOnePassSignature = pgpOnePassSignatureList[i];
                    Stream dIn = literalDataStream;
                    var keyIn = FindSignatureKey(signatureKeys, pgpOnePassSignature.KeyId);
                    if (keyIn == null)
                        continue;

                    pgpOnePassSignature.InitVerify(keyIn);

                    byte[] buf = new byte[BUFFER_SIZE];
                    int len;
                    while ((len = dIn.Read(buf, 0, buf.Length)) > 0)
                    {
                        pgpOnePassSignature.Update(buf, 0, len);
                    }

                    PgpSignature pgpSignature = pgpSignatureList[i];
                    if (pgpOnePassSignature.Verify(pgpSignature))
                    {
                        signatureStatus = SignatureStatus.Valid;
                        break;
                    }
                }

                return signatureStatus;
            }
            catch
            {
                return SignatureStatus.Error;
            }
        }

        private List<PgpPrivateKey> GetAllPrivateKeys()
        {
            List<PgpPrivateKey> PgpPrivateKeys = new List<PgpPrivateKey>();
            foreach (var keyInfo in this.PrivateKeys)
            {
                PgpKeyRingBundle pgpSec = new PgpKeyRingBundle(PgpUtilities.GetDecoderStream(keyInfo.PrivateKeyStream));

                var keyRings = pgpSec.GetSecretKeyRings();
                foreach(PgpSecretKeyRing keyRing in keyRings)
                {
                    var pgpSecKeys = keyRing.GetSecretKeys();
                    foreach(PgpSecretKey pgpSecKey in pgpSecKeys)
                    {
                        var privateKey = pgpSecKey.ExtractPrivateKey(keyInfo.PrivateKeyPassword == null ? null : keyInfo.PrivateKeyPassword.ToCharArray());
                        PgpPrivateKeys.Add(privateKey);
                    }
                }
            }

            return PgpPrivateKeys;
        }

        private List<PgpPublicKey> GetAllSignatureKeys()
        {
            List<PgpPublicKey> PgpSignatureKeys = new List<PgpPublicKey>();
            foreach (var publicKeyStream in this.SignatureKeys)
            {
                if (publicKeyStream.CanSeek)
                    publicKeyStream.Seek(0, SeekOrigin.Begin);

                PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(publicKeyStream));

                foreach (PgpPublicKeyRing keyRing in pgpPub.GetKeyRings())
                {
                    foreach (PgpPublicKey key in keyRing.GetPublicKeys())
                    {
                        if (key.IsEncryptionKey)
                        {
                            PgpSignatureKeys.Add(key);
                        }
                    }
                }
            }

            return PgpSignatureKeys;
        }

        private PgpPublicKey FindSignatureKey(List<PgpPublicKey> pgpPublicKeys, long keyId)
        {
            var publicKey = pgpPublicKeys.FirstOrDefault(x => x.KeyId == keyId);
            return publicKey;

        }

        private PgpPrivateKey FindPrivateKey(List<PgpPrivateKey> pgpPrivateKeys, long keyId)
        {
            var privateKey = pgpPrivateKeys.FirstOrDefault(x => x.KeyId == keyId);
            return privateKey;

        }

        #endregion

    }

    public enum SignatureStatus
    {
        NotChecked,
        NoSignature,
        Error,
        Valid,
        Invalid
    }
}