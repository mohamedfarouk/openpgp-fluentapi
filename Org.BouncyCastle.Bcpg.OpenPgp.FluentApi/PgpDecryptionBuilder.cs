using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.FluentApi
{
    public class PgpDecryptionBuilder
    {
        private Stream InStream;
        private Stream OutStream;

        private List<PrivateKeyInfo> PrivateKeys;
        private List<Stream> SignatureKeys;
        private bool VerifySignature;

        public PgpDecryptionBuilder()
        {
            OutStream = new MemoryStream();
            PrivateKeys = new List<PrivateKeyInfo>();
            SignatureKeys = new List<Stream>();
            VerifySignature = false;
        }

        public PgpDecryptionBuilder Decrypt(string inputFilePath)
        {
            if (string.IsNullOrEmpty(inputFilePath))
                throw new ArgumentNullException("inputFilePath");

            if (!Uri.IsWellFormedUriString(inputFilePath, UriKind.RelativeOrAbsolute))
                throw new ArgumentException("inputFilePath", "malformed file path");

            if (!File.Exists(inputFilePath))
                throw new ArgumentException("inputFilePath", "file does not exists");

            var fileInfo = new FileInfo(inputFilePath);
            var inputFileStream = File.OpenRead(inputFilePath);

            return Decrypt(fileInfo.OpenRead());
        }

        public PgpDecryptionBuilder Decrypt(Stream inputFileStream)
        {
            if (InStream != null)
                throw new InvalidOperationException("stream to encrypt already specified");

            InStream = inputFileStream ?? throw new ArgumentNullException("inputFileStream");

            return this;
        }

        public PgpDecryptionBuilder WriteOutputTo(string outfilePath, bool overwrite = true)
        {
            if (string.IsNullOrEmpty(outfilePath))
                throw new ArgumentNullException("outfilePath");

            if (!Uri.IsWellFormedUriString(outfilePath, UriKind.RelativeOrAbsolute))
                throw new ArgumentException("outfilePath", "malformed file path");

            if (File.Exists(outfilePath) && !overwrite)
                throw new ArgumentException("inputFilePath", "out file already exists");

            var stream = File.Open(outfilePath, FileMode.OpenOrCreate);

            return WriteOutputTo(stream);
        }

        public PgpDecryptionBuilder WriteOutputTo(Stream outStream)
        {
            if (OutStream != null)
                throw new InvalidOperationException("stream to encrypt already specified");

            OutStream = outStream ?? throw new ArgumentNullException("outStream");

            return this;
        }

        public PgpDecryptionBuilder WithPrivateKey(string privateKeyPath, string password)
        {
            if (string.IsNullOrEmpty(privateKeyPath))
                throw new ArgumentNullException("privateKeyPath");

            if (!Uri.IsWellFormedUriString(privateKeyPath, UriKind.RelativeOrAbsolute))
                throw new ArgumentException("privateKeyPath", "malformed file path");

            if (!File.Exists(privateKeyPath))
                throw new ArgumentException("privateKeyPath", "file does not exists");

            var privateKeyStream = File.OpenRead(privateKeyPath);

            return WithPrivateKey(privateKeyStream, password);
        }

        public PgpDecryptionBuilder WithPrivateKey(Stream privateKeyStream, string password)
        {
            var privateKeyInfo = new PrivateKeyInfo
            {
                PrivateKeyStream = privateKeyStream ?? throw new ArgumentNullException("privateKeyStream"),
                PrivateKeyPassword = password
            };

            PrivateKeys.Add(privateKeyInfo);

            return this;
        }

        public PgpDecryptionBuilder VerifySignatureUsingKey(string signatureKeyPath)
        {
            if (string.IsNullOrEmpty(signatureKeyPath))
                throw new ArgumentNullException("signatureKeyPath");

            if (!Uri.IsWellFormedUriString(signatureKeyPath, UriKind.RelativeOrAbsolute))
                throw new ArgumentException("signatureKeyPath", "malformed file path");

            if (!File.Exists(signatureKeyPath))
                throw new ArgumentException("signatureKeyPath", "file does not exists");

            var signatureKeyStream = File.OpenRead(signatureKeyPath);

            return VerifySignatureUsingKey(signatureKeyStream);
        }

        public PgpDecryptionBuilder VerifySignatureUsingKey(Stream signatureKeyStream)
        {
            SignatureKeys.Add(signatureKeyStream ?? throw new ArgumentNullException("signatureKeyStream"));
            VerifySignature = true;

            return this;
        }

        public PgpDecryptionTask Build() => new PgpDecryptionTask
        {
            InStream = InStream,
            OutStream = OutStream,
            PrivateKeys = PrivateKeys,
            SignatureKeys = SignatureKeys,
            CheckSignature = VerifySignature
        };

    }

    class PrivateKeyInfo
    {
        internal Stream PrivateKeyStream { get; set; }
        internal string PrivateKeyPassword { get; set; }
    }
}
