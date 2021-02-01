using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.FluentApi
{
    internal static class Utils
    {
        static string TempPath = System.IO.Path.GetTempPath();

        internal static Stream Streamify(this string theString, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            var stream = new MemoryStream(encoding.GetBytes(theString));
            return stream;
        }

        internal static string Stringfy(this Stream theStream, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            var buffer = theStream.ReadFully(0);
            return encoding.GetString(buffer);
        }

        internal static string Stringfy(this byte[] theStream, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            return encoding.GetString(theStream);
        }

        internal static string ToBase64String(this Stream theStream)
        {
            var buffer = theStream.ReadFully(0);
            return Convert.ToBase64String(buffer);
        }

        internal static byte[] ReadFully(this Stream stream, int position = 0)
        {
            if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("This is not a readable/seekable stream.");
            var originalPosition = stream.Position;

            try
            {
                stream.Position = position;
                var buffer = new byte[32768];
                using (var ms = new MemoryStream())
                {
                    while (true)
                    {
                        var read = stream.Read(buffer, 0, buffer.Length);
                        if (read <= 0)
                            return ms.ToArray();
                        ms.Write(buffer, 0, read);
                    }
                }

            }
            finally
            {
                stream.Position = originalPosition;
            }
        }

        internal static void Clear(this Stream stream)
        {
            if (!stream.CanWrite || !stream.CanSeek) throw new ArgumentException("This is not a writable/seekable stream.");

            stream.SetLength(0);
        }

        internal static FileInfo CreateTempFile(string fileName = null)
        {
            if (string.IsNullOrEmpty(fileName))
                fileName = Path.GetRandomFileName();

            var tempFilePath = Path.Combine(TempPath, fileName);
            var tempFile = new FileInfo(tempFilePath);

            return tempFile;
        }

        internal static bool IsPathValid(string path, out string error)
        {
            error = null;
            try
            {
                var fullPath = Path.GetFullPath(path);
            }
            catch(Exception ex)
            {
                error = $"{ex.GetType().Name}, {ex.Message}";
                return false;
            }
            return true;
        }
    }
}
