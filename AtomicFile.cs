using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace NutriculaInstaller
{
    /// <summary>
    /// Every file this installer creates or replaces goes through here (2026
    /// rule: files are always created atomically). The content is written to a
    /// uniquely named temp file in the SAME directory, flushed all the way to
    /// disk, and only then swapped over the real file in ONE operation
    /// (MoveFileEx with MOVEFILE_REPLACE_EXISTING). A reader - the Broker, MT4/MT5,
    /// an antivirus - therefore sees either the complete old file or the complete
    /// new file, never a partial or momentarily missing one, and a crash/power
    /// loss mid-write leaves the old file untouched (only a stray temp file).
    /// There is deliberately no "delete the old file, then move the new one"
    /// step anywhere: that leaves a window in which the file does not exist.
    /// </summary>
    internal static class AtomicFile
    {
        private const uint MOVEFILE_REPLACE_EXISTING = 0x1;
        private const uint MOVEFILE_WRITE_THROUGH = 0x8;
        private const int ERROR_SHARING_VIOLATION = 32;
        private const int ERROR_LOCK_VIOLATION = 33;
        private const int ERROR_ACCESS_DENIED = 5;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool MoveFileExW(string existingFileName, string newFileName, uint flags);

        /// <summary>A unique temp path next to <paramref name="finalPath"/>.</summary>
        public static string NewTempPath(string finalPath)
        {
            return finalPath + ".nutricula_tmp_" + Guid.NewGuid().ToString("N");
        }

        /// <summary>
        /// Opens the temp file for writing. Callers write into it, call
        /// <c>Flush(true)</c> (or just Dispose after writing with WriteThrough),
        /// and then call <see cref="Replace"/>.
        /// </summary>
        public static FileStream CreateTemp(string tempPath, int bufferSize = 64 * 1024, bool useAsync = false)
        {
            return new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None,
                bufferSize, useAsync ? FileOptions.Asynchronous | FileOptions.WriteThrough : FileOptions.WriteThrough);
        }

        /// <summary>Atomically swaps the finished temp file over <paramref name="finalPath"/>.</summary>
        public static void Replace(string tempPath, string finalPath)
        {
            // A just-written file is sometimes still being scanned by an
            // antivirus, which can make the replace fail briefly with a sharing
            // violation - retry a few times before giving up.
            int lastError = 0;
            for (int attempt = 0; attempt < 6; attempt++)
            {
                if (MoveFileExW(tempPath, finalPath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return;
                lastError = Marshal.GetLastWin32Error();
                if (lastError != ERROR_SHARING_VIOLATION && lastError != ERROR_LOCK_VIOLATION && lastError != ERROR_ACCESS_DENIED) break;
                Thread.Sleep(250);
            }
            TryDelete(tempPath);
            throw new IOException("Could not replace the file atomically: " + finalPath, new Win32Exception(lastError));
        }

        /// <summary>Atomically writes <paramref name="data"/> to <paramref name="finalPath"/>.</summary>
        public static void WriteAllBytes(string finalPath, byte[] data)
        {
            string temp = NewTempPath(finalPath);
            try
            {
                using (FileStream fs = CreateTemp(temp))
                {
                    byte[] bytes = data ?? new byte[0];
                    fs.Write(bytes, 0, bytes.Length);
                    fs.Flush(true);
                }
                Replace(temp, finalPath);
            }
            catch
            {
                TryDelete(temp);
                throw;
            }
        }

        /// <summary>Atomically writes text (UTF-8, no BOM) to <paramref name="finalPath"/>.</summary>
        public static void WriteAllText(string finalPath, string text)
        {
            WriteAllBytes(finalPath, new System.Text.UTF8Encoding(false).GetBytes(text ?? string.Empty));
        }

        /// <summary>Atomically copies a file: temp copy first, then a single replace.</summary>
        public static void Copy(string sourcePath, string finalPath)
        {
            string temp = NewTempPath(finalPath);
            try
            {
                using (FileStream src = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (FileStream dst = CreateTemp(temp))
                {
                    src.CopyTo(dst, 64 * 1024);
                    dst.Flush(true);
                }
                Replace(temp, finalPath);
            }
            catch
            {
                TryDelete(temp);
                throw;
            }
        }

        public static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { }
        }
    }
}
