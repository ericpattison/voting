using System;
using System.Security.Cryptography;
using System.Text;

namespace guid_extensions {
    public static class GuidFactory {
        
        public static Guid V3(Guid nsId, String name) {
            var hash = EncodeName(nsId, name, MD5.Create());
            var guid = ConvertHashToGuidBytes(hash);

            guid[6] = (byte)((guid[6] & 0x0F) | (3 << 4));
            guid[8] = (byte)((guid[8] & 0x3F) | 0x80);

            SwapByteOrder(guid);
            
            return new Guid(guid);
        }
        
        public static Guid V5(Guid nsId, String name) {
            var hash = EncodeName(nsId, name, SHA1.Create());
            var guid = ConvertHashToGuidBytes(hash);
            
            guid[6] = (byte)((guid[6] & 0x0F) | (5 << 4));
            guid[8] = (byte)((guid[8] & 0x3F) | 0x80);

            SwapByteOrder(guid);

            return new Guid(guid);
        }

        private static byte[] EncodeName(Guid nsId, String name, HashAlgorithm algorithm) {
            if(String.IsNullOrEmpty(name))
                throw new ArgumentNullException("name");

            var nameBytes = Encoding.UTF8.GetBytes(name);
            var nsBytes = nsId.ToByteArray();

            SwapByteOrder(nsBytes);

            algorithm.TransformBlock(nsBytes, 0, nsBytes.Length, null, 0);
            algorithm.TransformFinalBlock(nameBytes, 0, nameBytes.Length);

            return algorithm.Hash;
        }

        private static byte[] ConvertHashToGuidBytes(byte[] hash) {
            byte[] guid = new byte[16];
            Array.Copy(hash, 0, guid, 0, 16);
            return guid;
        }

        private static void SwapByteOrder(byte[] guid) {
            SwapBytes(guid, 0, 3);
            SwapBytes(guid, 1, 2);
            SwapBytes(guid, 4, 5);
            SwapBytes(guid, 6, 7);
        }

        private static void SwapBytes(byte[] guid, int l, int r) {
            byte t = guid[l];
            guid[l] = guid[r];
            guid[r] = t;
        }
    }
}
