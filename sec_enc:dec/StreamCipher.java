
/* Written by David Lax <dlax@uchicago.edu>, 1/25/16
 * StreamCipher.java
 * This encrypts or decrypts a stream of bytes, using a stream cipher,
 * which itself uses a pseudorandom generator from PRGen.java
 */


public class StreamCipher {
    // This class encrypts or decrypts a stream of bytes, using a stream cipher.
    
    public static final int KeySizeBits = 192;  // The design is such that(NonceSizeBytes || KeysizeBytes) gives the 256 bits to satisfy PRGen
    
    public static final int KeySizeBytes = KeySizeBits/8;
    
    public static final int NonceSizeBits = 64;
    public static final int NonceSizeBytes = NonceSizeBits/8;
    
    // these fields are private, so that other programs cannot access their values!
    private PRGen prg;
    private byte[] seed;
    
    public StreamCipher(byte[] key) {
        // <key> is the key, which must be KeySizeBytes bytes in length.     
        assert key.length == KeySizeBytes;
        seed = key;
    }
    
// WARNING:
    // It is an error to call setNonce with the same nonce
    //    more than once on a single StreamCipher object.
    // StreamCipher does not check for nonce uniqueness;
    //    that is the responsibility of the caller.
    
    public void setNonce(byte[] arr, int offset){
        // Reset to initial state, and set a new nonce.
        // The nonce is in arr[offset] thru arr[offset+NonceSizeBytes-1].
        
        assert arr.length == NonceSizeBytes+offset;
        
        int len = NonceSizeBytes+KeySizeBytes;
        byte[] newseed = new byte[len];                
        System.arraycopy(arr, offset, newseed, 0, NonceSizeBytes);
        System.arraycopy(seed, 0, newseed, NonceSizeBytes, KeySizeBytes);  // newseed must satisfy the 32 B contract for PRG
        prg = new PRGen(newseed);
        
    }
    
    public void setNonce(byte[] nonce) {
        // A wrapper for setNonce, with the basecase offset = 0
        // Reset to initial state, and set a new nonce       
        assert nonce.length == NonceSizeBytes;
        setNonce(nonce, 0);
    }
    
    public byte cryptByte(byte in) {
        // Encrypt/decrypt the next byte in the stream, with 
        //   PRG_seed.output() ? <in> 
        //                  where <in> may be m or c

        byte[] bytes = new byte[1]; // size doesn't matter; only need one next Byte from prgen.
        
        if (bytes == null) System.out.println("null array ... :/ ");
        prg.nextBytes(bytes);
        
        return (byte) (bytes[0]^in);
        
    }
    
    public void cryptBytes(byte[] inBuf, int inOffset, byte[] outBuf, int outOffset, int numBytes) {
        // Encrypt/decrypt the next <numBytes> bytes in the stream
        // Take input bytes from inBuf[inOffset] thru inBuf[inOffset+numBytes-1]
        // Put output bytes at outBuf[outOffset] thru outBuf[outOffset+numBytes-1];
        
        for(int i = 0; i < numBytes; i++) {
            outBuf[i+outOffset] = cryptByte(inBuf[i+inOffset]);   
        }
    }
    
//    public static void main(String[] argv) {
//        byte[] test = new byte[KeySizeBytes]; 
//        System.out.println("the key length is "+ test.length); 
//        
//// initialize arbitrary test sequence of bytes
//        for(int i = 0; i < KeySizeBytes; i++) {
//            test[i] = (byte) ((12-(i^2))*13); 
//        }
//        
//        StreamCipher s = new StreamCipher(test);
//        byte[] n = new byte[192];
//        byte[] temp = TrueRandomness.get();
//        byte[] r1 = new byte[NonceSizeBytes];
//        System.arraycopy(temp,0, r1,0, NonceSizeBytes);
//        s.setNonce(r1,0);
//        byte[] msg = {'s','e','n','d',' ','h', 'e', 'l','p',' ', 'n','o','w'};
//        byte[] c = new byte[256]; 
//        System.out.println("Message is: " + new String(msg));
//        s.cryptBytes(msg, 0, c, 0, 13);
//        char[] enc = new char[13];
//        for(int i = 0; i < enc.length; i++){
//            enc[i] = (char) c[i];
//        }
//        System.out.println("Encrypted message is: " + new String(enc));
//        s.setNonce(r1);
//        
//        byte[] d = new byte[256]; // for decryption
//        s.cryptBytes(c, 0, d, 0, 13); 
//        char[] dec = new char[13];
//        
//        for(int i = 0; i < dec.length; i++){
//            dec[i] = (char) d[i];
//        }
//        System.out.println("Decrypted message is: " + new String(dec));
//        System.out.println("Now to check another message\n\n");
//        mainRoutineTwo();
//    }
    
//    public static void mainRoutineTwo() {
//        byte[] test = new byte[KeySizeBytes]; 
//        // initialize arbitrary test sequence of bytes
//        for(int i = 0; i < KeySizeBytes; i++) {
//            test[i] = (byte) ((144-(i^18))*2); 
//        }
//        StreamCipher s = new StreamCipher(test);
//        byte[] n = new byte[192];
//        byte[]r1 = {'k','u','v','i','a','6','8',',','9'}; 
//        s.setNonce(r1,1);
//        byte[] msg = {'d','a','v', 'i', 'd',' ','b','o','w','i','e',' ','l', 'i', 'v', 'e', 's', '!'};
//        byte[] c = new byte[256]; 
//        System.out.println("Message is: " + new String(msg));
//        s.cryptBytes(msg, 0, c, 0, 18);
//        char[] enc = new char[18];
//        for(int i = 0; i < enc.length; i++){
//            enc[i] = (char) c[i];
//        }
//        System.out.println("Encrypted message is: " + new String(enc));
//        byte[] r2 = {'u','v','i','a','6','8',',','9'};
//        s.setNonce(r2);
//        
//        byte[] d = new byte[256]; // for decryption
//        s.cryptBytes(c, 0, d, 0, 18); 
//        char[] dec = new char[18];
//        
//        for(int i = 0; i < dec.length; i++){
//            dec[i] = (char) d[i];
//        }
//        System.out.println("Decrypted message is: " + new String(dec));
//    }

}