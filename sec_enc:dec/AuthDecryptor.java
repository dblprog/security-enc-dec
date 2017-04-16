/* Written by David Lax <dlax@uchicago.edu>, 1/25/16
 * AuthDecryptor.java
 * 
 * This class is used to decrypt and authenticate a sequence of values that were encrypted by an AuthEncryptor.
 * Upon decrypting, returns <null> if the integrity of the message (or nonce if the nonce is included) cannot be verified.
 */

public class AuthDecryptor {
    
    // Same design as AuthEncryptor, quite literally: 
    
    public static final int KeySizeBits = AuthEncryptor.KeySizeBits;
    public static final int KeySizeBytes = AuthEncryptor.KeySizeBytes;
    
    public static final int NonceSizeBytes = AuthEncryptor.NonceSizeBytes;
    public static final int SubKeySizeBytes = (KeySizeBytes/2);
    
    
    // these fields are private, so that other programs cannot access their values!
    
    private final int KeySizeSplitBits = 192;                // keep private to prevent information loss
    private final int KeySizeSplitBytes = KeySizeSplitBits/8;
    private final int KeySizeAfterBytes = KeySizeBytes-KeySizeSplitBytes;
    
    private StreamCipher sc;
    private PRF prf;
    
    private byte[]dkey;          // decryptor key
    private byte[]mackey;        // mac key 
    
    public AuthDecryptor(byte[] key) {
        assert key.length == KeySizeBytes;
        
        dkey = new byte[KeySizeSplitBytes];
        mackey = new byte[KeySizeAfterBytes];
        
        System.arraycopy(key, 0, dkey, 0, KeySizeSplitBytes);                      // dkey is the first  192bits of the key
        System.arraycopy(key, KeySizeSplitBytes, mackey, 0, KeySizeAfterBytes);    // mackey is the remaining 256bits of the key
        
        sc = new StreamCipher(dkey);    // initialize streamcipher with decryption key        
    }
    
    public byte[] decrypt(byte[] in, byte[] nonce, boolean nonceIncluded) {
        // Decrypt and authenticate the contents of <in>.  The value passed in will normally
        //    have been created by calling encrypt() with the same nonce in an AuthEncryptor 
        //    that was initialized with the same key as this AuthDecryptor.
        // If the integrity of <in> cannot be verified, then this method returns null.   Otherwise it returns 
        //    a newly allocated byte-array containing the plaintext value that was originally 
        //    passed to encrypt().
        
        // some constants to reduce and simplify future computations:
        
        int inlen = in.length;
        int keylen = KeySizeAfterBytes;
        int maclen = PRF.OutputSizeBytes;
        int noncelen = StreamCipher.NonceSizeBytes;
        int msglen = inlen - maclen;       // <in> includes at least msg + mac (potentially also noncelen)  
        
        
        byte[] newnonce = new byte[noncelen];     // will be used iff nonceIncluded; if valid, then <nonce> will be overwritten by <newnonce>
        byte[] mac_in;                            // to store appropriate input to mac
        
        prf = new PRF(mackey);                                               // Initialize PRF (a MAC) with mackey
        
        if(nonceIncluded) {
            System.arraycopy(in, inlen-noncelen, newnonce, 0, noncelen);
            
            mac_in = new byte[msglen];                  // msglen includes msg + noncelen
            msglen -= noncelen;                         // we update msglen; <in> included msg + mac + noncelen; subtract noncelen
            
            System.arraycopy(in, 0, mac_in, 0, msglen);                // copy encrypted message into <mac_in>
            System.arraycopy(newnonce, 0, mac_in, msglen, noncelen);  // append nonce to <mac_in>
            
        } else {                   // !(nonceIncluded)
            
            mac_in = new byte[msglen];                                 // msglen includes only msg
            System.arraycopy(in, 0, mac_in, 0, msglen);                // copy encrypted message into <mac_in>
            
            // we won't use newnonce, so there's no need to update it
            // everything else is equivalently done for this case.            
        }         
        
        byte[] enc = new byte[msglen];                               
        System.arraycopy(in, 0, enc, 0, msglen);                     // <enc> holds encrypted message, enc(m) 
        
        byte[] cmac = prf.eval(mac_in, 0, mac_in.length);     // <cmac> holds the computed MAC_k2(enc(m)) or MAC_k2(enc(m)||nonce), depending whether nonce was passed 
        
        byte[] pmac = new byte[maclen];
        System.arraycopy(in, msglen, pmac, 0, maclen);   // and <passedmac> holds the passed MAC_k2(enc(m)) or MAC_k2(enc(m)||nonce), depending ^
        
        // printing statements for testing
        
//        System.out.println("in ADecrypt, encrypted message is:                  " + new String(enc) +"\n");     // (which should be enc(m)
//        if(nonceIncluded)         System.out.println("while mac(enc(m)||nonce) is:            " + new String(cmac));
//        else                      System.out.println("while mac(enc(m)) is:                  " + new String(cmac));            
//        System.out.println("and passed mac(enc(m)) is:   " + new String(pmac) +"\n");
        
        // If the integrity of <in> cannot be verified, then this method returns null:
        
        if(!(new String(pmac).equals( new String(cmac)))) {
            // additional printing statement for testing
//            System.out.println("They weren't equal! Should they have been?");  
            return null;                                                         
        }                                          
        
        // Because we compared the mac of our properly split input and compared it to the passed mac,
        // where the calculted value was dependent upon the passed nonce, we have verified either the encrypted
        // message itself, or the pair of the encrypted message and the nonce; 
        // If Mallory added to the end of or otherwise modified the message or the input, 
        // this will *also* return null, since the odds of her inserting the proper bytes AND the MAC of those bytes 
        // matching the beginning of the MAC of the encrypted value are astronomically small. 
        
        if(nonceIncluded) nonce = newnonce;  // everything in <in> was valid; may set nonce = newnonce if the nonce was actually included;
        
        // otherwise, we've gotten this far, meaning the integrity of the cyphertext has been verified via mac;
        // we continue with the actual decrypting:
        
        byte[] ret = new byte[msglen]; 
        sc.setNonce(nonce);                                        // Initializing nonce for decryption
        sc.cryptBytes(enc, 0, ret, 0, msglen);   // Decrypts the contents of <enc(m)> and stores in <ret>         
        
        return ret;
        
    }
}