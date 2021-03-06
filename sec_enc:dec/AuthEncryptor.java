/* Written by David Lax <dlax@uchicago.edu>, 1/25/16
 * AuthEncryptor.java
 * 
 * This class is used to compute the authenticated encryption of values.
 * Authenticated encryption protects the confidentiality of a value, so that the only
 * way to recover the initial value is to do authenticated decryption of the value using the 
 * same key and nonce that were used to encrypt it.   At the same time, authenticated encryption
 * protects the integrity of a value, so that a party decrypting the value using
 * the same key and nonce (that were used to decrypt it) can verify that nobody 
 * has tampered with the value since it was encrypted.
 */

public class AuthEncryptor {
    
    
    public static final int KeySizeBits = 448; 
    
    // by design, 
    // both keys, ekey = (NonceSizeBytes || KeySizeSplitBytes) 
    // and key2 = KeysizeBytes-Key1SizeBytes          should give the 256 bits to satisfy PRGen, 
    
    public static final int KeySizeBytes = KeySizeBits/8; 
    public static final int NonceSizeBytes = StreamCipher.NonceSizeBytes;
    
    // these fields are private, so that other programs cannot access their values!

    private final int KeySizeSplitBits = 192;                   // keep private to prevent information leakage as to where keys are split (why not)
    private final int KeySizeSplitBytes = KeySizeSplitBits/8;
    
    private int KeySizeAfterBytes = KeySizeBytes-KeySizeSplitBytes;
    
    private StreamCipher sc;
    private PRF prf;
    private byte[]ekey;
    private byte[]mackey;
    
    public AuthEncryptor(byte[] key) {
        assert key.length == KeySizeBytes;
        
        // split key into one key for Encrypt, and one for MAC
        
        ekey = new byte[KeySizeSplitBytes];
        mackey = new byte[KeySizeAfterBytes];
        
        System.arraycopy(key, 0, ekey, 0, KeySizeSplitBytes);                      // ekey is the first  192bits of the key
        System.arraycopy(key, KeySizeSplitBytes, mackey, 0, KeySizeAfterBytes);    // key2 is the remaining 256bits of the key
        
        sc = new StreamCipher(ekey);    // initialize streamcipher with encryption key, ekey        
    }
    
    public byte[] encrypt(byte[] in, byte[] nonce, boolean includeNonce) {
        
        // Callers are forbidden to pass in the same nonce more than once;
        //    but this code will not check for violations of this rule.
        
        int msglen = in.length; 
        byte[] enc = new byte[msglen];           // byte array for encrypted message
        
        sc.setNonce(nonce);                      // Initializing nonce for encryption
        sc.cryptBytes(in, 0, enc, 0, msglen);    // Encrypts the contents of <in> and stores in <enc>         
        
        prf = new PRF(mackey);                                               // Initialize PRF (a MAC) with mackey
        
        int maclen = PRF.OutputSizeBytes;         // length of output of mac
        byte[] mac_out;                           // to store output of mac
        byte[] ret;                               // return value; size of ret (and what it holds) depends on whether nonce will be included. 
        
        // Additionally will MAC to guarantee AuthEncryption:
        
        if(includeNonce) {
            ret = new byte[msglen+maclen+NonceSizeBytes];        // (encrypted msg) and (mac of encrypted message || nonce) and (nonce) 
            
            // The nonce will be included as part of the output iff <includeNonce>.  The nonce is appended in plaintext
            // to protect the nonce from being viewed by Eve, we MAC both the encrypted message and the nonce we're about to append:
            
            int big_maclen = msglen+NonceSizeBytes;
            byte[] to_mac = new byte[big_maclen];                              // will mac (encrypted message || nonce)
            System.arraycopy(enc, 0, to_mac, 0, msglen);
            System.arraycopy(nonce, 0, to_mac, msglen, NonceSizeBytes);        // to_mac holds desired input to pass to mac
            
            mac_out = prf.eval(to_mac, 0, big_maclen);                         // mac_out holds desired ouput of mac

            System.arraycopy(nonce, 0, ret, msglen+maclen, NonceSizeBytes);    // append nonce to end of <ret> (after msglen+maclen bytes)
            
        } else {
            mac_out = prf.eval(enc, 0, msglen);              // just call mac on encrypted message: <mac_out> holds MAC_k2(enc(m))        
            ret = new byte[msglen+maclen];                   // encrypted msg and mac of encrypted message            
        }
        
        // In either case, we:
        
        System.arraycopy(enc, 0, ret, 0, msglen);               // copy <enc> to beginning of <ret>
        System.arraycopy(mac_out, 0, ret, msglen, maclen);      // copy <mac> to end of <enc> in <ret>
        
        return ret;   // Finally returns newly allocated byte[] containing the authenticated encryption of the input.        
    }
        
//    public static void main (String [] args) {
//        byte[] temp = TrueRandomness.get();
//        byte[] seed = new byte[56];
//        System.arraycopy(temp, 0, seed, 0, 16);
//        System.arraycopy(temp, 0, seed, 16, 16);
//        System.arraycopy(temp, 0, seed, 32, 16);
//        System.arraycopy(temp, 7, seed, 48, 8);
//        
//        AuthEncryptor ae = new AuthEncryptor(seed);
//        byte[] msg1 = {'H','i',',',' ', 'h','o','w',' ','a','r','e',' ', 'y','o','u','?'}; // a typical message
//        byte[] nonce1 = {'a','g','5','9',';','`','p','8'};
//        byte[] out = ae.encrypt(msg1, nonce1, false);
//        System.out.println("The entire encryption of \"Hi, how are you?\" is:  \"" + new String(out) +"\"\n");
//        AuthDecryptor de = new AuthDecryptor(seed);
//        byte[] out1 = de.decrypt(out, nonce1, false);
//        if(out1 == null) {System.out.println("we've got some debugging to do!"); }
//        else { System.out.println("The decryption of \"" + new String(out) +"\" is: \""+ new String(out1) +"\"");
//            if(new String(out1).equals(new String(msg1))) System.out.println("Success!");
//        }
//        
//        System.out.println("\nNow let's try with the nonceincluded...\n");
//        System.out.println("... with the right nonce passed:");
//        byte[] seed2 = {'N','h','J','l','U','o','R','P','C','T','M','u','l','9','F','1','y','d','f','v','1','k','K','f','q','E','j','a','M','w','T','v','Q','H','e','D','r','x','E','G','X','b','0','E','o','F','C','k','i','4','s','U','k','l','O','p'};      
//        AuthEncryptor ae2 = new AuthEncryptor(seed2);
//        byte[] msg2 = {'H','i','!',' ', 'I','\'','m',' ','w','e','l','l', ' ', 'a','n','d', ' ','y','o','u','?'}; // a typical reply
//        byte[] nonce2 = {'t','Y','d','d','a','2','d',']'};
//        byte[] out2 = ae2.encrypt(msg2, nonce2, true);
//        System.out.println("The entire encryption of \"Hi! I'm well, and you?\" is:  " + new String(out2) +"\n");
//        AuthDecryptor de2 = new AuthDecryptor(seed2);
//        byte[] out21 = de2.decrypt(out2, nonce2, true);
//        if(out21 != null) {System.out.println("The decryption of \"" + new String(out2) +"\" is: "+ new String(out21));
//            if(new String(out21).equals(new String(msg2))) System.out.println("Success!");
//        } else System.out.println("More debugging! Oh boy!");
//        
//        
//        System.out.println("... and with the wrong nonce passed:");
//        byte[] out22 = de2.decrypt(out2,nonce1,false);
//        if(out22 == null) System.out.println("Yay! It broke as it should have!");
//        else System.out.println("Well, this shouldn't have passed.");
//
//        System.out.println("\n ... and with the wrong nonce passed another way:");
//        byte[] out3 = out2;
//        System.arraycopy(nonce1, 0, out3, out2.length-NonceSizeBytes, NonceSizeBytes); //changing passed nonce... mac equality should break
//        byte[] out23 = de2.decrypt(out3,nonce2,true);
//        if(out23 == null) System.out.println("Yay! It broke as it should have!\n");
//        else System.out.println("Well, this shouldn't have passed.\n");
//    }   
}