
import java.util.Random;

/* Written by David Lax <dlax@uchicago.edu>, 1/27/16
 * PRGen.java
 * This implements a pseudorandom generator with backtracking resistance.  
 * It extends java.util.Random, which provides a useful set of utility methods that all build on next(.).  
*/

public class PRGen extends Random {

    // This pseudorandom generator has the following properties:
    // 1) it is pseudorandom (indistinguishable from a truly random generator without knowing the key)
    // 2) it is deterministic (the same sequences of calls to generators with the same seeds have the same results)
    // 3) it is backtracking-resistant (if an adversary is able to observe the full state, s/he cannot reconstruct previous output)
     
    public static final int SeedSizeBits = 256;
    public static final int SeedSizeBytes = SeedSizeBits/8;
    
    // these fields are private, so that other programs cannot access their values!
    
    private PRF prf;
    private byte[] state;
    
    private static final byte[] output = {'o','u','t','p','u','t'};
    private static final byte[] advance = {'a','d','v','a','n','c','e'};
    
    
    public PRGen(byte[] seed) {
        super();
        assert seed.length == SeedSizeBytes;
        state = seed;               // initial state
        prf = new PRF(state);       // create PRF with key
    }
    
    protected int next(int bits) {
        byte[] out = prf.eval(output);     // byte array equal to output of PRF(arbitrary constant)
        int o = (out[0] | (out[1] << 8) | (out[2] << 16) | (out[3] << 24));  // to compress into a single byte
        int toshift = 32 - bits;    // unsigned shift by (32-<bits>) to return <bits> bits
        int r = o >>> (toshift);       
        
        state = prf.eval(advance); // update state
        prf = new PRF(state);    // update the prf for back-tracking resistance
//        System.out.println("should return "+ bits +" bits, or "+ (bits >>> 3) + " bytes");
        return r;  
    }
    
//    public static void main(String[] argv) {
//        byte[] cd = new byte[32]; 

//        byte[] temp = TrueRandomness.get(); 
//        System.arraycopy(temp, 0, cd, 0, 16);
//        System.arraycopy(temp, 0, cd, 16, 16);
//            PRGen p = new PRGen(cd);
//        
//        System.out.println("temp[4] will ask prgen for "+ (int) temp[4] + " bits");
//
//        System.out.println("prgen(next) is "+ p.next((int) temp[4]));
//        System.out.println("prgen(next) is "+ p.next((int) (temp[3])));
//        System.out.println("prgen(next) is "+ p.next((int) (temp[12])));
//        System.out.println("sanity checking prgen.next:");
//        byte[] derp = new byte[32];
//        p.nextBytes(derp);
//        for(int i = 0; i < 32; i++) {
//            System.out.println(derp[i] << 3);
//        }
//    }
}