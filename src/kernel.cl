// Sha256 and Address Miner Kernel
// Sha256 code from kristforge (legacy branch)
// https://github.com/tmpim/kristforge/tree/legacy
// Licensed under MIT
// Modifications licensed under the pmkam project license

// Sha256

typedef union UINT {
    uint i;
    uchar c[4];
} UINT;

#ifdef __ENDIAN_LITTLE__
    #define UINT_BYTE_BE(U, I) ((U).c[3 - (I)])
#else
    #define UINT_BYTE_BE(U, I) ((U).c[(I)])
#endif

// right rotate macro
#define RR(x, y) rotate((uint)(x), -((uint)(y)))

// sha256 macros
#define CH(x, y, z) bitselect((z), (y), (x))
#define MAJ(x, y, z) bitselect((x), (y), (z) ^ (x))
#define EP0(x) (RR((x), 2) ^ RR((x), 13) ^ RR((x), 22))
#define EP1(x) (RR((x), 6) ^ RR((x), 11) ^ RR((x), 25))
#define SIG0(x) (RR((x), 7) ^ RR((x), 18) ^ ((x) >> 3))
#define SIG1(x) (RR((x), 17) ^ RR((x), 19) ^ ((x) >> 10))

// sha256 initial hash values
#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

// sha256 round constants
__constant uint K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// sha256 round constants added to a precomputed schedule of
// the second block from a 64-byte message
__constant uint K2[64] = {
    0xc28a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf374,
    0x649b69c1, 0xf0fe4786, 0x0fe1edc6, 0x240cf254, 0x4fe9346f, 0x6cc984be, 0x61b9411e, 0x16f988fa,
    0xf2c65152, 0xa88e5a6d, 0xb019fc65, 0xb9d99ec7, 0x9a1231c3, 0xe70eeaa0, 0xfdb1232b, 0xc7353eb0,
    0x3069bad5, 0xcb976d5f, 0x5a0f118f, 0xdc1eeefd, 0x0a35b689, 0xde0b7a04, 0x58f4ca9d, 0xe15d5b16,
    0x007f3e86, 0x37088980, 0xa507ea32, 0x6fab9537, 0x17406110, 0x0d8cd6f1, 0xcdaa3b6d, 0xc0bbbe37,
    0x83613bda, 0xdb48a363, 0x0b02e931, 0x6fd15ca7, 0x521afaca, 0x31338431, 0x6ed41a95, 0x6d437890,
    0xc39c91f2, 0x9eccabbd, 0xb5c9a0e6, 0x532fb63c, 0xd2c741c6, 0x07237ea3, 0xa4954b68, 0x4c191d76
};

// perform a single round of sha256 transformation on the given data
inline void digest64(UINT m[64], UINT H[8]) {
    int i;
    uint a, b, c, d, e, f, g, h, t1, t2;

#pragma unroll
    for (i = 16; i < 64; i++) {
        m[i].i = SIG1(m[i - 2].i)
            + m[i - 7].i
            + SIG0(m[i - 15].i)
            + m[i - 16].i;
    }

    a = H0;
    b = H1;
    c = H2;
    d = H3;
    e = H4;
    f = H5;
    g = H6;
    h = H7;

#pragma unroll
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i].i;
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    a += H0;
    b += H1;
    c += H2;
    d += H3;
    e += H4;
    f += H5;
    g += H6;
    h += H7;

    H[0].i = a;
    H[1].i = b;
    H[2].i = c;
    H[3].i = d;
    H[4].i = e;
    H[5].i = f;
    H[6].i = g;
    H[7].i = h;

#pragma unroll
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K2[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    H[0].i += a;
    H[1].i += b;
    H[2].i += c;
    H[3].i += d;
    H[4].i += e;
    H[5].i += f;
    H[6].i += g;
    H[7].i += h;
}

// Address miner

#define THREAD_ITER 4096 // How many addresses each work unit checks
#define CHAIN_SIZE (16 * 8) // 16 stored iterations with 8 bytes each
#define MAX_CHAIN_ITER 16 // The max amout of iterations the check_address function does before giving up.
                          // Must not be greater than CHAIN_SIZE / 8. (otherwise false positives will happen without any other benefit).
                          // A max chain iter of n means a failure probability of at most (7/9)^n per address checked.

// precomputed message block conversions for sha256(hex)
__shared ushort DATA_TO_HEX_TO_M[256] = {
	12336, 12337, 12338, 12339, 12340, 12341, 12342, 12343, 12344, 12345, 12385, 12386,
	12387, 12388, 12389, 12390, 12592, 12593, 12594, 12595, 12596, 12597, 12598, 12599,
	12600, 12601, 12641, 12642, 12643, 12644, 12645, 12646, 12848, 12849, 12850, 12851,
	12852, 12853, 12854, 12855, 12856, 12857, 12897, 12898, 12899, 12900, 12901, 12902,
	13104, 13105, 13106, 13107, 13108, 13109, 13110, 13111, 13112, 13113, 13153, 13154,
	13155, 13156, 13157, 13158, 13360, 13361, 13362, 13363, 13364, 13365, 13366, 13367,
	13368, 13369, 13409, 13410, 13411, 13412, 13413, 13414, 13616, 13617, 13618, 13619,
	13620, 13621, 13622, 13623, 13624, 13625, 13665, 13666, 13667, 13668, 13669, 13670,
	13872, 13873, 13874, 13875, 13876, 13877, 13878, 13879, 13880, 13881, 13921, 13922,
	13923, 13924, 13925, 13926, 14128, 14129, 14130, 14131, 14132, 14133, 14134, 14135,
	14136, 14137, 14177, 14178, 14179, 14180, 14181, 14182, 14384, 14385, 14386, 14387,
	14388, 14389, 14390, 14391, 14392, 14393, 14433, 14434, 14435, 14436, 14437, 14438,
	14640, 14641, 14642, 14643, 14644, 14645, 14646, 14647, 14648, 14649, 14689, 14690,
	14691, 14692, 14693, 14694, 24880, 24881, 24882, 24883, 24884, 24885, 24886, 24887,
	24888, 24889, 24929, 24930, 24931, 24932, 24933, 24934, 25136, 25137, 25138, 25139,
	25140, 25141, 25142, 25143, 25144, 25145, 25185, 25186, 25187, 25188, 25189, 25190,
	25392, 25393, 25394, 25395, 25396, 25397, 25398, 25399, 25400, 25401, 25441, 25442,
	25443, 25444, 25445, 25446, 25648, 25649, 25650, 25651, 25652, 25653, 25654, 25655,
	25656, 25657, 25697, 25698, 25699, 25700, 25701, 25702, 25904, 25905, 25906, 25907,
	25908, 25909, 25910, 25911, 25912, 25913, 25953, 25954, 25955, 25956, 25957, 25958,
	26160, 26161, 26162, 26163, 26164, 26165, 26166, 26167, 26168, 26169, 26209, 26210,
	26211, 26212, 26213, 26214 };

// Converts a sha256 hash to hexadecimal
inline void hash_to_hex(const UINT hash[8], UINT hex[64]) {
#ifdef __NV_CL_C_VERSION
#pragma unroll
    for (int i = 0; i < 16; i += 2) {
        uchar h, h1, h2;

        h = UINT_BYTE_BE(hash[i / 2], 0);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i], 1) = h1 + (h1 < 10 ? '0' : 'a' - 10);
        UINT_BYTE_BE(hex[i], 0) = h2 + (h2 < 10 ? '0' : 'a' - 10);

        h = UINT_BYTE_BE(hash[i / 2], 1);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i], 3) = h1 + (h1 < 10 ? '0' : 'a' - 10);
        UINT_BYTE_BE(hex[i], 2) = h2 + (h2 < 10 ? '0' : 'a' - 10);

        h = UINT_BYTE_BE(hash[i / 2], 2);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i + 1], 1) = h1 + (h1 < 10 ? '0' : 'a' - 10);
        UINT_BYTE_BE(hex[i + 1], 0) = h2 + (h2 < 10 ? '0' : 'a' - 10);

        h = UINT_BYTE_BE(hash[i / 2], 3);
        h1 = h % 16;
        h2 = h / 16;
        UINT_BYTE_BE(hex[i + 1], 3) = h1 + (h1 < 10 ? '0' : 'a' - 10);
        UINT_BYTE_BE(hex[i + 1], 2) = h2 + (h2 < 10 ? '0' : 'a' - 10);
    }
#else
#pragma unroll
	for (int i = 0; i < 8; i++) {
		// convert the raw bytes, straight to M, skipping the conversion to hex
		// because it has already been precomputed.
        hex[i * 2].i = upsample(DATA_TO_HEX_TO_M[UINT_BYTE_BE(hash[i], 0)], DATA_TO_HEX_TO_M[UINT_BYTE_BE(hash[i], 1)]);
        hex[i * 2 + 1].i = upsample(DATA_TO_HEX_TO_M[UINT_BYTE_BE(hash[i], 2)], DATA_TO_HEX_TO_M[UINT_BYTE_BE(hash[i], 3)]);
	}
#endif
}

// Converts a byte to the one used by the trie
// byte | krist | trie_char
// 0    | 0     | 0
// 6    | 0     | 0
// 7    | 1     | 1
// 69   | 9     | 9
// 70   | a     | 10
// 251  | z     | 35
// 252  | e     | 14
// 255  | e     | 14
inline uchar make_address_byte_s(uchar byte) {
    uchar byte_div_7 = byte / 7;
    if (byte_div_7 == 36) {
        return 14;
    }
    return byte_div_7;
}

// A 'hash chain'
// Composed of:
// - chain: A circular buffer with the first 8 bytes from every hash that is
//          outputted from iterating sha256.
// - last_hash: The (32-byte) hash from the last iteration.
// - chain_start: The write pointer for the chain buffer.
// - protein: A circular buffer with trie_char form of the first byte from each
//            chain hash, shifted back by 18 iterations.
// - protein_start: The write pointer for the protein buffer.
//
// Instead of doing 30+ hashes for every address we check, we iterate
// the hash several times and put the result in an array, referred to here
// as the 'hash chain'.
// Krist uses information from H(pk), H(H(pk)), H(H(H(pk))), ... to make
// an address. we store all these in an array and we 'shift' the array such
// that pk' = H(pk); H(pk') = H(H(pk)), ... Shifting the chain like this
// requires only a single call to sha256 and yields a new pkey/address pair
// to check for term matches.
// Finally, Kristwallet only needs the first 8 bytes from every hash, so
// we only store that (as well as the seed and last hash, so we can shift).
typedef struct HASH_CHAIN_T {
    UINT last_hash[8];
    uint chain_start;
    uchar chain[CHAIN_SIZE];
    uchar protein[18];
    uint protein_start;
} HASH_CHAIN_T;

// Advances a hash chain by 1 iteration:
// - Sets last_hash to sha256(last_hash).
// - Writes the address byte from the first byte from the chain buffer to the
//   protein buffer.
// - Writes the first 8 bytes from last_hash to the chain buffer.
inline void shift_chain(HASH_CHAIN_T *chain) {
    UINT hash_hex[64];
    hash_to_hex(chain->last_hash, hash_hex);
    digest64(hash_hex, chain->last_hash);

    chain->protein[chain->protein_start] = make_address_byte_s(
        chain->chain[chain->chain_start]
    );
    chain->protein_start = (chain->protein_start + 1) % 18;

#pragma unroll
    for (int i = 0; i < 8; i++) {
        chain->chain[chain->chain_start + i] = UINT_BYTE_BE(chain->last_hash[i / 4], i % 4);
    }
    chain->chain_start = (chain->chain_start + 8) % CHAIN_SIZE;
}

// 0 - Dead end
// 1 - There are valid prefixes
// 2 - There is a full term that matches this
inline int iter_prefix_search(const uchar addr_char, uint* index, __global const uint *trie) {
    uint trie_data;

    trie_data = trie[*index + addr_char];
    switch (trie_data) {
        case 0:
            return 0;
        case 1:
            return 2;
        default:
            *index += (trie_data - 1) * 36;
            return 1;
    }
}

// Given a hash chain, uses its information to generate an address without hashing anything
// such that the resulting address' pkey can be found from the seed that constructed the hash chain
inline bool check_address(const HASH_CHAIN_T *chain,__global const uint *trie) {
    uint chain_index = chain->chain_start;
    uint link;
    uint iter = 0;
    uchar v2[9];

    int i = 0;
    uint trie_index = 0;
    bool used_protein[9] = {};
    while (i < 8 && iter < MAX_CHAIN_ITER) {
        link = chain->chain[chain_index + i] % 9;
        if (!used_protein[link]) {
            v2[i] = chain->protein[(chain->protein_start + 2 * link) % 18];
            used_protein[link] = true;

            int found = iter_prefix_search(v2[i], &trie_index, trie);
            switch (found) {
                case 0:
                    return false;
                case 1:
                    i++;
                    break;
                case 2:
                    return true;
            }
        } else {
            chain_index = (chain_index + 8) % CHAIN_SIZE;
            iter++;
        }
    }

    if (iter >= MAX_CHAIN_ITER) {
        return 0;
    }

    // Put in last char in the address
#pragma unroll
    for (i = 0; i < 9; i++) {
        if (!used_protein[i]) {
            v2[8] = chain->protein[(chain->protein_start + 2 * i) % 18];
            break;
        }
    }

    return iter_prefix_search(v2[8], &trie_index, trie) == 2;
}

__kernel void mine(
    __constant const uchar *entropy,      // 10 bytes
    __global const uint *trie,            // Variable size
    const ulong nonce,
    __global uchar *solved,               // 1 byte
    __global uchar *pkey                  // 32 bytes
) {
    uint gid = get_global_id(0);

    // Generate seed from hashing some arguments
    uint gid_seed = gid;
    ulong nonce_seed = nonce;
    UINT seed[64] = {};

    for (int i = 0; i < 10; i++) {
        UINT_BYTE_BE(seed[i / 4], i % 4) = entropy[i];
    }
    seed[3].i = gid_seed;
    seed[4].i = nonce_seed % UINT_MAX;
    seed[5].i = nonce_seed / UINT_MAX;

    UINT seed_hash[8];
    digest64(seed, seed_hash);

    // Make chain and protein
    HASH_CHAIN_T chain;
    chain.chain_start = 0;
    chain.protein_start = 0;

    // Put seed into the last chain hash
    for (int i = 0; i < 8; i++) {
        chain.last_hash[i] = seed_hash[i];
    }

    // Populate chain
    shift_chain(&chain); // krist's makev2address hashes the pkey twice before doing its thing
    shift_chain(&chain); // if the address from 0 or 1 was a match, we would not have the key without doing this

    for (int i = 1; i < 18; i++) {
        shift_chain(&chain);
    }
    for (int i = 0; i < CHAIN_SIZE; i += 8) {
        shift_chain(&chain);
    }

    // Mine
    bool solution_found = false;
    uint solution_found_at;
    for (int i = 0; i < THREAD_ITER; i++) {
        if (check_address(&chain, trie)) {
            solution_found = true;
            solution_found_at = i;
        }
        shift_chain(&chain);
    }

    // Re-do hashes to find proper pkey
    // This *may* be faster to do on CPU due to higher clock frequencies
    if (solution_found) {
        UINT hash_byte[8];
        UINT hash_hex[64];
        hash_to_hex(seed_hash, hash_hex);

        for (int i = 0; i < solution_found_at; i++) {
            digest64(hash_hex, hash_byte);
            hash_to_hex(hash_byte, hash_hex);
        }

        *solved = 1;
        for (int i = 0; i < 32; i++) {
            pkey[i] = UINT_BYTE_BE(hash_byte[i / 4], i % 4);
        }
    }
}
