/*
 * 2023-09-10 Converted to Rust
 *
 * This is D3DES (V5.09) by Richard Outerbridge with the double and
 * triple-length support removed for use in VNC.  Also the bytebit[] array
 * has been reversed so that the most significant bit in each byte of the
 * key is ignored, not the least significant.
 *
 * These changes are:
 *  Copyright (C) 1999 AT&T Laboratories Cambridge.  All Rights Reserved.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/* D3DES (V5.09) -
 *
 * A portable, public domain, version of the Data Encryption Standard.
 *
 * Written with Symantec's THINK (Lightspeed) C by Richard Outerbridge.
 * Thanks to: Dan Hoey for his excellent Initial and Inverse permutation
 * code;  Jim Gillogly & Phil Karn for the DES key schedule code; Dennis
 * Ferguson, Eric Young and Dana How for comparing notes; and Ray Lau,
 * for humouring me on.
 *
 * Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge.
 * (GEnie : OUTER; CIS : [71755,204]) Graven Imagery, 1992.
 */

const BYTEBIT: [u8; 8] = [0o1, 0o2, 0o4, 0o10, 0o20, 0o40, 0o100, 0o200];

const BIGBYTE: [u32; 24] = [
    0x800000, 0x400000, 0x200000, 0x100000, 0x80000, 0x40000, 0x20000, 0x10000, 0x8000, 0x4000,
    0x2000, 0x1000, 0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1,
];

/* Use the key schedule specified in the Standard (ANSI X3.92-1981). */
const PC1: [usize; 56] = [
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59,
    51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28,
    20, 12, 4, 27, 19, 11, 3,
];

const TOTROT: [u32; 16] = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

const PC2: [usize; 48] = [
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51,
    30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
];

const SP1: [u32; 64] = [
    0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400, 0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000, 0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000, 0x00010004, 0x00010400, 0x00000000, 0x01010004,
];

const SP2: [u32; 64] = [
    0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000, 0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000, 0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020, 0x80000000, 0x80100020, 0x80108020, 0x00108000,
];

const SP3: [u32; 64] = [
    0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000, 0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208, 0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000, 0x00020208, 0x00000008, 0x08020008, 0x00020200,
];

const SP4: [u32; 64] = [
    0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002000, 0x00802080,
];

const SP5: [u32; 64] = [
    0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100, 0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000, 0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000, 0x00000000, 0x40080000, 0x02080100, 0x40000100,
];

const SP6: [u32; 64] = [
    0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010, 0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000, 0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000, 0x20404000, 0x20000000, 0x00400010, 0x20004010,
];

const SP7: [u32; 64] = [
    0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002, 0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802, 0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800, 0x04000002, 0x04000800, 0x00000800, 0x00200002,
];

const SP8: [u32; 64] = [
    0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000, 0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000, 0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040, 0x00001040, 0x00040040, 0x10000000, 0x10041000,
];

#[derive(PartialEq, Eq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

pub struct Des {
    generated_key: [u32; 32],
}

impl Des {
    pub fn new(key: &[u8], direction: Direction) -> Self {
        Self {
            generated_key: Self::deskey(key, direction),
        }
    }

    fn deskey(key: &[u8], direction: Direction) -> [u32; 32] {
        let mut l;
        let mut m;
        let mut n;

        let mut pc1m = [0u8; 56];
        let mut pcr = [0u8; 56];
        let mut kn = [0u32; 32];

        for j in 0..56 {
            l = PC1[j] as isize;
            m = l & 07;
            pc1m[j] = if key[(l >> 3) as usize] & BYTEBIT[m as usize] != 0 {
                1
            } else {
                0
            };
        }

        for i in 0..16 {
            m = if direction == Direction::Decrypt {
                (15 - i) << 1
            } else {
                i << 1
            };
            n = m + 1;
            kn[m as usize] = 0;
            kn[n as usize] = 0;

            for j in 0..28 {
                l = j + TOTROT[i as usize] as isize;
                pcr[j as usize] = if l < 28 {
                    pc1m[l as usize]
                } else {
                    pc1m[(l - 28) as usize]
                };
            }
            for j in 28..56 {
                l = j + TOTROT[i as usize] as isize;
                pcr[j as usize] = if l < 56 {
                    pc1m[l as usize]
                } else {
                    pc1m[(l - 28) as usize]
                };
            }
            for j in 0..24 {
                if pcr[PC2[j]] != 0 {
                    kn[m as usize] |= BIGBYTE[j as usize];
                }
                if pcr[PC2[j + 24]] != 0 {
                    kn[n as usize] |= BIGBYTE[j as usize];
                }
            }
        }
        Self::cookey(kn)
    }

    fn cookey(raw1: [u32; 32]) -> [u32; 32] {
        let mut dough = [0u32; 32];

        let mut raw0_index;
        let mut raw1_index = 0usize;
        let mut cook_index = 0usize;

        for _ in 0..16 {
            raw0_index = raw1_index;
            raw1_index += 1;
            dough[cook_index] = (raw1[raw0_index] & 0x00fc0000) << 6;
            dough[cook_index] |= (raw1[raw0_index] & 0x00000fc0) << 10;
            dough[cook_index] |= (raw1[raw1_index] & 0x00fc0000) >> 10;
            dough[cook_index] |= (raw1[raw1_index] & 0x00000fc0) >> 6;
            cook_index += 1;
            dough[cook_index] = (raw1[raw0_index] & 0x0003f000) << 12;
            dough[cook_index] |= (raw1[raw0_index] & 0x0000003f) << 16;
            dough[cook_index] |= (raw1[raw1_index] & 0x0003f000) >> 4;
            dough[cook_index] |= raw1[raw1_index] & 0x0000003f;
            cook_index += 1;
            raw1_index += 1;
        }
        dough
    }

    pub fn encrypt_block(&self, inblock: &[u8]) -> [u8; 8] {
        assert!(inblock.len() == 8);
        let work = Self::scrunch(inblock);
        let result = self.desfn(&work);
        Self::unscrunch(&result)
    }

    fn scrunch(outof: &[u8]) -> [u32; 2] {
        let mut into = [0u32; 2];
        into[0] = (outof[0] as u32) << 24
            | (outof[1] as u32) << 16
            | (outof[2] as u32) << 8
            | outof[3] as u32;
        into[1] = (outof[4] as u32) << 24
            | (outof[5] as u32) << 16
            | (outof[6] as u32) << 8
            | outof[7] as u32;
        into
    }

    fn unscrunch(outof: &[u32]) -> [u8; 8] {
        let mut into = [0u8; 8];
        into[0] = ((outof[0] >> 24) & 0xFF) as u8;
        into[1] = ((outof[0] >> 16) & 0xFF) as u8;
        into[2] = ((outof[0] >> 8) & 0xFF) as u8;
        into[3] = (outof[0] & 0xFF) as u8;
        into[4] = ((outof[1] >> 24) & 0xFF) as u8;
        into[5] = ((outof[1] >> 16) & 0xFF) as u8;
        into[6] = ((outof[1] >> 8) & 0xFF) as u8;
        into[7] = (outof[1] & 0xFF) as u8;
        into
    }

    fn desfn(&self, block: &[u32]) -> [u32; 2] {
        let mut fval;
        let mut leftt = block[0];
        let mut right = block[1];
        let mut work = ((leftt >> 4) ^ right) & 0x0f0f0f0f;

        right ^= work;
        leftt ^= work << 4;
        work = ((leftt >> 16) ^ right) & 0x0000ffff;
        right ^= work;
        leftt ^= work << 16;
        work = ((right >> 2) ^ leftt) & 0x33333333;
        leftt ^= work;
        right ^= work << 2;
        work = ((right >> 8) ^ leftt) & 0x00ff00ff;
        leftt ^= work;
        right ^= work << 8;
        right = ((right << 1) | ((right >> 31) & 1)) & 0xffffffff;
        work = (leftt ^ right) & 0xaaaaaaaa;
        leftt ^= work;
        right ^= work;
        leftt = ((leftt << 1) | ((leftt >> 31) & 1)) & 0xffffffff;

        // register unsigned long fval, work, right, leftt;
        let mut key_index = 0;
        for _round in 0..8 {
            work = (right << 28) | (right >> 4);
            work ^= self.generated_key[key_index];
            key_index += 1;
            fval = SP7[work as usize & 0x3f];
            fval |= SP5[(work as usize >> 8) & 0x3f];
            fval |= SP3[(work as usize >> 16) & 0x3f];
            fval |= SP1[(work as usize >> 24) & 0x3f];
            work = right ^ self.generated_key[key_index];
            key_index += 1;
            fval |= SP8[work as usize & 0x3f];
            fval |= SP6[(work as usize >> 8) & 0x3f];
            fval |= SP4[(work as usize >> 16) & 0x3f];
            fval |= SP2[(work as usize >> 24) & 0x3f];
            leftt ^= fval;
            work = (leftt << 28) | (leftt >> 4);
            work ^= self.generated_key[key_index];
            key_index += 1;
            fval = SP7[work as usize & 0x3f];
            fval |= SP5[(work as usize >> 8) & 0x3f];
            fval |= SP3[(work as usize >> 16) & 0x3f];
            fval |= SP1[(work as usize >> 24) & 0x3f];
            work = leftt ^ self.generated_key[key_index];
            key_index += 1;
            fval |= SP8[work as usize & 0x3f];
            fval |= SP6[(work as usize >> 8) & 0x3f];
            fval |= SP4[(work as usize >> 16) & 0x3f];
            fval |= SP2[(work as usize >> 24) & 0x3f];
            right ^= fval;
        }

        right = (right << 31) | (right >> 1);
        work = (leftt ^ right) & 0xaaaaaaaa;
        leftt ^= work;
        right ^= work;
        leftt = (leftt << 31) | (leftt >> 1);
        work = ((leftt >> 8) ^ right) & 0x00ff00ff;
        right ^= work;
        leftt ^= work << 8;
        work = ((leftt >> 2) ^ right) & 0x33333333;
        right ^= work;
        leftt ^= work << 2;
        work = ((right >> 16) ^ leftt) & 0x0000ffff;
        leftt ^= work;
        right ^= work << 16;
        work = ((right >> 4) ^ leftt) & 0x0f0f0f0f;
        leftt ^= work;
        right ^= work << 4;

        [right, leftt]
    }

    /* Validation sets:
     *
     * Single-length key, single-length plaintext -
     * Key	  : 0123 4567 89ab cdef
     * Plain  : 0123 4567 89ab cde7
     * Cipher : c957 4425 6a5e d31d
     *
     * Double-length key, single-length plaintext -
     * Key	  : 0123 4567 89ab cdef fedc ba98 7654 3210
     * Plain  : 0123 4567 89ab cde7
     * Cipher : 7f1d 0a77 826b 8aff
     *
     * Double-length key, double-length plaintext -
     * Key	  : 0123 4567 89ab cdef fedc ba98 7654 3210
     * Plain  : 0123 4567 89ab cdef 0123 4567 89ab cdff
     * Cipher : 27a0 8440 406a df60 278f 47cf 42d6 15d7
     *
     * Triple-length key, single-length plaintext -
     * Key	  : 0123 4567 89ab cdef fedc ba98 7654 3210 89ab cdef 0123 4567
     * Plain  : 0123 4567 89ab cde7
     * Cipher : de0b 7c06 ae5e 0ed5
     *
     * Triple-length key, double-length plaintext -
     * Key	  : 0123 4567 89ab cdef fedc ba98 7654 3210 89ab cdef 0123 4567
     * Plain  : 0123 4567 89ab cdef 0123 4567 89ab cdff
     * Cipher : ad0d 1b30 ac17 cf07 0ed1 1c63 81e4 4de5
     *
     * d3des V5.0a rwo 9208.07 18:44 Graven Imagery
     **********************************************************************/
}

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_gen_key() {
        let des = Des::new(b"bananen!", Direction::Encrypt);
        println!("{:?}", des.generated_key);
    }

    #[test]
    fn test_scrunch() {
        let source = [0, 1, 2, 3, 4, 5, 6, 7];
        let scrunched = Des::scrunch(&source);
        let unscrunched = Des::unscrunch(&scrunched);
        assert_eq!(source, unscrunched);
    }

    #[test]
    fn test_encrypt_block() {
        let des = Des::new(b"bananen!", Direction::Encrypt);
        let challenge = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let block_a = des.encrypt_block(&challenge[0..8]);
        let block_b = des.encrypt_block(&challenge[8..16]);
        println!("{:x?} {:x?}", block_a, block_b);
    }
}
