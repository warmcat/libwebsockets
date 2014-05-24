/* pos 0000:   0 */    0x67 /* 'g' */, 0x25, 0x00  /* (to 0x0025 state   1) */,
                       0x70 /* 'p' */, 0x27, 0x00  /* (to 0x002A state   5) */,
                       0x6F /* 'o' */, 0x30, 0x00  /* (to 0x0036 state  10) */,
                       0x68 /* 'h' */, 0x3C, 0x00  /* (to 0x0045 state  18) */,
                       0x63 /* 'c' */, 0x45, 0x00  /* (to 0x0051 state  23) */,
                       0x73 /* 's' */, 0x60, 0x00  /* (to 0x006F state  34) */,
                       0x75 /* 'u' */, 0x9F, 0x00  /* (to 0x00B1 state  64) */,
                       0x0D /* '.' */, 0xB3, 0x00  /* (to 0x00C8 state  84) */,
                       0x61 /* 'a' */, 0xEA, 0x00  /* (to 0x0102 state 134) */,
                       0x69 /* 'i' */, 0xFB, 0x00  /* (to 0x0116 state 141) */,
                       0x64 /* 'd' */, 0x68, 0x01  /* (to 0x0186 state 232) */,
                       0x72 /* 'r' */, 0x6B, 0x01  /* (to 0x018C state 237) */,
                       0x08, /* fail */
/* pos 0025:   1 */    0xE5 /* 'e' -> */,
/* pos 0026:   2 */    0xF4 /* 't' -> */,
/* pos 0027:   3 */    0xA0 /* ' ' -> */,
/* pos 0028:   4 */    0x00, 0x00                  /* - terminal marker  0 - */,
/* pos 002a:   5 */    0x6F /* 'o' */, 0x07, 0x00  /* (to 0x0031 state   6) */,
                       0x72 /* 'r' */, 0x17, 0x01  /* (to 0x0144 state 178) */,
                       0x08, /* fail */
/* pos 0031:   6 */    0xF3 /* 's' -> */,
/* pos 0032:   7 */    0xF4 /* 't' -> */,
/* pos 0033:   8 */    0xA0 /* ' ' -> */,
/* pos 0034:   9 */    0x00, 0x01                  /* - terminal marker  1 - */,
/* pos 0036:  10 */    0x70 /* 'p' */, 0x07, 0x00  /* (to 0x003D state  11) */,
                       0x72 /* 'r' */, 0x81, 0x00  /* (to 0x00BA state  72) */,
                       0x08, /* fail */
/* pos 003d:  11 */    0xF4 /* 't' -> */,
/* pos 003e:  12 */    0xE9 /* 'i' -> */,
/* pos 003f:  13 */    0xEF /* 'o' -> */,
/* pos 0040:  14 */    0xEE /* 'n' -> */,
/* pos 0041:  15 */    0xF3 /* 's' -> */,
/* pos 0042:  16 */    0xA0 /* ' ' -> */,
/* pos 0043:  17 */    0x00, 0x02                  /* - terminal marker  2 - */,
/* pos 0045:  18 */    0x6F /* 'o' */, 0x07, 0x00  /* (to 0x004C state  19) */,
                       0x74 /* 't' */, 0xB1, 0x00  /* (to 0x00F9 state 126) */,
                       0x08, /* fail */
/* pos 004c:  19 */    0xF3 /* 's' -> */,
/* pos 004d:  20 */    0xF4 /* 't' -> */,
/* pos 004e:  21 */    0xBA /* ':' -> */,
/* pos 004f:  22 */    0x00, 0x03                  /* - terminal marker  3 - */,
/* pos 0051:  23 */    0x6F /* 'o' */, 0x07, 0x00  /* (to 0x0058 state  24) */,
                       0x61 /* 'a' */, 0xF7, 0x00  /* (to 0x014B state 184) */,
                       0x08, /* fail */
/* pos 0058:  24 */    0x6E /* 'n' */, 0x07, 0x00  /* (to 0x005F state  25) */,
                       0x6F /* 'o' */, 0x0C, 0x01  /* (to 0x0167 state 210) */,
                       0x08, /* fail */
/* pos 005f:  25 */    0x6E /* 'n' */, 0x07, 0x00  /* (to 0x0066 state  26) */,
                       0x74 /* 't' */, 0x0B, 0x01  /* (to 0x016D state 215) */,
                       0x08, /* fail */
/* pos 0066:  26 */    0xE5 /* 'e' -> */,
/* pos 0067:  27 */    0xE3 /* 'c' -> */,
/* pos 0068:  28 */    0xF4 /* 't' -> */,
/* pos 0069:  29 */    0xE9 /* 'i' -> */,
/* pos 006a:  30 */    0xEF /* 'o' -> */,
/* pos 006b:  31 */    0xEE /* 'n' -> */,
/* pos 006c:  32 */    0xBA /* ':' -> */,
/* pos 006d:  33 */    0x00, 0x04                  /* - terminal marker  4 - */,
/* pos 006f:  34 */    0xE5 /* 'e' -> */,
/* pos 0070:  35 */    0xE3 /* 'c' -> */,
/* pos 0071:  36 */    0xAD /* '-' -> */,
/* pos 0072:  37 */    0xF7 /* 'w' -> */,
/* pos 0073:  38 */    0xE5 /* 'e' -> */,
/* pos 0074:  39 */    0xE2 /* 'b' -> */,
/* pos 0075:  40 */    0xF3 /* 's' -> */,
/* pos 0076:  41 */    0xEF /* 'o' -> */,
/* pos 0077:  42 */    0xE3 /* 'c' -> */,
/* pos 0078:  43 */    0xEB /* 'k' -> */,
/* pos 0079:  44 */    0xE5 /* 'e' -> */,
/* pos 007a:  45 */    0xF4 /* 't' -> */,
/* pos 007b:  46 */    0xAD /* '-' -> */,
/* pos 007c:  47 */    0x6B /* 'k' */, 0x19, 0x00  /* (to 0x0095 state  48) */,
                       0x70 /* 'p' */, 0x28, 0x00  /* (to 0x00A7 state  55) */,
                       0x64 /* 'd' */, 0x3F, 0x00  /* (to 0x00C1 state  78) */,
                       0x76 /* 'v' */, 0x48, 0x00  /* (to 0x00CD state  87) */,
                       0x6F /* 'o' */, 0x4E, 0x00  /* (to 0x00D6 state  95) */,
                       0x65 /* 'e' */, 0x53, 0x00  /* (to 0x00DE state 102) */,
                       0x61 /* 'a' */, 0x5C, 0x00  /* (to 0x00EA state 113) */,
                       0x6E /* 'n' */, 0x61, 0x00  /* (to 0x00F2 state 120) */,
                       0x08, /* fail */
/* pos 0095:  48 */    0xE5 /* 'e' -> */,
/* pos 0096:  49 */    0xF9 /* 'y' -> */,
/* pos 0097:  50 */    0x31 /* '1' */, 0x0A, 0x00  /* (to 0x00A1 state  51) */,
                       0x32 /* '2' */, 0x0A, 0x00  /* (to 0x00A4 state  53) */,
                       0x3A /* ':' */, 0x2E, 0x00  /* (to 0x00CB state  86) */,
                       0x08, /* fail */
/* pos 00a1:  51 */    0xBA /* ':' -> */,
/* pos 00a2:  52 */    0x00, 0x05                  /* - terminal marker  5 - */,
/* pos 00a4:  53 */    0xBA /* ':' -> */,
/* pos 00a5:  54 */    0x00, 0x06                  /* - terminal marker  6 - */,
/* pos 00a7:  55 */    0xF2 /* 'r' -> */,
/* pos 00a8:  56 */    0xEF /* 'o' -> */,
/* pos 00a9:  57 */    0xF4 /* 't' -> */,
/* pos 00aa:  58 */    0xEF /* 'o' -> */,
/* pos 00ab:  59 */    0xE3 /* 'c' -> */,
/* pos 00ac:  60 */    0xEF /* 'o' -> */,
/* pos 00ad:  61 */    0xEC /* 'l' -> */,
/* pos 00ae:  62 */    0xBA /* ':' -> */,
/* pos 00af:  63 */    0x00, 0x07                  /* - terminal marker  7 - */,
/* pos 00b1:  64 */    0xF0 /* 'p' -> */,
/* pos 00b2:  65 */    0xE7 /* 'g' -> */,
/* pos 00b3:  66 */    0xF2 /* 'r' -> */,
/* pos 00b4:  67 */    0xE1 /* 'a' -> */,
/* pos 00b5:  68 */    0xE4 /* 'd' -> */,
/* pos 00b6:  69 */    0xE5 /* 'e' -> */,
/* pos 00b7:  70 */    0xBA /* ':' -> */,
/* pos 00b8:  71 */    0x00, 0x08                  /* - terminal marker  8 - */,
/* pos 00ba:  72 */    0xE9 /* 'i' -> */,
/* pos 00bb:  73 */    0xE7 /* 'g' -> */,
/* pos 00bc:  74 */    0xE9 /* 'i' -> */,
/* pos 00bd:  75 */    0xEE /* 'n' -> */,
/* pos 00be:  76 */    0xBA /* ':' -> */,
/* pos 00bf:  77 */    0x00, 0x09                  /* - terminal marker  9 - */,
/* pos 00c1:  78 */    0xF2 /* 'r' -> */,
/* pos 00c2:  79 */    0xE1 /* 'a' -> */,
/* pos 00c3:  80 */    0xE6 /* 'f' -> */,
/* pos 00c4:  81 */    0xF4 /* 't' -> */,
/* pos 00c5:  82 */    0xBA /* ':' -> */,
/* pos 00c6:  83 */    0x00, 0x0A                  /* - terminal marker 10 - */,
/* pos 00c8:  84 */    0x8A /* '.' -> */,
/* pos 00c9:  85 */    0x00, 0x0B                  /* - terminal marker 11 - */,
/* pos 00cb:  86 */    0x00, 0x0C                  /* - terminal marker 12 - */,
/* pos 00cd:  87 */    0xE5 /* 'e' -> */,
/* pos 00ce:  88 */    0xF2 /* 'r' -> */,
/* pos 00cf:  89 */    0xF3 /* 's' -> */,
/* pos 00d0:  90 */    0xE9 /* 'i' -> */,
/* pos 00d1:  91 */    0xEF /* 'o' -> */,
/* pos 00d2:  92 */    0xEE /* 'n' -> */,
/* pos 00d3:  93 */    0xBA /* ':' -> */,
/* pos 00d4:  94 */    0x00, 0x0D                  /* - terminal marker 13 - */,
/* pos 00d6:  95 */    0xF2 /* 'r' -> */,
/* pos 00d7:  96 */    0xE9 /* 'i' -> */,
/* pos 00d8:  97 */    0xE7 /* 'g' -> */,
/* pos 00d9:  98 */    0xE9 /* 'i' -> */,
/* pos 00da:  99 */    0xEE /* 'n' -> */,
/* pos 00db: 100 */    0xBA /* ':' -> */,
/* pos 00dc: 101 */    0x00, 0x0E                  /* - terminal marker 14 - */,
/* pos 00de: 102 */    0xF8 /* 'x' -> */,
/* pos 00df: 103 */    0xF4 /* 't' -> */,
/* pos 00e0: 104 */    0xE5 /* 'e' -> */,
/* pos 00e1: 105 */    0xEE /* 'n' -> */,
/* pos 00e2: 106 */    0xF3 /* 's' -> */,
/* pos 00e3: 107 */    0xE9 /* 'i' -> */,
/* pos 00e4: 108 */    0xEF /* 'o' -> */,
/* pos 00e5: 109 */    0xEE /* 'n' -> */,
/* pos 00e6: 110 */    0xF3 /* 's' -> */,
/* pos 00e7: 111 */    0xBA /* ':' -> */,
/* pos 00e8: 112 */    0x00, 0x0F                  /* - terminal marker 15 - */,
/* pos 00ea: 113 */    0xE3 /* 'c' -> */,
/* pos 00eb: 114 */    0xE3 /* 'c' -> */,
/* pos 00ec: 115 */    0xE5 /* 'e' -> */,
/* pos 00ed: 116 */    0xF0 /* 'p' -> */,
/* pos 00ee: 117 */    0xF4 /* 't' -> */,
/* pos 00ef: 118 */    0xBA /* ':' -> */,
/* pos 00f0: 119 */    0x00, 0x10                  /* - terminal marker 16 - */,
/* pos 00f2: 120 */    0xEF /* 'o' -> */,
/* pos 00f3: 121 */    0xEE /* 'n' -> */,
/* pos 00f4: 122 */    0xE3 /* 'c' -> */,
/* pos 00f5: 123 */    0xE5 /* 'e' -> */,
/* pos 00f6: 124 */    0xBA /* ':' -> */,
/* pos 00f7: 125 */    0x00, 0x11                  /* - terminal marker 17 - */,
/* pos 00f9: 126 */    0xF4 /* 't' -> */,
/* pos 00fa: 127 */    0xF0 /* 'p' -> */,
/* pos 00fb: 128 */    0xAF /* '/' -> */,
/* pos 00fc: 129 */    0xB1 /* '1' -> */,
/* pos 00fd: 130 */    0xAE /* '.' -> */,
/* pos 00fe: 131 */    0xB1 /* '1' -> */,
/* pos 00ff: 132 */    0xA0 /* ' ' -> */,
/* pos 0100: 133 */    0x00, 0x12                  /* - terminal marker 18 - */,
/* pos 0102: 134 */    0x63 /* 'c' */, 0x07, 0x00  /* (to 0x0109 state 135) */,
                       0x75 /* 'u' */, 0x54, 0x00  /* (to 0x0159 state 197) */,
                       0x08, /* fail */
/* pos 0109: 135 */    0xE3 /* 'c' -> */,
/* pos 010a: 136 */    0xE5 /* 'e' -> */,
/* pos 010b: 137 */    0xF0 /* 'p' -> */,
/* pos 010c: 138 */    0xF4 /* 't' -> */,
/* pos 010d: 139 */    0x3A /* ':' */, 0x07, 0x00  /* (to 0x0114 state 140) */,
                       0x2D /* '-' */, 0x19, 0x00  /* (to 0x0129 state 159) */,
                       0x08, /* fail */
/* pos 0114: 140 */    0x00, 0x13                  /* - terminal marker 19 - */,
/* pos 0116: 141 */    0xE6 /* 'f' -> */,
/* pos 0117: 142 */    0xAD /* '-' -> */,
/* pos 0118: 143 */    0xED /* 'm' -> */,
/* pos 0119: 144 */    0xEF /* 'o' -> */,
/* pos 011a: 145 */    0xE4 /* 'd' -> */,
/* pos 011b: 146 */    0xE9 /* 'i' -> */,
/* pos 011c: 147 */    0xE6 /* 'f' -> */,
/* pos 011d: 148 */    0xE9 /* 'i' -> */,
/* pos 011e: 149 */    0xE5 /* 'e' -> */,
/* pos 011f: 150 */    0xE4 /* 'd' -> */,
/* pos 0120: 151 */    0xAD /* '-' -> */,
/* pos 0121: 152 */    0xF3 /* 's' -> */,
/* pos 0122: 153 */    0xE9 /* 'i' -> */,
/* pos 0123: 154 */    0xEE /* 'n' -> */,
/* pos 0124: 155 */    0xE3 /* 'c' -> */,
/* pos 0125: 156 */    0xE5 /* 'e' -> */,
/* pos 0126: 157 */    0xBA /* ':' -> */,
/* pos 0127: 158 */    0x00, 0x14                  /* - terminal marker 20 - */,
/* pos 0129: 159 */    0x65 /* 'e' */, 0x07, 0x00  /* (to 0x0130 state 160) */,
                       0x6C /* 'l' */, 0x0E, 0x00  /* (to 0x013A state 169) */,
                       0x08, /* fail */
/* pos 0130: 160 */    0xEE /* 'n' -> */,
/* pos 0131: 161 */    0xE3 /* 'c' -> */,
/* pos 0132: 162 */    0xEF /* 'o' -> */,
/* pos 0133: 163 */    0xE4 /* 'd' -> */,
/* pos 0134: 164 */    0xE9 /* 'i' -> */,
/* pos 0135: 165 */    0xEE /* 'n' -> */,
/* pos 0136: 166 */    0xE7 /* 'g' -> */,
/* pos 0137: 167 */    0xBA /* ':' -> */,
/* pos 0138: 168 */    0x00, 0x15                  /* - terminal marker 21 - */,
/* pos 013a: 169 */    0xE1 /* 'a' -> */,
/* pos 013b: 170 */    0xEE /* 'n' -> */,
/* pos 013c: 171 */    0xE7 /* 'g' -> */,
/* pos 013d: 172 */    0xF5 /* 'u' -> */,
/* pos 013e: 173 */    0xE1 /* 'a' -> */,
/* pos 013f: 174 */    0xE7 /* 'g' -> */,
/* pos 0140: 175 */    0xE5 /* 'e' -> */,
/* pos 0141: 176 */    0xBA /* ':' -> */,
/* pos 0142: 177 */    0x00, 0x16                  /* - terminal marker 22 - */,
/* pos 0144: 178 */    0xE1 /* 'a' -> */,
/* pos 0145: 179 */    0xE7 /* 'g' -> */,
/* pos 0146: 180 */    0xED /* 'm' -> */,
/* pos 0147: 181 */    0xE1 /* 'a' -> */,
/* pos 0148: 182 */    0xBA /* ':' -> */,
/* pos 0149: 183 */    0x00, 0x17                  /* - terminal marker 23 - */,
/* pos 014b: 184 */    0xE3 /* 'c' -> */,
/* pos 014c: 185 */    0xE8 /* 'h' -> */,
/* pos 014d: 186 */    0xE5 /* 'e' -> */,
/* pos 014e: 187 */    0xAD /* '-' -> */,
/* pos 014f: 188 */    0xE3 /* 'c' -> */,
/* pos 0150: 189 */    0xEF /* 'o' -> */,
/* pos 0151: 190 */    0xEE /* 'n' -> */,
/* pos 0152: 191 */    0xF4 /* 't' -> */,
/* pos 0153: 192 */    0xF2 /* 'r' -> */,
/* pos 0154: 193 */    0xEF /* 'o' -> */,
/* pos 0155: 194 */    0xEC /* 'l' -> */,
/* pos 0156: 195 */    0xBA /* ':' -> */,
/* pos 0157: 196 */    0x00, 0x18                  /* - terminal marker 24 - */,
/* pos 0159: 197 */    0xF4 /* 't' -> */,
/* pos 015a: 198 */    0xE8 /* 'h' -> */,
/* pos 015b: 199 */    0xEF /* 'o' -> */,
/* pos 015c: 200 */    0xF2 /* 'r' -> */,
/* pos 015d: 201 */    0xE9 /* 'i' -> */,
/* pos 015e: 202 */    0xFA /* 'z' -> */,
/* pos 015f: 203 */    0xE1 /* 'a' -> */,
/* pos 0160: 204 */    0xF4 /* 't' -> */,
/* pos 0161: 205 */    0xE9 /* 'i' -> */,
/* pos 0162: 206 */    0xEF /* 'o' -> */,
/* pos 0163: 207 */    0xEE /* 'n' -> */,
/* pos 0164: 208 */    0xBA /* ':' -> */,
/* pos 0165: 209 */    0x00, 0x19                  /* - terminal marker 25 - */,
/* pos 0167: 210 */    0xEB /* 'k' -> */,
/* pos 0168: 211 */    0xE9 /* 'i' -> */,
/* pos 0169: 212 */    0xE5 /* 'e' -> */,
/* pos 016a: 213 */    0xBA /* ':' -> */,
/* pos 016b: 214 */    0x00, 0x1A                  /* - terminal marker 26 - */,
/* pos 016d: 215 */    0xE5 /* 'e' -> */,
/* pos 016e: 216 */    0xEE /* 'n' -> */,
/* pos 016f: 217 */    0xF4 /* 't' -> */,
/* pos 0170: 218 */    0xAD /* '-' -> */,
/* pos 0171: 219 */    0x6C /* 'l' */, 0x07, 0x00  /* (to 0x0178 state 220) */,
                       0x74 /* 't' */, 0x0C, 0x00  /* (to 0x0180 state 227) */,
                       0x08, /* fail */
/* pos 0178: 220 */    0xE5 /* 'e' -> */,
/* pos 0179: 221 */    0xEE /* 'n' -> */,
/* pos 017a: 222 */    0xE7 /* 'g' -> */,
/* pos 017b: 223 */    0xF4 /* 't' -> */,
/* pos 017c: 224 */    0xE8 /* 'h' -> */,
/* pos 017d: 225 */    0xBA /* ':' -> */,
/* pos 017e: 226 */    0x00, 0x1B                  /* - terminal marker 27 - */,
/* pos 0180: 227 */    0xF9 /* 'y' -> */,
/* pos 0181: 228 */    0xF0 /* 'p' -> */,
/* pos 0182: 229 */    0xE5 /* 'e' -> */,
/* pos 0183: 230 */    0xBA /* ':' -> */,
/* pos 0184: 231 */    0x00, 0x1C                  /* - terminal marker 28 - */,
/* pos 0186: 232 */    0xE1 /* 'a' -> */,
/* pos 0187: 233 */    0xF4 /* 't' -> */,
/* pos 0188: 234 */    0xE5 /* 'e' -> */,
/* pos 0189: 235 */    0xBA /* ':' -> */,
/* pos 018a: 236 */    0x00, 0x1D                  /* - terminal marker 29 - */,
/* pos 018c: 237 */    0x61 /* 'a' */, 0x07, 0x00  /* (to 0x0193 state 238) */,
                       0x65 /* 'e' */, 0x0A, 0x00  /* (to 0x0199 state 243) */,
                       0x08, /* fail */
/* pos 0193: 238 */    0xEE /* 'n' -> */,
/* pos 0194: 239 */    0xE7 /* 'g' -> */,
/* pos 0195: 240 */    0xE5 /* 'e' -> */,
/* pos 0196: 241 */    0xBA /* ':' -> */,
/* pos 0197: 242 */    0x00, 0x1E                  /* - terminal marker 30 - */,
/* pos 0199: 243 */    0xE6 /* 'f' -> */,
/* pos 019a: 244 */    0xE5 /* 'e' -> */,
/* pos 019b: 245 */    0xF2 /* 'r' -> */,
/* pos 019c: 246 */    0xE5 /* 'e' -> */,
/* pos 019d: 247 */    0xF2 /* 'r' -> */,
/* pos 019e: 248 */    0xBA /* ':' -> */,
/* pos 019f: 249 */    0x00, 0x1F                  /* - terminal marker 31 - */,
/* total size 417 bytes */
