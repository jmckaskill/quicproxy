#include "http.h"
#include <stdint.h>


struct huffman_encoding {
	uint32_t value;
	size_t bits;
};

static struct huffman_encoding huffman[] = {
	{0x14, 6},     // ' ' (32)  | 010100
	{0x3F8, 10},   // '!' (33)  | 11111110
	{ 0x3f9, 10},  // '"' (34)  | 1111111001                    
	{ 0xffa, 12},  // '#' (35)  | 111111111010                  
	{ 0x1ff9, 13}, // '$' (36)  | 1111111111001                 
	{ 0x15, 6},    // '%' (37)  | 010101                        
	{ 0xf8, 8},    // '&' (38)  | 11111000                      
	{ 0x7fa, 11},  // ''' (39)  | 11111111010                   
	{ 0x3fa, 10},  // '(' (40)  | 1111111010                    
	{ 0x3fb, 10},  // ')' (41)  | 1111111011                    
	{ 0xf9, 8},    // '*' (42)  | 11111001                      
	{ 0x7fb, 11},  // '+' (43)  | 11111111011                   
	{ 0xfa, 8},    // ',' (44)  | 11111010                      
	{ 0x16, 6},    // '-' (45)  | 010110                        
	{ 0x17, 6},    // '.' (46)  | 010111                        
	{ 0x18, 6},    // '/' (47)  | 011000                        
	{ 0x0, 5},     // '0' (48)  | 00000                         
	{ 0x1, 5},     // '1' (49)  | 00001                         
	{ 0x2, 5},     // '2' (50)  | 00010                         
	{ 0x19, 6},    // '3' (51)  | 011001                        
	{ 0x1a, 6},    // '4' (52)  | 011010                        
	{ 0x1b, 6},    // '5' (53)  | 011011                        
	{ 0x1c, 6},    // '6' (54)  | 011100                        
	{ 0x1d, 6},    // '7' (55)  | 011101                        
	{ 0x1e, 6},    // '8' (56)  | 011110                        
	{ 0x1f, 6},    // '9' (57)  | 011111                        
	{ 0x5c, 7},    // ':' (58)  | 1011100                       
	{ 0xfb, 8},    // ';' (59)  | 11111011                      
	{ 0x7ffc, 15}, // '<' (60)  | 111111111111100               
	{ 0x20, 6},    // '=' (61)  | 100000                        
	{ 0xffb, 12},  // '>' (62)  | 111111111011                  
	{ 0x3fc, 10},  // '?' (63)  | 1111111100                    
	{ 0x1ffa, 13}, // '@' (64)  | 1111111111010                 
	{ 0x21, 6},    // 'A' (65)  | 100001                        
	{ 0x5d, 7},    // 'B' (66)  | 1011101                       
	{ 0x5e, 7},    // 'C' (67)  | 1011110                       
	{ 0x5f, 7},    // 'D' (68)  | 1011111                       
	{ 0x60, 7},    // 'E' (69)  | 1100000                       
	{ 0x61, 7},    // 'F' (70)  | 1100001                       
	{ 0x62, 7},    // 'G' (71)  | 1100010                       
	{ 0x63, 7},    // 'H' (72)  | 1100011                       
	{ 0x64, 7},    // 'I' (73)  | 1100100                       
	{ 0x65, 7},    // 'J' (74)  | 1100101                       
	{ 0x66, 7},    // 'K' (75)  | 1100110                       
	{ 0x67, 7},    // 'L' (76)  | 1100111                       
	{ 0x68, 7},    // 'M' (77)  | 1101000                       
	{ 0x69, 7},    // 'N' (78)  | 1101001                       
	{ 0x6a, 7},    // 'O' (79)  | 1101010                       
	{ 0x6b, 7},    // 'P' (80)  | 1101011                       
	{ 0x6c, 7},    // 'Q' (81)  | 1101100                       
	{ 0x6d, 7},    // 'R' (82)  | 1101101                       
	{ 0x6e, 7},    // 'S' (83)  | 1101110                       
	{ 0x6f, 7},    // 'T' (84)  | 1101111                       
	{ 0x70, 7},    // 'U' (85)  | 1110000                       
	{ 0x71, 7},    // 'V' (86)  | 1110001                       
	{ 0x72, 7},    // 'W' (87)  | 1110010                       
	{ 0xfc, 8},    // 'X' (88)  | 11111100                      
	{ 0x73, 7},    // 'Y' (89)  | 1110011                       
	{ 0xfd, 8},    // 'Z' (90)  | 11111101                      
	{ 0x1ffb, 13}, // '[' (91)  | 1111111111011                 
	{ 0x7fff0, 19},// '\' (92)  | 1111111111111110000          
	{ 0x1ffc, 13}, // ']' (93)  | 1111111111100                 
	{ 0x3ffc, 14}, // '^' (94)  | 11111111111100                
	{ 0x22, 6},    // '_' (95)  | 100010                        
	{ 0x7ffd, 15}, // '`' (96)  | 111111111111101               
	{ 0x3, 5},     // 'a' (97)  | 00011                         
	{ 0x23, 6},    // 'b' (98)  | 100011                        
	{ 0x4, 5},     // 'c' (99)  | 00100                         
	{ 0x24, 6},    // 'd' (100) | 100100                       
	{ 0x5, 5},     // 'e' (101) | 00101                        
	{ 0x25, 6},    // 'f' (102) | 100101                       
	{ 0x26, 6},    // 'g' (103) | 100110                       
	{ 0x27, 6},    // 'h' (104) | 100111                       
	{ 0x6, 5},     // 'i' (105) | 00110                        
	{ 0x74, 7},    // 'j' (106) | 1110100                      
	{ 0x75, 7},    // 'k' (107) | 1110101                      
	{ 0x28, 6},    // 'l' (108) | 101000                       
	{ 0x29, 6},    // 'm' (109) | 101001                       
	{ 0x2a, 6},    // 'n' (110) | 101010                       
	{ 0x7, 5},     // 'o' (111) | 00111                        
	{ 0x2b, 6},    // 'p' (112) | 101011                       
	{ 0x76, 7},    // 'q' (113) | 1110110                      
	{ 0x2c, 6},    // 'r' (114) | 101100                       
	{ 0x8, 5},     // 's' (115) | 01000                        
	{ 0x9, 5},     // 't' (116) | 01001                        
	{ 0x2d, 6},    // 'u' (117) | 101101                       
	{ 0x77, 7},    // 'v' (118) | 1110111                      
	{ 0x78, 7},    // 'w' (119) | 1111000                      
	{ 0x79, 7},    // 'x' (120) | 1111001                      
	{ 0x7a, 7},    // 'y' (121) | 1111010                      
	{ 0x7b, 7},    // 'z' (122) | 1111011                      
	{ 0x7ffe, 15}, // '{' (123) | 111111111111110              
	{ 0x7fc, 11},  // '|' (124) | 11111111100                  
	{ 0x3ffd, 14}, // '}' (125) | 11111111111101               
	{ 0x1ffd, 13}, // '~' (126) | 1111111111101                
};

int hq_encode_header_name(uint8_t *buf, const char *name) {
	size_t bytes = 0;
	size_t bits = 0;
	uint16_t u = 0;
	while (*name) {
		char ch = *(name++);
		if ((unsigned char)ch > '~' || ch < ' ') {
			return -1;
		} else if (!bits && ch == ':') {
			// allow leading colons for the pseudo-headers
		} else if (!('a' <= ch && ch <= 'z') && !('0' <= ch && ch <= '9') && ch != '-') {
			return -1;
		}
		// all supported characters [a-z,0-9,-] are encoded in less that 8 bits
		// that means we can use a 16 bit shift register

		struct huffman_encoding e = huffman[ch - ' '];
		u <<= e.bits;
		u |= e.value;
		bits += e.bits;
		if (bits / 8 > bytes) {
			buf[++bytes] = (uint8_t)(u >> (bits&7));
			if (bytes == HDR_MAX_SIZE-1) {
				return -1;
			}
		}
	}
	// finish out padding as a series of 1 bits
	size_t pad = (8 - (bits & 7)) & 7;
	if (pad) {
		u <<= pad;
		u |= (1 << pad) - 1;
		buf[++bytes] = (uint8_t)u;
	}
	buf[0] = (uint8_t)bytes;
	return 0;
}

uint8_t HTTP_AGE[] = { 2, 28, 197 };
uint8_t HTTP_DATE[] = { 3, 144, 105, 47 };
uint8_t HTTP_ETAG[] = { 3, 42, 71, 55 };
uint8_t HTTP_LINK[] = { 3, 160, 213, 117 };
uint8_t HTTP_PATH[] = { 4, 185, 88, 211, 63 };
uint8_t HTTP_ACCEPT[] = { 4, 25, 8, 90, 211 };
uint8_t HTTP_COOKIE[] = { 4, 33, 207, 212, 197 };
uint8_t HTTP_RANGE[] = { 4, 176, 117, 76, 95 };
uint8_t HTTP_VARY[] = { 4, 238, 59, 61, 127 };
uint8_t HTTP_METHOD[] = { 5, 185, 73, 83, 57, 228 };
uint8_t HTTP_SCHEME[] = { 5, 184, 130, 78, 90, 75 };
uint8_t HTTP_STATUS[] = { 5, 184, 132, 141, 54, 163 };
uint8_t HTTP_ALT_SVC[] = { 5, 29, 9, 89, 29, 201 };
uint8_t HTTP_ORIGIN[] = { 5, 61, 134, 152, 213, 127 };
uint8_t HTTP_PURPOSE[] = { 5, 174, 219, 43, 58, 11 };
uint8_t HTTP_REFERER[] = { 5, 176, 178, 150, 194, 217 };
uint8_t HTTP_SERVER[] = { 5, 65, 108, 238, 91, 63 };
uint8_t HTTP_IF_RANGE[] = { 6, 52, 171, 88, 58, 166, 47 };
uint8_t HTTP_LOCATION[] = { 6, 160, 228, 26, 76, 122, 191 };
uint8_t HTTP_EARLY_DATA[] = { 7, 40, 236, 163, 210, 210, 13, 35 };
uint8_t HTTP_EXPECT_CT[] = { 7, 47, 154, 202, 68, 172, 68, 255 };
uint8_t HTTP_FORWARDED[] = { 7, 148, 246, 120, 29, 146, 22, 79 };
uint8_t HTTP_SET_COOKIE[] = { 7, 65, 82, 177, 14, 126, 166, 47 };
uint8_t HTTP_USER_AGENT[] = { 7, 181, 5, 177, 97, 204, 90, 147 };
uint8_t HTTP_AUTHORITY[] = { 8, 184, 59, 83, 57, 236, 50, 125, 127 };
uint8_t HTTP_ACCEPT_RANGES[] = { 9, 25, 8, 90, 210, 181, 131, 170, 98, 163 };
uint8_t HTTP_AUTHORIZATION[] = { 9, 29, 169, 156, 246, 27, 216, 210, 99, 213 };
uint8_t HTTP_CACHE_CONTROL[] = { 9, 32, 201, 57, 86, 33, 234, 77, 135, 163 };
uint8_t HTTP_CONTENT_TYPE[] = { 9, 33, 234, 73, 106, 74, 201, 245, 89, 127 };
uint8_t HTTP_IF_NONE_MATCH[] = { 9, 52, 171, 84, 122, 138, 181, 35, 73, 39 };
uint8_t HTTP_LAST_MODIFIED[] = { 9, 160, 104, 74, 212, 158, 67, 74, 98, 201 };
uint8_t HTTP_CONTENT_LENGTH[] = { 10, 33, 234, 73, 106, 74, 212, 22, 169, 147, 63 };
uint8_t HTTP_ACCEPT_ENCODING[] = { 11, 25, 8, 90, 210, 177, 106, 33, 228, 53, 83, 127 };
uint8_t HTTP_ACCEPT_LANGUAGE[] = { 11, 25, 8, 90, 210, 181, 3, 170, 107, 71, 49, 127 };
uint8_t HTTP_CONTENT_ENCODING[] = { 11, 33, 234, 73, 106, 74, 197, 168, 135, 144, 213, 77 };
uint8_t HTTP_X_FORWARDED_FOR[] = { 11, 242, 180, 167, 179, 192, 236, 144, 178, 45, 41, 236 };
uint8_t HTTP_X_FRAME_OPTIONS[] = { 11, 242, 180, 182, 14, 146, 172, 122, 210, 99, 212, 143 };
uint8_t HTTP_X_XSS_PROTECTION[] = { 12, 242, 183, 148, 33, 106, 236, 58, 74, 68, 152, 245, 127 };
uint8_t HTTP_IF_MODIFIED_SINCE[] = { 12, 52, 171, 82, 121, 13, 41, 139, 34, 200, 53, 68, 47 };
uint8_t HTTP_CONTENT_DISPOSITION[] = { 13, 33, 234, 73, 106, 74, 210, 25, 21, 157, 6, 73, 143, 87 };
uint8_t HTTP_TIMING_ALLOW_ORIGIN[] = { 14, 73, 169, 53, 83, 44, 58, 40, 63, 133, 143, 97, 166, 53, 95 };
uint8_t HTTP_X_CONTENT_TYPE_OPTIONS[] = { 16, 242, 177, 15, 82, 75, 82, 86, 79, 170, 202, 177, 235, 73, 143, 82, 63 };
uint8_t HTTP_CONTENT_SECURITY_POLICY[] = { 16, 33, 234, 73, 106, 74, 200, 41, 45, 176, 201, 244, 181, 103, 160, 196, 245 };
uint8_t HTTP_STRICT_TRANSPORT_SECURITY[] = { 17, 66, 108, 49, 18, 178, 108, 29, 72, 172, 246, 37, 100, 20, 150, 216, 100, 250 };
uint8_t HTTP_UPGRADE_INSECURE_REQUESTS[] = { 18, 182, 185, 172, 28, 133, 88, 213, 32, 164, 182, 194, 173, 97, 123, 90, 84, 37, 31 };
uint8_t HTTP_ACCESS_CONTROL_ALLOW_ORIGIN[] = { 19, 25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 29, 20, 31, 194, 199, 176, 211, 26, 175 };
uint8_t HTTP_ACCESS_CONTROL_ALLOW_HEADERS[] = { 20, 25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 29, 20, 31, 194, 211, 148, 114, 22, 196, 127 };
uint8_t HTTP_ACCESS_CONTROL_ALLOW_METHODS[] = { 20, 25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 29, 20, 31, 194, 212, 149, 51, 158, 68, 127 };
uint8_t HTTP_ACCESS_CONTROL_EXPOSE_HEADERS[] = { 20, 25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 47, 154, 206, 130, 173, 57, 71, 33, 108, 71 };
uint8_t HTTP_ACCESS_CONTROL_REQUEST_METHOD[] = { 20, 25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 176, 189, 173, 42, 18, 181, 37, 76, 231, 147 };
uint8_t HTTP_ACCESS_CONTROL_REQUEST_HEADERS[] = { 21, 25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 176, 189, 173, 42, 18, 180, 229, 28, 133, 177, 31 };
uint8_t HTTP_ACCESS_CONTROL_ALLOW_CREDENTIALS[] = { 22, 25, 8, 84, 33, 98, 30, 164, 216, 122, 22, 29, 20, 31, 194, 196, 176, 178, 22, 164, 152, 116, 35 };

int hq_static_header_name(const uint8_t *name) {
	switch (name[0]) {
	default:
		return -1;
	case 2:
		return memcmp(HTTP_AGE + 1, name, 2) ? -1 : 2;
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
	case 12:
	case 13:
	case 14:
	case 16:
	case 17:
	case 18:
	case 19:
	case 20:
	case 21:
	case 22:
		return -1;
	}
}

#if 0
0    | :authority                  |                              |
1    | :path                       | /                            |
2    | age                         | 0                            |
3    | content-disposition         |                              |
4    | content-length              | 0                            |
5    | cookie                      |                              |
6    | date                        |                              |
7    | etag                        |                              |
8    | if-modified-since           |                              |
9    | if-none-match               |                              |
10   | last-modified               |                              |
11   | link                        |                              |
12   | location                    |                              |
13   | referer                     |                              |
14   | set-cookie                  |                              |
15   | :method                     | CONNECT                      |
16   | :method                     | DELETE                       |
17   | :method                     | GET                          |
18   | :method                     | HEAD                         |
19   | :method                     | OPTIONS                      |
20   | :method                     | POST                         |
21   | :method                     | PUT                          |
22   | :scheme                     | http                         |
23   | :scheme                     | https                        |
24   | :status                     | 103                          |
25   | :status                     | 200                          |
26   | :status                     | 304                          |
27   | :status                     | 404                          |
28   | :status                     | 503                          |
29   | accept                      | */ *                          |
30   | accept                      | application/dns-message      |
31   | accept-encoding             | gzip, deflate, br            |
32   | accept-ranges               | bytes                        |
33   | access-control-allow-       | cache-control                |
     | headers                     |                              |
34   | access-control-allow-       | content-type                 |
     | headers                     |                              |
35   | access-control-allow-origin | *                            |
36   | cache-control               | max-age=0                    |
37   | cache-control               | max-age=2592000              |
38   | cache-control               | max-age=604800               |
39   | cache-control               | no-cache                     |
40   | cache-control               | no-store                     |
41   | cache-control               | public, max-age=31536000     |
42   | content-encoding            | br                           |
43   | content-encoding            | gzip                         |
44   | content-type                | application/dns-message      |
45   | content-type                | application/javascript       |
46   | content-type                | application/json             |
47   | content-type                | application/x-www-form-      |
     |                             | urlencoded                   |
48   | content-type                | image/gif                    |
49   | content-type                | image/jpeg                   |
50   | content-type                | image/png                    |
51   | content-type                | text/css                     |
52   | content-type                | text/html; charset=utf-8     |
53   | content-type                | text/plain                   |
54   | content-type                | text/plain;charset=utf-8     |
55   | range                       | bytes=0-                     |
56   | strict-transport-security   | max-age=31536000             |
57   | strict-transport-security   | max-age=31536000;            |
     |                             | includesubdomains            |
58   | strict-transport-security   | max-age=31536000;            |
     |                             | includesubdomains; preload   |
59   | vary                        | accept-encoding              |
60   | vary                        | origin                       |
61   | x-content-type-options      | nosniff                      |
62   | x-xss-protection            | 1; mode=block                |
63   | :status                     | 100                          |
64   | :status                     | 204                          |
65   | :status                     | 206                          |
66   | :status                     | 302                          |
67   | :status                     | 400                          |
68   | :status                     | 403                          |
69   | :status                     | 421                          |
70   | :status                     | 425                          |
71   | :status                     | 500                          |
72   | accept-language             |                              |
73   | access-control-allow-       | FALSE                        |
     | credentials                 |                              |
74   | access-control-allow-       | TRUE                         |
     | credentials                 |                              |
75   | access-control-allow-       | *                            |
     | headers                     |                              |
76   | access-control-allow-       | get                          |
     | methods                     |                              |
77   | access-control-allow-       | get, post, options           |
     | methods                     |                              |
78   | access-control-allow-       | options                      |
     | methods                     |                              |
79   | access-control-expose-      | content-length               |
     | headers                     |                              |
80   | access-control-request-     | content-type                 |
     | headers                     |                              |
81   | access-control-request-     | get                          |
     | method                      |                              |
82   | access-control-request-     | post                         |
     | method                      |                              |
83   | alt-svc                     | clear                        |
84   | authorization               |                              |
85   | content-security-policy     | script-src 'none'; object-   |
     |                             | src 'none'; base-uri 'none'  |
86   | early-data                  | 1                            |
87   | expect-ct                   |                              |
88   | forwarded                   |                              |
89   | if-range                    |                              |
90   | origin                      |                              |
91   | purpose                     | prefetch                     |
92   | server                      |                              |
93   | timing-allow-origin         | *                            |
94   | upgrade-insecure-requests   | 1                            |
95   | user-agent                  |                              |
96   | x-forwarded-for             |                              |
97   | x-frame-options             | deny                         |
98   | x-frame-options             | sameorigin                  
#endif

