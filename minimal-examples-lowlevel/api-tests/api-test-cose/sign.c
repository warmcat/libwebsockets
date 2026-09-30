/*
 * lws-api-test-jose - RFC8152 cose_sign tests
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Raw key CBOR created from descriptions at
 *
 * https://github.com/cose-wg/Examples/blob/master/KeySet.txt
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <fcntl.h>

static const uint8_t
	sign1_pass_01[] = {
		/*
		 * https://github.com/cose-wg/Examples/blob/master/
		 * sign1-tests/sign-pass-01.json
		 */
		0xd2, 0x84, 0x41, 0xa0, 0xa2,
		0x01, 0x26, 0x04, 0x42, 0x31,
		0x31, 0x54, 0x54, 0x68, 0x69,
		0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x63,
		0x6f, 0x6e, 0x74, 0x65, 0x6e,
		0x74, 0x2e, 0x58, 0x40, 0x87,
		0xdb, 0x0d, 0x2e, 0x55, 0x71,
		0x84, 0x3b, 0x78, 0xac, 0x33,
		0xec, 0xb2, 0x83, 0x0d, 0xf7,
		0xb6, 0xe0, 0xa4, 0xd5, 0xb7,
		0x37, 0x6d, 0xe3, 0x36, 0xb2,
		0x3c, 0x59, 0x1c, 0x90, 0xc4,
		0x25, 0x31, 0x7e, 0x56, 0x12,
		0x7f, 0xbe, 0x04, 0x37, 0x00,
		0x97, 0xce, 0x34, 0x70, 0x87,
		0xb2, 0x33, 0xbf, 0x72, 0x2b,
		0x64, 0x07, 0x2b, 0xeb, 0x44,
		0x86, 0xbd, 0xa4, 0x03, 0x1d,
		0x27, 0x24, 0x4f },
	/*
	 * sign1_pass_01 with the kid changed to "22", which matches no key
	 * in keyset1: validation must survive with the no-key result (-1001)
	 */
	sign1_kid_mismatch_01[] = {
		0xd2, 0x84, 0x41, 0xa0, 0xa2,
		0x01, 0x26, 0x04, 0x42, 0x32,
		0x32, 0x54, 0x54, 0x68, 0x69,
		0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x63,
		0x6f, 0x6e, 0x74, 0x65, 0x6e,
		0x74, 0x2e, 0x58, 0x40, 0x87,
		0xdb, 0x0d, 0x2e, 0x55, 0x71,
		0x84, 0x3b, 0x78, 0xac, 0x33,
		0xec, 0xb2, 0x83, 0x0d, 0xf7,
		0xb6, 0xe0, 0xa4, 0xd5, 0xb7,
		0x37, 0x6d, 0xe3, 0x36, 0xb2,
		0x3c, 0x59, 0x1c, 0x90, 0xc4,
		0x25, 0x31, 0x7e, 0x56, 0x12,
		0x7f, 0xbe, 0x04, 0x37, 0x00,
		0x97, 0xce, 0x34, 0x70, 0x87,
		0xb2, 0x33, 0xbf, 0x72, 0x2b,
		0x64, 0x07, 0x2b, 0xeb, 0x44,
		0x86, 0xbd, 0xa4, 0x03, 0x1d,
		0x27, 0x24, 0x4f },

	sign1_pass_02[] = {
		0xd2, 0x84, 0x43, 0xa1, 0x01,
		0x26, 0xa1, 0x04, 0x42, 0x31,
		0x31, 0x54, 0x54, 0x68, 0x69,
		0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x63,
		0x6f, 0x6e, 0x74, 0x65, 0x6e,
		0x74, 0x2e, 0x58, 0x40, 0x10,
		0x72, 0x9c, 0xd7, 0x11, 0xcb,
		0x38, 0x13, 0xd8, 0xd8, 0xe9,
		0x44, 0xa8, 0xda, 0x71, 0x11,
		0xe7, 0xb2, 0x58, 0xc9, 0xbd,
		0xca, 0x61, 0x35, 0xf7, 0xae,
		0x1a, 0xdb, 0xee, 0x95, 0x09,
		0x89, 0x12, 0x67, 0x83, 0x7e,
		0x1e, 0x33, 0xbd, 0x36, 0xc1,
		0x50, 0x32, 0x6a, 0xe6, 0x27,
		0x55, 0xc6, 0xbd, 0x8e, 0x54,
		0x0c, 0x3e, 0x8f, 0x92, 0xd7,
		0xd2, 0x25, 0xe8, 0xdb, 0x72,
		0xb8, 0x82, 0x0b },

	sign1_pass_02_ext[] = {
		0x11, 0xaa, 0x22, 0xbb, 0x33,
		0xcc, 0x44, 0xdd, 0x55, 0x00,
		0x66, 0x99 },

	sign1_pass_03[] = {
		0x84, 0x43, 0xa1, 0x01, 0x26,
		0xa1, 0x04, 0x42, 0x31, 0x31,
		0x54, 0x54, 0x68, 0x69, 0x73,
		0x20, 0x69, 0x73, 0x20, 0x74,
		0x68, 0x65, 0x20, 0x63, 0x6f,
		0x6e, 0x74, 0x65, 0x6e, 0x74,
		0x2e, 0x58, 0x40, 0x8e, 0xb3,
		0x3e, 0x4c, 0xa3, 0x1d, 0x1c,
		0x46, 0x5a, 0xb0, 0x5a, 0xac,
		0x34, 0xcc, 0x6b, 0x23, 0xd5,
		0x8f, 0xef, 0x5c, 0x08, 0x31,
		0x06, 0xc4, 0xd2, 0x5a, 0x91,
		0xae, 0xf0, 0xb0, 0x11, 0x7e,
		0x2a, 0xf9, 0xa2, 0x91, 0xaa,
		0x32, 0xe1, 0x4a, 0xb8, 0x34,
		0xdc, 0x56, 0xed, 0x2a, 0x22,
		0x34, 0x44, 0x54, 0x7e, 0x01,
		0xf1, 0x1d, 0x3b, 0x09, 0x16,
		0xe5, 0xa4, 0xc3, 0x45, 0xca,
		0xcb, 0x36 },
	sign1_fail_01[] = {
		0xd9, 0x03, 0xe6, 0x84, 0x43,
		0xa1, 0x01, 0x26, 0xa1, 0x04,
		0x42, 0x31, 0x31, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x58,
		0x40, 0x8e, 0xb3, 0x3e, 0x4c,
		0xa3, 0x1d, 0x1c, 0x46, 0x5a,
		0xb0, 0x5a, 0xac, 0x34, 0xcc,
		0x6b, 0x23, 0xd5, 0x8f, 0xef,
		0x5c, 0x08, 0x31, 0x06, 0xc4,
		0xd2, 0x5a, 0x91, 0xae, 0xf0,
		0xb0, 0x11, 0x7e, 0x2a, 0xf9,
		0xa2, 0x91, 0xaa, 0x32, 0xe1,
		0x4a, 0xb8, 0x34, 0xdc, 0x56,
		0xed, 0x2a, 0x22, 0x34, 0x44,
		0x54, 0x7e, 0x01, 0xf1, 0x1d,
		0x3b, 0x09, 0x16, 0xe5, 0xa4,
		0xc3, 0x45, 0xca, 0xcb, 0x36 },
	sign1_fail_02[] = {
		0xd2, 0x84, 0x43, 0xa1, 0x01,
		0x26, 0xa1, 0x04, 0x42, 0x31,
		0x31, 0x54, 0x54, 0x68, 0x69,
		0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x63,
		0x6f, 0x6e, 0x74, 0x65, 0x6e,
		0x74, 0x2f, 0x58, 0x40, 0x8e,
		0xb3, 0x3e, 0x4c, 0xa3, 0x1d,
		0x1c, 0x46, 0x5a, 0xb0, 0x5a,
		0xac, 0x34, 0xcc, 0x6b, 0x23,
		0xd5, 0x8f, 0xef, 0x5c, 0x08,
		0x31, 0x06, 0xc4, 0xd2, 0x5a,
		0x91, 0xae, 0xf0, 0xb0, 0x11,
		0x7e, 0x2a, 0xf9, 0xa2, 0x91,
		0xaa, 0x32, 0xe1, 0x4a, 0xb8,
		0x34, 0xdc, 0x56, 0xed, 0x2a,
		0x22, 0x34, 0x44, 0x54, 0x7e,
		0x01, 0xf1, 0x1d, 0x3b, 0x09,
		0x16, 0xe5, 0xa4, 0xc3, 0x45,
		0xca, 0xcb, 0x36 },
	sign1_fail_03[] = {
		0xd2, 0x84, 0x45, 0xa1, 0x01,
		0x39, 0x03, 0xe6, 0xa1, 0x04,
		0x42, 0x31, 0x31, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x58,
		0x40, 0x8e, 0xb3, 0x3e, 0x4c,
		0xa3, 0x1d, 0x1c, 0x46, 0x5a,
		0xb0, 0x5a, 0xac, 0x34, 0xcc,
		0x6b, 0x23, 0xd5, 0x8f, 0xef,
		0x5c, 0x08, 0x31, 0x06, 0xc4,
		0xd2, 0x5a, 0x91, 0xae, 0xf0,
		0xb0, 0x11, 0x7e, 0x2a, 0xf9,
		0xa2, 0x91, 0xaa, 0x32, 0xe1,
		0x4a, 0xb8, 0x34, 0xdc, 0x56,
		0xed, 0x2a, 0x22, 0x34, 0x44,
		0x54, 0x7e, 0x01, 0xf1, 0x1d,
		0x3b, 0x09, 0x16, 0xe5, 0xa4,
		0xc3, 0x45, 0xca, 0xcb, 0x36 },
	sign1_fail_04[] = {
		0xd2, 0x84, 0x4a, 0xa1, 0x01,
		0x67, 0x75, 0x6e, 0x6b, 0x6e,
		0x6f, 0x77, 0x6e, 0xa1, 0x04,
		0x42, 0x31, 0x31, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x58,
		0x40, 0x8e, 0xb3, 0x3e, 0x4c,
		0xa3, 0x1d, 0x1c, 0x46, 0x5a,
		0xb0, 0x5a, 0xac, 0x34, 0xcc,
		0x6b, 0x23, 0xd5, 0x8f, 0xef,
		0x5c, 0x08, 0x31, 0x06, 0xc4,
		0xd2, 0x5a, 0x91, 0xae, 0xf0,
		0xb0, 0x11, 0x7e, 0x2a, 0xf9,
		0xa2, 0x91, 0xaa, 0x32, 0xe1,
		0x4a, 0xb8, 0x34, 0xdc, 0x56,
		0xed, 0x2a, 0x22, 0x34, 0x44,
		0x54, 0x7e, 0x01, 0xf1, 0x1d,
		0x3b, 0x09, 0x16, 0xe5, 0xa4,
		0xc3, 0x45, 0xca, 0xcb, 0x36 },

		/* sign1/fail05 is missing upstream */

	sign1_fail_06[] = {
		0xd2, 0x84, 0x45, 0xa2, 0x01,
		0x26, 0x03, 0x00, 0xa1, 0x04,
		0x42, 0x31, 0x31, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x58,
		0x40, 0x8e, 0xb3, 0x3e, 0x4c,
		0xa3, 0x1d, 0x1c, 0x46, 0x5a,
		0xb0, 0x5a, 0xac, 0x34, 0xcc,
		0x6b, 0x23, 0xd5, 0x8f, 0xef,
		0x5c, 0x08, 0x31, 0x06, 0xc4,
		0xd2, 0x5a, 0x91, 0xae, 0xf0,
		0xb0, 0x11, 0x7e, 0x2a, 0xf9,
		0xa2, 0x91, 0xaa, 0x32, 0xe1,
		0x4a, 0xb8, 0x34, 0xdc, 0x56,
		0xed, 0x2a, 0x22, 0x34, 0x44,
		0x54, 0x7e, 0x01, 0xf1, 0x1d,
		0x3b, 0x09, 0x16, 0xe5, 0xa4,
		0xc3, 0x45, 0xca, 0xcb, 0x36 },

	sign1_fail_07[] = {
		0xd2, 0x84, 0x43, 0xa1, 0x01,
		0x26, 0xa1, 0x04, 0x42, 0x31,
		0x31, 0x54, 0x54, 0x68, 0x69,
		0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x63,
		0x6f, 0x6e, 0x74, 0x65, 0x6e,
		0x74, 0x2e, 0x58, 0x40, 0x65,
		0x20, 0xbb, 0xaf, 0x20, 0x81,
		0xd7, 0xe0, 0xed, 0x0f, 0x95,
		0xf7, 0x6e, 0xb0, 0x73, 0x3d,
		0x66, 0x70, 0x05, 0xf7, 0x46,
		0x7c, 0xec, 0x4b, 0x87, 0xb9,
		0x38, 0x1a, 0x6b, 0xa1, 0xed,
		0xe8, 0xe0, 0x0d, 0xf2, 0x9f,
		0x32, 0xa3, 0x72, 0x30, 0xf3,
		0x9a, 0x84, 0x2a, 0x54, 0x82,
		0x1f, 0xdd, 0x22, 0x30, 0x92,
		0x81, 0x9d, 0x77, 0x28, 0xef,
		0xb9, 0xd3, 0xa0, 0x08, 0x0b,
		0x75, 0x38, 0x0b },

	sign_pass_01[] = {
		0xd8, 0x62, 0x84, 0x41, 0xa0,
		0xa0, 0x54, 0x54, 0x68, 0x69,
		0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x63,
		0x6f, 0x6e, 0x74, 0x65, 0x6e,
		0x74, 0x2e, 0x81, 0x83, 0x43,
		0xa1, 0x01, 0x26, 0xa1, 0x04,
		0x42, 0x31, 0x31, 0x58, 0x40,
		0xe2, 0xae, 0xaf, 0xd4, 0x0d,
		0x69, 0xd1, 0x9d, 0xfe, 0x6e,
		0x52, 0x07, 0x7c, 0x5d, 0x7f,
		0xf4, 0xe4, 0x08, 0x28, 0x2c,
		0xbe, 0xfb, 0x5d, 0x06, 0xcb,
		0xf4, 0x14, 0xaf, 0x2e, 0x19,
		0xd9, 0x82, 0xac, 0x45, 0xac,
		0x98, 0xb8, 0x54, 0x4c, 0x90,
		0x8b, 0x45, 0x07, 0xde, 0x1e,
		0x90, 0xb7, 0x17, 0xc3, 0xd3,
		0x48, 0x16, 0xfe, 0x92, 0x6a,
		0x2b, 0x98, 0xf5, 0x3a, 0xfd,
		0x2f, 0xa0, 0xf3, 0x0a },

	sign_pass_02[] = {
		0xd8, 0x62, 0x84, 0x40, 0xa0,
		0x54, 0x54, 0x68, 0x69, 0x73,
		0x20, 0x69, 0x73, 0x20, 0x74,
		0x68, 0x65, 0x20, 0x63, 0x6f,
		0x6e, 0x74, 0x65, 0x6e, 0x74,
		0x2e, 0x81, 0x83, 0x43, 0xa1,
		0x01, 0x26, 0xa1, 0x04, 0x42,
		0x31, 0x31, 0x58, 0x40, 0xcb,
		0xb8, 0xda, 0xd9, 0xbe, 0xaf,
		0xb8, 0x90, 0xe1, 0xa4, 0x14,
		0x12, 0x4d, 0x8b, 0xfb, 0xc2,
		0x6b, 0xed, 0xf2, 0xa9, 0x4f,
		0xcb, 0x5a, 0x88, 0x24, 0x32,
		0xbf, 0xf6, 0xd6, 0x3e, 0x15,
		0xf5, 0x74, 0xee, 0xb2, 0xab,
		0x51, 0xd8, 0x3f, 0xa2, 0xcb,
		0xf6, 0x26, 0x72, 0xeb, 0xf4,
		0xc7, 0xd9, 0x93, 0xb0, 0xf4,
		0xc2, 0x44, 0x76, 0x47, 0xd8,
		0x31, 0xba, 0x57, 0xcc, 0xa8,
		0x6b, 0x93, 0x0a },

	sign_pass_03[] = {
		0x84, 0x40, 0xa0, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x81,
		0x83, 0x43, 0xa1, 0x01, 0x26,
		0xa1, 0x04, 0x42, 0x31, 0x31,
		0x58, 0x40, 0xe2, 0xae, 0xaf,
		0xd4, 0x0d, 0x69, 0xd1, 0x9d,
		0xfe, 0x6e, 0x52, 0x07, 0x7c,
		0x5d, 0x7f, 0xf4, 0xe4, 0x08,
		0x28, 0x2c, 0xbe, 0xfb, 0x5d,
		0x06, 0xcb, 0xf4, 0x14, 0xaf,
		0x2e, 0x19, 0xd9, 0x82, 0xac,
		0x45, 0xac, 0x98, 0xb8, 0x54,
		0x4c, 0x90, 0x8b, 0x45, 0x07,
		0xde, 0x1e, 0x90, 0xb7, 0x17,
		0xc3, 0xd3, 0x48, 0x16, 0xfe,
		0x92, 0x6a, 0x2b, 0x98, 0xf5,
		0x3a, 0xfd, 0x2f, 0xa0, 0xf3,
		0x0a },

	sign_fail_01[] = {
		0xd9, 0x03, 0xe6, 0x84, 0x40,
		0xa0, 0x54, 0x54, 0x68, 0x69,
		0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x63,
		0x6f, 0x6e, 0x74, 0x65, 0x6e,
		0x74, 0x2e, 0x81, 0x83, 0x43,
		0xa1, 0x01, 0x26, 0xa1, 0x04,
		0x42, 0x31, 0x31, 0x58, 0x40,
		0xe2, 0xae, 0xaf, 0xd4, 0x0d,
		0x69, 0xd1, 0x9d, 0xfe, 0x6e,
		0x52, 0x07, 0x7c, 0x5d, 0x7f,
		0xf4, 0xe4, 0x08, 0x28, 0x2c,
		0xbe, 0xfb, 0x5d, 0x06, 0xcb,
		0xf4, 0x14, 0xaf, 0x2e, 0x19,
		0xd9, 0x82, 0xac, 0x45, 0xac,
		0x98, 0xb8, 0x54, 0x4c, 0x90,
		0x8b, 0x45, 0x07, 0xde, 0x1e,
		0x90, 0xb7, 0x17, 0xc3, 0xd3,
		0x48, 0x16, 0xfe, 0x92, 0x6a,
		0x2b, 0x98, 0xf5, 0x3a, 0xfd,
		0x2f, 0xa0, 0xf3, 0x0a },

	sign_fail_02[] = {
		0xd8, 0x62, 0x84, 0x40, 0xa0,
		0x54, 0x54, 0x68, 0x69, 0x73,
		0x20, 0x69, 0x73, 0x20, 0x74,
		0x68, 0x65, 0x20, 0x63, 0x6f,
		0x6e, 0x74, 0x65, 0x6e, 0x74,
		0x2e, 0x81, 0x83, 0x43, 0xa1,
		0x01, 0x26, 0xa1, 0x04, 0x42,
		0x31, 0x31, 0x58, 0x40, 0xe2,
		0xae, 0xaf, 0xd4, 0x0d, 0x69,
		0xd1, 0x9d, 0xfe, 0x6e, 0x52,
		0x07, 0x7c, 0x5d, 0x7f, 0xf4,
		0xe4, 0x08, 0x28, 0x2c, 0xbe,
		0xfb, 0x5d, 0x06, 0xcb, 0xf4,
		0x14, 0xaf, 0x2e, 0x19, 0xd9,
		0x82, 0xac, 0x45, 0xac, 0x98,
		0xb8, 0x54, 0x4c, 0x90, 0x8b,
		0x45, 0x07, 0xde, 0x1e, 0x90,
		0xb7, 0x17, 0xc3, 0xd3, 0x48,
		0x16, 0xfe, 0x92, 0x6a, 0x2b,
		0x98, 0xf5, 0x3a, 0xfd, 0x2f,
		0xa0, 0xf3, 0x0b },

	sign_fail_03[] = {
		0xd8, 0x62, 0x84, 0x40, 0xa0,
		0x54, 0x54, 0x68, 0x69, 0x73,
		0x20, 0x69, 0x73, 0x20, 0x74,
		0x68, 0x65, 0x20, 0x63, 0x6f,
		0x6e, 0x74, 0x65, 0x6e, 0x74,
		0x2e, 0x81, 0x83, 0x45, 0xa1,
		0x01, 0x39, 0x03, 0xe6, 0xa1,
		0x04, 0x42, 0x31, 0x31, 0x58,
		0x40, 0xe2, 0xae, 0xaf, 0xd4,
		0x0d, 0x69, 0xd1, 0x9d, 0xfe,
		0x6e, 0x52, 0x07, 0x7c, 0x5d,
		0x7f, 0xf4, 0xe4, 0x08, 0x28,
		0x2c, 0xbe, 0xfb, 0x5d, 0x06,
		0xcb, 0xf4, 0x14, 0xaf, 0x2e,
		0x19, 0xd9, 0x82, 0xac, 0x45,
		0xac, 0x98, 0xb8, 0x54, 0x4c,
		0x90, 0x8b, 0x45, 0x07, 0xde,
		0x1e, 0x90, 0xb7, 0x17, 0xc3,
		0xd3, 0x48, 0x16, 0xfe, 0x92,
		0x6a, 0x2b, 0x98, 0xf5, 0x3a,
		0xfd, 0x2f, 0xa0, 0xf3, 0x0a },

	sign_fail_04[] = {
		0xd8, 0x62, 0x84, 0x40, 0xa0,
		0x54, 0x54, 0x68, 0x69, 0x73,
		0x20, 0x69, 0x73, 0x20, 0x74,
		0x68, 0x65, 0x20, 0x63, 0x6f,
		0x6e, 0x74, 0x65, 0x6e, 0x74,
		0x2e, 0x81, 0x83, 0x4a, 0xa1,
		0x01, 0x67, 0x75, 0x6e, 0x6b,
		0x6e, 0x6f, 0x77, 0x6e, 0xa1,
		0x04, 0x42, 0x31, 0x31, 0x58,
		0x40, 0xe2, 0xae, 0xaf, 0xd4,
		0x0d, 0x69, 0xd1, 0x9d, 0xfe,
		0x6e, 0x52, 0x07, 0x7c, 0x5d,
		0x7f, 0xf4, 0xe4, 0x08, 0x28,
		0x2c, 0xbe, 0xfb, 0x5d, 0x06,
		0xcb, 0xf4, 0x14, 0xaf, 0x2e,
		0x19, 0xd9, 0x82, 0xac, 0x45,
		0xac, 0x98, 0xb8, 0x54, 0x4c,
		0x90, 0x8b, 0x45, 0x07, 0xde,
		0x1e, 0x90, 0xb7, 0x17, 0xc3,
		0xd3, 0x48, 0x16, 0xfe, 0x92,
		0x6a, 0x2b, 0x98, 0xf5, 0x3a,
		0xfd, 0x2f, 0xa0, 0xf3, 0x0a },

		/* fail 5 missing upstream */

	sign_fail_06[] = {
		0xd8, 0x62, 0x84, 0x43, 0xa1,
		0x03, 0x00, 0xa0, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x81,
		0x83, 0x43, 0xa1, 0x01, 0x26,
		0xa1, 0x04, 0x42, 0x31, 0x31,
		0x58, 0x40, 0xe2, 0xae, 0xaf,
		0xd4, 0x0d, 0x69, 0xd1, 0x9d,
		0xfe, 0x6e, 0x52, 0x07, 0x7c,
		0x5d, 0x7f, 0xf4, 0xe4, 0x08,
		0x28, 0x2c, 0xbe, 0xfb, 0x5d,
		0x06, 0xcb, 0xf4, 0x14, 0xaf,
		0x2e, 0x19, 0xd9, 0x82, 0xac,
		0x45, 0xac, 0x98, 0xb8, 0x54,
		0x4c, 0x90, 0x8b, 0x45, 0x07,
		0xde, 0x1e, 0x90, 0xb7, 0x17,
		0xc3, 0xd3, 0x48, 0x16, 0xfe,
		0x92, 0x6a, 0x2b, 0x98, 0xf5,
		0x3a, 0xfd, 0x2f, 0xa0, 0xf3,
		0x0a },

	sign_fail_07[] = {
		0xd8, 0x62, 0x84, 0x41, 0xa0,
		0xa0, 0x54, 0x54, 0x68, 0x69,
		0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x63,
		0x6f, 0x6e, 0x74, 0x65, 0x6e,
		0x74, 0x2e, 0x81, 0x83, 0x43,
		0xa1, 0x01, 0x26, 0xa1, 0x04,
		0x42, 0x31, 0x31, 0x58, 0x40,
		0xd7, 0x1c, 0x05, 0xdb, 0x52,
		0xc9, 0xce, 0x7f, 0x1b, 0xf5,
		0xaa, 0xc0, 0x13, 0x34, 0xbb,
		0xea, 0xca, 0xc1, 0xd8, 0x6a,
		0x23, 0x03, 0xe6, 0xee, 0xaa,
		0x89, 0x26, 0x6f, 0x45, 0xc0,
		0x1e, 0xd6, 0x02, 0xca, 0x64,
		0x9e, 0xaf, 0x79, 0x0d, 0x8b,
		0xc9, 0x9d, 0x24, 0x58, 0x45,
		0x7c, 0xa6, 0xa8, 0x72, 0x06,
		0x19, 0x40, 0xe7, 0xaf, 0xbe,
		0x48, 0xe2, 0x89, 0xdf, 0xac,
		0x14, 0x6a, 0xe2, 0x58 },

	sign_hmac_01[] = {
		0xd8, 0x61, 0x85, 0x43, 0xa1,
		0x01, 0x05, 0xa0, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x58,
		0x20, 0x2b, 0xdc, 0xc8, 0x9f,
		0x05, 0x82, 0x16, 0xb8, 0xa2,
		0x08, 0xdd, 0xc6, 0xd8, 0xb5,
		0x4a, 0xa9, 0x1f, 0x48, 0xbd,
		0x63, 0x48, 0x49, 0x86, 0x56,
		0x51, 0x05, 0xc9, 0xad, 0x5a,
		0x66, 0x82, 0xf6, 0x81, 0x83,
		0x40, 0xa2, 0x01, 0x25, 0x04,
		0x4a, 0x6f, 0x75, 0x72, 0x2d,
		0x73, 0x65, 0x63, 0x72, 0x65,
		0x74, 0x40 },

	sign_hmac_02[] = {
		0xd8, 0x61, 0x85, 0x43, 0xa1,
		0x01, 0x06, 0xa0, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x58,
		0x30, 0xb3, 0x09, 0x7f, 0x70,
		0x00, 0x9a, 0x11, 0x50, 0x74,
		0x09, 0x59, 0x8a, 0x83, 0xe1,
		0x5b, 0xbb, 0xbf, 0x19, 0x82,
		0xdc, 0xe2, 0x8e, 0x5a, 0xb6,
		0xd5, 0xa6, 0xaf, 0xf6, 0x89,
		0x7b, 0xd2, 0x4b, 0xb8, 0xb7,
		0x47, 0x96, 0x22, 0xc9, 0x40,
		0x1b, 0x24, 0x09, 0x0d, 0x45,
		0x82, 0x06, 0xd5, 0x87, 0x81,
		0x83, 0x40, 0xa2, 0x01, 0x25,
		0x04, 0x46, 0x73, 0x65, 0x63,
		0x2d, 0x34, 0x38, 0x40 },

	sign_hmac_03[] = {
		0xd8, 0x61, 0x85, 0x43, 0xa1,
		0x01, 0x07, 0xa0, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x58,
		0x40, 0xcd, 0x28, 0xa6, 0xb3,
		0xcf, 0xbb, 0xbf, 0x21, 0x48,
		0x51, 0xb9, 0x06, 0xe0, 0x50,
		0x05, 0x6c, 0xb4, 0x38, 0xa8,
		0xb8, 0x89, 0x05, 0xb8, 0xb7,
		0x46, 0x19, 0x77, 0x02, 0x27,
		0x11, 0xa9, 0xd8, 0xac, 0x5d,
		0xbc, 0x54, 0xe2, 0x9a, 0x56,
		0xd9, 0x26, 0x04, 0x6b, 0x40,
		0xfc, 0x26, 0x07, 0xc2, 0x5b,
		0x34, 0x44, 0x54, 0xaa, 0x5f,
		0x68, 0xde, 0x09, 0xa3, 0xe5,
		0x25, 0xd3, 0x86, 0x5a, 0x05,
		0x81, 0x83, 0x40, 0xa2, 0x01,
		0x25, 0x04, 0x46, 0x73, 0x65,
		0x63, 0x2d, 0x36, 0x34, 0x40 },

	sign_hmac_04[] = {
		0xd8, 0x61, 0x85, 0x43, 0xa1,
		0x01, 0x05, 0xa0, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x58,
		0x20, 0x2b, 0xdc, 0xc8, 0x9f,
		0x05, 0x82, 0x16, 0xb8, 0xa2,
		0x08, 0xdd, 0xc6, 0xd8, 0xb5,
		0x4a, 0xa9, 0x1f, 0x48, 0xbd,
		0x63, 0x48, 0x49, 0x86, 0x56,
		0x51, 0x05, 0xc9, 0xad, 0x5a,
		0x66, 0x82, 0xf7, 0x81, 0x83,
		0x40, 0xa2, 0x01, 0x25, 0x04,
		0x4a, 0x6f, 0x75, 0x72, 0x2d,
		0x73, 0x65, 0x63, 0x72, 0x65,
		0x74, 0x40 },

	sign_hmac_05[] = {
		0xd8, 0x61, 0x85, 0x43, 0xa1,
		0x01, 0x04, 0xa0, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x48,
		0x6f, 0x35, 0xca, 0xb7, 0x79,
		0xf7, 0x78, 0x33, 0x81, 0x83,
		0x40, 0xa2, 0x01, 0x25, 0x04,
		0x4a, 0x6f, 0x75, 0x72, 0x2d,
		0x73, 0x65, 0x63, 0x72, 0x65,
		0x74, 0x40 },

	enc_hmac_01[] = {
		0xd1, 0x84, 0x43, 0xa1, 0x01,
		0x05, 0xa0, 0x54, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x69, 0x73,
		0x20, 0x74, 0x68, 0x65, 0x20,
		0x63, 0x6f, 0x6e, 0x74, 0x65,
		0x6e, 0x74, 0x2e, 0x58, 0x20,
		0xa1, 0xa8, 0x48, 0xd3, 0x47,
		0x1f, 0x9d, 0x61, 0xee, 0x49,
		0x01, 0x8d, 0x24, 0x4c, 0x82,
		0x47, 0x72, 0xf2, 0x23, 0xad,
		0x4f, 0x93, 0x52, 0x93, 0xf1,
		0x78, 0x9f, 0xc3, 0xa0, 0x8d,
		0x8c, 0x58 },

	enc_hmac_02[] = {
		0xd1, 0x84, 0x43, 0xa1, 0x01,
		0x06, 0xa0, 0x54, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x69, 0x73,
		0x20, 0x74, 0x68, 0x65, 0x20,
		0x63, 0x6f, 0x6e, 0x74, 0x65,
		0x6e, 0x74, 0x2e, 0x58, 0x30,
		0x99, 0x8d, 0x26, 0xc6, 0x45,
		0x9a, 0xae, 0xec, 0xf4, 0x4e,
		0xd2, 0x0c, 0xe0, 0x0c, 0x8c,
		0xce, 0xdf, 0x0a, 0x1f, 0x3d,
		0x22, 0xa9, 0x2f, 0xc0, 0x5d,
		0xb0, 0x8c, 0x5a, 0xeb, 0x1c,
		0xb5, 0x94, 0xca, 0xaf, 0x5a,
		0x5c, 0x5e, 0x2e, 0x9d, 0x01,
		0xcc, 0xe7, 0xe7, 0x7a, 0x93,
		0xaa, 0x8c, 0x62 },

	enc_hmac_03[] = {
		0xd1, 0x84, 0x43, 0xa1, 0x01,
		0x07, 0xa0, 0x54, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x69, 0x73,
		0x20, 0x74, 0x68, 0x65, 0x20,
		0x63, 0x6f, 0x6e, 0x74, 0x65,
		0x6e, 0x74, 0x2e, 0x58, 0x40,
		0x4a, 0x55, 0x5b, 0xf9, 0x71,
		0xf7, 0xc1, 0x89, 0x1d, 0x9d,
		0xdf, 0x30, 0x4a, 0x1a, 0x13,
		0x2e, 0x2d, 0x6f, 0x81, 0x74,
		0x49, 0x47, 0x4d, 0x81, 0x3e,
		0x6d, 0x04, 0xd6, 0x59, 0x62,
		0xbe, 0xd8, 0xbb, 0xa7, 0x0c,
		0x17, 0xe1, 0xf5, 0x30, 0x8f,
		0xa3, 0x99, 0x62, 0x95, 0x9a,
		0x4b, 0x9b, 0x8d, 0x7d, 0xa8,
		0xe6, 0xd8, 0x49, 0xb2, 0x09,
		0xdc, 0xd3, 0xe9, 0x8c, 0xc0,
		0xf1, 0x1e, 0xdd, 0xf2 },

	enc_hmac_04[] = {
		0xd1, 0x84, 0x43, 0xa1, 0x01,
		0x05, 0xa0, 0x54, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x69, 0x73,
		0x20, 0x74, 0x68, 0x65, 0x20,
		0x63, 0x6f, 0x6e, 0x74, 0x65,
		0x6e, 0x74, 0x2e, 0x58, 0x20,
		0xa1, 0xa8, 0x48, 0xd3, 0x47,
		0x1f, 0x9d, 0x61, 0xee, 0x49,
		0x01, 0x8d, 0x24, 0x4c, 0x82,
		0x47, 0x72, 0xf2, 0x23, 0xad,
		0x4f, 0x93, 0x52, 0x93, 0xf1,
		0x78, 0x9f, 0xc3, 0xa0, 0x8d,
		0x8c, 0x59 },

	enc_hmac_05[] = {
		0xd1, 0x84, 0x43, 0xa1, 0x01,
		0x04, 0xa0, 0x54, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x69, 0x73,
		0x20, 0x74, 0x68, 0x65, 0x20,
		0x63, 0x6f, 0x6e, 0x74, 0x65,
		0x6e, 0x74, 0x2e, 0x48, 0x11,
		0xf9, 0xe3, 0x57, 0x97, 0x5f,
		0xb8, 0x49 }
#if 0
,

	countersign_sign_01[] = {
		0xd8, 0x62, 0x84, 0x43, 0xa1,
		0x03, 0x00, 0xa0, 0x54, 0x54,
		0x68, 0x69, 0x73, 0x20, 0x69,
		0x73, 0x20, 0x74, 0x68, 0x65,
		0x20, 0x63, 0x6f, 0x6e, 0x74,
		0x65, 0x6e, 0x74, 0x2e, 0x81,
		0x83, 0x43, 0xa1, 0x01, 0x27,
		0xa2, 0x07, 0x83, 0x43, 0xa1,
		0x01, 0x27, 0xa1, 0x04, 0x42,
		0x31, 0x31, 0x58, 0x40, 0x8e,
		0x1b, 0xe2, 0xf9, 0x45, 0x3d,
		0x26, 0x48, 0x12, 0xe5, 0x90,
		0x49, 0x91, 0x32, 0xbe, 0xf3,
		0xfb, 0xf9, 0xee, 0x9d, 0xb2,
		0x7c, 0x2c, 0x16, 0x87, 0x88,
		0xe3, 0xb7, 0xeb, 0xe5, 0x06,
		0xc0, 0x4f, 0xd3, 0xd1, 0x9f,
		0xaa, 0x9f, 0x51, 0x23, 0x2a,
		0xf5, 0xc9, 0x59, 0xe4, 0xef,
		0x47, 0x92, 0x88, 0x34, 0x64,
		0x7f, 0x56, 0xdf, 0xbe, 0x93,
		0x91, 0x12, 0x88, 0x4d, 0x08,
		0xef, 0x25, 0x05, 0x04, 0x42,
		0x31, 0x31, 0x58, 0x40, 0x77,
		0xf3, 0xea, 0xcd, 0x11, 0x85,
		0x2c, 0x4b, 0xf9, 0xcb, 0x1d,
		0x72, 0xfa, 0xbe, 0x6b, 0x26,
		0xfb, 0xa1, 0xd7, 0x60, 0x92,
		0xb2, 0xb5, 0xb7, 0xec, 0x83,
		0xb8, 0x35, 0x57, 0x65, 0x22,
		0x64, 0xe6, 0x96, 0x90, 0xdb,
		0xc1, 0x17, 0x2d, 0xdc, 0x0b,
		0xf8, 0x84, 0x11, 0xc0, 0xd2,
		0x5a, 0x50, 0x7f, 0xdb, 0x24,
		0x7a, 0x20, 0xc4, 0x0d, 0x5e,
		0x24, 0x5f, 0xab, 0xd3, 0xfc,
		0x9e, 0xc1, 0x06 }
#endif
;

extern const struct {
	const uint8_t		*set;
	size_t			len;
} keyset1, key3, key8, key9, key10;

static int
xcb(lws_cose_sig_ext_pay_t *x)
{
	x->ext = sign1_pass_02_ext;
	x->xl = sizeof(sign1_pass_02_ext);

	return LCOSESIGEXTCB_RET_FINISHED;
}

/*
 * Optionally checks that the payload the validator reports is exactly ref
 */

struct pay_check {
	const uint8_t		*ref;
	size_t			len;
	size_t			pos;
	char			bad;
};

static int
pay_check_cb(struct lws_cose_validate_context *cps, void *opaque,
	     const uint8_t *paychunk, size_t paychunk_len)
{
	struct pay_check *pc = (struct pay_check *)opaque;

	(void)cps;

	if (paychunk_len > pc->len - pc->pos ||
	    memcmp(pc->ref + pc->pos, paychunk, paychunk_len))
		pc->bad = 1;
	else
		pc->pos += paychunk_len;

	return 0;
}

/*
 * Validates in against set, returning 0 only if the object produced exactly
 * want results, and all of them are a pass
 */

static int
validate_all_pass(struct lws_context *cx, lws_dll2_owner_t *set,
		  enum lws_cose_sig_types sigtype, const uint8_t *in,
		  size_t in_len, uint32_t want, struct pay_check *pc)
{
	lws_cose_validate_create_info_t info;
	struct lws_cose_validate_context *cps;
	lws_dll2_owner_t *o;
	int n = 1;

	memset(&info, 0, sizeof(info));
	info.cx		= cx;
	info.keyset	= set;
	info.sigtype	= sigtype;
	if (pc) {
		info.pay_cb	= pay_check_cb;
		info.pay_opaque	= pc;
	}

	cps = lws_cose_validate_create(&info);
	if (!cps)
		return 1;

	if (lws_cose_validate_chunk(cps, in, in_len, NULL)) {
		lwsl_err("%s: validate_chunk failed\n", __func__);
		goto bail;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != want) {
		lwsl_err("%s: %d results\n", __func__, lws_dll2_count(o));
		goto bail;
	}

	n = 0;
	lws_start_foreach_dll(struct lws_dll2 *, p, lws_dll2_get_head(o)) {
		lws_cose_validate_res_t *res = lws_container_of(p,
						lws_cose_validate_res_t, list);

		if (res->result) {
			lwsl_err("%s: result %d\n", __func__, res->result);
			n = 1;
		}
	} lws_end_foreach_dll(p);

	if (pc && (pc->bad || pc->pos != pc->len)) {
		lwsl_err("%s: payload differs\n", __func__);
		n = 1;
	}

bail:
	lws_cose_validate_destroy(&cps);

	return n;
}

/*
 * Arrays in the unprotected bucket of a cose_signature or a COSE_recipient,
 * like an RFC9360 x5chain (label 33), are just header values: the end of one
 * of their items is not the end of the bucket.  The unprotected bucket is not
 * covered by the signature or MAC, so a cose-wg example with such a bucket
 * spliced in instead of its own must still validate.
 *
 * in[ofs] is the start of the old bucket, which is old_len long.
 */

static int
splice_validate(struct lws_context *cx, lws_dll2_owner_t *set,
		enum lws_cose_sig_types sigtype, const uint8_t *in,
		size_t in_len, size_t ofs, size_t old_len,
		const uint8_t *bucket, size_t bucket_len)
{
	uint8_t obj[640];
	size_t tail = in_len - ofs - old_len;

	if (ofs + bucket_len + tail > sizeof(obj))
		return 1;

	memcpy(obj, in, ofs);
	memcpy(obj + ofs, bucket, bucket_len);
	memcpy(obj + ofs + bucket_len, in + ofs + old_len, tail);

	return validate_all_pass(cx, set, sigtype, obj,
				 ofs + bucket_len + tail, 1, NULL);
}

/* where the signer's unprotected {4: '11'} is in sign_pass_01 */
#define SP01_UNPROT_OFS		33
#define SP01_UNPROT_LEN		5
/* where the recipient's unprotected {1: -6, 4: 'our-secret'} is in
 * sign_hmac_01 */
#define SH01_UNPROT_OFS		66
#define SH01_UNPROT_LEN		15

static const uint8_t
	/* {33: [h'01020304', h'05060708'], 4: '11'} */
	unprot_x5c2_kid[] = {
		0xa2, 0x18, 0x21, 0x82, 0x44, 0x01, 0x02, 0x03,
		0x04, 0x44, 0x05, 0x06, 0x07, 0x08, 0x04, 0x42,
		0x31, 0x31 },
	/* {4: '11', 33: [h'01020304', h'05060708']} */
	unprot_kid_x5c2[] = {
		0xa2, 0x04, 0x42, 0x31, 0x31, 0x18, 0x21, 0x82,
		0x44, 0x01, 0x02, 0x03, 0x04, 0x44, 0x05, 0x06,
		0x07, 0x08 },
	/* {33: [h'01020304'], 4: '11'} */
	unprot_x5c1_kid[] = {
		0xa2, 0x18, 0x21, 0x81, 0x44, 0x01, 0x02, 0x03,
		0x04, 0x04, 0x42, 0x31, 0x31 },
	/* {1: -6, 4: 'our-secret', 33: [h'01020304', h'05060708']} */
	unprot_rcpt_x5c2[] = {
		0xa3, 0x01, 0x25, 0x04, 0x4a, 0x6f, 0x75, 0x72,
		0x2d, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x18,
		0x21, 0x82, 0x44, 0x01, 0x02, 0x03, 0x04, 0x44,
		0x05, 0x06, 0x07, 0x08 };

static int
test_cose_nested_unprotected(struct lws_context *cx)
{
	uint8_t big[512], *p = big;
	lws_dll2_owner_t set;
	int n;

	lwsl_user("%s: arrays in signer / recipient unprotected buckets\n",
		  __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	/*
	 * An x5chain whose two certificates, like real ones, are much bigger
	 * than any protected bucket: {33: [h'30...', h'31...'], 4: '11'}
	 */

	*p++ = 0xa2;
	*p++ = 0x18;
	*p++ = 0x21;
	*p++ = 0x82;
	for (n = 0; n < 2; n++) {
		*p++ = 0x58;
		*p++ = 200;
		memset(p, 0x30 + n, 200);
		p += 200;
	}
	*p++ = 0x04;
	*p++ = 0x42;
	*p++ = 0x31;
	*p++ = 0x31;

	/* the cases are independent, run and report them all */

	n = splice_validate(cx, &set, SIGTYPE_MULTI, sign_pass_01,
			    sizeof(sign_pass_01), SP01_UNPROT_OFS,
			    SP01_UNPROT_LEN, unprot_x5c2_kid,
			    sizeof(unprot_x5c2_kid));
	n |= splice_validate(cx, &set, SIGTYPE_MULTI, sign_pass_01,
			     sizeof(sign_pass_01), SP01_UNPROT_OFS,
			     SP01_UNPROT_LEN, unprot_kid_x5c2,
			     sizeof(unprot_kid_x5c2)) << 1;
	n |= splice_validate(cx, &set, SIGTYPE_MULTI, sign_pass_01,
			     sizeof(sign_pass_01), SP01_UNPROT_OFS,
			     SP01_UNPROT_LEN, unprot_x5c1_kid,
			     sizeof(unprot_x5c1_kid)) << 2;
	n |= splice_validate(cx, &set, SIGTYPE_MULTI, sign_pass_01,
			     sizeof(sign_pass_01), SP01_UNPROT_OFS,
			     SP01_UNPROT_LEN, big,
			     lws_ptr_diff_size_t(p, big)) << 3;
	n |= splice_validate(cx, &set, SIGTYPE_MAC, sign_hmac_01,
			     sizeof(sign_hmac_01), SH01_UNPROT_OFS,
			     SH01_UNPROT_LEN, unprot_rcpt_x5c2,
			     sizeof(unprot_rcpt_x5c2)) << 4;

	lws_cose_key_set_destroy(&set);

	if (n)
		lwsl_err("%s: failed cases 0x%x\n", __func__, n);

	return !!n;
}

/*
 * Signs pay into obj the way a streaming application does: the payload is
 * passed in seg-sized chunks, and the object comes out through an output
 * buffer of only out_room bytes, drained whenever the signer says AGAIN
 */

static int
sign_streamed(struct lws_context *cx, lws_dll2_owner_t *set,
	      enum lws_cose_sig_types sigtype, const cose_param_t *algs,
	      const lws_cose_key_t * const *keys, int nkeys,
	      const uint8_t *pay, size_t pay_len, size_t seg, size_t out_room,
	      uint8_t *obj, size_t obj_max, size_t *obj_len)
{
	struct lws_cose_sign_context *csc;
	lws_cose_sign_create_info_t i;
	enum lws_lec_pctx_ret r;
	size_t ofs = 0, s;
	lws_lec_pctx_t lec;
	uint8_t out[128];
	int k;

	if (out_room > sizeof(out))
		return 1;

	memset(&i, 0, sizeof(i));
	i.cx			= cx;
	i.keyset		= set;
	i.lec			= &lec;
	i.sigtype		= sigtype;
	i.inline_payload_len	= pay_len;
	i.flags			= LCSC_FL_ADD_CBOR_TAG;

	lws_lec_init(&lec, out, out_room);

	csc = lws_cose_sign_create(&i);
	if (!csc)
		return 1;

	for (k = 0; k < nkeys; k++)
		if (lws_cose_sign_add(csc, algs[k], keys[k]))
			goto bail;

	*obj_len = 0;

	do {
		s = pay_len - ofs;
		if (s > seg)
			s = seg;

		do {
			r = lws_cose_sign_payload_chunk(csc, pay + ofs, s);
			if (r == LWS_LECPCTX_RET_FAIL)
				goto bail;

			if (lec.used > obj_max - *obj_len ||
			    (r == LWS_LECPCTX_RET_AGAIN && !lec.used))
				/* too big, or no progress */
				goto bail;

			memcpy(obj + *obj_len, out, lec.used);
			*obj_len += lec.used;
			lws_lec_setbuf(&lec, out, out_room);

		} while (r == LWS_LECPCTX_RET_AGAIN);

		ofs += s;
	} while (ofs < pay_len);

	lws_cose_sign_destroy(&csc);

	return 0;

bail:
	lws_cose_sign_destroy(&csc);

	return 1;
}

/*
 * A payload much bigger than the output buffer, passed in chunks that are
 * bigger or smaller than the output buffer, or all at once, through output
 * windows of every size from 1 to 80 bytes: the object must carry the payload
 * exactly once, in order, with one good signature over it per signer, for
 * COSE_Sign1, COSE_Mac0 and a two-signer COSE_Sign
 */

static int
test_cose_sign_streamed(struct lws_context *cx)
{
	static const size_t segs[] = { 7, 256, 1000 };
	const lws_cose_key_t *keys[2], *hkey[1];
	uint8_t pay[1000], obj[1400];
	struct pay_check pc;
	lws_dll2_owner_t set;
	cose_param_t algs[2];
	lws_cose_key_t *ck;
	size_t n, ol, room;
	int ret = 1;

	lwsl_user("%s: streamed payload bigger than the output\n", __func__);

	for (n = 0; n < sizeof(pay); n++)
		pay[n] = (uint8_t)(n * 7 + 3);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	/* a second signing key, of another curve, for the COSE_Sign */

	ck = lws_cose_key_generate(cx, LWSCOSE_WKKTV_EC2,
				   (1 << LWSCOSE_WKKO_SIGN) |
				   (1 << LWSCOSE_WKKO_VERIFY),
				   0, "P-384", (const uint8_t *)"p384", 4);
	if (!ck) {
		lwsl_err("%s: P-384 keygen fail\n", __func__);
		goto bail;
	}
	lws_dll2_add_tail(&ck->list, &set);

	keys[0] = lws_cose_key_from_set(&set, (const uint8_t *)"11", 2);
	keys[1] = ck;
	hkey[0] = lws_cose_key_from_set(&set, (const uint8_t *)"our-secret",
					10);
	if (!keys[0] || !hkey[0])
		goto bail;

	for (room = 1; room <= 80; room++) {
		size_t seg = segs[room % LWS_ARRAY_SIZE(segs)];

		/* COSE_Sign1, ES256 */

		algs[0] = LWSCOSE_WKAECDSA_ALG_ES256;
		if (sign_streamed(cx, &set, SIGTYPE_SINGLE, algs, keys, 1,
				  pay, sizeof(pay), seg, room, obj,
				  sizeof(obj), &ol)) {
			lwsl_err("%s: sign1 room %d fail\n", __func__,
				 (int)room);
			goto bail;
		}

		memset(&pc, 0, sizeof(pc));
		pc.ref = pay;
		pc.len = sizeof(pay);
		if (validate_all_pass(cx, &set, SIGTYPE_SINGLE, obj, ol, 1,
				      &pc)) {
			lwsl_err("%s: sign1 room %d invalid\n", __func__,
				 (int)room);
			goto bail;
		}

		/* COSE_Mac0, HMAC 256/256 */

		algs[0] = LWSCOSE_WKAHMAC_256_256;
		if (sign_streamed(cx, &set, SIGTYPE_MAC0, algs, hkey, 1,
				  pay, sizeof(pay), seg, room, obj,
				  sizeof(obj), &ol)) {
			lwsl_err("%s: mac0 room %d fail\n", __func__,
				 (int)room);
			goto bail;
		}

		memset(&pc, 0, sizeof(pc));
		pc.ref = pay;
		pc.len = sizeof(pay);
		if (validate_all_pass(cx, &set, SIGTYPE_MAC0, obj, ol, 1,
				      &pc)) {
			lwsl_err("%s: mac0 room %d invalid\n", __func__,
				 (int)room);
			goto bail;
		}

		/* COSE_Sign, ES256 + ES384 */

		algs[0] = LWSCOSE_WKAECDSA_ALG_ES256;
		algs[1] = LWSCOSE_WKAECDSA_ALG_ES384;
		if (sign_streamed(cx, &set, SIGTYPE_MULTI, algs, keys, 2,
				  pay, sizeof(pay), seg, room, obj,
				  sizeof(obj), &ol)) {
			lwsl_err("%s: sign room %d fail\n", __func__,
				 (int)room);
			goto bail;
		}

		memset(&pc, 0, sizeof(pc));
		pc.ref = pay;
		pc.len = sizeof(pay);
		if (validate_all_pass(cx, &set, SIGTYPE_MULTI, obj, ol, 2,
				      &pc)) {
			lwsl_err("%s: sign room %d invalid\n", __func__,
				 (int)room);
			goto bail;
		}
	}

	ret = 0;

bail:
	lws_cose_key_set_destroy(&set);

	return ret;
}



int
test_cose_sign(struct lws_context *context)
{
	struct lws_cose_validate_context *cps;
	lws_cose_validate_create_info_t info;
	lws_cose_validate_res_t *res;
	lws_dll2_owner_t set;
	lws_dll2_owner_t *o;
	int n;

	memset(&info, 0, sizeof(info));

	info.cx = context;
	info.keyset = &set;

#if 1
	{
		int fd = open("sign_hmac01.sig",
			      LWS_O_CREAT | LWS_O_TRUNC | LWS_O_WRONLY, 0600);

		if (fd >= 0) {
			write(fd, sign_hmac_01, sizeof(sign_hmac_01));
			close(fd);
		}
	}
#endif

	/*
	 * valid sign1 we have key for
	 */

	lwsl_user("%s: sign1/sign-pass-01\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_SINGLE;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_pass_01, sizeof(sign1_pass_01),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail1;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result)
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid sign1 but empty key set, so can't judge it
	 */

	lwsl_user("%s: sign1/sign-pass-01 - no key\n", __func__);

	lws_dll2_owner_clear(&set);

	info.sigtype = SIGTYPE_SINGLE;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_pass_01, sizeof(sign1_pass_01),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail1;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result)
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid sign1 whose kid is in no key of the keyset, so it can't be
	 * matched to an alg: this must produce the -1001 result, not crash
	 * at payload or signature time with an empty alg list (F-032)
	 */

	lwsl_user("%s: sign1/sign-pass-01 - kid mismatch\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_SINGLE;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_kid_mismatch_01,
				    sizeof(sign1_kid_mismatch_01), NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail1;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result != -1001)
		/* must be the no-key result, not a pass */
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid sign1
	 */

	lwsl_user("%s: sign1/sign-pass-02\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_SINGLE;
	info.ext_cb = xcb;
	info.ext_len = sizeof(sign1_pass_02_ext);
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_pass_02, sizeof(sign1_pass_02),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail1;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result)
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid sign1 without enclosing tag
	 */

	lwsl_user("%s: sign1/sign-pass-03\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_SINGLE;
	info.ext_cb = NULL;
	info.ext_len = 0;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_pass_03, sizeof(sign1_pass_03),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail1;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result)
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * sign1 with wrong tag
	 */

	lwsl_user("%s: sign1/sign-fail-01\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_SINGLE;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_fail_01, sizeof(sign1_fail_01),
				    NULL);
	if (!n) {
		lwsl_notice("%s: sign_val_chunk should have failed\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * invalid sign1, signature tampered
	 */

	lwsl_user("%s: sign1/sign-fail-02\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_SINGLE;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_fail_02, sizeof(sign1_fail_02),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail1;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result)
		/* validation result must be fail */
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * invalid sign1, alg tampered
	 */

	lwsl_user("%s: sign1/sign-fail-03\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_SINGLE;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_fail_03, sizeof(sign1_fail_03),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail1;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result)
		/* validation result must be fail */
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * invalid sign1, alg sign tampered
	 */

	lwsl_user("%s: sign1/sign-fail-04\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_SINGLE;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_fail_04, sizeof(sign1_fail_04),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail1;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result)
		/* validation result must be fail */
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * invalid sign1, protected attributes tampered
	 */

	lwsl_user("%s: sign1/sign-fail-06\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_SINGLE;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_fail_06, sizeof(sign1_fail_06),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail1;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result)
		/* validation result must be fail */
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * invalid sign1, protected attribute removed
	 */

	lwsl_user("%s: sign1/sign-fail-07\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_SINGLE;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign1_fail_07, sizeof(sign1_fail_07),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail1;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result)
		/* validation result must be fail */
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid sign we have key for
	 */

	lwsl_user("%s: sign/sign-pass-01\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MULTI;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_pass_01, sizeof(sign_pass_01),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_notice("%s: results: %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result)
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid sign we have key for
	 */

	lwsl_user("%s: sign/sign-pass-02\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MULTI;
	info.ext_cb = xcb;
	info.ext_len = sizeof(sign1_pass_02_ext);
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_pass_02, sizeof(sign_pass_02),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_notice("%s: results: %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result)
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid sign we have key for
	 */

	lwsl_user("%s: sign/sign-pass-03\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MULTI;
	info.ext_cb = NULL;
	info.ext_len = 0;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_pass_03, sizeof(sign_pass_03),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_notice("%s: results: %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result)
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * wrong cbor tag
	 */

	lwsl_user("%s: sign/sign-fail-01\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MULTI;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_fail_01, sizeof(sign_fail_01),
				    NULL);
	if (!n) {
		lwsl_notice("%s: sign_val_chunk should fail\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * tampered signature
	 */

	lwsl_user("%s: sign/sign-fail-02\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MULTI;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_fail_02, sizeof(sign_fail_02),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_notice("%s: results: %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result)
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * tampered sign alg -999
	 */

	lwsl_user("%s: sign/sign-fail-03\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MULTI;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_fail_03, sizeof(sign_fail_03),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_notice("%s: results: %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * tampered sign alg 0
	 */

	lwsl_user("%s: sign/sign-fail-04\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MULTI;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_fail_04, sizeof(sign_fail_04),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_notice("%s: results: %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * add protected attribute
	 */

	lwsl_user("%s: sign/sign-fail-06\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MULTI;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_fail_06, sizeof(sign_fail_06),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_notice("%s: results: %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result)
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * remove protected attribute
	 */

	lwsl_user("%s: sign/sign-fail-07\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MULTI;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_fail_07, sizeof(sign_fail_07),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_notice("%s: results: %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result)
		goto bail1;

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);


	/*
	 * valid HMAC sign we have key for
	 */

	lwsl_user("%s: hmac-examples/hmac-01\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MAC;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_hmac_01, sizeof(sign_hmac_01),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result) {
		lwsl_err("%s: result is fail\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid HMAC sign we have key for
	 */

	lwsl_user("%s: hmac-examples/hmac-02\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MAC;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_hmac_02, sizeof(sign_hmac_02),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result) {
		lwsl_err("%s: result is fail\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);


	/*
	 * valid HMAC sign we have key for
	 */

	lwsl_user("%s: hmac-examples/hmac-03\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MAC;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_hmac_03, sizeof(sign_hmac_03),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result) {
		lwsl_err("%s: result is fail\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * invalid HMAC sign we have key for
	 */

	lwsl_user("%s: hmac-examples/hmac-04 fail mac tag\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MAC;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_hmac_04, sizeof(sign_hmac_04),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result) {
		lwsl_err("%s: result is wrongly succeeding\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid HMAC sign we have key for HS256/64
	 */

	lwsl_user("%s: hmac-examples/hmac-05\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, keyset1.set, keyset1.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MAC;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, sign_hmac_05, sizeof(sign_hmac_05),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result) {
		lwsl_err("%s: result is fail\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid HMAC sign with implicit HS256 key
	 */

	lwsl_user("%s: hmac-examples/enc-01\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, key3.set, key3.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MAC0;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, enc_hmac_01, sizeof(enc_hmac_01),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result) {
		lwsl_err("%s: result is fail\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid HMAC sign with implicit HS384 key
	 */

	lwsl_user("%s: hmac-examples/enc-02\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, key8.set, key8.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MAC0;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, enc_hmac_02, sizeof(enc_hmac_02),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result) {
		lwsl_err("%s: result is fail\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid HMAC sign with implicit HS512 key
	 */

	lwsl_user("%s: hmac-examples/enc-03\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, key9.set, key9.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MAC0;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, enc_hmac_03, sizeof(enc_hmac_03),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result) {
		lwsl_err("%s: result is fail\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * invalid HMAC sign with implicit HS256 key, tampered hmac tag
	 */

	lwsl_user("%s: hmac-examples/enc-04\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, key3.set, key3.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MAC0;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, enc_hmac_04, sizeof(enc_hmac_04),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (!res->result) {
		lwsl_err("%s: result wrongly succeeds\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	/*
	 * valid HMAC sign with implicit HS256 key, HS256/64
	 */

	lwsl_user("%s: hmac-examples/enc-05\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, key3.set, key3.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_MAC0;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, enc_hmac_05, sizeof(enc_hmac_05),
				    NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result) {
		lwsl_err("%s: result is fail\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);

	if (test_cose_nested_unprotected(context))
		return 1;

	if (test_cose_sign_streamed(context))
		return 1;

#if 0
	/*
	 * valid Ed25519 signature with countersignature from same key + alg
	 */

	lwsl_user("%s: countersign/sign-01\n", __func__);

	lws_dll2_owner_clear(&set);
	if (!lws_cose_key_import(&set, NULL, NULL, key10.set, key10.len)) {
		lwsl_notice("%s: key import fail\n", __func__);
		return 1;
	}

	info.sigtype = SIGTYPE_COUNTERSIGNED;
	cps = lws_cose_validate_create(&info);
	if (!cps) {
		lwsl_notice("%s: sign_val_create fail\n", __func__);
		goto bail;
	}

	n = lws_cose_validate_chunk(cps, countersign_sign_01,
					 sizeof(countersign_sign_01), NULL);
	if (n) {
		lwsl_notice("%s: sign_val_chunk failed\n", __func__);
		goto bail1;
	}

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1) {
		lwsl_err("%s: result count %d\n", __func__, lws_dll2_count(o));
		goto bail1;
	}

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);
	if (res->result) {
		lwsl_err("%s: result is fail\n", __func__);
		goto bail1;
	}

	lws_cose_validate_destroy(&cps);
	lws_cose_key_set_destroy(&set);
#endif

	return 0;

bail1:
	lws_cose_validate_destroy(&cps);
bail:
	lws_cose_key_set_destroy(&set);

	return 1;
}

/*
 * EdDSA end-to-end: F-033 found EdDSA COSE crashed in key checks on both
 * sign and validate, so it had plausibly never worked.  These sign a sign1
 * with EdDSA and validate the result, for both a freshly-generated key and
 * an imported OKP key that arrives with an int curve (cose_key10, kid "11").
 */

static const uint8_t eddsa_payload[] = "This is the content.";

static int
eddsa_sign1(struct lws_context *cx, lws_dll2_owner_t *set,
	    const lws_cose_key_t *ck, uint8_t *out, size_t out_len,
	    size_t *out_total)
{
	lws_cose_sign_create_info_t i;
	struct lws_cose_sign_context *csc;
	lws_lec_pctx_t lec;
	size_t tot = 0;
	enum lws_lec_pctx_ret n = LWS_LECPCTX_RET_FINISHED;

	memset(&i, 0, sizeof(i));
	i.cx			= cx;
	i.keyset		= set;
	i.lec			= &lec;
	i.sigtype		= SIGTYPE_SINGLE;
	i.inline_payload_len	= sizeof(eddsa_payload) - 1;
	i.flags			= LCSC_FL_ADD_CBOR_TAG;

	lws_lec_init(&lec, out, out_len);

	csc = lws_cose_sign_create(&i);
	if (!csc)
		return 1;

	if (lws_cose_sign_add(csc, LWSCOSE_WKAEDDSA_ALG_EDDSA, ck)) {
		lws_cose_sign_destroy(&csc);
		return 1;
	}

	do {
		n = lws_cose_sign_payload_chunk(csc, eddsa_payload,
						 i.inline_payload_len);
		if (n == LWS_LECPCTX_RET_FAIL)
			goto bail;

		if (!lec.used)
			continue;

		tot += lec.used;
		if (tot >= out_len && n == LWS_LECPCTX_RET_AGAIN)
			/* no room left for the rest of it */
			goto bail;

		lws_lec_setbuf(&lec, out + tot, out_len - tot);

	} while (n == LWS_LECPCTX_RET_AGAIN);

	lws_cose_sign_destroy(&csc);

	*out_total = tot;

	return 0;

bail:
	lws_cose_sign_destroy(&csc);

	return 1;
}

/*
 * Validates the sign1 in against keyset... non-zero return means the
 * result was not what want_fail asks for (0: signature must validate,
 * 1: validation of the object must fail)
 */

static int
eddsa_validate(struct lws_context *cx, lws_dll2_owner_t *set,
	       const uint8_t *in, size_t in_len, int want_fail)
{
	lws_cose_validate_create_info_t info;
	struct lws_cose_validate_context *cps;
	lws_cose_validate_res_t *res;
	lws_dll2_owner_t *o;
	int n = 1;

	memset(&info, 0, sizeof(info));
	info.cx		= cx;
	info.keyset	= set;
	info.sigtype	= SIGTYPE_SINGLE;

	cps = lws_cose_validate_create(&info);
	if (!cps)
		return 1;

	if (lws_cose_validate_chunk(cps, in, in_len, NULL))
		goto bail;

	o = lws_cose_validate_results(cps);
	if (lws_dll2_count(o) != 1)
		goto bail;

	res = lws_container_of(lws_dll2_get_head(o), lws_cose_validate_res_t, list);

	/* non-zero result is a validation failure */

	n = res->result ? 1 : 0;
	if (want_fail)
		n = !n;

bail:
	lws_cose_validate_destroy(&cps);

	return n;
}

static int
eddsa_sign1_ok(struct lws_context *cx, lws_dll2_owner_t *set,
	       const lws_cose_key_t *ck)
{
	uint8_t out[512];
	size_t ol;

	if (eddsa_sign1(cx, set, ck, out, sizeof(out), &ol)) {
		lwsl_err("%s: EdDSA sign1 fail\n", __func__);
		return 1;
	}

	/* we need at least the trailing signature byte to tamper with */

	if (!ol || ol > sizeof(out))
		return 1;

	if (eddsa_validate(cx, set, out, ol, 0)) {
		lwsl_err("%s: EdDSA sign1 does not validate\n", __func__);
		return 1;
	}

	/* a tampered trailing signature byte must fail validation */

	out[ol - 1] ^= 0x80;
	if (eddsa_validate(cx, set, out, ol, 1)) {
		lwsl_err("%s: tampered EdDSA sign1 wrongly validated\n",
				__func__);
		return 1;
	}

	return 0;
}

int
test_cose_sign_eddsa(struct lws_context *context)
{
	lws_cose_key_t *ck;
	lws_dll2_owner_t set;
	cose_param_t alg;

	/*
	 * Some TLS backends, eg GnuTLS, do not implement EdDSA at all...
	 * detect it via the public api and skip this part cleanly
	 */

	{
		struct lws_genec_ctx probe;
		memset(&probe, 0, sizeof(probe));

		if (lws_geneddsa_create(&probe, context, NULL)) {
			lwsl_notice("%s: no EdDSA backend support, skipping "
				    "EdDSA sign tests\n", __func__);
			return 0;
		}

		lws_genec_destroy(&probe);
	}

	/* the alg name lookup has to be able to find EdDSA */

	alg = lws_cose_name_to_alg("EdDSA");
	if (alg != LWSCOSE_WKAEDDSA_ALG_EDDSA) {
		lwsl_err("%s: EdDSA alg name lookup fail\n", __func__);
		return 1;
	}

	/*
	 * Sign and validate with a freshly-generated Ed25519 key
	 */

	lwsl_user("%s: eddsa/sign1 generated key\n", __func__);

	ck = lws_cose_key_generate(context, LWSCOSE_WKKTV_OKP,
				   (1 << LWSCOSE_WKKO_SIGN) |
				   (1 << LWSCOSE_WKKO_VERIFY),
				   0, "Ed25519", (const uint8_t *)"ed-keyid", 8);
	if (!ck) {
		lwsl_err("%s: OKP Ed25519 keygen fail\n", __func__);
		return 1;
	}

	lws_dll2_owner_clear(&set);
	lws_dll2_add_tail(&ck->list, &set);

	if (eddsa_sign1_ok(context, &set, ck))
		goto bail;

	lws_cose_key_set_destroy(&set);

	/*
	 * Sign and validate with an imported OKP key using an int curve
	 */

	lwsl_user("%s: eddsa/sign1 imported int-crv key\n", __func__);

	lws_dll2_owner_clear(&set);
	ck = lws_cose_key_import(&set, NULL, NULL, key10.set, key10.len);
	if (!ck) {
		lwsl_err("%s: key10 import fail\n", __func__);
		return 1;
	}

	if (eddsa_sign1_ok(context, &set, ck))
		goto bail;

	lws_cose_key_set_destroy(&set);

	return 0;

bail:
	lws_cose_key_set_destroy(&set);

	lwsl_err("%s: selftest failed ++++++++++++++++++++\n", __func__);

	return 1;
}
