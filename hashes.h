#ifndef HASHES_H
#define HASHES_H

uint64_t alu_true[]= {0x2718fa7f3e1fc5fd, 0xbfb80e0bf97c1433, 0x3b6fa4195439f4ba, 0x442e4c8e19685ada};
uint64_t alu_false[]= {0x7f6536a7dfb677d5, 0x6c256c463b22c393, 0x7ac22cf0b55e8d98, 0xd27d6f40c1927fd4};
uint64_t alu_b0[]= {0x8bfe54c3f0abfdb1, 0xb537edc0f744f968, 0x3b370f0c4fdf1aed, 0xf95b1d6e1ac2c72c};
uint64_t alu_b1[]= {0x154a66766e63fed2, 0xaebe5f6a4c32bdd8, 0x9b667233232f477a, 0x799ebdc89ef862f1};
uint64_t alu_b2[]= {0x8383702a0454c223, 0x12e1e608df7bfa6c, 0x468b250fb953a94b, 0x791f75964e45ccad};
uint64_t alu_b3[]= {0x38b424a22e90cf2f, 0xb24ed4b7f0397e8a, 0x989bf8d7be137a5a, 0x666b3f0dd65faaf1};
uint64_t alu_b4[]= {0x8d9675de3bf82d90, 0xa16a8398c5f0e1b, 0x2272b9c7e721646f, 0x77d14f4f56e00ce3};
uint64_t alu_b5[]= {0x7b0b362346f85efe, 0x710a27f17e9507a8, 0x280fa055224cf218, 0x63a31164dbadc27f};
uint64_t alu_b6[]= {0xa7796964b2e64153, 0x10f3a1073065570e, 0x1a9fdd9bec219416, 0xf15a00de5af74856};
uint64_t alu_b7[]= {0xa7796964b2e64153, 0x10f3a1073065570e, 0x1a9fdd9bec219416, 0xf15a00de5af74856};
uint64_t alu_add8l[]= {0x2e92d8d2e9f2af40, 0x4967698e64d4af47, 0x70a81dbd5f785871, 0x804894bf660211e7};
uint64_t alu_add8h[]= {0xa7796964b2e64153, 0x10f3a1073065570e, 0x1a9fdd9bec219416, 0xf15a00de5af74856};
uint64_t alu_inv8[]= {0xd7687fb71668cd, 0xd6bd424daa3efc01, 0x52cc51313b97b57c, 0xabc6aa3d2ac0ec92};
uint64_t alu_inv16[]= {0x8241bf9512f8dd1c, 0xfc73120fde1eb869, 0x108ee1edf0ab884b, 0x37da1aa01516fe49};
uint64_t alu_clamp32[]= {0xbed6ddd1dcf9f386, 0x979ee753c188a4c1, 0x114b81049a1a82d3, 0xb8bedd623fabfe4c};
uint64_t alu_mul_sum8l[]= {0x2e92d8d2e9f2af40, 0x4967698e64d4af47, 0x70a81dbd5f785871, 0x804894bf660211e7};
uint64_t alu_mul_sum8h[]= {0xa7796964b2e64153, 0x10f3a1073065570e, 0x1a9fdd9bec219416, 0xf15a00de5af74856};
uint64_t alu_mul_shl2[]= {0x33b9babcb963ea50, 0x5803460170cd7faa, 0xd3275e90481f0311, 0x65f2254f9a28b4e9};
uint64_t alu_mul_sums[]= {0xd7bdec7827b3a7fe, 0xcf898ce94119eead, 0xb0bef1f562c7bb96, 0xc5bb6f456ae324be};
uint64_t alu_div_shl1_8_c_d[]= {0xd7bdec7827b3a7fe, 0xcf898ce94119eead, 0xb0bef1f562c7bb96, 0xc5bb6f456ae324be};
uint64_t alu_div_shl1_8_d[]= {0x56788da3b7bcc969, 0xd8b310cd5df1a45e, 0x276d7386418bca5b, 0x9478bb28a3d95675};
uint64_t alu_div_shl2_8_d[]= {0x33b9babcb963ea50, 0x5803460170cd7faa, 0xd3275e90481f0311, 0x65f2254f9a28b4e9};
uint64_t alu_div_shl3_8_d[]= {0x2817522f804bc8d8, 0xf0e426f600d14b7b, 0x21676c7d3af267a2, 0xd9bdc54a035326be};
uint64_t alu_sex8[]= {0xd7bdec7827b3a7fe, 0xcf898ce94119eead, 0xb0bef1f562c7bb96, 0xc5bb6f456ae324be};

uint64_t *hashes[] = {
	alu_true,
	alu_false,
	alu_b0,
	alu_b1,
	alu_b2,
	alu_b3,
	alu_b4,
	alu_b5,
	alu_b6,
	alu_b7,
	alu_add8l,
	alu_add8h,
	alu_inv8,
	alu_inv16,
	alu_clamp32,
	alu_mul_sum8l,
	alu_mul_sum8h,
	alu_mul_shl2,
	alu_mul_sums,
	alu_div_shl1_8_c_d,
	alu_div_shl1_8_d,
	alu_div_shl2_8_d,
	alu_div_shl3_8_d,
	alu_sex8};

#endif
