//! This crate inplements the ntlm hash in pure rust
//!
//! # Usage :
//! ```rust
//!use ntlm_hash::*
//!println!("{}", ntlm_hash("some_string"))
//! ```
//! # Limitation :
//! 	This crate hashes only strings of less than

// this implementation is just a translated version of the one available here : https://openwall.info/wiki/john/NTLM

// a comment that I left out from the original c inplementation :
/* 
Written by Alain Espinosa <alainesp@gmail.com> in 2008
and placed in the public domain.
 
Notes:
- the mayor length of the key its 27 character. This is a restriction of this
implementation and its very simple to bypass.
*/
 


//Init values
const INIT_A: u32 = 0x67452301;
const INIT_B: u32 = 0xefcdab89;
const INIT_C: u32 = 0x98badcfe;
const INIT_D: u32 = 0x10325476;
 
const SQRT_2: u32 = 0x5a827999;
const SQRT_3: u32 = 0x6ed9eba1;
 
const ITOA16: [char; 16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

/// The main function of this crate : the raw hash function
pub fn ntlm_crypt(nt_buffer: [u32; 16]) -> [u32; 4]
{
	let mut a = INIT_A;
	let mut b = INIT_B;
	let mut c = INIT_C;
	let mut d = INIT_D;
 
	/* Round 1 */
	a = a.wrapping_add(d ^ (b & (c ^ d))).wrapping_add(nt_buffer[0]);a = (a << 3 ) | (a >> 29);
	d = d.wrapping_add(c ^ (a & (b ^ c))).wrapping_add(nt_buffer[1]);d = (d << 7 ) | (d >> 25);
	c = c.wrapping_add(b ^ (d & (a ^ b))).wrapping_add(nt_buffer[2]);c = (c << 11) | (c >> 21);
	b = b.wrapping_add(a ^ (c & (d ^ a))).wrapping_add(nt_buffer[3]);b = (b << 19) | (b >> 13);
 
	a = a.wrapping_add(d ^ (b & (c ^ d))).wrapping_add(nt_buffer[4]);a = (a << 3 ) | (a >> 29);
	d = d.wrapping_add(c ^ (a & (b ^ c))).wrapping_add(nt_buffer[5]);d = (d << 7 ) | (d >> 25);
	c = c.wrapping_add(b ^ (d & (a ^ b))).wrapping_add(nt_buffer[6]);c = (c << 11) | (c >> 21);
	b = b.wrapping_add(a ^ (c & (d ^ a))).wrapping_add(nt_buffer[7]);b = (b << 19) | (b >> 13);

	a = a.wrapping_add(d ^ (b & (c ^ d))).wrapping_add(nt_buffer[8]);a = (a << 3 ) | (a >> 29);
	d = d.wrapping_add(c ^ (a & (b ^ c))).wrapping_add(nt_buffer[9]);d = (d << 7 ) | (d >> 25);
	c = c.wrapping_add(b ^ (d & (a ^ b))).wrapping_add(nt_buffer[10]);c = (c << 11) | (c >> 21);
	b = b.wrapping_add(a ^ (c & (d ^ a))).wrapping_add(nt_buffer[11]);b = (b << 19) | (b >> 13);
 
	a = a.wrapping_add(d ^ (b & (c ^ d))).wrapping_add(nt_buffer[12]);a = (a << 3 ) | (a >> 29);
	d = d.wrapping_add(c ^ (a & (b ^ c))).wrapping_add(nt_buffer[13]);d = (d << 7 ) | (d >> 25);
	c = c.wrapping_add(b ^ (d & (a ^ b))).wrapping_add(nt_buffer[14]);c = (c << 11) | (c >> 21);
	b = b.wrapping_add(a ^ (c & (d ^ a))).wrapping_add(nt_buffer[15]);b = (b << 19) | (b >> 13);
 

	/* Round 2 */
	a = a.wrapping_add((b & (c | d)) | (c & d)).wrapping_add(nt_buffer[0]).wrapping_add(SQRT_2); a = (a<<3 ) | (a>>29);
	d = d.wrapping_add((a & (b | c)) | (b & c)).wrapping_add(nt_buffer[4]).wrapping_add(SQRT_2); d = (d<<5 ) | (d>>27);
	c = c.wrapping_add((d & (a | b)) | (a & b)).wrapping_add(nt_buffer[8]).wrapping_add(SQRT_2); c = (c<<9 ) | (c>>23);
	b = b.wrapping_add((c & (d | a)) | (d & a)).wrapping_add(nt_buffer[12]).wrapping_add(SQRT_2); b = (b<<13) | (b>>19);
 
	a = a.wrapping_add((b & (c | d)) | (c & d)).wrapping_add(nt_buffer[1]).wrapping_add(SQRT_2); a = (a<<3 ) | (a>>29);
	d = d.wrapping_add((a & (b | c)) | (b & c)).wrapping_add(nt_buffer[5]).wrapping_add(SQRT_2); d = (d<<5 ) | (d>>27);
	c = c.wrapping_add((d & (a | b)) | (a & b)).wrapping_add(nt_buffer[9]).wrapping_add(SQRT_2); c = (c<<9 ) | (c>>23);
	b = b.wrapping_add((c & (d | a)) | (d & a)).wrapping_add(nt_buffer[13]).wrapping_add(SQRT_2); b = (b<<13) | (b>>19);
    
	a = a.wrapping_add((b & (c | d)) | (c & d)).wrapping_add(nt_buffer[2]).wrapping_add(SQRT_2); a = (a<<3 ) | (a>>29);
	d = d.wrapping_add((a & (b | c)) | (b & c)).wrapping_add(nt_buffer[6]).wrapping_add(SQRT_2); d = (d<<5 ) | (d>>27);
	c = c.wrapping_add((d & (a | b)) | (a & b)).wrapping_add(nt_buffer[10]).wrapping_add(SQRT_2); c = (c<<9 ) | (c>>23);
	b = b.wrapping_add((c & (d | a)) | (d & a)).wrapping_add(nt_buffer[14]).wrapping_add(SQRT_2); b = (b<<13) | (b>>19);
 
	a = a.wrapping_add((b & (c | d)) | (c & d)).wrapping_add(nt_buffer[3]).wrapping_add(SQRT_2); a = (a<<3 ) | (a>>29);
	d = d.wrapping_add((a & (b | c)) | (b & c)).wrapping_add(nt_buffer[7]).wrapping_add(SQRT_2); d = (d<<5 ) | (d>>27);
	c = c.wrapping_add((d & (a | b)) | (a & b)).wrapping_add(nt_buffer[11]).wrapping_add(SQRT_2); c = (c<<9 ) | (c>>23);
	b = b.wrapping_add((c & (d | a)) | (d & a)).wrapping_add(nt_buffer[15]).wrapping_add(SQRT_2); b = (b<<13) | (b>>19);
 

	/* Round 3 */
	a = a.wrapping_add(d ^ c ^ b).wrapping_add(nt_buffer[0]).wrapping_add(SQRT_3); a = (a << 3 ) | (a >> 29);
	d = d.wrapping_add(c ^ b ^ a).wrapping_add(nt_buffer[8]).wrapping_add(SQRT_3); d = (d << 9 ) | (d >> 23);
	c = c.wrapping_add(b ^ a ^ d).wrapping_add(nt_buffer[4]).wrapping_add(SQRT_3); c = (c << 11) | (c >> 21);
	b = b.wrapping_add(a ^ d ^ c).wrapping_add(nt_buffer[12]).wrapping_add(SQRT_3); b = (b << 15) | (b >> 17);
 
	a = a.wrapping_add(d ^ c ^ b).wrapping_add(nt_buffer[2]).wrapping_add(SQRT_3); a = (a << 3 ) | (a >> 29);
	d = d.wrapping_add(c ^ b ^ a).wrapping_add(nt_buffer[10]).wrapping_add(SQRT_3); d = (d << 9 ) | (d >> 23);
	c = c.wrapping_add(b ^ a ^ d).wrapping_add(nt_buffer[6]).wrapping_add(SQRT_3); c = (c << 11) | (c >> 21);
	b = b.wrapping_add(a ^ d ^ c).wrapping_add(nt_buffer[14]).wrapping_add(SQRT_3); b = (b << 15) | (b >> 17);
 
	a = a.wrapping_add(d ^ c ^ b).wrapping_add(nt_buffer[1]).wrapping_add(SQRT_3); a = (a << 3 ) | (a >> 29);
	d = d.wrapping_add(c ^ b ^ a).wrapping_add(nt_buffer[9]).wrapping_add(SQRT_3); d = (d << 9 ) | (d >> 23);
	c = c.wrapping_add(b ^ a ^ d).wrapping_add(nt_buffer[5]).wrapping_add(SQRT_3); c = (c << 11) | (c >> 21);
	b = b.wrapping_add(a ^ d ^ c).wrapping_add(nt_buffer[13]).wrapping_add(SQRT_3); b = (b << 15) | (b >> 17);
 
	a = a.wrapping_add(d ^ c ^ b).wrapping_add(nt_buffer[3]).wrapping_add(SQRT_3); a = (a << 3 ) | (a >> 29);
	d = d.wrapping_add(c ^ b ^ a).wrapping_add(nt_buffer[11]).wrapping_add(SQRT_3); d = (d << 9 ) | (d >> 23);
	c = c.wrapping_add(b ^ a ^ d).wrapping_add(nt_buffer[7]).wrapping_add(SQRT_3); c = (c << 11) | (c >> 21);
	b = b.wrapping_add(a ^ d ^ c).wrapping_add(nt_buffer[15]).wrapping_add(SQRT_3); b = (b << 15) | (b >> 17);
    
    [a.wrapping_add(INIT_A), b.wrapping_add(INIT_B), c.wrapping_add(INIT_C), d.wrapping_add(INIT_D)]
}	
 
/// This function takes care of the Unicode conversion and the padding
/// it takes an array of bytes as input so do `str.as_bytes()` to use the function on a &str
pub fn prepare_key(key: &[u8]) -> [u32; 16]
{
    let mut nt_buffer = [0u32; 16];
	let length = key.len() as u32;
	for i in 0..16 {
        nt_buffer[i] = 0;
    }
	//The length of key need to be <= 27
	for i in 0usize..(length/2) as usize {
	    nt_buffer[i] = key[2*i] as u32 | ((key[2*i+1] as u32) << 16);
    }
	
	let i = (length/2) as usize;
	//padding
	if length % 2 == 1 {
		nt_buffer[i] = key[(length-1) as usize] as u32 | 0x800000;
    }
	else {
		nt_buffer[i]=0x80;
    }
	//put the length
	nt_buffer[14] = length << 4;
    nt_buffer
}
 
/// This function converts the output of `ntlm_crypt` to hexadecimal form
pub fn convert_hex(output: &mut [u32; 4]) -> String
{
    let mut hex_format: [char; 32] = [' '; 32];
	//Iterate the integer
	for i in 0..4
	{
		let mut n: u32 = output[i];
		//iterate the bytes of the integer		
		for j in 0..4
		{
			let mut convert = n % 256;
			hex_format[i*8+j*2+1] = ITOA16[(convert%16) as usize];
			convert = convert/16;
			hex_format[i*8+j*2+0] = ITOA16[(convert%16) as usize];
			n /= 256;
		}	
	}
	let mut out = String::new();
	hex_format.iter().for_each(|&c| out.push(c));
	out
}

/// This function takes a string and output a hex of the ntlm hash
pub fn ntlm_hash(s: &str) -> String {
	convert_hex(&mut ntlm_crypt(prepare_key(s.as_bytes())))
}

#[test]
fn limit() {
	println!("{}", ntlm_hash("0123456789012345678901234567890"));
}