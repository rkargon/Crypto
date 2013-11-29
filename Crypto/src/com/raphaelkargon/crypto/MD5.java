package com.raphaelkargon.crypto;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Implements an md5 hash algorithm.
 * Can be used to check integrity of downloaded files or other data.
 * 
 * @author Raphael Kargon
 * @version 1.0
 */
public class MD5 {
	
	//Initial constants for md5 algorithm
	static int A = 0x67452301;
	static int B = 0xefcdab89;
	static int C = 0x98badcfe;
	static int D = 0x10325476;
	
	//This is defined as decimal parts of absolute value of sines of integers 1 .. 64, multiplied by 2^32 and rounded off.
	static int[] K = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
			0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8,
			0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
			0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51,
			0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
			0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905,
			0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681,
			0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60,
			0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
			0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
			0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
			0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314,
			0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
	
	//define left-rotation amounts for each round
	static int[] S = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17,
			22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11,
			16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21,
			6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };
	
	/**
	 * Implements an MD5 algorithm on a byte array. Other methods convert their parameters to byte[]
	 * and then call this.
	 * 
	 * To pass an empty message, use MD5Hash("") or MD5Hash(new byte[0]).
	 * 
	 * @param msg The byte array of data to be hashed
	 * @return The 16-byte hash result
	 */
	public static byte[] MD5Hash(byte[] msg)
	{
		int bytelength = msg.length;
		long bitlength = bytelength*8; //this is appended to the message as part of padding
		int newlength, paddedlength;
		byte[] paddedmsg;
		
		/* MESSAGE PADDING */
		
		//determines the new length of the message, minus the 64 bits at the end
		for(newlength=bytelength+1; newlength%64 != 56; newlength++);
		paddedlength = newlength+8;
		
		paddedmsg = new byte[paddedlength];
		
		for(int i=0; i<bytelength; i++) paddedmsg[i] = msg[i]; //copy original message
		paddedmsg[bytelength] = -128 ;//append 1  bit to message. In two's-complement format, -128 = 10000000.
		for(int i=bytelength+1; i<newlength; i++) paddedmsg[i]=0;//append 0s to message until bit length is 64 bits short of multiple of 512
		for(int i=0; i<8; i++) paddedmsg[newlength+i]=(byte)(bitlength>>(8*i));//add length of original message to last 64 bits
		
		/* HASHING */

		//final hash values
		int a_f = A, b_f=B, c_f=C, d_f=D;

		//for each block
		for(int i=0; i<paddedlength; i+=64){
			int[] words = new int[16];
			
			//break up 512-bit (64-byte) block into 16 32-bit (4-byte) words, stored as ints 
			for(int j=0; j<64; j+=4) words[j/4] = (int) ((paddedmsg[i+j]&0xFFL) | (paddedmsg[i+j+1]&0xFFL)<<8 | (paddedmsg[i+j+2]&0xFFL)<<16 | (paddedmsg[i+j+3]&0xFFL)<<24);
			
			//initialize tmp hash values, used for operations in each round
			int a = a_f, b=b_f, c=c_f, d=d_f;

			//64 rounds
			for(int k=0; k<64; k++){
				int f, g; //used in left rotation step
				
				if(k<16){
					f = (b & c) | ((~b) & d);
					g=k;
				}
				else if (k<32){
					f = (d & b) | ((~d) & c);
					g = (5*k+1) % 16;
				}
				else if (k<48){
					f = b ^ c ^ d;
					g = (3*k + 5) % 16;
				}
				else{
					f = c ^ (b | (~d));
					g = (7*k) % 16;
				}
				
				//every block gets shifted up, but a is processed first before being sent to b
				int dtmp = d;
				d = c;
				c = b;
				b = b + leftrotate((int)((a & 0xFFFFFFFFL) + (f & 0xFFFFFFFFL) + (K[k] & 0xFFFFFFFFL) + (words[g] & 0xFFFFFFFFL)), S[k]);
				a = dtmp;
			}
			
			//update hash values using current block
			a_f += a;
			b_f += b;
			c_f += c;
			d_f += d;
			
		}
		

		ByteBuffer hashbuffer = ByteBuffer.allocate(16);
		hashbuffer.order(ByteOrder.LITTLE_ENDIAN);
		hashbuffer.putInt(a_f);
		hashbuffer.putInt(b_f);
		hashbuffer.putInt(c_f);
		hashbuffer.putInt(d_f);

		byte[] hash=hashbuffer.array();
		return hash;
	}
	
	/**
	 * calculates the MD5 hash of a string by converting it to a byte array 
	 * and passing it to {@link #MD5Hash(byte[])}.
	 * 
	 * @param msg The String containing the message
	 * @return The MD5 hash of the message
	 */
	public static byte[] MD5Hash(String msg)
	{
		return MD5Hash(msg.getBytes());
	}
	
	/**
	 * Takes an 8-byte <code>long</code> number and calculates its 
	 * MD5 hash by converting it to a byte array.
	 * NOTE: The <code>long</code> passed to this function will always
	 * be considered as 8 bytes, so <code>0L</code> is NOT the same as an
	 * empty message.
	 * 
	 * @param n The <code>long</code> number to be hashed
	 * @return The hash of <code>n</code>
	 */
	public static  byte[] MD5Hash(long n)
	{
		byte[] msg = new byte[8];
		for(int i=0; i<8; i++) {
			msg[i] = (byte) (n>> (8*i));
		}
		return MD5Hash(msg);
	}
	
	/**
	 * Takes an 4-byte <code>int</code> number and calculates its 
	 * MD5 hash by converting it to a byte array.
	 * NOTE: The <code>int</code> passed to this function will always
	 * be considered as 4 bytes, so <code>0</code> is NOT the same as an
	 * empty message.
	 * 
	 * @param n The <code>int</code> number to be hashed
	 * @return The hash of <code>n</code>
	 */
	public static byte[] MD5Hash(int n)
	{
		byte[] msg = new byte[4];
		for(int i=0; i<4; i++){
			msg[i] = (byte)(n >> (8*i));
		}
		return MD5Hash(msg);
	}
	
	/**
	 * Takes an 2-byte <code>short</code> number and calculates its 
	 * MD5 hash by converting it to a byte array.
	 * NOTE: The <code>short</code> passed to this function will always
	 * be considered as 2 bytes, so <code>0</code> is NOT the same as an
	 * empty message.
	 * 
	 * @param n The <code>short</code> number to be hashed
	 * @return The hash of <code>n</code>
	 */
	public static byte[] MD5Hash(short n)
	{
		byte[] msg = new byte[2];
		for(int i=0; i<2; i++){
			msg[i] = (byte)(n >> (8*i));
		}
		return MD5Hash(msg);
	}
	
	/**
	 * Takes byte of data and calculates its MD5 hash. 
	 * 
	 * @param n The <code>byte</code> to be hashed
	 * @return The hash of <code>n</code>
	 */
	public static byte[] MD5Hash(byte n)
	{
		byte[] msg = {n};
		return MD5Hash(msg);
	}
	
	/**
	 * Used during the hash calculation. Takes an integer x and rotates it
	 * to the left a given number of times. 
	 * 
	 * @param x the integer to be rotated
	 * @param shift the amount to rotate the integer (should be <=32).
	 * @return the rotated integer
	 */
	private static int leftrotate(int x, int shift)
	{
		return (x << shift) | (x>>>(32-shift));
	}
	
	/**
	 * Tests the MD5 class with known values. Similar to "md5 -x" in command prompt
	 * 
	 * @param args the filename of the file being hashed
	 */
	public static void main(String[] args) {

		String[] tests={"", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "MD5 has not yet (2001-09-03) been broken, but sufficient attacks have been made that its security is in some doubt", "MD5 has (2013-11-29) been broken and is no longer cryptographically secure"};
		String[] testhashes={"d41d8cd98f00b204e9800998ecf8427e", "0cc175b9c0f1b6a831c399e269772661", "900150983cd24fb0d6963f7d28e17f72", "f96b697d7cb7938d525a2f31aaf161d0", "c3fcd3d76192e4007dfb496cca67e13b", "d174ab98d277d9f5a5611c2c9f419d9f", "57edf4a22be3c955ac49da2e2107b67a", "b50663f41d44d92171cb9976bc118538", "cc933090abb10c1b3e4886b1b10bd6cf"};

		for(int i=0; i<tests.length; i++){
			String hash = byteArrayToHexString(MD5Hash(tests[i]));
			System.out.print("MD5(\""+tests[i]+"\") = "+hash+" -- ");
			System.out.print(hash.equals(testhashes[i]) ? "verified correct!" : "INCORRECT!");
			System.out.println();
		}
		
	}

	/**
	 * Returns the hexademical representation of a byte array,
	 * where each byte is represented as a two-digit unsigned hexadecimal
	 * number. This method is used print the hash, which is stored as a 
	 * byte array.
	 * 
	 * @param arr The byte array to display
	 * @return The hexadecimal string of the byte array
	 */
	public static String byteArrayToHexString(byte[] arr)
	{
		String str="";
		for (int i = 0; i < 16; i++)
			str+=String.format("%02x", arr[i]);
		
		return str;
	}
	
}
