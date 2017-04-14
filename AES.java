import java.io.*;
import java.util.*;

public class AES
{
	//Used the code provided by https://www.cs.utexas.edu/~byoung/cs361/mixColumns-cheat-sheet
	final static int[] LogTable = {
	0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3, 
	100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193, 
	125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120, 
	101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142, 
	150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56, 
	102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16, 
	126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186, 
	43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87, 
	175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232, 
	44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160, 
	127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183, 
	204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157, 
	151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209, 
	83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171, 
	68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165, 
	103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7};

	//Used the code provided by https://www.cs.utexas.edu/~byoung/cs361/mixColumns-cheat-sheet
	final static int[] AlogTable = {
	1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53, 
	95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170, 
	229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49, 
	83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205, 
	76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136, 
	131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154, 
	181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163, 
	254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160, 
	251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65, 
	195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117, 
	159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 
	155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84, 
	252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202, 
	69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14, 
	18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23, 
	57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1};

	static int[][] sbox = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, 
	                       {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, 
	                       {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
	                       {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, 
	                       {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, 
	                       {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, 
	                       {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, 
	                       {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, 
	                       {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, 
	                       {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, 
	                       {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, 
	                       {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, 
	                       {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, 
	                       {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, 
	                       {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, 
	                       {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

	static int[][] invsbox = {{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb}, 
	                          {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, 
	                          {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e}, 
	                          {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, 
	                          {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92}, 
	                          {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, 
	                          {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06}, 
	                          {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b}, 
	                          {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73}, 
	                          {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e}, 
	                          {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b}, 
	                          {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4}, 
	                          {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, 
	                          {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef}, 
	                          {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, 
	                          {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};





	public static void main(String[] args) throws java.io.IOException
	{
		System.out.println("PROGRAM START");

		//encrypting 
		Scanner sc =null;
		String key =null;
		FileWriter fw = null;
		byte[][] matTxt = new byte[4][4];	//the plaintext -> ciphertext
		byte[][] matKey = new byte[4][4];	//the key that will be altered
		File f = new File(args[2].replace(".txt",".enc"));
		try
		{ 
			fw  = new FileWriter(f); 
	    	sc  = new Scanner(new File(args[1]));
			key = sc.nextLine();
			sc  = new Scanner(new File(args[2]));
		}
		catch(Exception e){System.out.println("initial scanner fail");}
		String[][] mat = new String[4][4];
		while(sc.hasNextLine())
		{
			String s = padString(sc.nextLine());
			s = s.substring(0,32);
			//System.out.println(s);
			mat = AESencrypt(s,key);
			s = print_as_string(mat);
			fw.write(s);
		}
		fw.close();
		printMat(mat);

		System.out.println("PROGRAM END");
	}
	public static String[][] createMat(String s)
	{
		String[][] mat = new String[4][4];
		String temp = s;
		for(int i= 0;i<4;++i)
		{
			for(int j = 0; j<4;++j)
			{
				mat[j][i] = temp.substring(0,2);
				temp = temp.substring(2);
				//System.out.println(temp);
			}
		}
		return mat;
	}

	public static StringBuilder toBinary(String s)
	{
		byte[] bytes = s.getBytes();
		StringBuilder binary = new StringBuilder();
		for (byte b : bytes)
  		{
     		int val = b;
     		for (int i = 0; i < 8; i++)
     		{
        		binary.append((val & 128) == 0 ? 0 : 1);
        		val <<= 1;
     		}
  		}
  		return binary;
	}

	public static String[][] AESencrypt(String s, String key)
	{
		//System.out.println("START AESencrypt filler");
		String[][] text = new String[4][4];
		String[][] roundkey = new String[4][4];
		String ret = "String to encrypt: "+s+" \nKey used: "+key+"\n\n";
		int rc = 0;		//count the number of rounds
		Scanner sc=null;
		keyExpansion(key);
		try
		{sc = new Scanner(new File("expandedKey.txt"));}
		catch(Exception e){}
		text = createMat(s);
		//print_as_string(text);
		roundkey = createMat(sc.nextLine());
		//print_as_string(text);
		//System.out.println();
		//printMat(roundkey);
		//initial round
		RoundKeyDemo(text,roundkey);
		roundkey = createMat(sc.nextLine());
		//actual round
		for(int i=1;i<=13;++i)
		{
			subByteDemo(text);
			//print_as_string(text);
			RowShiftDemo(text);
			//print_as_string(text);
			for(int j=0;j<4;++j)
			{
				mixColumn(text,j);
			}
			//print_as_string(text);
			RoundKeyDemo(text,roundkey);
			//print_as_string(text);
			roundkey = createMat(sc.nextLine());
			//System.out.println();
		}
		//final round
		subByteDemo(text);
		RowShiftDemo(text);
		RoundKeyDemo(text,roundkey);

		//System.out.println("END AESencrypt filler");
		return text;
	}

	public static String padString(String s)
	{
		while(s.length()<32)
		{
			s=s+"0";
		}
		return s;
	}

	//Used the code provided by https://www.cs.utexas.edu/~byoung/cs361/mixColumns-cheat-sheet
	private static byte mul (int a, byte b) 
	{
		int inda = (a < 0) ? (a + 256) : a;
		int indb = (b < 0) ? (b + 256) : b;

		if ( (a != 0) && (b != 0) ) 
		{
	    	int index = (LogTable[inda] + LogTable[indb]);
	    	byte val = (byte)(AlogTable[ index % 255 ] );
	    	return val;
		}
		else 
	    	return 0;
	}

	private static int mul2 (int a, int b) 
	{
		int inda = (a < 0) ? (a + 256) : a;
		int indb = (b < 0) ? (b + 256) : b;

		if ( (a != 0) && (b != 0) ) 
		{
	    	int index = (LogTable[inda] + LogTable[indb]);
	    	int val = (AlogTable[ index % 255 ] );
	    	return val;
		}
		else 
	    	return 0;
	}

	//Used the code provided by https://www.cs.utexas.edu/~byoung/cs361/mixColumns-cheat-sheet
	// In the following two methods, the input c is the column number in
    // your evolving state matrix st (which originally contained 
    // the plaintext input but is being modified).  Notice that the state here is defined as an
    // array of bytes.  If your state is an array of integers, you'll have
    // to make adjustments. 
	public static void mixColumn2 (byte[][] st, int c) 
	{
	
		byte a[] = new byte[4];
	
		for (int i = 0; i < 4; i++) 
	    	a[i] = st[i][c];
	
		// This is exactly the same as mixColumns1, if 
		// the mul columns somehow match the b columns there.
		st[0][c] = (byte)(mul(2,a[0]) ^ a[2] ^ a[3] ^ mul(3,a[1]));
		st[1][c] = (byte)(mul(2,a[1]) ^ a[3] ^ a[0] ^ mul(3,a[2]));
		st[2][c] = (byte)(mul(2,a[2]) ^ a[0] ^ a[1] ^ mul(3,a[3]));
		st[3][c] = (byte)(mul(2,a[3]) ^ a[1] ^ a[2] ^ mul(3,a[0]));
    }


    public static void mixColumn (String[][] st, int c) 
	{
	
		int a[] = new int[4];
	
		for (int i = 0; i < 4; i++) 
	    	a[i] = Integer.parseInt(st[i][c],16);
	
		// This is exactly the same as mixColumns1, if 
		// the mul columns somehow match the b columns there.
		st[0][c] = zerofiller(Integer.toHexString((mul2(2,a[0]) ^ a[2] ^ a[3] ^ mul2(3,a[1]))));
		st[1][c] = zerofiller(Integer.toHexString((mul2(2,a[1]) ^ a[3] ^ a[0] ^ mul2(3,a[2]))));
		st[2][c] = zerofiller(Integer.toHexString((mul2(2,a[2]) ^ a[0] ^ a[1] ^ mul2(3,a[3]))));
		st[3][c] = zerofiller(Integer.toHexString((mul2(2,a[3]) ^ a[1] ^ a[2] ^ mul2(3,a[0]))));
    }

    public static String zerofiller(String s)
    {
    	if(s.length()==1)
    		s="0"+s;
    	return s;
    }

    //Used the code provided by https://www.cs.utexas.edu/~byoung/cs361/mixColumns-cheat-sheet
    public void invMixColumn2 (byte[][] st, int c) 
    {
		byte a[] = new byte[4];
	
		for (int i = 0; i < 4; i++) 
		    a[i] = st[i][c];
		
		st[0][c] = (byte)(mul(0xE,a[0]) ^ mul(0xB,a[1]) ^ mul(0xD, a[2]) ^ mul(0x9,a[3]));
		st[1][c] = (byte)(mul(0xE,a[1]) ^ mul(0xB,a[2]) ^ mul(0xD, a[3]) ^ mul(0x9,a[0]));
		st[2][c] = (byte)(mul(0xE,a[2]) ^ mul(0xB,a[3]) ^ mul(0xD, a[0]) ^ mul(0x9,a[1]));
		st[3][c] = (byte)(mul(0xE,a[3]) ^ mul(0xB,a[0]) ^ mul(0xD, a[1]) ^ mul(0x9,a[2]));
    } 

    public static void printMat(String[][] mat)
    {
    	for(int i= 0;i<4;++i)
		{
			for(int j = 0; j<mat[i].length;++j)
			{
				System.out.print(mat[i][j]+" ");
			}
			System.out.println();
		}
		System.out.println();
    }

 	public static void RoundKeyDemo(String[][] t,String[][] k)
 	{
 		for(int i=0;i<4;++i)
 		{
 			for(int j=0;j<4;++j)
 			{
 				t[j][i] = XORstring(t[j][i],k[j][i]);
 			}
 		}
 	}

 	public static void RowShiftDemo(String[][] t)
 	{
 		for(int i=0;i<4;++i)
 		{
 			shiftRow(t[i],i);
 		}
 	}

 	public static String XORstring(String s1, String s2)
 	{
 		String ret = "";
 		String[] nybble = new String[4];
 		nybble[0] = ""+s1.charAt(0);
 		nybble[1] = ""+s1.charAt(1);
 		nybble[2] = ""+s2.charAt(0);
 		nybble[3] = ""+s2.charAt(1);

 		String temp1 = Integer.toHexString(Integer.parseInt(nybble[0],16) ^ Integer.parseInt(nybble[2],16));
 		String temp2 = Integer.toHexString(Integer.parseInt(nybble[1],16) ^ Integer.parseInt(nybble[3],16));
 		ret=temp1+temp2;
 		return ret;
 	}

 	public static void shiftRow(String [] s, int n)
 	{
 		String temp = "";
 		for(int i=0;i<n;++i)
 		{
 			temp = s[0];
 			for(int j=1;j<4;++j)
 			{
 				s[j-1] = s[j];
 			}
 			s[3] = temp;
 		}
 	}

 	public static void subByteDemo(String[][] mat)
 	{
 		for(int i = 0;i<4;++i)
 		{
 			for(int j = 0;j<4;++j)
 			{
				mat[i][j] = subByte(mat[i][j]);
 			}
 		}
 	}

 	public static String subByte(String s)
 	{
 		//System.out.println(s);
 		String[] nybble = new String[2];
 		nybble[0] = ""+s.charAt(0);
 		nybble[1] = ""+s.charAt(1);
 		int x = Integer.parseInt(nybble[0],16);
 		int y = Integer.parseInt(nybble[1],16);
 		String stemp = zerofiller(Integer.toHexString(sbox[x][y]));
 		return stemp;
 	}

 	public static void keyExpansion(String key)
 	{
 		//the key comes in as a 64 character string
 		File f = new File("expandedKey.txt");
 		String temp = key;
 		FileWriter fw = null;
 		try
 		{
 			fw = new FileWriter(f);
 		}
 		catch(Exception e){}
 		String[] _key = new String[240];
 		int count = 0;
 		while(temp.length()>0)
 		{
 			_key[count] = temp.substring(0,2);
			temp = temp.substring(2);
			count++;
 		}
 		expand_key(_key);
 		try
 		{
 			for(int i=0;i<_key.length;++i)
 			{
 				if(i%16==0 && i!=0)
 				{
 					fw.write("\n");
 				}
 				fw.write(_key[i]);
 			}
 			fw.close();
 		}
 		catch(Exception e){}

 		
 	}

 	public static int rcon(int in)
 	{
 		int c = 1;
 		if(in==0)
 			return 0;
 		while(in != 1)
 		{
 			int b;
 			b = c & 0x80;
 			c <<= 1;
 			if(b == 0x80)
 				c ^=0x1b;
 			in--;
 		}
 		return c;
 	}

 	public static void rotate(String[] in)
 	{
 		String x;
 		x = in[0];
 		for(int i = 0;i< 3;i++)
 		{
 			in[i] = in[i+1];
 		}
 		in[3]=x;
 	}

 	public static void schedule_core(String[] in, int c)
 	{
 		rotate(in);
 		for(int i=0;i<4;++i)
 		{
 			in[i] = subByte(in[i]);
 		}
 		in[0] = zerofiller(Integer.toHexString(Integer.parseInt(in[0],16)^rcon(c)));
 	}

 	public static void expand_key(String in[])
 	{
 		String[] t = new String[4];
 		int c = 32;
 		int _i = 1;
 		while(c<240)
 		{
 			for(int i=0;i<4;++i)
 			{
 				t[i] = in[i+c-4];
 			}
 			if(c%32==0)
 			{
 				schedule_core(t,_i);
 				_i++;
 			}
 			if(c%32==16)
 			{
 				for(int i=0;i<4;++i)
 				{
 					t[i] = subByte(t[i]);
 				}
 			}
 			for(int i=0;i<4;++i)
 			{
 				in[c] = zerofiller(Integer.toHexString(Integer.parseInt(in[c-32],16) ^ Integer.parseInt(t[i],16)));
 				c++;
 			}
 		}
 	}

 	public static String print_as_string(String[][] s)
 	{
 		String ret = "";
 		for(int i=0;i<4;i++)
 		{
 			for(int j=0;j<4;++j)
 			{
 				ret=ret+s[j][i];
 			}
 		}
 		return ret;
 	}


/*AES Model
Initial Round
	XOR with the CipherKey
Main Rounds
	1) subBytes
		taken from a lookup table
		_ _ _ _   _ _ _ _
		  0-f       0-f
	2) ShiftRows
		row 0 shifts 0
		row 1 shifts 1
		row 2 shifts 2
		row 3 shifts 3
	3) MixColumns
		taken care of for me
	4) AddRoundKey
		XOR with the key for that round
FinalRound
	1) subBytes
	2) ShiftRows
	3) AddRoundKey

Key Schedule

Expanded Key
	an array of 32 bit words numberd from 0-43
	first four columns are filled with a given cipher key
	words in position that are a multiple of 4 are calculated
		a) apply the RotWord and SubByte trans to the previous word
		   rotWord is column major
		b) XOR with the word that 4 positions back plus a constant Rcon
	The rest of the words of that 4x4 block are made by XOR the previous 
	word with the word 4 position back

*/
}






























