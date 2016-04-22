/*
@title: AES.cpp
@authors: Sarah Bartholomew, Spencer MacMaster, &  Ryan Zerbe
*/

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <string>
#include <cstdlib>
#include <ctime>

using namespace std;

typedef unsigned char byte;

//macro functions used in AES 
//source of xtime and Multiply macro functions: comp.ist.utl.pt/ec-csc/Code/Ciphers/AES_Encrypt.cpp

// xtime is a macro that finds the product of {02} and the argument to xtime modulo {1b}  
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))
// Multiplty is a macro used to multiply numbers in the field GF(2^8) 
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))

//Variables used in AES
const int Nb = 4; //Number of columns (32-bit words) comprising the State. From the AES standard, Nb = 4.
int Nk = 4; //Number of 32-bit words comprising the Cipher Key. From the AES standard, Nk = 4, 6, or 8.
int Nr = 10; //Number of rounds, which is a function of Nk and Nb(which is fixed). From the AES standard, Nr = 10, 12, or 14.

bool padded = false;
int l = 0;

//Various arrays used in AES
byte in[16];		//plaintext array to be encrypted
byte out[16];		//encryption key array
byte state[4][4];	//state array used in encryption
byte RoundKey[240]; //Array that stores the round key
byte K[32];			//Cipher Key

//Round Constant Word Array
int Rcon[255] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };

int getSBoxValue(int num1, int num2){
	int sbox[16][16] = {
		{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },  
		{ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },   
		{ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },   
		{ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },   
		{ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },   
		{ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },   
		{ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },   
		{ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },   
		{ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },   
		{ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },   
		{ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },   
		{ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },   
		{ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },   
		{ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },   
		{ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },	  
		{ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 } }; 
	return sbox[num1][num2];
}

int getSBoxInvert(int num1, int num2){
	int rsbox[16][16] = { 
		{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
		{ 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
		{ 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
		{ 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
		{ 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
		{ 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
		{ 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
		{ 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
		{ 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
		{ 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
		{ 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
		{ 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
		{ 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
		{ 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
		{ 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
		{ 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d } };
	return rsbox[num1][num2];
}

//forward declartions

//base functions
void main();
void PickKeyLength();
string encrpyt(string, string);	
string decrypt(string, string);	
string addPad(string);
string getPadChar();
string removePad(string);
string genKey();
void ctrKey(int);

//TESTER FUNCTIONS TODO REMOVE BEFORE SUBMISSION
void print();
void fill();
void test_ShiftRowFunctions();
void test_MixColumnsFunctions();
void test_SubBytesFunctions();
void test_RotWordFunctions();
void test_CipherFunctions();
void test_EncryptFunctions();
//END TESTER FUNCTIONS

//AES Functions
void KeyExpansion();

void AddRoundKey(int round);
void SubBytes();
void ShiftRows();
void MixColumns();
void RotWord(byte[4]);	
void SubWord(byte[4]);	
void InvMixColumns();
void InvShiftRows();
void InvSubBytes();	

void Cipher();	
void InvCipher();

//Updates the roundkey
void KeyExpansion(){
	int i, j;
	byte word[4], k;

	// The first round key is the key itself.
	for (i = 0; i<Nk; i++)
	{
		RoundKey[i * 4] = K[i * 4];
		RoundKey[i * 4 + 1] = K[i * 4 + 1];
		RoundKey[i * 4 + 2] = K[i * 4 + 2];
		RoundKey[i * 4 + 3] = K[i * 4 + 3];
	}

	// All other round keys are found from the previous round keys.
	while (i < (Nb * (Nr + 1)))
	{
		for (j = 0; j<4; j++) { word[j] = RoundKey[(i - 1) * 4 + j]; }
		if (i % Nk == 0) {
			RotWord(word);	SubWord(word);
			word[0] = word[0] ^ Rcon[i / Nk];
		}
		else if (Nk > 6 && i % Nk == 4){ SubWord(word); }

		RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ word[0];
		RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ word[1];
		RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ word[2];
		RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ word[3];
		i += 1;
	}

}

//Xors the round key to the state
void AddRoundKey(int round){
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j]; //^= applies the xor operation to the state
		}
	}
}

//modifies the state array by the values in sbox
void SubBytes(){
	int num1 = 0, num2 = 0;
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			num1 = (state[j][i] >> 4) & 0x0f; //state[j][i] = 0xXY num1 = X, num2 = Y;
			num2 = state[j][i] & 0x0f;
			state[j][i] = getSBoxValue(num1,num2);
		}
	}
}

//rotates word [0][1][2][3] -->[1][2][3][0]
void RotWord(byte word[4]){
	byte temp;
	temp = word[0];
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = temp;
}

//applies Sbox to a word
void SubWord(byte word[4]){
	int num1=0, num2=0;
	for (int i = 0; i < 4; i++){
		num1 = (word[i] >> 4) & 0x0f; //word[i] = 0xXY num1 = X, num2 = Y;
		num2 = word[i] & 0x0f;
		word[i] = getSBoxValue(num1,num2);
	}
}

//Shifts the values in state to the left
void ShiftRows()
{
	byte temp;

	// Shift first row 1 to left	
	temp = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp;

	// Shift second row 2 to left	
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;

	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	// Shift third row 3 to left
	temp = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = temp;
}

//MixColumns function mixes the columns of the state matrix
void MixColumns()
{
	byte Tmp, Tm, t;
	for (int i = 0; i<4; i++)
	{
		t = state[0][i];
		Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
		Tm = state[0][i] ^ state[1][i]; Tm = xtime(Tm); state[0][i] ^= Tm ^ Tmp;
		Tm = state[1][i] ^ state[2][i]; Tm = xtime(Tm); state[1][i] ^= Tm ^ Tmp;
		Tm = state[2][i] ^ state[3][i]; Tm = xtime(Tm); state[2][i] ^= Tm ^ Tmp;
		Tm = state[3][i] ^ t;			Tm = xtime(Tm); state[3][i] ^= Tm ^ Tmp;
	}
}

//Undoes the MixColumns Operation
void InvMixColumns(){
	byte a, b, c, d;
	for (int i = 0; i<4; i++) {
		a = state[0][i];
		b = state[1][i];
		c = state[2][i];
		d = state[3][i];

		state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

//Undoes the ShiftRows Operation
void InvShiftRows(){
	byte temp;

	//shift first row 1 to right	
	temp = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = temp;

	//shift second row 2 to right	
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;

	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	// shift third row 3 to Right
	temp = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = temp;
}

//Undoes the SubBytes Operation
void InvSubBytes(){
	int num1 = 0, num2 = 0;
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			num1 = (state[j][i] >> 4) & 0x0f; //state[j][i] = 0xXY num1 = X, num2 = Y;
			num2 = state[j][i] & 0x0f;
			state[j][i] = getSBoxInvert(num1, num2);
		}
	}
}

void Cipher(){
	//state = in
	for (int i = 0; i < 4; i++){
		state[i][0] = in[4 * i + 0];
		state[i][1] = in[4 * i + 1];
		state[i][2] = in[4 * i + 2];
		state[i][3] = in[4 * i + 3];
	}

	int round = 0;
	AddRoundKey(round);

	for (round = 1; round < Nr - 1; round++){
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(round);
	}

	SubBytes();
	ShiftRows();
	AddRoundKey(round);

	//out = state
	for (int i = 0; i < 4; i++){
		out[4 * i + 0] = state[i][0];
		out[4 * i + 1] = state[i][1];
		out[4 * i + 2] = state[i][2];
		out[4 * i + 3] = state[i][3];
	}
}

void InvCipher(){
	//state = in
	for (int i = 0; i < 4; i++){
		state[i][0] = in[4 * i + 0];
		state[i][1] = in[4 * i + 1];
		state[i][2] = in[4 * i + 2];
		state[i][3] = in[4 * i + 3];
	}
	int round = 0;
	AddRoundKey(round);

	for (round = 1; round < Nr - 1; round++){
		InvShiftRows();
		InvSubBytes();
		AddRoundKey(round);
		InvMixColumns();
	}

	InvShiftRows();
	InvSubBytes();
	AddRoundKey(round);

	//out = state
	for (int i = 0; i < 4; i++){
		out[4 * i + 0] = state[i][0];
		out[4 * i + 1] = state[i][1];
		out[4 * i + 2] = state[i][2];
		out[4 * i + 3] = state[i][3];
	}
}

//----------------------------------------EXECUTION-------------------------------------------//

//Function to determine the keylength used 128, 192 or 256 bits
void PickKeyLength(){
	// Recieve the length of key here.
	cout << "Select Keylength(1=128, 2=192, 3=256): ";
	cin >> Nr;
	switch (Nr){
	case 1:
		cout << "128 bit key selected." << endl;
		Nr = 128;
		break;
	case 2:
		cout << "192 bit key selected." << endl;
		Nr = 192;
		break;
	case 3:
		cout << "256 bit key selected." << endl;
		Nr = 256;
		break;
	default:
		cout << "<ERROR INVALID INPUT: " << Nr << " >" << endl << "Defaulting to 128 bit key." << endl;
		Nr = 128;
		break;
	}

	// Calculate Nk and Nr from the recieved value.
	Nk = Nr / 32;
	Nr = Nk + 6;
}

//applies a type of CTR AES cipher to the ciphertext
string encrpyt(string plntxt, string key){
	plntxt = addPad(plntxt);
	string a = "                ", b = "";

	for (int i = 0; i < 32; i++){ K[i] = key.at(i); }

	for (int i = 0; i < plntxt.length() / 16; i++){
		ctrKey(i);
		for (int j = 0; j < 16; j++){ in[j] = plntxt.at(16 * i + j); }
		Cipher();
		for (int j = 0; j < 16; j++){ a[j] = out[j]; }
		b.append(a);
	}

	return b;
}

//applies a type of CTR AES cipher to the ciphertext
string decrypt(string ciphtxt, string key){
	string a = "                ", b = "";
	for (int i = 0; i < ciphtxt.length() / 16; i++){
		ctrKey(i);
		for (int j = 0; j < 16; j++){ in[j] = ciphtxt.at(16 * i + j); }
		InvCipher();
		for (int j = 0; j < 16; j++){ a[j] = out[j]; }
		b.append(a);
	}
	b = removePad(b);
	return b;
}

//return the char that was used in the pad
string getPadChar(){
	string s = "";
	if (l == 1){ s = "!"; }
	else if (l == 2){ s = "\""; }
	else if (l == 3){ s = "#"; }
	else if (l == 4){ s = "$"; }
	else if (l == 5){ s = "%"; }
	else if (l == 6){ s = "&"; }
	else if (l == 7){ s = "\'"; }
	else if (l == 8){ s = "("; }
	else if (l == 9){ s = ")"; }
	else if (l == 10){ s = "*"; }
	else if (l == 11){ s = "+"; }
	else if (l == 12){ s = ","; }
	else if (l == 13){ s = "-"; }
	else if (l == 14){ s = "."; }
	else if (l == 15){ s = "/"; }
	return s;
}

//appends a pad char(s) to the end of the string to make it div by 16 and returns the new string 
string addPad(string txt){
	string str = txt;
	l = str.length() % 16;

	if (l != 0){
		for (int i = 0; i < 16 - l; i++){
			str.append(getPadChar());
		}
	}
	return str;
}

//undoes what the addPad function did do get back the original string
string removePad(string txt){
	string str = txt;
	for (int i = 0; i < l; i++){
		str = str.substr(0, str.find_last_of(getPadChar()));
	}
	return str;
}

//creates a block key by appling key xor count 
void ctrKey(int in){	
	byte bin[32];
	int n = in;
	for (int i = 31; i >= 0; i--){ 
		if (n - (int) (pow(2, i)) >= 0){
			bin[i] = '1';
			n -= (int) (pow(2,i));
		}
		else{ bin[i] = '0'; }
	}
	for (int i = 0; i < 32; i++){ K[i] ^= bin[31-i]; }
}

//genKey function adapted from www.cplusplus.com/forum/windows/88843/
string genKey(){
	char chara[] = { "0123456789" "!@#$%^&*" "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" };
	string s;
	int stringLength = sizeof(chara) - 1;
	srand(time(0));
	for (int i = 0; i < 32; ++i)
	{
		s += chara[rand() % stringLength];
	}
	return s;
}

//control point of the system
void main(){
	string txt = "", key = "";
	int testingMode = 1;//toggle value to turn on and off testing
						//turning off testing triggers manual mode

	cout << "Enter testing mode? (1 = yes, 0 = no): "; 
	cin >> testingMode;

	//TESTER FUNCTIONS
	if (testingMode == 1){
		test_ShiftRowFunctions();
		test_MixColumnsFunctions();
		test_SubBytesFunctions();
		test_RotWordFunctions();
		test_CipherFunctions();
		test_EncryptFunctions();
		system("Pause");
		//END TESTER FUNCTIONS
	}
	else {
		int n = 1;
		PickKeyLength(); // pick key length from 128, 192, or 256 bit key
		do{
			cin.ignore();
			cout << "Enter message to Encrypt: ";
			getline(cin, txt);
			key = genKey();

			cout << "Before Encryption: " << txt << endl;
			txt = encrpyt(txt, key);
			cout << "After Encryption: " << txt << endl;
			txt = decrypt(txt, key);
			cout << "After Decryption: " << txt << endl;

			cout << endl << "Encrypt another message? (1 = yes, 0 = no): ";
			cin >> n;
		} while (n == 1);
	}
}

//-----------------------------------------TESTER FUNCTIONS-----------------------------------//

//fills the state matrix for testing
void fill(){
	//testing shifts

	byte x = 'a';
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			x = x + 1;
			state[i][j] = x;
		}
	}
}

//prints contents of state matrix
void print(){
	//print state
	for (int i = 0; i < 4; i++){
		for (int j = 0; j < 4; j++){
			cout << "[" << state[i][j] << "]";
		}
		cout << endl;
	}
	cout << endl;
}

void test_ShiftRowFunctions(){
	cout << "#----------Testing ShiftRow-----------#" << endl; 
	cout << "//-------Initial State Matrix-------//" << endl;
	fill();
	print();

	ShiftRows();
	cout << "post ShiftRows State Matrix: " << endl;

	print();
	InvShiftRows();
	cout << "Post InvShiftRows State Matrix: " << endl;
	print();
}

void test_MixColumnsFunctions(){

	cout << "#--------Testing MixColumns----------#" << endl;
	cout << "//-------Initial State Matrix-------//" << endl;
	fill();
	print();

	MixColumns();
	cout << "post MixColumns State Matrix: " << endl;

	print();
	InvMixColumns();
	cout << "Post InvMixColumns State Matrix: " << endl;
	print();
}

void test_SubBytesFunctions(){
	cout << "#----------Testing SubBytes-----------#" << endl;
	cout << "//-------Initial State Matrix-------//" << endl;
	fill();
	print();

	SubBytes();
	cout << "post SubBytes State Matrix: " << endl;

	print();
	InvSubBytes();
	cout << "Post invSubBytes State Matrix: " << endl;
	print();
}

void test_RotWordFunctions(){
	cout << "#----------Testing RotWord-----------#" << endl;
	cout << "//-------Initial Word Matrix-------//" << endl;
	byte word[] = { 'a', 'b', 'c', 'd' };
	for (int i = 0; i < 4; i++){ cout << word[i]; }	cout << endl;
	RotWord(word);
	for (int i = 0; i < 4; i++){ cout << word[i]; }	cout << endl;

	cout << "#----------Testing SubWord-----------#" << endl;
	cout << "//-------Initial Word Matrix-------//" << endl;
	byte word1[] = { 'a', 'b', 'c', 'd' };
	for (int i = 0; i < 4; i++){ cout << word1[i]; }	cout << endl;
	SubWord(word1);
	for (int i = 0; i < 4; i++){ cout << word1[i]; }	cout << endl;
}

void test_CipherFunctions(){
	cout << "#-------Testing encrypt decrypt-------#" << endl;
	string txt = "Super Secret, Secret String";

	byte x = 'a';
	for (int i = 0; i < 16; i++){ x = x + 1; in[i] = x; }	
	
	cout << "Before Encryption: " << in << endl;
	Cipher();
	cout << "After Encryption: ";
	for (int i = 0; i < 16; i++){ cout << out[i]; } cout << endl;
	for (int i = 0; i < 16; i++){ in[i] = out[i]; }
	InvCipher();
	cout << "After Decryption: ";
	for (int i = 0; i < 16; i++){ cout << out[i]; } cout << endl;
}

void test_EncryptFunctions(){
	cout << "#-------Testing encrypt decrypt-------#" << endl;
	string txt = "Super Secret, Secret String";

	cout << "Before Encryption: " << txt << endl;
	string key = genKey();
	txt = encrpyt(txt, key);
	cout << "After Encryption: " << txt << endl;
	txt = decrypt(txt, key);
	cout << "After Decryption: " << txt << endl;
}
