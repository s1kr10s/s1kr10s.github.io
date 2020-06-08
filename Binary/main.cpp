#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <bits/stdc++.h>
using namespace std;

int res;
int c1[7];
int d2[7];
int e3[7];
int f4[7];
int g5[7];
int j6[7];
int i=0;
int z,x;
unsigned long t1,t2,t3;

BOOL anti_debug()
{
	BOOL result;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &result);
	return result;
}

int thetime(){
	t1 = GetTickCount();

	for (z=0; z < 10000000; z++) {
		x = z;
	}
	
	t2 = GetTickCount();
	t3 = t2-t1;
	
	if (t3 > 100) 
	{
		MessageBox(0, "Try Harder...", "CTF-2020", MB_OK );
		exit(0);
	}	
	return 0;
}

void flag1(){
	MessageBox(0, "Try Harder...", "CTF-2020", MB_OK );
	exit(1);
}

void flag2(){
	int i=1337;
	char flag[29] = "LTH}{4Ests01r_k1sD1f1c1lb4No";	
	
	if (i == 1316){
		printf("FLAG_IS: %s", flag);
	}
	exit(1);
}

void flag3(){
	MessageBox(0, "Try Harder...", "CTF-2020", MB_OK );
	exit(1);
}

int main(int argc, char** argv) {
	if(argc < 2) {
		flag1();
	}else{
		if (IsDebuggerPresent()) {
			flag2();
		}else{
			thetime();
			if (anti_debug()) {
				flag2();
			}else{
				__asm__ (
				"xor %%ebx, %%ebx;"
				"movl $50, %%ebx;"
				"movl %%ebx, %%ecx;"
				"pushl %%ecx;"
				"xor %%ecx, %%ecx;"
				"popl %%ecx;"
				"movl %%fs:0x30, %%eax;"
				"addl $104, %%eax;"
		        "movl (%%eax), %%eax;"
		        "andl $112, %%eax;"
		        "test %%eax, %%eax":"=a"(res)
				);
				if(res == 0) {
					printf("Keygen: 0x%x\n", t1);
					
					//llaves de xoreo intercalado
					int k1[] = {11,85,9,412,5,126,12,42,5,61,7,18,21};
				    int k1_size = (sizeof(k1)/sizeof(k1[0]));
				    
				    //letras a xorear intercalado
				    int l1[] = {69,12,102,23,64,34,127,342,113,454,51,565,119};
				    int l2[] = {122,43,116,21,69,87,83};
				    int l3[] = {88,27,119,85,93,82,75};
				    int l4[] = {47,42,43,67,0,2,37};
				    int l5[] = {2,24,92,23,92,87,15};
				    int l6[] = {45,89,66,19,1,7,96};
				    
				    for (int h = 0; h < k1_size; h+=2) {
				    	l1[h] ^= k1[h];
				    	c1[i] = l1[h];
				    	l2[i] ^= l1[h];
				    	d2[i] = l2[i];
				    	l3[i] ^= l2[i];
				    	e3[i] = l3[i];
				    	l4[i] ^= l3[i];
				    	f4[i] = l4[i];
				    	l5[i] ^= l4[i];
				    	g5[i] = l5[i];
				    	l6[i] ^= l5[i];
				    	j6[i] = l6[i];
				    	i+=1;
				    }
				    
				    if(t1 != t2){
						flag2();
					}else{
						flag1();
						printf("LTN{");
					    for(int k=0; k < 42; k++) {
					    	printf("%c", c1[k]);
						}
						printf("}");
					}
				}else{
					flag3();
				}
			}
		}
	}
	return 0;
}

/*
https://www.aldeid.com/wiki/TEB-Thread-Environment-Block
https://github.com/jaeyung1001/Anti-Debugging
https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=230d68b2-c80f-4436-9c09-ff84d049da33&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments
https://convert.town/ascii-to-text
78,111,69,115,116,52,98 = NoEst4b 
52,68,49,102,49,99,49 = 4D1f1c1
108,95,70,51,108,49,122 = l_F3l1z
67,117,109,112,108,51,95 = Cumpl3_
65,109,49,103,48,100,80 = Am1g0dP
108,52,115,116,49,99,48 = l4st1c0
*/
