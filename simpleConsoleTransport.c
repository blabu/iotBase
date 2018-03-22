/*
 * transport.c
 *
 *  Created on: Mar 22, 2018
 *      Author: okh
 */
#include "transport.h"
#include "stdio.h"

void sendTo(u16 size, byte_ptr data){
	printf("Try send data %s, size: %d\n",data,size);
	for(u16 i = 0; i<size; i++) {
		if(data[i])	printf("\'%c\' ", data[i]);
		else printf("%d ", data[i]);
	}
	printf("\n");
	execCallBack((void*)sendTo);
}

void receiveFrom(u16 size, byte_ptr result){
	result[0] = 0;
	strCat((string_t)result,"$V1001BC230=KEY;1234567890123456");
	u16 shift = strSize((string_t)result);
	result[shift] = 0x10;//0x65;
	result[shift+1] = 0xE8;//0x03;
	printf("Receive message %s \n", result);
	execCallBack((void*)receiveFrom);
}

// Функция сохрания параметры в память
void saveParameters(u16 id, byte_ptr key, u08 size) {
	printf("\nSave parameters!\n");
	key[size-1] = 0;
	printf("Cypher key:");
	for(u08 i = 0; i<16; i++) {
		printf("%d ", key[i]);
	}
	printf("\nId: %x\n", id);
	printf("\nKey: %s\n",key);
	execCallBack((void*)saveParameters);
}

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getParameters(u16* id, byte_ptr key, u08 size) {
	printf("Get parameters\n");
	*id = 12345;
	for(u08 i = 0; i<size; i++) {
		key[i] = (u08)(RandomSimple());
	}
}
