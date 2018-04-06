/*
 * transport.c
 *
 *  Created on: Mar 22, 2018
 *      Author: okh
 */
#include <transportClient.h>
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
	u16 generateId = 0x3537;
	u08 temp[32];
	result[0] = 0;
	strCat((string_t)result,"$V100190035=");
	memCpy(result+12, &generateId, sizeof(generateId));
	result[14] = 0;
	strCat((string_t)result,"1234567890123457");
	u16 shift = strSize((string_t)result);
	u16 c = CRC16(30, result);
	printf("CRC16 is %x\n", c);
	result[31] = (u08)(c>>8);
	result[30] = (u08)(c & 0xFF);
	printf("Receive message %s and size is %d\n", result, size);
	formFrame(32,temp,0x35,18,"751234567890123457");
	printf("Result: %s\n", temp);
	execCallBack((void*)receiveFrom);
}

// Функция сохрания параметры в память
void saveParameters(u16 id, byte_ptr key, u08 size) {
	printf("\nSave parameters!\n");
	key[size] = 0;
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
