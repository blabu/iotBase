/*
 * Frame.c
 *
 *  Created on: Mar 22, 2018
 *      Author: okh
 */
#include "crypt.h"
#include "frame.h"

/*Специфичные для протокола определения размеров*/
#define MESSAGE_SIZE 4
#define ID_SIZE  4
#define CRC_SIZE 2

const string_t header = "$V1";
const string_t WriteToServerSymb = ">";
const string_t ReadFromSeverSymb = "<";
const string_t OK = "OK;";


static u16 crc16(u16 size, byte_ptr data) {
	return CRC16(size, data);
}

// Дополняет справа символом symb строку str до размера size
static void fillRightStr(u16 size, string_t str, char symb) {
	s16 s = size - strSize(str);
	if(s <= 0) return;
	shiftStringRight(s,str);
	for(s16 i = 0; i<s; i++) {
		str[i] = symb;
	}
}

/*
 * Сформирует сообщение для отправки данных во внутренний буфер
 * bufSize - размер полезной информации
 * buf - указатель на полезную информацию для передачи (УЖЕ ЗАШИФРОВАННУЮ)
 * Возвращает результирующий ПОЛНЫЙ размер сообщения
 * */
u16 formFrame(u16 maxSize, byte_ptr result, u16 command, u16 dataSize, const byte_ptr data, bool_t isWrite) {
	if(strSize(header)+MESSAGE_SIZE+ID_SIZE+strSize(WriteToServerSymb)+dataSize+CRC_SIZE > maxSize) return 0; // Все сообщение не влезит в буфер

	char temp[6];
	//I
	memCpy(result,header,strSize(header)+1); // Копируем заголовок
	//II
	toStringUnsign(2, ID_SIZE+1+dataSize+CRC_SIZE, temp); // Вычисляем размер сообщения согласно протоколу (не входит заголовок и сам размер)
	fillRightStr(MESSAGE_SIZE,temp,'0'); // Формируем размер сообщения
	temp[4] = '\0';
	strCat((string_t)result,temp); // Добавляем размер сообщения
	//III
	toStringUnsign(2,command,temp);
	fillRightStr(ID_SIZE,temp,'0'); // Формируем Id
	temp[4] = '\0';
	strCat((string_t)result,temp); // Добавляем идентификатор
	//IV
	if(isWrite) strCat((string_t)result,WriteToServerSymb);
	else strCat((string_t)result,ReadFromSeverSymb);
	//V
	u16 size = strSize((string_t)result); // Вычисляем смещение для полезных данных
	memCpy(result+size,data,dataSize);
	size+=dataSize;
	//VI
	u16 c = crc16(size, result); // size - это размер абсолютно всего сообщения включая заголовок и длину сообщения без контрольной суммы
	result[size] = c & 0xFF; // Первый байт младший
	result[size+1] = c >> 8; // Второй байт старший
	printf("Form crc %x\n", c);
	return size+CRC_SIZE;
}

/*
 * Возвращает распарсенный идентификатор и полезное сообщение (ЕЩЕ ЗАШИФРОВАННОЕ)
 * */
u16 parseFrame(u16 sourceSize, const byte_ptr source, u16 sz, byte_ptr result) {
	if(str1_str2(header, (const string_t)source)) { // Проверяем заголовок
		char temp[5];
		memCpy(temp,source+strSize(header),MESSAGE_SIZE); // Достаем размер сообщения
		temp[4] = '\0';
		u16 size = (u16)toInt32(temp);
		if(size > sourceSize) return 0;  // Размер сообщения слишком большой
		printf("Parse size 0x%x = %d and source size is %d\n", size, size, sourceSize);
		memCpy(temp,source+strSize(header)+MESSAGE_SIZE,ID_SIZE); // Достаем идентификатор
		temp[4] = '\0';
		u16 id = (u16)toInt32(temp);
		printf("Parse Id %x\n",id);
		u16 argShift = strSize(header)+MESSAGE_SIZE+ID_SIZE+strSize(ReadFromSeverSymb); // Смещение от начала буфера для аргументов
		// включает в себя заголовок, длину сообщения, уникальный идентификатор и символ разделитель
		u16 crcShift = strSize(header)+MESSAGE_SIZE+size-CRC_SIZE; // Смещение от начала буфера для контрольной суммы
		// включает в себя загаловок, длину сообщения, само сообщение минус два байта самой контрольной суммы
		u16 crcReceive = ((u16)(source[crcShift+1])<<8) | source[crcShift]; // Достаем из сообщения контрольную сумму
		u16 crcCalc = crc16(crcShift,source); // Вычисляем контрольную сумму без учета самой контрольной суммы
		printf("Parse crc %x = %x, crc position %d\n", crcCalc, crcReceive, crcShift);
		if(crcReceive == crcCalc) {
			if(size-CRC_SIZE > sz) {
				memCpy(result,source+argShift,sz);
			}else {
				memCpy(result,source+argShift,size-CRC_SIZE);
			}
			return id;
		}
	}
	return 0;
}
