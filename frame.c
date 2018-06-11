/*
 * Frame.c
 *
 *  Created on: Mar 22, 2018
 *      Author: okh
 */
#include "crypt.h"
#include "frame.h"

const string_t OK = "OK;";

/*Специфичные для протокола определения размеров*/
#define DIRACTION_SIZE 1
#define VERSION_SIZE 2
#define MESSAGE_SIZE 4
#define ID_SIZE  4
#define CRC_SIZE 2

static const char startByte = '$';
static const string_t WriteToServerSymb = ">";
static const string_t ReadFromSeverSymb = "<";

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

#ifndef NULL
#define NULL 0
#endif

/*
 * Сформирует сообщение для отправки данных во внутренний буфер
 * maxSize - максимальный размер выходного буфера
 * result - указатель на место куда будет записан результат
 * command - В рамках текущего протокола идентификатор устройства
 * dataSize - размер полезной информации
 * data - указатель на полезную информацию для передачи (УЖЕ ЗАШИФРОВАННУЮ)
 * isWrite - флаг указывает на запись или на чтение формруется пакет
 * isSecure - флаг указывает по зашифрованному или нет каналу передаются данные
 * Возвращает размер сообщения (ноль если сформировать сообшение не удалось)
 * */
static u16 formFrameAscii(const u16 maxSize, byte_ptr result, const message_t*const msg) {
	if( sizeof(startByte)+VERSION_SIZE+MESSAGE_SIZE+ID_SIZE+DIRACTION_SIZE+CRC_SIZE + msg->dataSize > maxSize )
		return 0; // Все сообщение не влезит в буфер

	result[0] = startByte;
	result[1] = '\0';
	char temp[6];
	//I
	toStringUnsign(1,msg->version,temp);
	fillRightStr(VERSION_SIZE,temp,'0');
	temp[VERSION_SIZE] = '\0';
	strCat((string_t)result,temp);
	//II
	toStringUnsign(2, ID_SIZE+DIRACTION_SIZE + msg->dataSize + CRC_SIZE, temp); // Вычисляем размер сообщения согласно протоколу (не входит заголовок и сам размер)
	fillRightStr(MESSAGE_SIZE,temp,'0'); // Формируем размер сообщения
	temp[MESSAGE_SIZE] = '\0';
	strCat((string_t)result,temp); // Добавляем размер сообщения
	//III
	toStringUnsign(2,msg->deviceID,temp);
	fillRightStr(ID_SIZE,temp,'0'); // Формируем Id
	temp[ID_SIZE] = '\0';
	strCat((string_t)result,temp); // Добавляем идентификатор
	//IV
	if(msg->isWrite) strCat((string_t)result,WriteToServerSymb);
	else strCat((string_t)result,ReadFromSeverSymb);
	//V
	u16 size = strSize((string_t)result); // Вычисляем смещение для полезных данных
	memCpy(result+size,msg->data,msg->dataSize);
	size+=msg->dataSize;
	//VI
	u16 c = crc16(size, result); // size - это размер абсолютно всего сообщения включая заголовок и длину сообщения без контрольной суммы
	result[size] = c & 0xFF; // Первый байт младший
	result[size+1] = c >> 8; // Второй байт старший
	return size+CRC_SIZE;
}

/*
 * Возвращает длину полезного сообщения (ноль если распарсить не удалось)
 * parseId - заполняет найденным в сообщении идентификатором
 * sourceSize - размер исходного сообщения
 * source - указатель на исходное сообщение
 * sz - размер, больше которого не будет ничего записываться при формировании распарсенного сообщения
 * result - sz байт (или меньше) полученного сообщения (ЕЩЕ ЗАШИФРОВАННОЕ)
 * IsSecure - указатель куда будет записано канал передачи сообщения зашифрован или нет
 * */
static u16 parseFrameAscii(const u16 sourceSize, const byte_ptr source, message_t* result) {
	if(result == NULL || result->data == NULL || result->dataSize == 0) return 0;
	s16 poz = findSymb(startByte,(const string_t)source);
	if(poz < 0)	return 0; // Не нашли стартовый символ
	char temp[5];

	// I Парсим версию протокола
	temp[0] = source[poz+1];
	temp[1] = source[poz+2];
	temp[2] = '\0';
	result->version = toInt16(temp);

	// II Парсим размер полученного сообщения и вычисляем размер эффективного сообщения
	u16 effectiveSize = 0;
	memCpy(temp, source+poz+sizeof(startByte)+VERSION_SIZE, MESSAGE_SIZE); // Достаем размер сообщения
	temp[MESSAGE_SIZE] = '\0';
	u16 size = (u16)toInt32(temp);
	if(size > sourceSize) return 0;  // Еще не получено все сообщение
	effectiveSize = size - ID_SIZE - DIRACTION_SIZE - CRC_SIZE;

	// III Парсим идентификатор устройства
	memCpy(temp, source+poz+sizeof(startByte)+VERSION_SIZE+MESSAGE_SIZE, ID_SIZE); // Достаем идентификатор
	temp[ID_SIZE] = '\0';
	result->deviceID = (u16)toInt32(temp);

	// IV Определяем направление передачи данных
	memCpy(temp, source+poz+sizeof(startByte)+VERSION_SIZE+MESSAGE_SIZE+ID_SIZE, DIRACTION_SIZE);
	temp[DIRACTION_SIZE] = '\0';
	if(findStr(WriteToServerSymb, temp) >= 0) result->isWrite = TRUE;
	else result->isWrite = FALSE;

	// V  Выделяем сами данные и контрольную сумму
	u16 argShift = poz+sizeof(startByte)+VERSION_SIZE+MESSAGE_SIZE+ID_SIZE+DIRACTION_SIZE; // Смещение от начала буфера для аргументов
	// включает в себя заголовок, длину сообщения, уникальный идентификатор и символ разделитель
	u16 crcShift = poz+sizeof(startByte)+VERSION_SIZE+MESSAGE_SIZE+size-CRC_SIZE; // Смещение от начала буфера для контрольной суммы
	// включает в себя загаловок, длину сообщения, само сообщение минус два байта самой контрольной суммы
	u16 crcReceive = ((u16)(source[crcShift+1])<<8) | source[crcShift]; // Достаем из сообщения контрольную сумму
	u16 crcCalc = crc16(crcShift,source+poz); // Вычисляем контрольную сумму без учета самой контрольной суммы
	if(crcReceive == crcCalc) {
		if(effectiveSize > result->dataSize) {
			memCpy(result->data,source+argShift,result->dataSize);
		}else {
			memCpy(result->data,source+argShift,effectiveSize);
		}
		return effectiveSize;
	}
	result->deviceID = 0;
	return 0;
}


static u16 parseFrameBinary(const u16 sourceSize, const byte_ptr source, message_t* result) {
	if(result == NULL || result->data == NULL || result->dataSize == 0) return 0;
	s16 poz = findSymb(startByte,(const string_t)source);
	if(poz < 0)	return 0; // Не нашли стартовый символ
	u16 savePoz = poz;
	result->version = source[++poz];
	u16 allMessageSize = source[++poz];
	allMessageSize |= ((u16)source[++poz]<<8);
	if(sourceSize < allMessageSize) return 0; // Не получено ВСЕ сообщение
	u16 effectiveMessageSize = allMessageSize - sizeof(result->deviceID) - DIRACTION_SIZE - CRC_SIZE;
	result->deviceID = source[++poz];
	result->deviceID |= ((u16)source[++poz]<<8);
	if(findSymb(source[++poz],WriteToServerSymb) >= 0) result->isWrite = TRUE;
	else result->isWrite = FALSE;
	u16 crcShift = sizeof(startByte)+sizeof(result->version)+sizeof(result->dataSize)+allMessageSize-CRC_SIZE;
	u16 calcCRC = crc16(crcShift, source+savePoz);
	u16 reqCRC = source[savePoz+crcShift] | ((u16)source[savePoz+crcShift+1] << 8);
	if(calcCRC == reqCRC) {
		if(result->dataSize > effectiveMessageSize) {
			memCpy(result->data,source+poz+1,effectiveMessageSize);
			memSet(result->data+effectiveMessageSize,result->dataSize-effectiveMessageSize,0);
			return effectiveMessageSize;
		}
		else {
			memCpy(result->data,source+poz+1,result->dataSize);
			return result->dataSize;
		}
	}
	result->deviceID = 0;
	return 0;
}

static u16 formFrameBinary(const u16 maxSize, byte_ptr result, const message_t*const msg) {
	if( sizeof(startByte)+sizeof(msg->version)+sizeof(msg->dataSize)+sizeof(msg->deviceID)+DIRACTION_SIZE+CRC_SIZE + msg->dataSize > maxSize )
		return 0; // Все сообщение не влезит в буфер

	result[0] = startByte;
	result[1] = msg->version;
	u16 sz = sizeof(msg->deviceID)+DIRACTION_SIZE+msg->dataSize+CRC_SIZE;
	result[2] = (u08)(sz & 0xFF);
	result[3] = (u08)(sz >> 8);
	result[4] = (u08)(msg->deviceID & 0xFF);
	result[5] = (u08)(msg->deviceID >> 8);
	if(msg->isWrite) result[6] = WriteToServerSymb[0];
	else result[6] = ReadFromSeverSymb[0];
	memCpy(result+7,msg->data,msg->dataSize);
	sz = 7+msg->dataSize;
	u16 c = crc16(sz,result);
	result[sz] = (u08)(c & 0xFF);
	result[sz+1] = (u08)(c >> 8);
	return sz+2;
}




u16 formFrame(const u16 maxSize, byte_ptr result, const message_t*const msg) {
	return formFrameBinary(maxSize,result,msg);
}

u16 parseFrame(const u16 sourceSize, const byte_ptr source, message_t* result) {
	return parseFrameBinary(sourceSize, source, result);
}
