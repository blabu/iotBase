/*
 * Frame.c
 *
 *  Created on: Mar 22, 2018
 *      Author: okh
 */
#include "crypt.h"
#include "frame.h"
#include "config.h"


const string_t OK = "OK;";

/*Специфичные для протокола определения размеров*/
#define CRC_SIZE 2

static const char startByte = '$';

static u16 crc16(u16 size, byte_ptr data) {
	return CRC16(size, data);
}

#ifndef NULL
#define NULL 0
#endif

static s16 findByte(u08 byte, byte_ptr src, u08 maxSize) {
	if(src == NULL) return -1;
	u08 i = 0;
	while(src[i] != byte && i<maxSize) i++;
	if(i == maxSize) return -1;
	return (s16)i;
}

#include "logging.h"
/*
 * 8 байт оверхеда
 * $ (isSecure<<7) | 'MessgeType' 'messageID' 'dataSize' 'deviceID' "MESSAGE" CRC
 * */
static u16 parseFrameBinary(const u16 sourceSize, const byte_ptr source, message_t* result) {
	if(result == NULL || result->data == NULL || result->dataSize == 0) return 0;
	s16 poz = findByte(startByte, source, 5); //findSymb(startByte,(const string_t)source);
	if(poz < 0)	{
		writeLogStr("Undefined start symbol $");
		return 0; // Не нашли стартовый символ
	}
	u08 savePoz = (u08)poz;
	result->messageType = source[++poz]&0x7F;
	result->isSecure = (bool_t)(source[poz] >> 7);
	result->messageID = source[++poz];
	u16 allMessageSize = source[++poz];
	if(sourceSize < allMessageSize) return 0; // Не получено ВСЕ сообщение
	u08 effectiveMessageSize = allMessageSize - sizeof(result->deviceID) - CRC_SIZE;
	result->deviceID = source[++poz];
	result->deviceID |= ((u16)source[++poz]<<8);
	u16 crcShift = sizeof(startByte)+sizeof(result->messageType)+sizeof(result->messageID)+sizeof(result->dataSize)+allMessageSize-CRC_SIZE;
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
	writeLogStr("Incorrect checksum");
	result->deviceID = 0;
	return 0;
}

/*
 * 8 байт оверхеда
 * $ (isSecure<<7) | 'MessgeType' 'messageID' 'dataSize' 'deviceID' "MESSAGE" CRC
 * */
static u16 formFrameBinary(const u16 maxSize, byte_ptr result, const message_t*const msg) {
	if( sizeof(startByte)+sizeof(msg->messageType)+sizeof(msg->messageID)+sizeof(msg->dataSize)+sizeof(msg->deviceID) + CRC_SIZE + msg->dataSize > maxSize )
		return 0; // Все сообщение не влезит в буфер

	result[0] = startByte;
	result[1] = msg->messageType | ((u08)msg->isSecure << 7);
	result[2] = 0; // Пока 0 сообщение больше чем в одном пакете не предусмотерно
	u08 sz = sizeof(msg->deviceID)+msg->dataSize+CRC_SIZE;
	result[3] = sz;
	result[4] = (u08)(msg->deviceID & 0xFF);
	result[5] = (u08)(msg->deviceID >> 8);
	memCpy(result+6,msg->data,msg->dataSize);
	sz = 6+msg->dataSize;
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
