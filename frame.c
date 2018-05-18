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

const string_t header = "$01"; // ДЛИНА ОБЯЗАТЕЛЬНО ДОЛЖНА СОВПАДАТЬ
const string_t headerSecure = "$02";
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
 * maxSize - максимальный размер выходного буфера
 * result - указатель на место куда будет записан результат
 * command - В рамках текущего протокола идентификатор устройства
 * dataSize - размер полезной информации
 * data - указатель на полезную информацию для передачи (УЖЕ ЗАШИФРОВАННУЮ)
 * isWrite - флаг указывает на запись или на чтение формруется пакет
 * isSecure - флаг указывает по зашифрованному или нет каналу передаются данные
 * Возвращает размер сообщения (ноль если сформировать сообшение не удалось)
 * */
u16 formFrame(const u16 maxSize, byte_ptr result, u16 command, const u16 dataSize, const byte_ptr data, bool_t isWrite, bool_t isSecure) {
	if(strSize(header)+MESSAGE_SIZE+ID_SIZE+strSize(WriteToServerSymb)+dataSize+CRC_SIZE > maxSize) return 0; // Все сообщение не влезит в буфер

	char temp[6];
	//I
	if(isSecure) memCpy(result,headerSecure,strSize(headerSecure)+1); // Копируем зашифрованный заголовок
	else memCpy(result,header,strSize(header)+1); // Копируем заголовок
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
	//printf("Form crc %x\n", c);
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
u16 parseFrame(u16*const parseId, const u16 sourceSize, const byte_ptr source, const u16 sz, byte_ptr result, bool_t* isSecure) {
	if(parseId == NULL || result == NULL || isSecure == NULL) return 0;
	s16 poz = findStr(header, (const string_t)source); // Проверяем заголовок НЕ зашифрованный
	if(poz < 0) {  //Если НЕ нашли пытаемся найти заголовок зашифрованный
		poz = findStr(headerSecure, (const string_t)source);
		*isSecure = TRUE;
	} else *isSecure = FALSE;
	if(poz >= 0) {
		u16 effectiveSize = 0;
		char temp[5];
		memCpy(temp,source+poz+strSize(header),MESSAGE_SIZE); // Достаем размер сообщения
		temp[4] = '\0';
		u16 size = (u16)toInt32(temp);
		if(size > sourceSize) return 0;  // Размер сообщения слишком большой
		effectiveSize = size - ID_SIZE - strSize(ReadFromSeverSymb)-CRC_SIZE;
		memCpy(temp,source+poz+strSize(header)+MESSAGE_SIZE,ID_SIZE); // Достаем идентификатор
		temp[4] = '\0';
		*parseId = (u16)toInt32(temp);
		u16 argShift = poz + strSize(header)+MESSAGE_SIZE+ID_SIZE+strSize(ReadFromSeverSymb); // Смещение от начала буфера для аргументов
		// включает в себя заголовок, длину сообщения, уникальный идентификатор и символ разделитель
		u16 crcShift = poz + strSize(header)+MESSAGE_SIZE+size-CRC_SIZE; // Смещение от начала буфера для контрольной суммы
		// включает в себя загаловок, длину сообщения, само сообщение минус два байта самой контрольной суммы
		u16 crcReceive = ((u16)(source[crcShift+1])<<8) | source[crcShift]; // Достаем из сообщения контрольную сумму
		u16 crcCalc = crc16(crcShift,source+poz); // Вычисляем контрольную сумму без учета самой контрольной суммы
		if(crcReceive == crcCalc) {
			if(effectiveSize > sz) {
				memCpy(result,source+argShift,sz);
			}else {
				memCpy(result,source+argShift,effectiveSize);
			}
			return effectiveSize;
		}
		*parseId = 0;
		return 0;
	}
	*parseId = 0;
	return 0;
}
