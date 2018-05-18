/*
 * IotProtocol.c
 *
 *  Created on: 11 мар. 2018 г.
 *      Author: blabu
 */
#include <transportClient.h>
#include "IotProtocolClient.h"
#include "frame.h"
#include "crypt.h"
#include "MyString.h"

#include "logging.h"
/*
 * Result message has a form $01xxxxYYYYPAAA...AAAcc
 * where '$' - start symbol
 * 01 - version of protocol (02 - Secure version)
 * xxxx - MESSAGE_SIZE message size ascii format (max 'FFFF')
 * YYYY - unique device identificator
 *  'P' - delim symbol between identifier and arguments
 *  AAA...AAA - arguments of function (may be binary) and can be crypted
 *  cc - CRC16 binary не зашифрованный
 *  Для шифрования используется симметричный алгоритм AES128 (с ключом в 16 байт)
 *  С каждой сессией передачи ключ меняется
 *  Заголовок пакета должен быть в формате ASCII строк для обеспечения совместивмости с предыдущими версиями
 * */

static Device_t device;
ProtocolStatus_t currentStatus;

static u08 BufTransmit[PROTOCOL_BUFFER_SIZE];
#define BufReceive BufTransmit /*The same buffer*/
//u08 BufReceive[PROTOCOL_BUFFER_SIZE];

void InitializeClient() {
	changeCallBackLabel(InitializeClient,getParameters);
	getParameters(KEY_SIZE, &device);
}

u16 getDeviceId(){
	return device.Id;
}

void setId(u16 id) {
	device.Id = id;
}

void setSecurity(bool_t enable) {
	device.isSecure = enable;
}

void setKey(u16 sz, byte_ptr key) {
	if(sz > KEY_SIZE) return;
	memCpy(device.Key, key, sz);
}

ProtocolStatus_t GetLastStatus() {
	ProtocolStatus_t temp = currentStatus;
	currentStatus = STATUS_OK;
	return temp;
}

static bool_t isCorrect(u16 id) {
	if(id > 0xFF) return TRUE;
	return FALSE;
}


// Отправка сообщения обновления ключа шифрования
void WriteClient(u16 size, byte_ptr message) {
	static u08 count = 0;
	static byte_ptr cypherMsg = NULL;
	u16 sz;
	u16 tempId;
	if(!device.Id) {
		currentStatus = DEVICEID_IS_NULL;
		count = 0;
		execCallBack(WriteClient);
		return;
	}
	if(currentStatus && currentStatus != STATUS_OK) count = 0xFF;
	switch(count) {
	case 0:
		if(!isCorrect(device.Id)) {
			currentStatus = DEVICEID_IS_NULL;
			execCallBack(WriteClient);
			return;
		}
		currentStatus = 0;
		if(cypherMsg != NULL) freeMem(cypherMsg);
		sz = size;
		while((sz & 0x0F) & 0x0F) sz++; // Дополняем размер до кратного 16-ти байт (размер блока)
		if(sz > PROTOCOL_BUFFER_SIZE) {count = 0xFF; currentStatus = STATUS_NO_SEND; break;}
		cypherMsg = allocMem(sz);
		if(cypherMsg == NULL) {
			count=0xFF;
			currentStatus = MEMMORY_ALOC_ERR;
			break;
		}
		count++;
		SetTask(enableTranseiver,0,0);
		registerCallBack((TaskMng)WriteClient,size,message,enableTranseiver);
		return;
	case 1: // Шифруем и отправляем
		sz = getAllocateMemmorySize(cypherMsg);
		byte_ptr tempMessage = message;
		if(sz > size) { // Дополняем сообщение нулями при необходимости
			tempMessage = allocMem(sz); if(tempMessage == NULL) {currentStatus = STATUS_NO_SEND; break;}
			memCpy(tempMessage,message,size);
			memSet(tempMessage+size,sz-size,0); // Дополняем до кратного 16-ти исходное сообщение нулями
		}
		for(u08 i = 0; i<sz; i+=KEY_SIZE) { // Шифруем
			if(device.isSecure) AesEcbEncrypt(tempMessage+i,device.Key,cypherMsg+i);
			else memCpy(cypherMsg+i,tempMessage+i,KEY_SIZE);
		}
		freeMem(tempMessage);
		sz = formFrame(PROTOCOL_BUFFER_SIZE, BufTransmit, device.Id, sz, cypherMsg, TRUE, device.isSecure); // Формируем
		if(!sz) { // Сформировать не получилось
			count=0xFF;
			currentStatus = STATUS_NO_SEND;
			break;
		}
		count++;
		registerCallBack((TaskMng)WriteClient, size, (BaseParam_t)message, sendTo);
		SetTask((TaskMng)sendTo, sz, BufTransmit);
		return;
	case 2: // Получаем ответ (новый ключ шифрования если все впорядке. Зашифрованный предыдущим ключом)
		count++;
		memSet(BufReceive,PROTOCOL_BUFFER_SIZE,0); // Очищаем буфер
		registerCallBack((TaskMng)WriteClient, size, (BaseParam_t)message, receiveFrom);
		SetTask((TaskMng)receiveFrom, PROTOCOL_BUFFER_SIZE, BufReceive); // Ждем ответ
		return;
	case 3: // Парсим ответ В ответ должен был прийти новый ключ шифрования
		sz = getAllocateMemmorySize(cypherMsg);
		sz = parseFrame(&tempId, PROTOCOL_BUFFER_SIZE, BufReceive, sz ,cypherMsg, &device.isSecure);
		if(tempId != device.Id) {
				currentStatus = STATUS_NO_SEND; // То мы получили не свой пакет
				count = 0xFF;
				break;
		}
		if(sz != KEY_SIZE) { // Если размер полезной информации не соответствует ключу значит произошла ошибка
			currentStatus = STATUS_NO_SEND;
			count = 0xFF;
			break;
		}
		if(device.isSecure) AesEcbDecrypt(cypherMsg,device.Key,BufReceive); // Расшифровуем полученное сообщение
		else memCpy(BufReceive,cypherMsg,KEY_SIZE); // Без шифрования
		count++;
		memCpy(device.Key,BufReceive,KEY_SIZE);
		registerCallBack((TaskMng)WriteClient,size,(BaseParam_t)message, saveParameters);
		saveParameters(device.Id,device.Key,KEY_SIZE,device.isSecure);
		currentStatus = STATUS_OK;
		return;
	case 4: // Отправка подтверждения о получении ключа шифрования (не шифрованное)
		sz = formFrame(PROTOCOL_BUFFER_SIZE, BufTransmit, device.Id, strSize(OK), (byte_ptr)OK, TRUE, FALSE);
		count++;
		registerCallBack((TaskMng)WriteClient,size,(BaseParam_t)message, sendTo);
		SetTask((TaskMng)sendTo,sz, BufTransmit);
		return;
	case 5:
		count++;
		SetTask(disableTranseiver,0,0);
		registerCallBack((TaskMng)WriteClient,size,message,disableTranseiver);
		return;
	default:
		count = 0;
		freeMem(cypherMsg); cypherMsg = NULL;
		execCallBack(WriteClient);
		return;
	}
	SetTask((TaskMng)WriteClient,size,message);
}

// Чтение данных с сервера
// Отправляет запрос на сервер Максимальный размер читаемых данных. В ответ получим данные
void ReadClient(u16 size, byte_ptr result) {
	const u08 ATTEMPT = 5;
	static u08 countAttempt = ATTEMPT;
	static u08 count = 0;
	u08 temp[KEY_SIZE], cypherMsg[KEY_SIZE];
	u16 tempId;
	byte_ptr temp_ptr;
	u08 sz;
	if(currentStatus && currentStatus != STATUS_OK) count = 0xFF;
	switch(count){
	case 0:
		currentStatus = 0;
		if(size > PROTOCOL_BUFFER_SIZE) {// Больше этого мы считать не сможем
			count = 0xFF;
			currentStatus = STATUS_NO_RECEIVE;
			break;
		}
		count++;
		SetTask(enableTranseiver,0,0);
		registerCallBack((TaskMng)ReadClient,size, result, enableTranseiver);
		return;
	case 1:
		toString(2,size,(string_t)temp); // Вставляем размер считываемых данных
		sz = strSize((string_t)temp);
		memSet(temp+sz,KEY_SIZE-sz,0); // Дополняем нулями отсавшееся пространство
		if(device.isSecure) AesEcbEncrypt(temp,device.Key,cypherMsg); // Эта информация точно будет меньше 16-ти байт (одного блока)
		else memCpy(cypherMsg,temp,sz); // Если без шифрования
		sz = formFrame(PROTOCOL_BUFFER_SIZE, BufTransmit, device.Id, KEY_SIZE, cypherMsg, FALSE, device.isSecure);
		if(sz) { // Если формирование фрейма прошло удачно
			count++;
			registerCallBack((TaskMng)ReadClient,size,result,sendTo);
			SetTask((TaskMng)sendTo,sz,BufTransmit);
			return;
		}
		currentStatus = STATUS_NO_RECEIVE;
		count = 0xFF;
		break;
	case 2:  // Собственно само чтение
		count++;
		registerCallBack((TaskMng)ReadClient,size,result,receiveFrom);
		memSet(BufReceive,PROTOCOL_BUFFER_SIZE,0); // Очищаем буфер
		SetTask((TaskMng)receiveFrom,PROTOCOL_BUFFER_SIZE,BufReceive);
		return;
	case 3: // Разшифровуем данные
		sz = size;
		while((sz & 0x0F) & 0x0F) sz++; // Дополняем размер до кратного 16-ти байт (размер блока)
		temp_ptr = allocMem(sz);
		if(temp_ptr == NULL) {
			count = 0xFF;
			currentStatus = MEMMORY_ALOC_ERR;
			break;
		}
		if(!parseFrame(&tempId, PROTOCOL_BUFFER_SIZE, BufReceive, sz, temp_ptr, &device.isSecure)) {
			if(countAttempt) {
				countAttempt--;
				count = 1;
				break;
			}else {
				writeLogStr("ERROR: Not receive answer\r\n");
				count = 5;
				break;
			}
		}
		if(tempId != device.Id) {
			freeMem(temp_ptr);
			count = 0xFF;
			currentStatus = STATUS_NO_RECEIVE;
			break;
		}
		for(u16 i = 0; i<sz; i+=KEY_SIZE) {
			if(device.isSecure) AesEcbDecrypt(temp_ptr+i,device.Key,BufReceive+i);
			else memCpy(BufReceive+i,temp_ptr+i,KEY_SIZE);
		}
		memCpy(result,BufReceive,size);
		freeMem(temp_ptr);
		count++;
		break;
	case 4:
		sz = formFrame(PROTOCOL_BUFFER_SIZE, BufTransmit, device.Id, strSize(OK), (byte_ptr)OK, TRUE, FALSE); // Подтверждение без шифрования
		count++;
		registerCallBack((TaskMng)ReadClient,size,result,sendTo);
		sendTo(sz,BufTransmit);
		currentStatus = STATUS_OK;
		return;
	case 5:
		count++;
		SetTask(disableTranseiver,0,0);
		registerCallBack((TaskMng)ReadClient,size,result,disableTranseiver);
		return;
	default:
		count = 0;
		countAttempt = ATTEMPT;
		execCallBack(ReadClient);
		return;
	}
	SetTask((TaskMng)ReadClient,size,result);
}

