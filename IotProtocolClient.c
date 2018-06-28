/*
 * IotProtocol.c
 *
 *  Created on: 11 мар. 2018 г.
 *      Author: blabu
 */
#include "IotProtocolClient.h"
#include "frame.h"
#include "crypt.h"
#include "MyString.h"
#include <transportClient.h>
#include "initLowLevelModule.h"
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

#ifndef NULL
#define NULL 0
#endif

//Пингуем сервер. Работает только если устройство не зарегистрировано и на сервере разрешена регистрация
void ScanEfire(BaseSize_t channel, ClientData_t* serverID) {
	static u08 count = 0;
	message_t msg;
	switch(count) {
	case 0:
		if(serverID->first > KEY_SIZE) serverID->first=KEY_SIZE; // Размер идентификатора не должен превышать 16 байт
		count++;
		registerCallBack((TaskMng)ScanEfire,channel,serverID,initTransportLayer);
		SetTask((TaskMng)initTransportLayer,(BaseSize_t)channel,(BaseParam_t)PING_ADDR);
		return;
	case 1:
		count++;
		registerCallBack((TaskMng)ScanEfire,channel,serverID,enableTranseiver);
		SetTimerTask(enableTranseiver,0,NULL,2);
		return;
	case 2: // Отправляем пинг
		msg.isWrite = TRUE;
		msg.deviceID = device.Id;
		msg.version = 0;
		msg.data = serverID->second;
		msg.dataSize = serverID->first;
		memCpy(msg.data,"ping;",strSize("ping:")+1);
		u08 sz = formFrame(PROTOCOL_BUFFER_SIZE,BufTransmit,&msg);
		if(!sz) {
			count = 0xFF;
			writeLogStr("Ping error\n");
			break;
		}
		count++;
		registerCallBack((TaskMng)ScanEfire,channel,serverID,sendTo);
		SetTask((TaskMng)sendTo,sz,BufTransmit);
		return;
	case 3:
		count++;
		memSet(BufReceive,PROTOCOL_BUFFER_SIZE,0);
		registerCallBack((TaskMng)ScanEfire,channel,serverID,receiveFrom);
		SetTask((TaskMng)receiveFrom, PROTOCOL_BUFFER_SIZE, BufReceive);
		return;
	case 4: // Читаем ответ
		msg.data = serverID->second;
		msg.dataSize = serverID->first;
		if(!parseFrame(PROTOCOL_BUFFER_SIZE,BufReceive,&msg)) { // Если пропарсить не получилось значит ничего не пришло
			count = 0xFF;
			writeLogStr("SERVER not find\n");
			memSet(msg.data,msg.dataSize,0);
			break;
		}
		if(msg.deviceID != device.Id) { // Идентификатор не совпал
			count = 0xFF;
			writeLogStr("Undefined server\n");
			memSet(msg.data,msg.dataSize,0);
			break;
		}
		writeLogStr("Server find");
		//no break;
	default: // Нашли серевр или нет все равно выключаем его
		count = 0;
		changeCallBackLabel(ScanEfire,disableTranseiver);
		SetTask(disableTranseiver,0,0);
		return;
	}
	SetTask((TaskMng)ScanEfire, channel, serverID);
}

// Отправка сообщения обновления ключа шифрования
void WriteClient(u16 size, byte_ptr message) {
	static u08 count = 0;
	static byte_ptr cypherMsg = NULL;
	u16 sz;
	message_t msg;
	if(!device.Id) {
		currentStatus = DEVICEID_IS_NULL;
		count = 0;
		execCallBack(WriteClient);
		return;
	}
	if(currentStatus && currentStatus != STATUS_OK) count = 0xFF;
	switch(count) {
	case 0: // Подготовка
		writeLogStr("START write to server");
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
			writeLogStr("ERROR: Mem error");
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
		msg.data = cypherMsg;
		msg.dataSize = sz;
		msg.deviceID = device.Id;
		msg.isWrite = TRUE;
		if(device.isSecure) msg.version = 1;
		else msg.version = 0;
		sz = formFrame(PROTOCOL_BUFFER_SIZE, BufTransmit, &msg);  // Формируем
		if(!sz) { // Формируем
			count=0xFF;
			writeLogStr("ERROR: Can not form msg");
			currentStatus = STATUS_NO_SEND;
			break;
		}
		count++;
		registerCallBack((TaskMng)WriteClient, size, (BaseParam_t)message, sendTo);
		SetTimerTask((TaskMng)sendTo, sz, BufTransmit,2);
		return;
	case 2: // Получаем ответ (новый ключ шифрования если все в порядке. Зашифрованный предыдущим ключом)
		count++;
		memSet(BufReceive,PROTOCOL_BUFFER_SIZE,0); // Очищаем буфер
		registerCallBack((TaskMng)WriteClient, size, (BaseParam_t)message, receiveFrom);
		SetTask((TaskMng)receiveFrom, PROTOCOL_BUFFER_SIZE, BufReceive); // Ждем ответ
		return;
	case 3: // Парсим ответ В ответ должен был прийти новый ключ шифрования
		sz = getAllocateMemmorySize(cypherMsg);
		msg.data = cypherMsg;
		msg.dataSize = sz;
		sz = parseFrame(PROTOCOL_BUFFER_SIZE, BufReceive, &msg);
		if(msg.deviceID != device.Id) {
				currentStatus = STATUS_NO_SEND; // То мы получили не свой пакет
				writeLogWhithStr("ERROR: Incorrect DeviceId ", msg.deviceID);
				writeLogU32(device.Id);
				count = 0xFF;
				break;
		}
		if(sz != KEY_SIZE) { // Если размер полезной информации не соответствует ключу значит произошла ошибка
			currentStatus = STATUS_NO_SEND;
			writeLogStr("ERROR: Incorrect message size");
			count = 0xFF;
			break;
		}
		switch(msg.version) {
			case 0: device.isSecure = FALSE; writeLogStr("WARN: Not secure\r\n"); break;
			case 1: device.isSecure = TRUE; break;
			default: device.isSecure = FALSE; writeLogStr("WARN: Protocol undef\r\n"); // Undefine version type
		}
		if(device.isSecure) {
			AesEcbDecrypt(cypherMsg,device.Key,BufReceive); // Расшифровуем полученное сообщение
			memCpy(device.Key,BufReceive,KEY_SIZE);
		}
		else  memCpy(device.Key,cypherMsg,KEY_SIZE); // Без шифрования
		count++;
		registerCallBack((TaskMng)WriteClient,size,(BaseParam_t)message, saveParameters);
		saveParameters(device.Id,device.Key,KEY_SIZE,device.isSecure);
		currentStatus = STATUS_OK;
		return;
	case 4: // Отправка подтверждения о получении ключа шифрования
		msg.data = (byte_ptr)OK;
		msg.dataSize = strSize(OK);
		msg.deviceID = device.Id;
		msg.isWrite = TRUE;
		if(device.isSecure) msg.version = 1;
		else msg.version = 0;
		while((msg.dataSize & 0x0F) & 0x0F) msg.dataSize++;
		if(device.isSecure) AesEcbEncrypt(msg.data,device.Key,cypherMsg);
		else memCpy(cypherMsg,msg.data,KEY_SIZE);
		msg.data = cypherMsg;
		sz = formFrame(PROTOCOL_BUFFER_SIZE, BufTransmit, &msg);
		count=11; // FIXME Перескакиваем подтверждение о приеме ОК
		registerCallBack((TaskMng)WriteClient,size,(BaseParam_t)message, sendTo);
		SetTask((TaskMng)sendTo,sz, BufTransmit);
		return;
	case 5:  // Ждем ОК
		count++;
		memSet(BufReceive,PROTOCOL_BUFFER_SIZE,0); // Очищаем буфер
		registerCallBack((TaskMng)WriteClient, size, (BaseParam_t)message, receiveFrom);
		SetTask((TaskMng)receiveFrom, PROTOCOL_BUFFER_SIZE, BufReceive); // Ждем ответ
		return;
	case 6: // Парсим ответ (ожидаем подтверждение об окончании сессии)
		sz = getAllocateMemmorySize(cypherMsg);
		msg.data = cypherMsg;
		msg.dataSize = sz;
		sz = parseFrame(PROTOCOL_BUFFER_SIZE, BufReceive, &msg);
		if(msg.deviceID != device.Id) {
				currentStatus = STATUS_NO_SEND; // То мы получили не свой пакет
				writeLogWhithStr("ERROR: Icorrect DeviceId ", msg.deviceID);
				writeLogU32(device.Id);
				writeLogStr((string_t)BufReceive);
				count = 0xFF;
				break;
		}
		if(sz != KEY_SIZE) { // Если размер полезной информации не соответствует ключу значит произошла ошибка
			writeLogStr("ERROR: Incorrect size for receive msg");
			currentStatus = STATUS_NO_SEND;
			count = 0xFF;
			break;
		}
		switch(msg.version) {
			case 0: device.isSecure = FALSE; writeLogStr("WARN: Not secure\r\n"); break;
			case 1: device.isSecure = TRUE; break;
			default: device.isSecure = FALSE; writeLogStr("WARN: Protocol undef\r\n"); // Undefine version type
		}
		if(device.isSecure) {
			AesEcbDecrypt(cypherMsg,device.Key,BufReceive); // Расшифровуем полученное сообщение
			if(findStr(OK,(string_t)BufReceive) >= 0) {
				count++;
				break;
			}
		}else {
			if(findStr(OK,(string_t)cypherMsg) >= 0) {
				count++;
				break;
			}
		}
		count = 0xFF;
		currentStatus = STATUS_NO_SEND;
		writeLogStr("ERROR: OK not find");
		break;
	case 7: // OK успешно ПОЛУЧЕН
		currentStatus = STATUS_OK;
		writeLogStr("OK finded");
		//no break
	default:
		writeLogStr("FINISH write to server");
		count = 0;
		freeMem(cypherMsg); cypherMsg = NULL;
		changeCallBackLabel((TaskMng)WriteClient,disableTranseiver);
		SetTask(disableTranseiver,0,0);
		return;
	}
	SetTask((TaskMng)WriteClient,size,message);
}

// Чтение данных с сервера
// Отправляет запрос на сервер Максимальный размер читаемых данных. В ответ получим данные
void ReadClient(u16 size, byte_ptr result) {
	static u08 count = 0;
	u08 temp[KEY_SIZE], cypherMsg[KEY_SIZE];
	message_t msg;
	u08 sz;
	if(currentStatus && currentStatus != STATUS_OK) count = 0xFF;
	switch(count){
	case 0:
		writeLogStr("START read from server");
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
	case 1: //Формируем запрос
		toString(2,size,(string_t)temp); // Вставляем размер считываемых данных
		strCat((string_t)temp,";");
		sz = strSize((string_t)temp);
		memCpy(temp+sz, result, KEY_SIZE-sz); // В оставшееся пространство копируем текст запроса (Если он есть)
		temp[KEY_SIZE-1]=0;
		if(device.isSecure) AesEcbEncrypt(temp,device.Key,cypherMsg); // Эта информация точно будет меньше 16-ти байт (одного блока)
		else memCpy(cypherMsg,temp,sz); // Если без шифрования
		msg.data = cypherMsg;
		msg.dataSize = KEY_SIZE;
		msg.deviceID = device.Id;
		msg.isWrite = FALSE;
		if(device.isSecure) msg.version = 1;
		else msg.version = 0;
		sz = formFrame(PROTOCOL_BUFFER_SIZE, BufTransmit, &msg);
		if(!sz) {
			currentStatus = STATUS_NO_RECEIVE;
			count = 0xFF;
			break;
		}
		count++;
		registerCallBack((TaskMng)ReadClient,size,result,sendTo);
		SetTimerTask((TaskMng)sendTo,sz,BufTransmit,2);
		return;
	case 2:  // Собственно само чтение
		count++;
		memSet(BufReceive,PROTOCOL_BUFFER_SIZE,0); // Очищаем буфер
		registerCallBack((TaskMng)ReadClient,size,result,receiveFrom);
		SetTask((TaskMng)receiveFrom,PROTOCOL_BUFFER_SIZE,BufReceive);
		return;
	case 3: // Разшифровуем данные
		sz = size;
		while((sz & 0x0F) & 0x0F) sz++; // Дополняем размер до кратного 16-ти байт (размер блока)
		msg.data = allocMem(sz);
		if(msg.data == NULL) { // Закончилась память
			count = 0xFF;
			currentStatus = MEMMORY_ALOC_ERR;
			break;
		}
		msg.dataSize = sz;
		if(!parseFrame(PROTOCOL_BUFFER_SIZE, BufReceive, &msg)) {
				writeLogStr("ERROR: Not receive answer\r\n");
				currentStatus = STATUS_NO_SEND;
				count = 0xFF;
				break;
		}
		if(msg.deviceID != device.Id) {
			freeMem(msg.data);
			count = 0xFF;
			writeLogWhithStr("ERROR: Icorrect DeviceId ", msg.deviceID);
			writeLogU32(device.Id);
			currentStatus = STATUS_NO_RECEIVE;
			break;
		}
		switch(msg.version) {
		case 0:	device.isSecure = FALSE;  writeLogStr("WARN: Not secure\r\n"); break;
		case 1:	device.isSecure = TRUE;	break;
		default:device.isSecure = FALSE;  writeLogStr("WARN: Protocol undef\r\n");
		}
		for(u16 i = 0; i<sz; i+=KEY_SIZE) {
			if(device.isSecure) AesEcbDecrypt(msg.data+i,device.Key,BufReceive+i);
			else memCpy(BufReceive+i,msg.data+i,KEY_SIZE);
		}
		memCpy(result,BufReceive,size);
		freeMem(msg.data);
		count++;
		break;
	case 4:  // Отправляем ОК
		msg.data = (byte_ptr)OK;
		msg.dataSize = strSize(OK);
		msg.deviceID = device.Id;
		msg.isWrite = TRUE;
		if(device.isSecure) {
			msg.version = 1;
			while((msg.dataSize & 0x0F) & 0x0F) msg.dataSize++;
		}
		else msg.version = 0;
		if(device.isSecure) {
			AesEcbEncrypt(msg.data,device.Key,cypherMsg);
			msg.data = cypherMsg;
		}
		sz = formFrame(PROTOCOL_BUFFER_SIZE, BufTransmit, &msg);
		count=11; // FIXME Перескакиваем подтверждение о приеме ОК
		registerCallBack((TaskMng)ReadClient,size,result,sendTo);
		SetTask((TaskMng)sendTo,sz,BufTransmit);
		currentStatus = STATUS_OK;
		return;
	case 5: // ОК отправили ждем подтверждения
		count++;
		memSet(BufReceive,PROTOCOL_BUFFER_SIZE,0); // Очищаем буфер
		registerCallBack((TaskMng)ReadClient, size, result, receiveFrom);
		SetTask((TaskMng)receiveFrom, PROTOCOL_BUFFER_SIZE, BufReceive); // Ждем ответ
		return;
	case 6: // Парсим ответ (ожидаем подтверждение об окончании сессии)
		sz = getAllocateMemmorySize(cypherMsg);
		msg.data = cypherMsg;
		msg.dataSize = KEY_SIZE;
		sz = parseFrame(PROTOCOL_BUFFER_SIZE, BufReceive, &msg);
		if(msg.deviceID != device.Id) {
				currentStatus = STATUS_NO_SEND; // То мы получили не свой пакет
				writeLogWhithStr("ERROR: Icorrect DeviceId ", msg.deviceID);
				writeLogStr((string_t)BufReceive);
				writeLogU32(device.Id);
				count = 0xFF;
				break;
		}
		if(sz != KEY_SIZE) { // Если размер полезной информации не соответствует ключу значит произошла ошибка
			currentStatus = STATUS_NO_SEND;
			writeLogStr("ERROR: Incorrect size received msg");
			count = 0xFF;
			break;
		}
		switch(msg.version) {
			case 0: device.isSecure = FALSE; writeLogStr("WARN: Not secure\r\n"); break;
			case 1: device.isSecure = TRUE; break;
			default: device.isSecure = FALSE; writeLogStr("WARN: Protocol undef\r\n"); // Undefine version type
		}
		if(device.isSecure) {
			AesEcbDecrypt(cypherMsg,device.Key,BufReceive); // Расшифровуем полученное сообщение
			if(findStr(OK,(string_t)BufReceive) >= 0) {
				count++;
				break;
			}
		}else {
			if(findStr(OK,(string_t)cypherMsg) >= 0) {
				count++;
				break;
			}
		}
		count = 0xFF;
		currentStatus = STATUS_NO_SEND;
		writeLogStr("ERROR: OK not find");
		break;
	case 7: // ОК успешно ПОЛУЧЕН
		writeLogStr("OK finded");
		currentStatus = STATUS_OK;
		// no break
	default:
		writeLogStr("FINISH read from server");
		count = 0;
		changeCallBackLabel((TaskMng)ReadClient,disableTranseiver);
		SetTask(disableTranseiver, 0, 0);
		return;
	}
	SetTask((TaskMng)ReadClient,size,result);
}
