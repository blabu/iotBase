/*
 * IotProtocolServer.c
 *
 *  Created on: Mar 28, 2018
 *      Author: okh
 */

#include "IotProtocolServer.h"
#include "transportServer.h"
#include "frame.h"
#include "crypt.h"
#include "List.h"
#include "logging.h"
#include "MyString.h"

#define KEY_SIZE 16

static bool_t isSecure = FALSE;
static ListNode_t* DeviceList = NULL; // Хранит указатель на голову списка устройств
static TaskMng WriteHandler = NULL;
static TaskMng ReadHandler = NULL;

typedef struct {
	u16 sessionId;
	ClientData_t buff;
	Device_t* dev;
	byte_ptr newKey;
} Client_t;

static Device_t* findDeviceById(u16 devId) {
	Device_t* result = NULL;
	ListNode_t* head = findHead(DeviceList);
	if(head == NULL) return result;
	while( (head = head->next) != NULL ) {
		if(head->data == NULL) break;
		result = ((Device_t*)(head->data));
		if( result->Id == devId ) break;
		result = NULL;
	}
	return result;
}

static u08 getTypeById(u16 id) {
	return (u08)(id>>8);
}

static u16 generateNewId(u08 type) {
	u16 temp = 0;
	do {
		temp = RandomSimple() & 0xFF;
		temp |= (u16)(type<<8);
	} while(findDeviceById(temp) != NULL);
	return temp;
}

static void generateKey(byte_ptr key) {
	for(u08 i = 0; i<KEY_SIZE; i+=4) {
		u32 temp = RandomSimple();
		*((u32*)(key+i)) = temp;
	}
	memCpy(key,"key:123456789012",KEY_SIZE); //TODO Удалить после отладки
}

static void freeClient(BaseSize_t sessionId, Client_t* c) {
	freeMem(c->buff.second);
	freeMem(c->newKey);
	freeMem((byte_ptr)c);
}

static void freeClientData(BaseSize_t sessionId, ClientData_t* d) {
	freeMem(d->second);
	freeMem((byte_ptr)d);
}

static void ClientWork(BaseSize_t count, BaseParam_t client);

static void NewDeviceCreate(BaseSize_t count, BaseParam_t client) {
	u08 buff[PROTOCOL_BUFFER_SIZE];
	Client_t* cl = (Client_t*)client;
	switch(count) {
	case 0:
		generateKey(cl->dev->Key);
		cl->dev->Id = generateNewId(cl->dev->Id);
		if(putToEndList(DeviceList,(void*)cl->dev, sizeof(Device_t)) == NULL) { // Записываем новое устройство в список всех устройств
			writeLogStr("ERROR: DeviceList overflow\r\n");
			count = 0xFF;
			break;
		}
		count++;
		registerCallBack(NewDeviceCreate,count,(BaseParam_t)cl,saveAllParameters);
		saveAllParameters(DeviceList); // Сохраняем все включае новое устройство
		return;
	case 1: //Формируем ответ клиенту с генерированными данными
		memCpy(buff, &(cl->dev->Id), sizeof(cl->dev->Id)); // Копируем в ответ клиенту идентификатор
		memCpy(buff+sizeof(cl->dev->Id),cl->dev->Key, KEY_SIZE); //Копируем в ответ клиенту ключ шифрования
		u16 sz = formFrame(cl->buff.first, cl->buff.second, getTypeById(cl->dev->Id), sizeof(cl->dev->Id)+KEY_SIZE, buff, TRUE); // Отправляем запрос
		if(sz) {
			cl->buff.first = sz;
			count++;
			registerCallBack(NewDeviceCreate,count,(BaseParam_t)cl,(void*)((u32*)sendToClient + cl->sessionId));
			SetTask((TaskMng)sendToClient, cl->sessionId, (BaseParam_t)(&cl->buff));
			return;
		}
		else {
			writeLogStr("ERROR: Can not form frame for new dev\r\n");
			execCallBack((void*)((u32*)NewDeviceCreate + cl->sessionId));
			return;
		}
	case 2: // Ожидаем подтверждения получения нового ключа шифрования
		count++;
		registerCallBack(NewDeviceCreate,count, (BaseParam_t)cl, (void*)((u32*)receiveFromClient+cl->sessionId));
		SetTask((TaskMng)receiveFromClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	case 3: //
		count++;
		if(findStr(OK,(string_t)cl->buff.second) > 0) { // подтверждение отправляется без шифрования
			writeLogStr("OK for reg func finded\r\n");
			memCpy(cl->dev->Key,cl->newKey,KEY_SIZE);
		}else {
			writeLogStr("ERROR: OK not find\r\n");
		}
		//no break;
	default:
		execCallBack((void*)((u32*)NewDeviceCreate + cl->sessionId));
		return;
	}
	SetTask(NewDeviceCreate,count,(BaseParam_t)cl);
}

static void DeviceWriteWork(BaseSize_t count, BaseParam_t client) { // Работа с найденым устройством из списка
	Client_t* cl = (Client_t*)client;
	u08 sz = 0;
	u08 tempBuff[KEY_SIZE];
	ClientData_t* d;
	switch(count) {
	case 0:
		count++;
		if(WriteHandler != NULL) { // Копируем полученные данные и отправляем на анализ
			d = (ClientData_t*)allocMem(sizeof(ClientData_t));  // Выделяем память под наши данные
			if(d != NULL) {
				d->first = cl->buff.first;
				d->second = allocMem(d->first);
				if(d->second == NULL) {
					freeMem((byte_ptr)d);
					count = 0xFF;
					break; // Если выделить не удалось отправляем новый ключ
				}
				memCpy(d->second,cl->buff.second,d->first); // Копируем данные
				registerCallBack((TaskMng)freeClientData, cl->sessionId, d, (void*)((u32*)WriteHandler+cl->dev->Id)); // Ставим колбэк для очистки памяти
				SetTask(WriteHandler, cl->dev->Id, (BaseParam_t)(d)); // Отправляем данные на анализ
			}
			break; // Здесь продолжим работу Отправим новый ключ
		} else {
			writeLogStr("ERROR: WriteHandler undefined\r\n");
			count = 0xFF;
		}
		break;
	case 1: // Генерируем, шифруем и отправляем новый ключ шифрования
		cl->buff.first = getAllocateMemmorySize(cl->buff.second);
		cl->newKey = allocMem(KEY_SIZE);
		if(cl->newKey == NULL) {
			count=0xFF;
			break;
		}
		generateKey(cl->newKey);
		// Эти данные равный длине ключа шифрования
		if(isSecure) AesEcbEncrypt(cl->newKey,cl->dev->Key,tempBuff); // Шифруем старым ключом
		else memCpy(tempBuff,cl->newKey,KEY_SIZE);
		sz = formFrame(cl->buff.first,cl->buff.second,cl->dev->Id,KEY_SIZE,tempBuff,TRUE);
		if(!sz) {
			count = 0xFF;
			break;
		}
		count++;
		registerCallBack(DeviceWriteWork,count,(BaseParam_t)cl, (void*)((u32*)sendToClient+cl->sessionId));
		SetTask((TaskMng)sendToClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	case 2: // Ожидаем подтверждения получения нового ключа шифрования
		count++;
		registerCallBack(DeviceWriteWork,count, (BaseParam_t)cl, (void*)((u32*)receiveFromClient+cl->sessionId));
		SetTask((TaskMng)receiveFromClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	case 3: //
		count++;
		if(findStr(OK,(string_t)cl->buff.second) > 0) { // подтверждение отправляется без шифрования
			writeLogStr("OK for write func finded\r\n");
			memCpy(cl->dev->Key,cl->newKey,KEY_SIZE);
			saveAllParameters(DeviceList);
		}else {
			writeLogStr("ERROR: OK not find\r\n");
		}
		//no break;
	default:
		execCallBack((void*)((u32*)DeviceWriteWork + cl->sessionId));
		return;
	}
	SetTask(DeviceWriteWork,count,(BaseParam_t)cl);
}

static void DeviceReadWork(BaseSize_t count, BaseParam_t client) { // Работа с найденым устройством из списка
	Client_t* cl = (Client_t*)client;
	u16 sz = 0;
	u08 tempArray[PROTOCOL_BUFFER_SIZE];
	switch(count) {
	case 0: // Анализ размера запрашиваемого сообщения
		if(ReadHandler != NULL) {
			byte_ptr tempBuff;
			sz = (u16)toInt32((string_t)(cl->buff.second)); // Определяем размер запрашиваемой информации
			cl->buff.first = getAllocateMemmorySize(cl->buff.second);
			if(sz > cl->buff.first) { // Если размера буфера не достаточно, перевыделяем его.
				tempBuff = cl->buff.second;
				cl->buff.second = allocMem(sz);
				if(cl->buff.second == NULL) {
					cl->buff.second = tempBuff;
					count= 0xFF;
					break;
				}
				memCpy(cl->buff.second,tempBuff,cl->buff.first);
				freeMem(tempBuff);
			}
			count++;
			cl->buff.first = sz;
			registerCallBack(DeviceReadWork,count,(BaseParam_t)cl, (void*)((u32*)ReadHandler + cl->dev->Id)); // Ожидаем ответа
			SetTask(ReadHandler, cl->dev->Id, (BaseParam_t)(&cl->buff));
			return; // Ожидаем колбэк со сформированным ответом
		}
		count = 0xFF;
		break;
	case 1: // в cl->buf.second содержится ответ
		sz = cl->buff.first;
		cl->buff.first = getAllocateMemmorySize(cl->buff.second);
		while((sz & 0x0F) & 0x0F) sz++; // Дополняем размер до кратного 16-ти байт (размер блока)
		if(sz > PROTOCOL_BUFFER_SIZE) {sz = PROTOCOL_BUFFER_SIZE;}
		for(u08 i = 0; i<sz; i+=KEY_SIZE) {
			if(isSecure) AesEcbEncrypt(cl->buff.second+i,cl->dev->Key,tempArray+i);
			else memCpy(tempArray+i,cl->buff.second+i,KEY_SIZE);
		}
		if(PROTOCOL_BUFFER_SIZE > cl->buff.first) {
			freeMem(cl->buff.second);
			cl->buff.second = allocMem(PROTOCOL_BUFFER_SIZE);
			if(cl->buff.second == NULL) {count=0xff; break;}
			cl->buff.first = PROTOCOL_BUFFER_SIZE;
		}
		sz = formFrame(cl->buff.first,cl->buff.second,cl->dev->Id,sz, tempArray,TRUE);
		if(!sz) {
			count = 0xFF;
			break;
		}
		count++;
		registerCallBack(DeviceReadWork,count,(BaseParam_t)cl,(void*)((u32*)sendToClient + cl->sessionId));
		SetTask((TaskMng)sendToClient,cl->sessionId, (BaseParam_t)(&cl->buff));
		return;
	case 2: // Ждем подтверждения о получении
		count++;
		registerCallBack(DeviceReadWork,count, (BaseParam_t)cl, (void*)((u32*)receiveFromClient+cl->sessionId));
		SetTask((TaskMng)receiveFromClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	case 3: //
		count++;
		if(findStr(OK,(string_t)cl->buff.second) > 0) { // подтверждение отправляется без шифрования
			writeLogStr("OK find!!!\r\n");
		}else {
			writeLogStr("ERROR: OK not find\r\n");
		}
		//no break;
	default:
		execCallBack((void*)((u32*)DeviceReadWork + cl->sessionId));
		return;
	}
	SetTask(DeviceReadWork,count,(BaseParam_t)cl);
}

static void ClientWork(BaseSize_t arg_n, BaseParam_t client) {
	u16 id;
	u16 effectiveSize;
	s16 isWriteToServer = 0;
	Client_t* cl = (Client_t*)client;
	u08 buff[PROTOCOL_BUFFER_SIZE]; // Для разшифровки полученного сообщения
	if(findStr(WriteToServerSymb,(string_t)cl->buff.second) > 0) isWriteToServer = 1; // Значит пакет на запись данных на сервер
	else if(findStr(ReadFromSeverSymb,(string_t)cl->buff.second) > 0) isWriteToServer = -1; // Значит пакет на чтение данных с сервера
	if(!isWriteToServer) { // Значит не известный пакет
		execCallBack((void*)((u32*)ClientWork+cl->sessionId));
		return;
	}
	effectiveSize = parseFrame(&id, cl->buff.first,cl->buff.second, PROTOCOL_BUFFER_SIZE, buff); // Парсим сообщение (проверка контрольной суммы)
	if(id != 0 && effectiveSize > 0) {	// Если парсинг сообщения прошел успешно
		cl->dev = findDeviceById(id);	// Пытаемся найти идентификатор
		if(cl->dev != NULL) { // Нашли такое устройство
			for(u08 i = 0; i<cl->buff.first; i+=KEY_SIZE) {
				if(isSecure) AesEcbDecrypt(buff+i,cl->dev->Key,cl->buff.second+i); // Расшифровуем полученное сообщение
				else memCpy(cl->buff.second+i, buff+i, KEY_SIZE); // Без шифрования
			}
			if(isWriteToServer > 0) { // Если сообщение на запись данных на сервер
				cl->buff.first = effectiveSize; // Сохраняем размер полезного сообщения
				changeCallBackLabel((void*)((u32*)ClientWork + cl->sessionId), (void*)((u32*)DeviceWriteWork + cl->sessionId));
				SetTask(DeviceWriteWork,0,(BaseParam_t)cl); // Запуская воркера на запись
				return;
			} else { // Иначе сообщения на чтение с сервера
				changeCallBackLabel((void*)((u32*)ClientWork + cl->sessionId), (void*)((u32*)DeviceReadWork + cl->sessionId));
				SetTask(DeviceReadWork,0,(BaseParam_t)cl); // Запускаям воркера на чтение
				return;
			}
		}
		else  // Если устройство мы не нашли в списке устройств
			if(id < 0xFF) {// Значит устройства с таким Id не существует проверяем не ригистрация ли это
			cl->dev = (Device_t*)allocMem(sizeof(Device_t));
			if(cl->dev == NULL) {
				execCallBack((void*)((u32*)ClientWork+cl->sessionId));
				return;
			}
			writeLogStr((string_t)cl->buff.second);
			cl->dev->Id = id;
			changeCallBackLabel((void*)((u32*)ClientWork + cl->sessionId), (void*)((u32*)NewDeviceCreate + cl->sessionId));
			SetTask(NewDeviceCreate,0,(BaseParam_t)cl);
			return;
		}
	}
	execCallBack((void*)((u32*)ClientWork+cl->sessionId));
	return;
}

static void InitializeServer() {
	DeviceList = createNewList(NULL);
	changeCallBackLabel(InitializeServer,(void*)getAllParameters);
	getAllParameters(DeviceList);
}

void SetClientHandlers(TaskMng writeHandler, TaskMng readHandler) {
	WriteHandler = writeHandler;
	ReadHandler = readHandler;
}

void ServerIotWork(BaseSize_t arg_n, BaseParam_t arg_p) {
	if(DeviceList == NULL) {
		registerCallBack(ServerIotWork,arg_n,arg_p,InitializeServer);
		InitializeServer();
		return;
	}
	u16 sessionId = getNextReadyDevice();
	if(sessionId) {
		Client_t* c = (Client_t*)allocMem(sizeof(Client_t));
		if(c != NULL) { // Удалось создать клиента
			c->sessionId = sessionId;
			c->buff.first = PROTOCOL_BUFFER_SIZE;
			c->buff.second = allocMem(c->buff.first);
			if(c->buff.second != NULL) {
				registerCallBack(ClientWork, 0, (BaseParam_t)c, (void*)((u32*)receiveFromClient+sessionId));
				registerCallBack((TaskMng)freeClient,sessionId,(BaseParam_t)c,(void*)((u32*)ClientWork+sessionId));
				SetTask((TaskMng)receiveFromClient, sessionId, (BaseParam_t)(&c->buff));
			}
		}
	}
	SetTimerTask(ServerIotWork,sessionId,arg_p,TIME_DELAY_IF_BUSY);
}
