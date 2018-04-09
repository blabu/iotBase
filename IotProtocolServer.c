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

#define KEY_SIZE 16

static bool_t isSecure = FALSE;
static ListNode_t* DeviceList = NULL; // Хранит указатель на голову списка устройств

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
	//memCpy(key,"1234567890123456",KEY_SIZE); // Удалить после отладки
}

static void freeClient(BaseSize_t sessionId, Client_t* c) {
	freeMem(c->buff.second);
	freeMem(c->newKey);
	freeMem((byte_ptr)c);
}

static void ClientWork(BaseSize_t count, BaseParam_t client);

static void NewDeviceCreate(BaseSize_t id, BaseParam_t client) {
	u08 buff[PROTOCOL_BUFFER_SIZE];
	Client_t* cl = (Client_t*)client;
	generateKey(cl->dev->Key);
	cl->dev->Id = generateNewId(id);
	printf("New deviceId %x for type %x\n", cl->dev->Id, id);
	putToEndList(DeviceList,(void*)cl->dev, sizeof(Device_t)); // Записываем новое устройство в список всех устройств
	memCpy(buff, &(cl->dev->Id), sizeof(cl->dev->Id));
	memCpy(buff+sizeof(cl->dev->Id),cl->dev->Key, KEY_SIZE); // Формируем ответ клиенту с генерированными данными
	u16 sz = formFrame(cl->buff.first, cl->buff.second,id,sizeof(cl->dev->Id)+KEY_SIZE, buff, TRUE); // Отправляем запрос
	if(sz) {
		cl->buff.first = sz;
		printf("Send to client in session %d,  %s\n",cl->sessionId, cl->buff.second);
		changeCallBackLabel((void*)((u32*)NewDeviceCreate + cl->sessionId), (void*)((u32*)sendToClient + cl->sessionId));
		SetTask(sendToClient, cl->sessionId, (BaseParam_t)(&cl->buff));
		return;
	}
	else {
		execCallBack((void*)((u32*)NewDeviceCreate + cl->sessionId));
	}
}

static void DeviceWriteWork(BaseSize_t count, BaseParam_t client) { // Работа с найденым устройством из списка
	Client_t* cl = (Client_t*)client;
	u08 sz = 0;
	u08 tempBuff[KEY_SIZE];
	switch(count) {
	case 0:
		count++;
		writeLogStr((string_t)(cl->buff.second));// TODO Анализ полученной информации из cl->buff.second (на запись)
		break;
	case 1:
		cl->newKey = allocMem(KEY_SIZE);
		if(cl->newKey == NULL) {
			count=0xFF;
			break;
		}
		generateKey(cl->newKey);
		if(isSecure) AesEcbEncrypt(cl->newKey,cl->dev->Key,tempBuff);
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
	case 2:
		count++;
		registerCallBack(DeviceWriteWork,count,(BaseParam_t)cl, (void*)((u32*)receiveFromClient+cl->sessionId));
		SetTask((TaskMng)receiveFromClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	case 3:
		count++;
		if(findStr(OK,(string_t)cl->buff.second) > 0) { // подтверждение отправляется без шифрования
			memCpy(cl->dev->Key,cl->newKey,KEY_SIZE);
			saveAllParameters(DeviceList);
		}else {
			printf("OK not find\n");
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
	writeLogStr((string_t)(cl->buff.second));// TODO Анализ полученной информации из cl->buff.second
	execCallBack((void*)((u32*)DeviceReadWork + cl->sessionId));
}

static void ClientWork(BaseSize_t arg_n, BaseParam_t client) {
	u16 id;
	s16 isWriteToServer = 0;
	Client_t* cl = (Client_t*)client;
	u08 buff[PROTOCOL_BUFFER_SIZE];
	if(findStr(WriteToServerSymb,(string_t)cl->buff.second) > 0) isWriteToServer = 1; // Значит пакет на запись данных на сервер
	else if(findStr(ReadFromSeverSymb,(string_t)cl->buff.second) > 0) isWriteToServer = -1; // Значит пакет на чтение данных с сервера
	if(!isWriteToServer) { // Значит не известный пакет
		execCallBack((void*)((u32*)ClientWork+cl->sessionId));
		return;
	}
	id = parseFrame(cl->buff.first,cl->buff.second, PROTOCOL_BUFFER_SIZE, buff);
	if(id != 0) {
		cl->dev = findDeviceById(id);
		if(cl->dev != NULL){ // Нашли такое устройство
			for(u08 i = 0; i<cl->buff.first; i+=KEY_SIZE) {
				if(isSecure) AesEcbDecrypt(buff+i,cl->dev->Key,cl->buff.second+i); // Расшифровуем полученное сообщение
				else memCpy(cl->buff.second+i, buff+i, KEY_SIZE); // Без шифрования
			}
			if(isWriteToServer > 0) {
				changeCallBackLabel((void*)((u32*)ClientWork + cl->sessionId), (void*)((u32*)DeviceWriteWork + cl->sessionId));
				SetTask(DeviceWriteWork,0,(BaseParam_t)cl);
				return;
			} else {
				changeCallBackLabel((void*)((u32*)ClientWork + cl->sessionId), (void*)((u32*)DeviceReadWork + cl->sessionId));
				SetTask(DeviceReadWork,0,(BaseParam_t)cl);
				return;
			}
		}
		else if(id < 0xFF) {// Значит устройства с таким Id не существует и это регистрация
			cl->dev = (Device_t*)allocMem(sizeof(Device_t));
			printf("device pointer %p\n",cl->dev);
			if(cl->dev == NULL) {
				execCallBack((void*)((u32*)ClientWork+cl->sessionId));
				return;
			}
			changeCallBackLabel((void*)((u32*)ClientWork + cl->sessionId), (void*)((u32*)NewDeviceCreate + cl->sessionId));
			SetTask(NewDeviceCreate,id,(BaseParam_t)cl);
			return;
		}
		printf("Undefined id in list %d\n", id);
	}
	execCallBack((void*)((u32*)ClientWork+cl->sessionId));
	return;
}

void print(BaseSize_t a, BaseParam_t data) {
	if(data == NULL) return;
	printf("Try print in foreach %d, %p\n", a, data);
	Device_t* d = (Device_t*)data;
	writeLogU32(d->Id);
}

static void InitializeServer() {
	printf("Try init\n");
	DeviceList = createNewList(NULL);
	changeCallBackLabel(InitializeServer,(void*)getAllParameters);
	getAllParameters(DeviceList);
	ForEachListNodes(DeviceList,print,FALSE,11);
	printf("Pointer %p\n",DeviceList);
}

void SetClientHandler(TaskMng handler, BaseSize_t arg_n, BaseParam_t arg_p) {

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
		printf("Client pointer %p in session Id %d\n",c,sessionId);
		if(c != NULL) { // Удалось создать клиента
			c->sessionId = sessionId;
			c->buff.first = PROTOCOL_BUFFER_SIZE;
			c->buff.second = allocMem(c->buff.first);
			printf("Client buffer pointer %p\n",c->buff.second);
			if(c->buff.second != NULL) {
				registerCallBack(ClientWork, 0, (BaseParam_t)c, (void*)((u32*)receiveFromClient+sessionId));
				registerCallBack((TaskMng)freeClient,sessionId,(BaseParam_t)c,(void*)((u32*)ClientWork+sessionId));
				SetTask(receiveFromClient, sessionId, (BaseParam_t)(&c->buff));
			}
		}
	}
	SetTimerTask(ServerIotWork,sessionId,arg_p,TIME_DELAY_IF_BUSY);
}
