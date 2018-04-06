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
//static const string_t keyAttribute = "KEY;";

static bool_t isSecure = FALSE;
static ListNode_t* DeviceList = NULL; // Хранит указатель на голову списка устройств

typedef struct {
	u16 sessionId;
	PAIR(u16, byte_ptr) buff;
	Device_t* dev;
} Client_t;



static u16 generateNewId(u08 type) {
	u16 temp = RandomSimple() & 0xFF;
	return temp | (u16)(type<<8);
}

static void generateKey(byte_ptr key) {
	for(u08 i = 0; i<KEY_SIZE; i+=4) {
		u32 temp = RandomSimple();
		*((u32*)(key+i)) = temp;
	}
	//memCpy(key,"1234567890123456",KEY_SIZE);
}

static void freeClient(Client_t* c) {
	freeMem(c->buff.second);
	freeMem((byte_ptr)c);
}

Device_t* findDeviceById(u16 devId) {
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

static void ClientWork(BaseSize_t count, BaseParam_t client);

static void NewDeviceCreate(BaseSize_t id, BaseParam_t client) {
	u08 buff[PROTOCOL_BUFFER_SIZE];
	Client_t* cl = (Client_t*)client;
	generateKey(cl->dev->Key);
	cl->dev->Id = generateNewId(id);  // TODO Убедится в уникальности идентификатора
	printf("New deviceId %x for type %x\n", cl->dev->Id, id);
	putToEndList(DeviceList,(void*)cl->dev, sizeof(Device_t)); // Записываем новое устройство в список всех устройств
	memCpy(buff, &(cl->dev->Id), sizeof(cl->dev->Id));
	memCpy(buff+sizeof(cl->dev->Id),cl->dev->Key, KEY_SIZE); // Формируем ответ клиенту с генерированными данными
	u16 sz = formFrame(cl->buff.first, cl->buff.second,id,sizeof(cl->dev->Id)+KEY_SIZE, buff); // Отправляем запрос
	if(sz) {
		cl->buff.first = sz;
		printf("Send to client in session %d,  %s\n",cl->sessionId, cl->buff.second);
		changeCallBackLabel((void*)((u32*)NewDeviceCreate + cl->sessionId), (void*)((u32*)sendToClient + cl->sessionId));
		SetTask(sendToClient, cl->sessionId, (BaseParam_t)(&cl->buff));
		return;
	}
	else execCallBack((void*)((u32*)NewDeviceCreate + cl->sessionId));
}

static void DeviceWork(BaseSize_t count, BaseParam_t client) { // Работа с найденым устройством из списка
	Client_t* cl = (Client_t*)client;
	writeLogStr((string_t)(cl->buff.second));// TODO Анализ полученной информации из cl->buff.second
	execCallBack((void*)((u32*)DeviceWork + cl->sessionId));
}

static void ClientWork(BaseSize_t count, BaseParam_t client) {
	u16 id;
	Client_t* cl = (Client_t*)client;
	u08 buff[PROTOCOL_BUFFER_SIZE];
	switch(count) {
	case 0:
		id = parseFrame(cl->buff.first,cl->buff.second, PROTOCOL_BUFFER_SIZE, buff);
		if(id != 0) {
			cl->dev = findDeviceById(id);
			if(cl->dev != NULL){ // Нашли такое устройство
				for(u08 i = 0; i<cl->buff.first; i+=KEY_SIZE) {
					if(isSecure) AesEcbDecrypt(buff+i,cl->dev->Key,cl->buff.second+i); // Расшифровуем полученное сообщение
					else memCpy(cl->buff.second+i, buff+i, KEY_SIZE); // Без шифрования
				}
				registerCallBack(ClientWork, count, (BaseParam_t)cl, (void*)((u32*)DeviceWork + cl->sessionId));
				SetTask(DeviceWork,0,(BaseParam_t)cl);
				return;
			}
			else if(id < 0xFF) {// Значит устройства с таким Id не существует и это регистрация
				cl->dev = (Device_t*)allocMem(sizeof(Device_t));
				if(cl->dev == NULL) {count = 0xFF; break;}
				count++;
				registerCallBack(ClientWork, count, (BaseParam_t)cl, (void*)((u32*)NewDeviceCreate + cl->sessionId));
				SetTask(NewDeviceCreate,id,(BaseParam_t)cl);
				return;
			}
		}
		count = 0xFF;
		break;
	case 1:
		printf("Call back in session id %d\n",cl->sessionId);
		//no break
	default:
		freeClient(cl);
		printf("Finish client work\n");
		execCallBack((void*)((u32*)ClientWork+cl->sessionId));
		return;
	}
	SetTask(ClientWork,count,(BaseParam_t)cl);
}

static void InitializeServer() {
	printf("Try init\n");
	DeviceList = createNewList(10);
	changeCallBackLabel(InitializeServer,(void*)getAllParameters);
	getAllParameters(DeviceList);
	printf("Pointer %p\n",DeviceList);
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
				SetTask(receiveFromClient, sessionId, (BaseParam_t)(&c->buff));
			}
		}
	}
	SetTimerTask(ServerIotWork,sessionId,arg_p,TIME_DELAY_IF_BUSY);
}
