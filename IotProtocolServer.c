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

#define KEY_SIZE 16

static const string_t keyAttribute = "KEY;";
static const string_t registerAttribute = "?;REG";

static bool_t isSecure = FALSE;
static ListNode_t* DeviceList; // Хранит указатель на голову списка устройств

typedef struct {
	u16 sessionId;
	PAIR(u16, byte_ptr) buff;
	Device_t* dev;
} Client_t;



static u16 generateNewId(u08 type) {
	u08 temp = RandomSimple() & 0xFF;
	return ((u16)type<<8) & temp;
}

static void generateKey(byte_ptr key) {
	for(u08 i = 0; i<KEY_SIZE; i+=4) {
		u32 temp = RandomSimple();
		*((u32*)(key+i)) = temp;
	}
}

static void freeClient(Client_t* c) {
	freeMem(c->buff.second);
	freeMem(c);
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

static void ClientWork(BaseSize_t count, BaseParam_t client) {
	u16 id;
	Client_t* cl = (Client_t*)client;
	u08 buff[PROTOCOL_BUFFER_SIZE];
	u16 sz;
	switch(count) {
	case 0:
		count++;
		id = parseFrame(cl->buff.first,cl->buff.second, PROTOCOL_BUFFER_SIZE, buff);
		if(id != 0) {
			cl->dev = findDeviceById(id);
			if(cl->dev != NULL){
				sz = cl->buff.first;
				for(u08 i = 0; i<sz; i+=KEY_SIZE) {
					if(isSecure) AesEcbDecrypt(buff+i,cl->dev->Key,cl->buff.second+i); // Расшифровуем полученное сообщение
					else memCpy(cl->buff.second+i, buff+i, KEY_SIZE); // Без шифрования
				}
				writeLogStr((string_t)cl->buff.second);// Анализ полученной информации из cl->buff.second
			}
			else if(id < 0xFF) {// Значит устройства с таким Id не существует и это регистрация
				if(str1_str2(registerAttribute,(string_t)buff)) { // Получили атрибут регистрации
					cl->dev = (Device_t*)allocMem(sizeof(Device_t));
					if(cl->dev == NULL) {count=0xFF; break;}
					generateKey(cl->dev->Key);
					cl->dev->Id = generateNewId(id);  // TODO Убедится в уникальности идентификатора
					putToEndList(DeviceList,(void*)cl->dev,sizeof(Device_t));
					count++;
					memCpy(buff,keyAttribute,strSize(keyAttribute));
					memCpy(buff+strSize(keyAttribute),cl->dev->Key, KEY_SIZE);
					sz = formFrame(cl->buff.first, cl->buff.second,cl->dev->Id,strSize(keyAttribute)+KEY_SIZE,buff);
					if(sz) {
						cl->buff.first = sz;
						registerCallBack(ClientWork,count,(BaseParam_t)cl,(void*)((u32)sendToClient+cl->sessionId));
						sendToClient(cl->sessionId,&cl->buff);
					}
					else {
						count=0xFF;
						break;
					}
				}
			}
		}
		count = 0xFF;
		break;
	default:
		printf("Finish");
		freeClient(cl);
		execCallBack(ClientWork);
		return;
	}
	SetTask(ClientWork,count,(BaseParam_t)cl);
}

void InitializeServer() {
	DeviceList = createNewList(NULL);
	changeCallBackLabel(InitializeServer,(void*)getAllParameters);
	getAllParameters(DeviceList);
}

void ServerIotWork(BaseSize_t arg_n, BaseParam_t arg_p) {
	u16 sessionId = getNextReady();
	if(sessionId) {
		Client_t* c = (Client_t*)allocMem(sizeof(Client_t));
		if(c != NULL) {
			c->sessionId = sessionId;
			c->buff.first = 32;
			c->buff.second = allocMem(c->buff.first);
			if(c->buff.second != NULL) {
				registerCallBack(ClientWork, 0, (BaseParam_t)c, (void*)((u32)receiveFromClient+sessionId));
				receiveFromClient(sessionId,&c->buff);
			}
		}
	}
	SetTimerTask(StartServerIot,sessionId,arg_p,TIME_DELAY_IF_BUSY);
}
