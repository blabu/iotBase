/*
 * IotProtocolServer.c
 *
 *  Created on: Mar 28, 2018
 *      Author: okh
 */

#include "IotProtocolServer.h"
#include "transportServer.h"
#include "frame.h"

#define KEY_SIZE 16


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
//
//static void ClientWork(BaseSize_t count, BaseParam_t buffer) {
//	u08 tempContent[PROTOCOL_BUFFER_SIZE];
//	switch(count){
//	case 0:{
//		u16 TempId = parseFrame(getAllocateMemmorySize(buffer),buffer,PROTOCOL_BUFFER_SIZE,tempContent);
//		if(!TempId) {memSet(buffer,getAllocateMemmorySize(buffer),0); count--; break;}
//		if(TempId < 0xFF) { // Если ID < 255 значит это тип
//			s16 poz = findStr(registerAttribute,tempContent);
//			if(poz < 0) {memSet(buffer,getAllocateMemmorySize(buffer),0); count--; break;}
//			TempId = generateNewId((u08)TempId);
//			memSet(tempContent,KEY_SIZE,0);
//			generateKey(tempContent);
//			u16 sz = formFrame(getAllocateMemmorySize(buffer), buffer, TempId, KEY_SIZE, tempContent);
//			count++;
//			registerCallBack(ClientWork, count, buffer, sendTo);
//			SetTask(sendTo,sz,buffer);
//			return;
//		} else {
//
//		}
//	}
//	case 1: // wait OK
//		count++;
//		registerCallBack(ClientWork,count,buffer,receiveFrom);
//		receiveFrom(getAllocateMemmorySize(buffer),buffer);
//	case 2:// check OK
//	default:
//		execCallBack(ClientWork);
//		return;
//	}
//}
//
//void ServerWork(BaseSize_t count, BaseParam_t buffer) {
//	switch(count) {
//	case 0:
//		if(buffer != NULL) freeMem(buffer);
//		buffer = allocMem(PROTOCOL_BUFFER_SIZE);
//		if(buffer == NULL) {count = 0xFF; break;}
//		memSet(buffer,getAllocateMemmorySize(buffer),0);
//		count++;
//		//no break;
//	case 1:
//		count++;
//		registerCallBack(ServerWork,count,buffer,receiveFrom);
//		SetTask(receiveFrom,getAllocateMemmorySize(buffer),buffer);
//		return;
//	case 2:
//		if(!str1_str2(header,(string_t)buffer)) { count--; break; } // Заголовок должен присутствовать
////		registerCallBack(ServerWork,0,buffer,ClientWork);
////		SetTask(ClientWork,0,buffer);
//		return;
//	default:
//		freeMem(buffer);
//		execCallBack(ServerWork);
//		return;
//	}
//	SetTask(ServerWork,count,buffer);
//}

void StartServerIot() {
}
