/*
 * saveServer.c
 *
 *  Created on: 9 июн. 2018 г.
 *      Author: blabu
 */

#include "IotProtocolServer.h"
#include "logging.h"
#include "MyString.h"
#include "baseEntity.h"
#include "List.h"
#include "utility.h"
#include "usbd_cdc_if.h"

void updateDevice(Device_t* dev) {
	static char str[47];  //UP=S;XXXX;YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY;\r\n
	strClear(str);
	strCat(str,"UP=");
	serializeDevice(str+strSize(str),dev);
	CDC_Transmit_FS((byte_ptr)str,strSize(str));
	execCallBack((u32*)updateDevice + dev->Id);
}

void addNewDevice(Device_t* dev) {
	static char str[47];  //NEW=S;XXXX;YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY;\r\n
	strClear(str);
	strCat(str,"NEW=");
	serializeDevice(str+strSize(str),dev);
	CDC_Transmit_FS((byte_ptr)str,strSize(str));
	execCallBack((u32*)addNewDevice + dev->Id);
}

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getAllParameters(ListNode_t* DeviceList) {
	writeLogStr("Get all parameters");
	execCallBack(getAllParameters);
}

void getAllPushedDevice(ListNode_t* PushedList) {
	execCallBack(getAllPushedDevice);
}

void savePushedDevice(u16 Id, byte_ptr pushAddr) {
	char temp[25];
	strClear(temp);
	strCat(temp,"NEW_PUSH=");
	toStringUnsignDec(Id,temp+strSize(temp));
	strCat(temp,";");
	for(u08 i = 0; i<5; i++) {
		toStringUnsignDec(pushAddr[i],temp+strSize(temp));
	}
	writeLogTempString(temp);
	execCallBack((u32*)savePushedDevice+Id);
}
