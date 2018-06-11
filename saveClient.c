/*
 * saveClient.c
 *
 *  Created on: 9 июн. 2018 г.
 *      Author: blabu
 */
#include "IotProtocolClient.h"
#include "logging.h"
#include "MyString.h"
#include "baseEntity.h"
#include "utility.h"

static Device_t __device; //FIXME Наше хранилище (пока в ОЗУ)

#include "MyString.h"
// Функция сохрания параметры в память
void saveParameters(u16 id, byte_ptr key, u08 size,  bool_t isSecure) {
	__device.Id = id;
	__device.isSecure = isSecure;
	memCpy(__device.Key,key,size);
	char temp[50];
	temp[0] = 0; strCat(temp,"SV=");
	serializeDevice(temp+strSize(temp), &__device);
	writeLogTempString(temp);
	execCallBack(saveParameters);
}

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getParameters(u08 size, Device_t* dev) {
	dev->Id = __device.Id;
	memCpy(dev->Key, __device.Key, size);
	dev->isSecure = __device.isSecure;
	execCallBack(getParameters);
}

