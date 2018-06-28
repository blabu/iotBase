/*
 * hostDriverAPI.h
 *
 *  Created on: 21 черв. 2018 р.
 *      Author: Admin
 */

#ifndef HOSTDRIVERAPI_H_
#define HOSTDRIVERAPI_H_
#include "List.h"
#include "TaskMngr.h"
#include "baseEntity.h"

// Функция обновления устройства
void updateDevice(Device_t* dev);
void addNewDevice(Device_t* dev);

void savePushedDevice(u16 Id, byte_ptr pushAddr);

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getAllParameters(BaseSize_t count, ListNode_t* DeviceList);
void getAllPushedDevice(BaseSize_t count, ListNode_t* PushedList);

#endif /* HOSTDRIVERAPI_H_ */
