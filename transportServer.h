/*
 * transportServer.h
 *
 *  Created on: Mar 28, 2018
 *      Author: okh
 */

#ifndef TRANSPORTSERVER_H_
#define TRANSPORTSERVER_H_

#include "TaskMngr.h"
#include "List.h"

typedef struct {
	u16 Id;
	byte_ptr Key;
	u08 KeySize;
} Device_t;

// Для работы протокола необходимо реализовать эти функции. Каждая из функций ОБЯЗАТЕЛЬНО должна вызывать execCallBack себя же.

// Функция непосредственной отправки данных
void sendTo(u08 sessionId, u16 size, byte_ptr data);

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFrom(u08* sessionId, u16 size, byte_ptr result);

// Функция сохрания параметры в память
void saveParameters(ListNode_t* DeviceList);

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getParameters(ListNode_t* DeviceList);



#endif /* TRANSPORTSERVER_H_ */
