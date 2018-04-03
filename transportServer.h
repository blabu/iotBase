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
	u08 Key[16];
} Device_t;


// Функция непосредственной отправки данных
void sendToClient(u16 id, PAIR(u16, byte_ptr) *data);

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFromClient(u16 id, PAIR(u16, byte_ptr) *result);

// Вернет идентификатор следующего готового узла для работы. (0 означает, что нет готовых узлов)
u16 getNextReadyDevice();

// Функция сохрания параметры в память
void saveAllParameters(ListNode_t* DeviceList);

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getAllParameters(ListNode_t* DeviceList);


#endif /* TRANSPORTSERVER_H_ */
