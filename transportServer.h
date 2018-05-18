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
#include "initLowLevelModule.h"

#ifndef PROTOCOL_BUFFER_SIZE
#define PROTOCOL_BUFFER_SIZE 32 // Размер буферов приема и передачи
#endif

typedef PAIR(u16, byte_ptr) ClientData_t;

// Функция непосредственной отправки данных
void sendToClient(u16 id,  ClientData_t *data);

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFromClient(u16 id, ClientData_t *result);

// Вернет идентификатор следующего готового узла для работы. (0 означает, что нет готовых узлов)
u16 getNextReadyDevice();

// Функция обновления устройства
void updateDevice(Device_t* dev);

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getAllParameters(ListNode_t* DeviceList);

void addNewDevice(Device_t* dev);

#endif /* TRANSPORTSERVER_H_ */
