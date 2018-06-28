/*
 * transportServer.h
 *
 *  Created on: Mar 28, 2018
 *      Author: okh
 */

#ifndef TRANSPORTSERVER_H_
#define TRANSPORTSERVER_H_

#include "TaskMngr.h"
#include "baseEntity.h"

#ifndef PROTOCOL_BUFFER_SIZE
#define PROTOCOL_BUFFER_SIZE 32 // Размер буферов приема и передачи
#endif

// Функция непосредственной отправки данных
void sendToClient(u16 sessionID,  ClientData_t *data);

// В случае, когда сервер является инициатором передачи данных.
void pushToClient(BaseSize_t count, channelBuff_t* client);

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFromClient(u16 sessionID, ClientData_t *result);

// Вернет идентификатор следующего готового узла для работы. (0 означает, что нет готовых узлов)
u16 getNextReadyDevice();

#endif /* TRANSPORTSERVER_H_ */
