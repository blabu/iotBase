/*
 * IotProtocolServer.h
 *
 *  Created on: Mar 28, 2018
 *      Author: okh
 */

#ifndef IOTPROTOCOLSERVER_H_
#define IOTPROTOCOLSERVER_H_

#ifndef PROTOCOL_BUFFER_SIZE
#define PROTOCOL_BUFFER_SIZE 32 // Размер буферов приема и передачи
#endif
#include "TaskMngr.h"

void ServerIotWork(BaseSize_t arg_n, BaseParam_t arg_p);
void SetClientHandlers(TaskMng writeHandler, TaskMng readHandler);


#endif /* IOTPROTOCOLSERVER_H_ */
