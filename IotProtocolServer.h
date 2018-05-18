/*
 * IotProtocolServer.h
 *
 *  Created on: Mar 28, 2018
 *      Author: okh
 */

#ifndef IOTPROTOCOLSERVER_H_
#define IOTPROTOCOLSERVER_H_

#include "TaskMngr.h"

void allowRegistration(bool_t isEnable);
void ServerIotWork(BaseSize_t arg_n, BaseParam_t arg_p);
void SetClientHandlers(TaskMng writeHandler, TaskMng readHandler);

#endif /* IOTPROTOCOLSERVER_H_ */
