/*
 * initTransmitLL.h
 *
 *  Created on: 5 мая 2018 г.
 *      Author: blabu
 */

#ifndef INITLOWLEVELMODULE_H_
#define INITLOWLEVELMODULE_H_

#include "TaskMngr.h"
#include "baseEntity.h"

void initTransportLayer(u08 channel, byte_ptr serverID);

void serializeDevice(string_t devStr, Device_t* d);
// Вернет -1 если не получилось
s08 deserializeDevice(string_t devStr, Device_t* d);

#endif /* INITLOWLEVELMODULE_H_ */
