/*
 * initTransmitLL.h
 *
 *  Created on: 5 мая 2018 г.
 *      Author: blabu
 */

#ifndef INITTRANSMITLL_H_
#define INITTRANSMITLL_H_

#include "TaskMngr.h"

typedef struct {
	bool_t isSecure;
	u16 Id;
	u08 Key[16];
} Device_t;

void initTransportLayer(u08 channel, byte_ptr addrHeader);

#endif /* INITTRANSMITLL_H_ */
