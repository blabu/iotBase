/*
 * initTransmitLL.h
 *
 *  Created on: 5 мая 2018 г.
 *      Author: blabu
 */

#ifndef INITLOWLEVELMODULE_H_
#define INITLOWLEVELMODULE_H_

#include "TaskMngr.h"

#define KEY_SIZE 16

typedef struct {
	bool_t isSecure; // Флаг показывает работаем мы с шифрованием или без него
	u16 Id;		  // Id устройства
	u08 Key[KEY_SIZE]; // Ключ шифрования
} Device_t;

void initTransportLayer(u08 channel, byte_ptr addrHeader);

void serializeDevice(string_t devStr, Device_t* d);
void deserializeDevice(string_t devStr, Device_t* d);

#endif /* INITLOWLEVELMODULE_H_ */
