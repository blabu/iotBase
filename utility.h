/*
 * utility.h
 *
 *  Created on: 7 черв. 2018 р.
 *      Author: Admin
 */

#ifndef UTILITY_H_
#define UTILITY_H_

#include "baseEntity.h"
#include "MyString.h"

void serializeDevice(string_t devStr, Device_t* d);

// Вернет -1 если не получилось
s08 deserializeDevice(string_t devStr, Device_t* d);


#endif /* UTILITY_H_ */
