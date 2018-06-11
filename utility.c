/*
 * utility.c
 *
 *  Created on: 7 черв. 2018 р.
 *      Author: Admin
 */

#include "utility.h"

void serializeDevice(string_t devStr, Device_t* d) {
	if(devStr == NULL || d == NULL) return;
	char tempStr[6];
	strClear(devStr);
	toString(1,d->isSecure,tempStr);
	strCat(devStr,tempStr);
	strCat(devStr,";");
	toString(2,d->Id,tempStr);
	strCat(devStr,tempStr);
	strCat(devStr,";");
	for(u08 i = 0; i<KEY_SIZE; i++) {
		toString(1,d->Key[i],tempStr);
		strCat(devStr,tempStr);
	}
	strCat(devStr,";\r\n");
}

// Вернет -1 если не получилось
s08 deserializeDevice(string_t devStr, Device_t* d) {
	if(devStr == NULL || d == NULL) return -1;
	u08 c = strSplit(';',devStr);
	if(c<3) return -1;
	d->isSecure = toInt08(devStr);
	devStr += strSize(devStr);
	d->Id = toInt32(devStr);
	devStr += strSize(devStr);
	char tempStr[4];
	for(u08 i = 0; i<KEY_SIZE; i++) {
		tempStr[0] = *devStr++;
		tempStr[1] = *devStr++;
		tempStr[3] = 0;
		d->Key[i] = toInt16(tempStr);
	}
	return 0;
}
