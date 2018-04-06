/*
 * transportServerExample.c
 *
 *  Created on: Apr 2, 2018
 *      Author: okh
 */
#include "transportServer.h"
#include "frame.h"
#include "stdio.h"

// Функция непосредственной отправки данных
void sendToClient(u16 id, ClientData_t* data) {
	printf("Session id %d, Try send %d bytes\n", id, data->first);
	u08 i = 0;
	for(; i < 12; i++) {
		printf("%c ", data->second[i]);
	}
	for(;i < data->first;i++) {
		printf("0x%x ", data->second[i]);
	}
	printf("Finish\n");
	execCallBack((void*)((u32*)sendToClient + id));
}

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFromClient(u16 id, ClientData_t* result) {
	printf("Receive pointer %p\n",result->second);
	u08 s = formFrame(result->first, result->second, 0x35, 12,"Hello wor123");
	printf("Receive from client %s size is %d\n",result->second,s);
	execCallBack((void*)((u32*)receiveFromClient + id));
}

// Вернет идентификатор следующего готового узла для работы. (Отрицательное число означает, что нет готовых узлов)
u16 getNextReadyDevice() {
	static u08 count = 0;
	count++;
	if(!(count % 25)) {
		return count;
	}
	return 0;
}

// Функция сохрания параметры в память
void saveAllParameters(ListNode_t* DeviceList) {
	execCallBack(saveAllParameters);
}

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getAllParameters(ListNode_t* DeviceList) {
	execCallBack(getAllParameters);
}
