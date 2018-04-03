/*
 * transportServerExample.c
 *
 *  Created on: Apr 2, 2018
 *      Author: okh
 */
#include "transportServer.h"

// Функция непосредственной отправки данных
void sendToClient(u16 id, PAIR(u16, byte_ptr)* data) {
	for(u16 i = 0; i<data->first; i++) printf("%d ", data->second[i]);
	execCallBack((void*)((u32)sendToClient + id));
}

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFromClient(u16 id, PAIR(u16, byte_ptr) *result) {
	for(u16 i = 0; i<result->first; i++) result->second = i+0x30;
	execCallBack((void*)((u32)receiveFromClient + id));
}

// Вернет идентификатор следующего готового узла для работы. (Отрицательное число означает, что нет готовых узлов)
s32 getNextReady() {
	printf("Try next");
	return 10;
}

// Функция сохрания параметры в память
void saveAllParameters(ListNode_t* DeviceList) {
	execCallBack(saveAllParameters);
}

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getAllParameters(ListNode_t* DeviceList) {
	execCallBack(getAllParameters);
}
