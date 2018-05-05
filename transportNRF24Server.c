/*
 * transportNRF24Server.h
 *
 *  Created on: 5 мая 2018 г.
 *      Author: blabu
 */

#include "transportServer.h"
#include "nrf24.h"
#include "nrf24AppLayer.h"
#include "logging.h"
#include "MyString.h"
#include "initTransmitLL.h"

#define MAX_CHANNEL 2

typedef struct {
		bool_t isReady;
		u08 pipeNumber;
		channel_t pipe;
		byte_ptr buff;
} channelBuff_t;

channelBuff_t receiveBuf[MAX_CHANNEL];

void socetReceivePacet(BaseSize_t pipeNumber, BaseParam_t buff) {
	if(pipeNumber == receiveBuf[0].pipeNumber) {
		receiveBuf[0].isReady = TRUE;
		receiveBuf[0].buff = buff;
	}
}

// Устройство в режиме сервера всегда работает как приемник
void initTransportLayer(u08 channel, byte_ptr addrHeader) {
    nRF24_Init();
	nRF24_SetPowerMode(nRF24_PWR_DOWN);
	nRF24_CE_L();
	for(u08 i = 0; i<MAX_CHANNEL; i++) {
		receiveBuf[i].isReady = FALSE;
		receiveBuf[i].pipe.address[0] = i+1;  // Server address 1_5
		receiveBuf[i].pipe.address[1] = addrHeader[3]; // Server address 1_1
		receiveBuf[i].pipe.address[2] = addrHeader[2]; // Server address 1_2
		receiveBuf[i].pipe.address[3] = addrHeader[1]; // Server address 1_3
		receiveBuf[i].pipe.address[4] = addrHeader[0]; // Server address 1_4
		receiveBuf[i].pipe.channel = channel;
		receiveBuf[i].pipe.dataLength = 32;
		receiveBuf[i].pipeNumber = i;
	}
	registerCallBack((TaskMng)RXModeRetry,receiveBuf[0].pipeNumber,(BaseParam_t)(&receiveBuf[0].pipe),configureNRF24);
	SetTask(configureNRF24,nRF24_DR_250kbps,NULL);
	changeCallBackLabel(initTransportLayer,RXModeRetry);
	connectTaskToSignal(socetReceivePacet,(void*)nrf24ReceiveMessagesSignal);
}

// Функция непосредственной отправки данных
// Устройство всегда работает на прием информации (за исключение необходимости передать что-то)
void sendToClient(u16 id,  ClientData_t *data){
	static u08 count = 0;
	switch(count) {
		case 0:
			id--; // id всегда больше нуля (для приведения его к порядковому номеру в масиве см. getNextReadyDevice)
			if(id >= MAX_CHANNEL) {count = 0xff; break;}
			count++;
			registerCallBack((TaskMng)sendToClient,id,(BaseParam_t)data,TXModeRetry);
			SetTask((TaskMng)TXModeRetry,0,(BaseParam_t)&receiveBuf[id].pipe);
			return;
		case 1:
			count++;
			registerCallBack((TaskMng)sendToClient,id,(BaseParam_t)data,TransmitPacket);
			SetTask(TransmitPacket,receiveBuf[id].pipe.dataLength,data->second); // Необходимо заполнить весь буфер (можно мусором)
			return;
		case 2: // Возвращаемся в режим приема
			count++;
			registerCallBack((TaskMng)sendToClient,id,(BaseParam_t)data,RXModeRetry);
			SetTask((TaskMng)RXModeRetry,receiveBuf[id].pipeNumber,(BaseParam_t)&receiveBuf[id].pipe);
			return;
		default:
			count = 0;
			id++; // Для вызова колбэка вернем id (см. case 0)
			execCallBack((void*)((u32*)sendToClient + id));
			return;
	}
	SetTask((TaskMng)sendToClient,id,(BaseParam_t)data);
}

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFromClient(u16 id, ClientData_t *result){
	if(id >= MAX_CHANNEL) {
		// Здесь мы быть не должны
		execCallBack((void*)((u32*)receiveFromClient + id));
		return;
	}
	u08 i = id-1;
	if(receiveBuf[i].buff != NULL) { // Если есть данные
		memCpy(result->second,receiveBuf[i].buff,result->first); // Читаем ровно столько сколько попросили
		receiveBuf[i].buff = NULL; // Обнуляем буфер для получения следующих данных
		execCallBack((void*)((u32*)receiveFromClient + id));
		return;
	}
	SetTimerTask((TaskMng)receiveFromClient,id,(BaseParam_t)result,1);
	return;
}

// Вернет идентификатор следующего готового узла для работы. (0 означает, что нет готовых узлов)
u16 getNextReadyDevice(){
	for(u08 i = 0; i<2; i++) {
		if(receiveBuf[i].isReady) {
			receiveBuf[i].isReady = FALSE;
			return i+1;
		}
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


