/*
 * transportNRF24Server.h
 *
 *  Created on: 5 мая 2018 г.
 *      Author: blabu
 */

#include "nrf24.h"
#include "nrf24AppLayer.h"
#include "logging.h"
#include "MyString.h"
#include "initTransmitLL.h"
#include "transportServer.h"
#include "PlatformSpecific.h"

/*
 * Модуль всегда находится в режиме приема
 * Когда нужно что-то передать переключаемся на передатчик
 * и в конце обязательно возвращаемся на прием
 * */

#define MAX_CHANNEL 2

typedef struct {
		bool_t isBusy;
		bool_t isReady;
		u08 pipeNumber;
		channel_t pipe;
		byte_ptr buff;
} channelBuff_t;

static channelBuff_t receiveBuf[MAX_CHANNEL];

static void socetReceivePacet(BaseSize_t pipeNumber, BaseParam_t buff) {
	if(pipeNumber > MAX_CHANNEL) writeLogStr("ERROR: overflow pipe number\r\n");
	if(!receiveBuf[pipeNumber].isBusy) receiveBuf[pipeNumber].isReady = TRUE;
	receiveBuf[pipeNumber].buff = buff;
}

// Устройство в режиме сервера всегда работает как приемник
void initTransportLayer(u08 channel, byte_ptr addrHeader) {
    nRF24_Init();
	nRF24_SetPowerMode(nRF24_PWR_DOWN);
	nRF24_CE_L();
	for(u08 i = 0; i<MAX_CHANNEL; i++) {
		receiveBuf[i].isReady = FALSE;
		receiveBuf[i].isBusy  = FALSE;
		receiveBuf[i].pipe.address[0] = i+1;  // Server address 1_5
		receiveBuf[i].pipe.address[1] = addrHeader[3]; // Server address 1_1
		receiveBuf[i].pipe.address[2] = addrHeader[2]; // Server address 1_2
		receiveBuf[i].pipe.address[3] = addrHeader[1]; // Server address 1_3
		receiveBuf[i].pipe.address[4] = addrHeader[0]; // Server address 1_4
		receiveBuf[i].pipe.channel = channel;
		receiveBuf[i].pipe.dataLength = 32;
		receiveBuf[i].pipeNumber = i;
	}
	SetTask(configureNRF24,nRF24_DR_250kbps,NULL);
	registerCallBack((TaskMng)RXModeRetry,receiveBuf[0].pipeNumber,(BaseParam_t)(&receiveBuf[0].pipe),configureNRF24);
//	registerCallBack((TaskMng)RXModeRetry,receiveBuf[1].pipeNumber,(BaseParam_t)(&receiveBuf[0].pipe),(u32*)RXModeRetry+receiveBuf[0].pipeNumber);
	changeCallBackLabel(initTransportLayer,(u32*)RXModeRetry+receiveBuf[0].pipeNumber);
	connectTaskToSignal(socetReceivePacet,(void*)signalNrf24ReceiveMessages);
}

static void offSession(BaseSize_t id, BaseParam_t arg_p) {
	if(id > MAX_CHANNEL) {
		execCallBack(((void*)(u32*)offSession+id));
		return;
	}
	u08 i = id-1;
	receiveBuf[i].isBusy = FALSE;
	receiveBuf[i].buff = NULL;
	execCallBack(((void*)(u32*)offSession+id));
}

static void EnableTransmitter(u16 id,  ClientData_t *data) {
	nRF24_SetPowerMode(nRF24_PWR_DOWN);
	u08 i = id-1;
	updateTimer(offSession,id,NULL,TICK_PER_SECOND<<2);
	changeCallBackLabel((void*)((u32*)EnableTransmitter+id),TXModeRetry);
	SetTask((TaskMng)TXModeRetry,0,(BaseParam_t)&receiveBuf[i].pipe);
	return;
}

static void DisableTransmitter(u16 id,  ClientData_t *data) {
	u08 i = id-1;
	nRF24_SetPowerMode(nRF24_PWR_DOWN);
	changeCallBackLabel((void*)((u32*)DisableTransmitter+id),(u32*)RXModeRetry+receiveBuf[i].pipeNumber);
	SetTask((TaskMng)RXModeRetry,receiveBuf[i].pipeNumber,(BaseParam_t)&receiveBuf[i].pipe);
	return;
}

static void Send(u16 id,  ClientData_t *data){
	u08 i = id-1;
	changeCallBackLabel((void*)((u32*)Send+id),TransmitPacket);
	SetTimerTask(TransmitPacket,receiveBuf[i].pipe.dataLength,data->second,2); // Необходимо заполнить весь буфер (можно мусором)
	return;
}

// Функция непосредственной отправки данных
// Устройство всегда работает на прием информации (за исключение необходимости передать что-то)
void sendToClient(u16 id,  ClientData_t *data){
	if(id > MAX_CHANNEL) { execCallBack((void*)((u32*)sendToClient + id)); return;}
	u08 i = id-1;
	if(!receiveBuf[i].isBusy) {execCallBack((void*)((u32*)sendToClient + id)); return;}
	SetTask((TaskMng)EnableTransmitter,id,(BaseParam_t)data);
	registerCallBack((TaskMng)Send,id,(BaseParam_t)data,(void*)((u32*)EnableTransmitter+id));
	registerCallBack((TaskMng)DisableTransmitter,id,(BaseParam_t)data,(void*)((u32*)Send+id));
	changeCallBackLabel((void*)((u32*)sendToClient + id),(void*)((u32*)DisableTransmitter+id));
}

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFromClient(u16 id, ClientData_t *result){
	if(id > MAX_CHANNEL) {
		// Здесь мы быть не должны
		writeLogStr("ERROR: Incorrect session Id\r\n");
		execCallBack((void*)((u32*)receiveFromClient + id));
		return;
	}
	u08 i = id-1;
	if(receiveBuf[i].buff != NULL) { // Если есть данные
		updateTimer(offSession,id,NULL,TICK_PER_SECOND<<2);
		memCpy(result->second,receiveBuf[i].buff,result->first); // Читаем ровно столько сколько попросили
		receiveBuf[i].buff = NULL; // Обнуляем буфер для получения следующих данных
		execCallBack((void*)((u32*)receiveFromClient + id));
		return;
	} else if (!receiveBuf[i].isBusy) {
		execCallBack((void*)((u32*)receiveFromClient + id));
		return;
	}
	writeLogStr(".");
	SetTimerTask((TaskMng)receiveFromClient,id,(BaseParam_t)result,TIME_DELAY_IF_BUSY);
	return;
}

// Вернет идентификатор следующего готового узла для работы. (0 означает, что нет готовых узлов)
u16 getNextReadyDevice(){
	for(u08 i = 0; i<2; i++) {
		if(receiveBuf[i].isReady) {
			receiveBuf[i].isReady = FALSE;
			receiveBuf[i].isBusy = TRUE;
			SetTimerTask(offSession,i+1,NULL,TICK_PER_SECOND<<2);
			return i+1;
		}
	}
	return 0;
}

void printDevice(BaseSize_t arg_n, BaseParam_t device) {
	Device_t* dev = (Device_t*)device;
	writeLogU32(dev->Id);
}

// Функция сохрания параметры в память
void saveAllParameters(ListNode_t* DeviceList) {
	ForEachListNodes(DeviceList,printDevice,TRUE,0);
	writeLogStr("SAVE all parameters");
	execCallBack(saveAllParameters);
}

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getAllParameters(ListNode_t* DeviceList) {
	execCallBack(getAllParameters);
}


