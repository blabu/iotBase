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
#include "initLowLevelModule.h"
#include "transportServer.h"
#include "PlatformSpecific.h"
#include "config.h"
#include "led.h"


/*
 * Модуль всегда находится в режиме приема
 * Когда нужно что-то передать переключаемся на передатчик
 * и в конце обязательно возвращаемся на прием
 * */
#ifdef RETRY_ENABLE
#define RX_MODE RXModeRetry
#define TX_MODE TXModeRetry
#else
#define RX_MODE RXMode
#define TX_MODE TXMode
#endif

#define NRF1_MUTEX_1 1<<0
#define NRF1_MUTEX_2 1<<1

#define MAX_CHANNEL_1 5

static channelBuff_t receiveBuf[MAX_CHANNEL_1];
#ifdef SERVER
static void socetReceivePacet(BaseSize_t pipeNumber, BaseParam_t buff) {
	if(pipeNumber >= MAX_CHANNEL_1) writeLogStr("ERROR: incorrect pipe number");
	if(!receiveBuf[pipeNumber].isBusy) {
		writeSymb('+');
		writeLogU32(pipeNumber);
		receiveBuf[pipeNumber].isReady = TRUE;
	}
	if(receiveBuf[pipeNumber].buff == NULL){ // Аллоцируем память если еще этого не делали
		receiveBuf[pipeNumber].buff = allocMem(receiveBuf[pipeNumber].pipe.dataLength);
		if(receiveBuf[pipeNumber].buff == NULL){
			writeLogStr("ERROR: memmory allocate for receive buffer");
			receiveBuf[pipeNumber].buff = buff;  // Если памяти совсем нет, будем надеятся что успеем считать данные
			return;
		}
	}
	writeSymb('|');
	memCpy(receiveBuf[pipeNumber].buff,buff,receiveBuf[pipeNumber].pipe.dataLength);
}

// Устройство в режиме сервера всегда работает как приемник
void initTransportLayer(u08 channel, byte_ptr serverID) {
    nRF24_Init();
	nRF24_SetPowerMode(1, nRF24_PWR_DOWN);
	setChipEnable(1,FALSE);
	receiveBuf[0].isReady = FALSE; receiveBuf[0].isBusy  = FALSE;
	receiveBuf[0].buff = NULL;
	receiveBuf[0].pipeNumber = 0;
	receiveBuf[0].pipe.address[0] = PING_ADDR[0];  // Server address 1_5
	receiveBuf[0].pipe.address[1] = PING_ADDR[1]; // Server address 1_1
	receiveBuf[0].pipe.address[2] = PING_ADDR[2]; // Server address 1_2
	receiveBuf[0].pipe.address[3] = PING_ADDR[3]; // Server address 1_3
	receiveBuf[0].pipe.address[4] = PING_ADDR[4]; // Server address 1_4
	receiveBuf[0].pipe.channel = channel;
	receiveBuf[0].pipe.dataLength = 32;
	for(u08 i=1; i<MAX_CHANNEL_1; i++) {
		receiveBuf[i].isReady = FALSE; receiveBuf[i].isBusy  = FALSE;
		receiveBuf[i].buff = NULL;
		receiveBuf[i].pipeNumber = i;
		receiveBuf[i].pipe.address[0] = i+1;  // Server address 1_5
		receiveBuf[i].pipe.address[1] = serverID[1]; // Server address 1_1
		receiveBuf[i].pipe.address[2] = serverID[2]; // Server address 1_2
		receiveBuf[i].pipe.address[3] = serverID[3]; // Server address 1_3
		receiveBuf[i].pipe.address[4] = serverID[4]; // Server address 1_4
		receiveBuf[i].pipe.channel = channel;
		receiveBuf[i].pipe.dataLength = 32;
		registerCallBack((TaskMng)RX_MODE,receiveBuf[i].pipeNumber,(BaseParam_t)(&receiveBuf[i].pipe),(u32*)RX_MODE+receiveBuf[i-1].pipeNumber);
	}
	SetTask(configureNRF24,nRF24_DR_250kbps,NULL);
	registerCallBack((TaskMng)RX_MODE,receiveBuf[0].pipeNumber,(BaseParam_t)(&receiveBuf[0].pipe),configureNRF24);
	registerCallBack((TaskMng)FinishInitMultiReceiver,0, 0, (u32*)RX_MODE+receiveBuf[MAX_CHANNEL_1-1].pipeNumber);
	changeCallBackLabel(initTransportLayer,FinishInitMultiReceiver);
	connectTaskToSignal(socetReceivePacet,(void*)signalNrf24ReceiveMessages_1);
}
#endif

static void offSession(BaseSize_t sessionID, BaseParam_t arg_p) {
	if(sessionID > MAX_CHANNEL_1) {
		execCallBack(((void*)(u32*)offSession+sessionID));
		return;
	}
	writeLogWhithStr("Off session: ", sessionID);
	u08 i = sessionID-1;
	receiveBuf[i].isBusy = FALSE; receiveBuf[i].isReady = FALSE;
	freeMem(receiveBuf[i].buff);  receiveBuf[i].buff = NULL;
	LED_OFF();
	execCallBack(((void*)(u32*)offSession+sessionID));
}

static void EnableTransmitter(u16 sessionID,  ClientData_t *data) {
	GET_MUTEX(NRF1_MUTEX_1, EnableTransmitter,sessionID, data);
	nRF24_SetPowerMode(1, nRF24_PWR_DOWN);
	u08 i = sessionID-1;
	updateTimer(offSession,sessionID,NULL,(TICK_PER_SECOND>>1)); // Таймоут для очистки передатчика
	changeCallBackLabel((void*)((u32*)EnableTransmitter+sessionID),TX_MODE);
	SetTask((TaskMng)TX_MODE,0,(BaseParam_t)&receiveBuf[i].pipe);
	return;
}

static void DisableTransmitter(u16 sessionID,  ClientData_t *data) {
	nRF24_SetPowerMode(1, nRF24_PWR_DOWN);
	SetTask((TaskMng)RX_MODE,receiveBuf[0].pipeNumber,(BaseParam_t)&receiveBuf[0].pipe); // Восстанавливаем нулевой пайп
	registerCallBack((TaskMng)FinishInitMultiReceiver,0,0,(u32*)RX_MODE+receiveBuf[0].pipeNumber);
	changeCallBackLabel((u32*)DisableTransmitter+sessionID,FinishInitMultiReceiver);
	freeMutex(NRF1_MUTEX_1);
	return;
}

static void Send(u16 sessionID,  ClientData_t *data) {
	u08 i = sessionID-1;
	writeLogStr("SEND:");
	changeCallBackLabel((void*)((u32*)Send+sessionID),TransmitPacket);
	SetTimerTask(TransmitPacket,receiveBuf[i].pipe.dataLength,data->second,2); // Необходимо заполнить весь буфер (можно мусором)
	return;
}

// Функция непосредственной отправки данных
// Устройство всегда работает на прием информации (за исключение необходимости передать что-то)
void sendToClient(u16 sessionID,  ClientData_t *data) {
	if(sessionID > MAX_CHANNEL_1) { execCallBack((void*)((u32*)sendToClient + sessionID)); return;}
	u08 i = sessionID-1;
	if(!receiveBuf[i].isBusy) {execCallBack((void*)((u32*)sendToClient + sessionID)); return;}
	SetTask((TaskMng)EnableTransmitter,sessionID,(BaseParam_t)data); // Включаем передатчик (забираем мьютекс)
	registerCallBack((TaskMng)Send,sessionID,(BaseParam_t)data,(void*)((u32*)EnableTransmitter+sessionID));
	registerCallBack((TaskMng)DisableTransmitter,sessionID,(BaseParam_t)data,(void*)((u32*)Send+sessionID)); // Возвращаемся к приему (освобождаем мьютекс)
	changeCallBackLabel((void*)((u32*)sendToClient + sessionID),(void*)((u32*)DisableTransmitter+sessionID));
}

// В случае, когда сервер является инициатором передачи данных.
void pushToClient(BaseSize_t count, channelBuff_t* client) {
	switch(count) {
	case 0: // Настраиваем передатчик
		GET_MUTEX(NRF1_MUTEX_1, pushToClient, count, client); // Берем мьютекс
		nRF24_SetPowerMode(1, nRF24_PWR_DOWN);
		count++;
		registerCallBack((TaskMng)pushToClient,count,(BaseParam_t)client,TX_MODE);
		SetTask((TaskMng)TX_MODE,0,(BaseParam_t)&client->pipe);
		return;
	case 1:
		writeLogStr("PUSH:");
		count++;
		registerCallBack((TaskMng)pushToClient,count,(BaseParam_t)client,TransmitPacket);
		SetTimerTask(TransmitPacket,client->pipe.dataLength, client->buff,2); // Необходимо заполнить весь буфер (можно мусором)
		return;
	case 2:
		count++;
		nRF24_SetPowerMode(1, nRF24_PWR_DOWN);
		SetTask((TaskMng)RX_MODE,receiveBuf[0].pipeNumber,(BaseParam_t)&receiveBuf[0].pipe);
		registerCallBack((TaskMng)FinishInitMultiReceiver,0,0,(u32*)RX_MODE+receiveBuf[0].pipeNumber);
		registerCallBack((TaskMng)pushToClient, count, (BaseParam_t)client, FinishInitMultiReceiver);
		return;
	case 3:
		freeMutex(NRF1_MUTEX_1);
		execCallBack((u32*)pushToClient+client->pipeNumber);
	}
}

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFromClient(u16 sessionID, ClientData_t *result) {
	if(sessionID > MAX_CHANNEL_1) {
		// Здесь мы быть не должны
		writeLogStr("ERROR: Incorrect session Id");
		execCallBack((void*)((u32*)receiveFromClient + sessionID));
		return;
	}
	u08 i = sessionID-1;
	if(receiveBuf[i].buff != NULL) { // Если есть данные
		updateTimer(offSession,sessionID,NULL,(TICK_PER_SECOND>>1)); // Таймоут для очистки приемника
		memCpy(result->second,receiveBuf[i].buff,result->first); // Читаем ровно столько сколько попросили
		freeMem(receiveBuf[i].buff);
		receiveBuf[i].buff = NULL; // Обнуляем буфер для получения следующих данных
		writeLogWhithStr("Receive: ", sessionID);
		execCallBack((void*)((u32*)receiveFromClient + sessionID));
		return;
	} else if (!receiveBuf[i].isBusy) {
		writeLogStr("ERROR: buf already not busy");
		execCallBack((void*)((u32*)receiveFromClient + sessionID));
		return;
	}
	writeSymb('.');
	SetTimerTask((TaskMng)receiveFromClient,sessionID,(BaseParam_t)result,2);
	return;
}

// Вернет идентификатор следующего готового узла для работы. (0 означает, что нет готовых узлов)
u16 getNextReadyDevice() {
	for(u08 i = 0; i<MAX_CHANNEL_1; i++) {
		if(receiveBuf[i].isReady) {
			receiveBuf[i].isReady = FALSE;
			receiveBuf[i].isBusy = TRUE;
			SetTimerTask(offSession,i+1,NULL,(TICK_PER_SECOND>>1));
			char buf[20]; strClear(buf); strCat(buf,"Ready channel:"); toStringDec(i,buf+strSize(buf)); writeLogTempString(buf);
			LED_ON();
			return i+1;
		}
	}
	return 0;
}
