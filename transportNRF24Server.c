/*
 * transportNRF24Server.h
 *
 *  Created on: 5 мая 2018 г.
 *      Author: blabu
 */

#include <nrf24AppLayer_1.h>
#include <nrf24AppLayer_2.h>
#include "nrf24.h"
#include "logging.h"
#include "MyString.h"
#include "initLowLevelModule.h"
#include "transportServer.h"
#include "PlatformSpecific.h"
#include "config.h"
#include "led.h"

#define OFF_TIMEOUT (TICK_PER_SECOND>>1)

/*
 * Модуль всегда находится в режиме приема
 * Когда нужно что-то передать переключаемся на передатчик
 * и в конце обязательно возвращаемся на прием
 * */
#ifdef RETRY_ENABLE
#define RX_MODE_1 RXModeRetry_1
#define TX_MODE_1 TXModeRetry_1
#define RX_MODE_2 RXModeRetry_2
#define TX_MODE_2 TXModeRetry_2
#else
#define RX_MODE_1 RXMode_1
#define TX_MODE_1 TXMode_1
#define RX_MODE_2 RXMode_2
#define TX_MODE_2 TXMode_2
#endif

#define NRF_MUTEX_1 1<<0
#define NRF_MUTEX_2 1<<1

#define MAX_CHANNEL 5

#ifdef SERVER
static channelBuff_t receiveBuf[2][MAX_CHANNEL];

static void socetReceivePacet_1(BaseSize_t pipeNumber, BaseParam_t buff) {
	if(pipeNumber >= MAX_CHANNEL) writeLogStr("ERROR: incorrect pipe number");
	if(!receiveBuf[0][pipeNumber].isBusy) {
		writeSymb('+');
		writeLogU32(pipeNumber);
		receiveBuf[0][pipeNumber].isReady = TRUE;
	}
	if(receiveBuf[0][pipeNumber].buff == NULL){ // Аллоцируем память если еще этого не делали
		receiveBuf[0][pipeNumber].buff = allocMem(receiveBuf[0][pipeNumber].pipe.dataLength);
		if(receiveBuf[0][pipeNumber].buff == NULL){
			writeLogStr("ERROR: memory allocate for receive buffer");
			receiveBuf[0][pipeNumber].buff = buff;  // Если памяти совсем нет, будем надеятся что успеем считать данные
			return;
		}
	}
	writeSymb('|');
	memCpy(receiveBuf[0][pipeNumber].buff,buff,receiveBuf[0][pipeNumber].pipe.dataLength);
}

static void socetReceivePacet_2(BaseSize_t pipeNumber, BaseParam_t buff) {
	if(pipeNumber >= MAX_CHANNEL) writeLogStr("ERROR: incorrect pipe number");
	if(!receiveBuf[1][pipeNumber].isBusy) {
		writeSymb('+');
		writeLogU32(pipeNumber);
		receiveBuf[1][pipeNumber].isReady = TRUE;
	}
	if(receiveBuf[1][pipeNumber].buff == NULL){ // Аллоцируем память если еще этого не делали
		receiveBuf[1][pipeNumber].buff = allocMem(receiveBuf[1][pipeNumber].pipe.dataLength);
		if(receiveBuf[1][pipeNumber].buff == NULL){
			writeLogStr("ERROR: memory allocate for receive buffer");
			receiveBuf[1][pipeNumber].buff = buff;  // Если памяти совсем нет, будем надеятся что успеем считать данные
			return;
		}
	}
	writeSymb('|');
	memCpy(receiveBuf[1][pipeNumber].buff,buff,receiveBuf[1][pipeNumber].pipe.dataLength);
}

// Устройство в режиме сервера всегда работает как приемник
void initTransportLayer(u08 channel, byte_ptr serverID) {
	u08 chan[2];
	chan[0] = channel;
	if(channel > 60) chan[1] = channel - 60;
	else chan[1] = channel + 60;
	for(u08 k = 0; k<2; k++) {
		nRF24_Init(k);
		nRF24_SetPowerMode(k, nRF24_PWR_DOWN);
		setChipEnable(k,FALSE);
		receiveBuf[k][0].isReady = FALSE; receiveBuf[k][0].isBusy  = FALSE;
		receiveBuf[k][0].buff = NULL;
		receiveBuf[k][0].pipeNumber = 0;
		receiveBuf[k][0].pipe.address[0] = PING_ADDR[0];  // Server address 1_5
		receiveBuf[k][0].pipe.address[1] = PING_ADDR[1]; // Server address 1_1
		receiveBuf[k][0].pipe.address[2] = PING_ADDR[2]; // Server address 1_2
		receiveBuf[k][0].pipe.address[3] = PING_ADDR[3]; // Server address 1_3
		receiveBuf[k][0].pipe.address[4] = PING_ADDR[4]; // Server address 1_4
		receiveBuf[k][0].pipe.channel = chan[k];
		receiveBuf[k][0].pipe.dataLength = 32;
		for(u08 i=1; i<MAX_CHANNEL; i++) {
			receiveBuf[k][i].isReady = FALSE; receiveBuf[k][i].isBusy  = FALSE;
			receiveBuf[k][i].buff = NULL;
			receiveBuf[k][i].pipeNumber = i;
			receiveBuf[k][i].pipe.address[0] = i+1;  // Server address 1_5
			receiveBuf[k][i].pipe.address[1] = serverID[1]; // Server address 1_1
			receiveBuf[k][i].pipe.address[2] = serverID[2]; // Server address 1_2
			receiveBuf[k][i].pipe.address[3] = serverID[3]; // Server address 1_3
			receiveBuf[k][i].pipe.address[4] = serverID[4]; // Server address 1_4
			receiveBuf[k][i].pipe.channel = chan[k];
			receiveBuf[k][i].pipe.dataLength = 32;
			if(k==0) registerCallBack((TaskMng)RX_MODE_1,receiveBuf[k][i].pipeNumber,(BaseParam_t)(&receiveBuf[k][i].pipe),(u32*)RX_MODE_1+receiveBuf[k][i-1].pipeNumber);
			else if(k==1) registerCallBack((TaskMng)RX_MODE_2,receiveBuf[k][i].pipeNumber,(BaseParam_t)(&receiveBuf[k][i].pipe),(u32*)RX_MODE_2+receiveBuf[k][i-1].pipeNumber);
		}
	}
	SetTask(configureNRF24_1,nRF24_DR_250kbps,NULL);
	registerCallBack((TaskMng)RX_MODE_1,receiveBuf[0][0].pipeNumber,(BaseParam_t)(&receiveBuf[0][0].pipe),configureNRF24_1);
	registerCallBack((TaskMng)FinishInitMultiReceiver_1,0, 0, (u32*)RX_MODE_1+receiveBuf[0][MAX_CHANNEL-1].pipeNumber);
	connectTaskToSignal(socetReceivePacet_1,(void*)signalNrf24ReceiveMessages_1);

	SetTask(configureNRF24_2,nRF24_DR_250kbps,NULL);
	registerCallBack((TaskMng)RX_MODE_2,receiveBuf[1][0].pipeNumber,(BaseParam_t)(&receiveBuf[1][0].pipe),configureNRF24_2);
	registerCallBack((TaskMng)FinishInitMultiReceiver_2,0, 0, (u32*)RX_MODE_2+receiveBuf[1][MAX_CHANNEL-1].pipeNumber);
	connectTaskToSignal(socetReceivePacet_2,(void*)signalNrf24ReceiveMessages_2);

	changeCallBackLabel(initTransportLayer,FinishInitMultiReceiver_2);
	writeLogStr("INFO: Start init server");
}

static void offSession(BaseSize_t sessionID, BaseParam_t arg_p) {
	u08 moduleNumb = sessionID >> 4;
	u08 pipeNumb = sessionID & 0xF;
	if(pipeNumb > MAX_CHANNEL || moduleNumb > 1) {
		execCallBack(((void*)(u32*)offSession+sessionID));
		return;
	}
	writeLogWhithStr("INFO: Off session: ", sessionID);
	u08 i = pipeNumb-1;
	receiveBuf[moduleNumb][i].isBusy = FALSE; receiveBuf[moduleNumb][i].isReady = FALSE;
	freeMem(receiveBuf[moduleNumb][i].buff);  receiveBuf[moduleNumb][i].buff = NULL;
	LED_OFF();
	execCallBack(((void*)(u32*)offSession+sessionID));
}

static void EnableTransmitter(u16 sessionID,  ClientData_t *data) {
	u08 moduleNumb = sessionID >> 4;
	u08 pipeNumb = sessionID & 0xF;
	if(moduleNumb == 0) {
		GET_MUTEX(NRF_MUTEX_1, EnableTransmitter,sessionID, data);
		u08 i = pipeNumb-1;
		updateTimer(offSession,sessionID,NULL,OFF_TIMEOUT); // Таймоут для очистки передатчика
		changeCallBackLabel((void*)((u32*)EnableTransmitter+sessionID),TX_MODE_1);
		SetTask((TaskMng)TX_MODE_1,0,(BaseParam_t)&receiveBuf[moduleNumb][i].pipe);
	} else if(moduleNumb == 1) {
		GET_MUTEX(NRF_MUTEX_2, EnableTransmitter,sessionID, data);
		u08 i = pipeNumb-1;
		updateTimer(offSession,sessionID,NULL,OFF_TIMEOUT); // Таймоут для очистки передатчика
		changeCallBackLabel((void*)((u32*)EnableTransmitter+sessionID),TX_MODE_2);
		SetTask((TaskMng)TX_MODE_2,0,(BaseParam_t)&receiveBuf[moduleNumb][i].pipe);
	} else {
		execCallBack((void*)((u32*)EnableTransmitter+sessionID));
	}
}

static void DisableTransmitter(u16 sessionID,  ClientData_t *data) {
	u08 moduleNumb = sessionID >> 4;
	if(moduleNumb == 0) {
		SetTask((TaskMng)RX_MODE_1,receiveBuf[moduleNumb][0].pipeNumber,(BaseParam_t)&receiveBuf[moduleNumb][0].pipe); // Восстанавливаем нулевой пайп (участвовал в передачи)
		registerCallBack((TaskMng)FinishInitMultiReceiver_1,0,0,(u32*)RX_MODE_1+receiveBuf[moduleNumb][0].pipeNumber);
		changeCallBackLabel((u32*)DisableTransmitter+sessionID,FinishInitMultiReceiver_1);
		freeMutex(NRF_MUTEX_1);
	} else if (moduleNumb == 1){
		SetTask((TaskMng)RX_MODE_2,receiveBuf[moduleNumb][0].pipeNumber,(BaseParam_t)&receiveBuf[moduleNumb][0].pipe); // Восстанавливаем нулевой пайп (участвовал в передачи)
		registerCallBack((TaskMng)FinishInitMultiReceiver_2,0,0,(u32*)RX_MODE_2+receiveBuf[moduleNumb][0].pipeNumber);
		changeCallBackLabel((u32*)DisableTransmitter+sessionID,FinishInitMultiReceiver_2);
		freeMutex(NRF_MUTEX_2);
	}else {
		execCallBack((u32*)DisableTransmitter+sessionID);
	}
}

static void Send(u16 sessionID,  ClientData_t *data) {
	u08 moduleNumb = sessionID >> 4;
	u08 pipeNumb = sessionID & 0xF;
	u08 i = pipeNumb-1;
	if(moduleNumb == 0) {
		writeLogStr("INFO: Send nrf0:");
		changeCallBackLabel((void*)((u32*)Send+sessionID),TransmitPacket_1);
		SetTimerTask(TransmitPacket_1,receiveBuf[moduleNumb][i].pipe.dataLength,data->second,2); // Необходимо заполнить весь буфер (можно мусором)
	} else if(moduleNumb == 1){
		writeLogStr("INFO: Send nrf1:");
		changeCallBackLabel((void*)((u32*)Send+sessionID),TransmitPacket_2);
		SetTimerTask(TransmitPacket_2,receiveBuf[moduleNumb][i].pipe.dataLength,data->second,2); // Необходимо заполнить весь буфер (можно мусором)
	} else {
		writeLogStr("ERROR: send");
		execCallBack((void*)((u32*)Send+sessionID));
	}
}

// Функция непосредственной отправки данных
// Устройство всегда работает на прием информации (за исключение необходимости передать что-то)
void sendToClient(u16 sessionID,  ClientData_t *data) {
	u08 moduleNumb = sessionID >> 4;
	u08 pipeNumb = sessionID & 0xF;
	if(pipeNumb > MAX_CHANNEL || moduleNumb > 1) { execCallBack((void*)((u32*)sendToClient + sessionID)); return; }
	u08 i = pipeNumb-1;
	if(!receiveBuf[moduleNumb][i].isBusy) {execCallBack((void*)((u32*)sendToClient + sessionID)); return;}
	SetTask((TaskMng)EnableTransmitter,sessionID,(BaseParam_t)data); // Включаем передатчик (забираем мьютекс)
	registerCallBack((TaskMng)Send,sessionID,(BaseParam_t)data,(void*)((u32*)EnableTransmitter+sessionID));
	registerCallBack((TaskMng)DisableTransmitter,sessionID,(BaseParam_t)data,(void*)((u32*)Send+sessionID)); // Возвращаемся к приему (освобождаем мьютекс)
	changeCallBackLabel((void*)((u32*)sendToClient + sessionID),(void*)((u32*)DisableTransmitter+sessionID));
}

// В случае, когда сервер является инициатором передачи данных.
void pushToClient(BaseSize_t count, channelBuff_t* client) {
	if(count>0 && !client->isBusy) count = 0xFF;
	switch(count) {
	case 0: // Настраиваем передатчик
		GET_MUTEX(NRF_MUTEX_1, pushToClient, count, client);
		count++;
		client->isBusy = TRUE; client->isReady = FALSE;
		client->pipeNumber = 0;
		registerCallBack((TaskMng)pushToClient,count,(BaseParam_t)client,TX_MODE_1);
		SetTask((TaskMng)TX_MODE_1,0,(BaseParam_t)&client->pipe);
		return;
	case 1:
		writeLogStr("INFO: PUSH:");
		count++;
		registerCallBack((TaskMng)pushToClient,count,(BaseParam_t)client,TransmitPacket_1);
		SetTimerTask(TransmitPacket_1,client->pipe.dataLength, client->buff, 2); // Необходимо заполнить весь буфер (можно мусором)
		return;
	case 2: // Ждем ответ от клиента
		count++;
		memSet(client->buff,client->pipe.dataLength,0);
		SetTimerTask(offSession, client->pipeNumber+1, NULL, OFF_TIMEOUT); // Таймоут на получение ответа от клиента
		SetTask((TaskMng)RX_MODE_1,client->pipeNumber,(BaseParam_t)&client->pipe); // Выставляем модуль в режим приема
		registerCallBack((TaskMng)FinishInitMultiReceiver_1,0,0,(u32*)RX_MODE_1+client->pipeNumber);
		registerCallBack((TaskMng)pushToClient, count, (BaseParam_t)client, FinishInitMultiReceiver_1);
		freeMem(receiveBuf[0][client->pipeNumber].buff); receiveBuf[0][client->pipeNumber].buff = NULL; // Очищаем буфер
		return;
	case 3:
		if(receiveBuf[0][client->pipeNumber].buff != NULL) {
			count++;
			memCpy(client->buff,receiveBuf[0][client->pipeNumber].buff,client->pipe.dataLength);
		} else {
			writeSymb(':');
			SetTimerTask((TaskMng)pushToClient,count,(BaseParam_t)client,2);
			return;
		}
		// no break;
	case 4: // Возвращаем все как было до отправки PUSH
		count++;
		SetTask((TaskMng)RX_MODE_1,receiveBuf[0][0].pipeNumber,(BaseParam_t)&receiveBuf[0][0].pipe);
		registerCallBack((TaskMng)FinishInitMultiReceiver_1,0,0,(u32*)RX_MODE_1+receiveBuf[0][0].pipeNumber);
		registerCallBack((TaskMng)pushToClient, count, (BaseParam_t)client, FinishInitMultiReceiver_1);
		return;
	case 5:
		freeMutex(NRF_MUTEX_1);
		execCallBack((u32*)pushToClient+client->pipeNumber);
		return;
	default:
		writeLogStr("WARN: Undef error when try pushing");
		memSet(client->buff,client->pipe.dataLength,0);
		SetTask((TaskMng)RX_MODE_1,receiveBuf[0][0].pipeNumber,(BaseParam_t)&receiveBuf[0][0].pipe);
		registerCallBack((TaskMng)FinishInitMultiReceiver_1,0,0,(u32*)RX_MODE_1+receiveBuf[0][0].pipeNumber);
		freeMutex(NRF_MUTEX_1);
		execCallBack((u32*)pushToClient+client->pipeNumber);
		return;
	}
}

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFromClient(u16 sessionID, ClientData_t *result) {
	u08 moduleNumb = sessionID >> 4;
	u08 pipeNumb = sessionID & 0xF;
	if(pipeNumb > MAX_CHANNEL || moduleNumb > 1) {
		// Здесь мы быть не должны
		writeLogStr("ERROR: Incorrect session Id");
		execCallBack((void*)((u32*)receiveFromClient + sessionID));
		return;
	}
	u08 i = pipeNumb-1;
	if(receiveBuf[moduleNumb][i].buff != NULL) { // Если есть данные
		updateTimer(offSession, sessionID, NULL, OFF_TIMEOUT); // Таймоут для очистки приемника
		memCpy(result->second,receiveBuf[moduleNumb][i].buff,result->first); // Читаем ровно столько сколько попросили
		freeMem(receiveBuf[moduleNumb][i].buff);
		receiveBuf[moduleNumb][i].buff = NULL; // Обнуляем буфер для получения следующих данных
		writeLogWhithStr("INFO: Receive: ", sessionID);
		execCallBack((void*)((u32*)receiveFromClient + sessionID));
		return;
	} else if (!receiveBuf[moduleNumb][i].isBusy) {
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
	static u32 sessionCount = 0;
	for(u08 j = 0; j<2; j++) {
		for(u08 i = 0; i<MAX_CHANNEL; i++) {
			if(receiveBuf[j][i].isReady) {
				receiveBuf[j][i].isReady = FALSE;
				receiveBuf[j][i].isBusy = TRUE;
				u08 sessionID = (j<<4) | (i+1);
				SetTimerTask(offSession, sessionID, NULL, OFF_TIMEOUT);
				writeLogStr("\r\n----------------------------------------------\r\nNEW SESSION");
				writeLogU32(++sessionCount);
				LED_ON();
				return sessionID;
			}
		}
	}
	return 0;
}

#endif
