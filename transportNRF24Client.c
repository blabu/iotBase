/*
 * transportNRF24Client.c
 *
 *  Created on: 7 трав. 2018 р.
 *      Author: Admin
 */

#include <nrf24AppLayer_1.h>
#include "transportClient.h"
#include "logging.h"
#include "nrf24.h"
#include "config.h"
#include "initLowLevelModule.h"
#include "utility.h"

/*
 * Модуль всегда находится в режиме приема
 * Когда нужно что-то передать переключаемся на передатчик
 * и в конце обязательно возвращаемся на прием.
 * */

#ifdef RETRY_ENABLE
#define RX_MODE_1 RXModeRetry_1
#define TX_MODE_1 TXModeRetry_1
#else
#define RX_MODE_1 RXMode_1
#define TX_MODE_1 TXMode_1
#endif

#ifndef NULL
#define NULL 0
#endif

static channelBuff_t receiveBuf;

#ifndef SERVER
static void socetReceivePacet(BaseSize_t pipeNumber, BaseParam_t buff) {
	if(pipeNumber == receiveBuf.pipeNumber) {
		writeSymb('+');
		receiveBuf.buff = buff;
		receiveBuf.isBusy = TRUE;
	}
}

void initTransportLayer(u08 channel, byte_ptr serverID) {
    nRF24_Init(0);
	nRF24_SetPowerMode(0, nRF24_PWR_DOWN);
	setChipEnable(0,FALSE);
	receiveBuf.isReady = FALSE; receiveBuf.isBusy = FALSE;
	receiveBuf.pipe.address[0] = serverID[0];  // Server address 1_5
	receiveBuf.pipe.address[1] = serverID[1]; // Server address 1_1
	receiveBuf.pipe.address[2] = serverID[2]; // Server address 1_2
	receiveBuf.pipe.address[3] = serverID[3]; // Server address 1_3
	receiveBuf.pipe.address[4] = serverID[4]; // Server address 1_4
	receiveBuf.pipe.channel = channel;
	receiveBuf.pipe.dataLength = 32;
	receiveBuf.pipeNumber = nRF24_PIPE1; // Нулевой занят для приема передатчика с подтверждением
	disconnectTaskFromSignal(socetReceivePacet,(void*)signalNrf24ReceiveMessages_1);
	connectTaskToSignal(socetReceivePacet,(void*)signalNrf24ReceiveMessages_1);
	SetTask(configureNRF24_1,nRF24_DR_250kbps,NULL);
	changeCallBackLabel(initTransportLayer,configureNRF24_1);
}
#endif

void enableTranseiver(BaseSize_t arg_n, BaseParam_t arg_p) {
	if(receiveBuf.isReady) { // Если мы уже включены
		execCallBack(enableTranseiver);
		return;
	}
	receiveBuf.isReady = TRUE;
	SetTask((TaskMng)RX_MODE_1,receiveBuf.pipeNumber,(BaseParam_t)(&receiveBuf.pipe));
	registerCallBack((TaskMng)FinishInitMultiReceiver_1,0,0,(u32*)RX_MODE_1+receiveBuf.pipeNumber);
	changeCallBackLabel(enableTranseiver,FinishInitMultiReceiver_1);
}

void disableTranseiver(BaseSize_t arg_n, BaseParam_t arg_p) {
	writeLogStr("TR OFF\r\n");
	receiveBuf.isReady = FALSE; receiveBuf.isBusy = FALSE;
	nRF24_SetPowerMode(0, nRF24_PWR_DOWN);
	setChipEnable(0,FALSE);
	execCallBack(disableTranseiver);
}

// Функция непосредственной отправки данных
void sendTo(u16 size, byte_ptr data) {
	static u08 count = 0;
	if(!receiveBuf.isReady) count = 0xFF;
	switch(count) {
	case 0:
		count++;
		writeLogStr("SEND:");
		registerCallBack((TaskMng)sendTo,size,(BaseParam_t)data,TX_MODE_1);
		SetTask((TaskMng)TX_MODE_1,0,(BaseParam_t)&receiveBuf.pipe);
		return;
	case 1:case 2:case 3:case 4:case 5: count++; break; // Задержка для модуля передачи данных
	case 6:
		count++;
		registerCallBack((TaskMng)sendTo,size,(BaseParam_t)data,TransmitPacket_1);
		SetTask(TransmitPacket_1,receiveBuf.pipe.dataLength,data); // Необходимо заполнить весь буфер (можно мусором)
		return;
	case 7: // Возвращаемся в режим приема
		count=0;
		SetTask((TaskMng)RX_MODE_1,receiveBuf.pipeNumber,(BaseParam_t)&receiveBuf.pipe);
		registerCallBack((TaskMng)FinishInitMultiReceiver_1,0,0,(u32*)RX_MODE_1+receiveBuf.pipeNumber);
		changeCallBackLabel((TaskMng)sendTo,FinishInitMultiReceiver_1);
		return;
	default:
		count = 0;
		execCallBack(sendTo);
		return;
	}
	SetTask((TaskMng)sendTo,size,data);
}

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFrom(u16 size, byte_ptr result) {
	static const u08 ATTEMPT = 237; // 237 раз пытаемся прочитать с интервалом TIME_DELAY_IF_BUSY
	static u08 tryReceiveAttempt = ATTEMPT;
	if(receiveBuf.buff != NULL) { // Если есть данные
		tryReceiveAttempt = ATTEMPT;
		memCpy(result,receiveBuf.buff,size); // Читаем ровно столько сколько попросили
		receiveBuf.buff = NULL; // Обнуляем буфер для получения следующих данных
		writeLogStr("RECEIVE:");
		execCallBack(receiveFrom);
		return;
	}
	writeSymb('.');
	if((tryReceiveAttempt--) > 0) SetTimerTask((TaskMng)receiveFrom,size,(BaseParam_t)result,TIME_DELAY_IF_BUSY);
	else {
		tryReceiveAttempt = ATTEMPT;
		execCallBack(receiveFrom);
	}
	return;
}
