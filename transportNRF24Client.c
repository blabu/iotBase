/*
 * transportNRF24Client.c
 *
 *  Created on: 7 трав. 2018 р.
 *      Author: Admin
 */

#include "transportClient.h"
#include "logging.h"
#include "nrf24.h"
#include "nrf24AppLayer.h"
#include "config.h"
#include "initLowLevelModule.h"
#include "utility.h"

/*
 * Модуль всегда находится в режиме приема
 * Когда нужно что-то передать переключаемся на передатчик
 * и в конце обязательно возвращаемся на прием.
 * */

#ifdef RETRY_ENABLE
#define RX_MODE RXModeRetry
#define TX_MODE TXModeRetry
#else
#define RX_MODE RXMode
#define TX_MODE TXMode
#endif

static channelBuff_t receiveBuf;

#ifndef SERVER
static void socetReceivePacet(BaseSize_t pipeNumber, BaseParam_t buff) {
	if(!receiveBuf.isBusy) {
		writeSymb('+');
		receiveBuf.buff = buff;
		receiveBuf.isBusy = TRUE;
	}
}

void initTransportLayer(u08 channel, byte_ptr serverID) {
    nRF24_Init();
	nRF24_SetPowerMode(1, nRF24_PWR_DOWN);
	setChipEnable(1,FALSE);
	receiveBuf.isReady = FALSE; receiveBuf.isBusy = FALSE;
	receiveBuf.pipe.address[0] = serverID[0];  // Server address 1_5
	receiveBuf.pipe.address[1] = serverID[1]; // Server address 1_1
	receiveBuf.pipe.address[2] = serverID[2]; // Server address 1_2
	receiveBuf.pipe.address[3] = serverID[3]; // Server address 1_3
	receiveBuf.pipe.address[4] = serverID[4]; // Server address 1_4
	receiveBuf.pipe.channel = channel;
	receiveBuf.pipe.dataLength = 32;
	receiveBuf.pipeNumber = nRF24_PIPE1; // Нулевой занят для приема передатчика с подтверждением
	connectTaskToSignal(socetReceivePacet,(void*)signalNrf24ReceiveMessages_1);
	SetTask(configureNRF24,nRF24_DR_250kbps,NULL);
	changeCallBackLabel(initTransportLayer,configureNRF24);
}
#endif

void enableTranseiver(BaseSize_t arg_n, BaseParam_t arg_p) {
	if(receiveBuf.isReady) { // Если мы уже включены
		execCallBack(enableTranseiver);
		return;
	}
	receiveBuf.isReady = TRUE;
	SetTask((TaskMng)RX_MODE,receiveBuf.pipeNumber,(BaseParam_t)(&receiveBuf.pipe));
	registerCallBack((TaskMng)FinishInitMultiReceiver,0,0,(u32*)RX_MODE+receiveBuf.pipeNumber);
	changeCallBackLabel(enableTranseiver,FinishInitMultiReceiver);
}

void disableTranseiver(BaseSize_t arg_n, BaseParam_t arg_p) {
	writeLogStr("TR OFF\r\n");
	receiveBuf.isReady = FALSE; receiveBuf.isBusy = FALSE;
	nRF24_SetPowerMode(1, nRF24_PWR_DOWN);
	setChipEnable(1,FALSE);
	execCallBack(disableTranseiver);
}

// Функция непосредственной отправки данных
void sendTo(u16 size, byte_ptr data) {
	static u08 count = 0;
	if(!receiveBuf.isReady) count = 0xFF;
	switch(count) {
	case 0:
		nRF24_SetPowerMode(1, nRF24_PWR_DOWN);
		count++;
		writeLogStr("SEND:");
		registerCallBack((TaskMng)sendTo,size,(BaseParam_t)data,TX_MODE);
		SetTask((TaskMng)TX_MODE,0,(BaseParam_t)&receiveBuf.pipe);
		return;
	case 1:case 2: count++; SetTask((TaskMng)sendTo,size,data); break; // Задержка для модуля передачи данных
	case 3:
		count++;
		registerCallBack((TaskMng)sendTo,size,(BaseParam_t)data,TransmitPacket);
		SetTask(TransmitPacket,receiveBuf.pipe.dataLength,data); // Необходимо заполнить весь буфер (можно мусором)
		return;
	case 4: // Возвращаемся в режим приема
		count++;
		nRF24_SetPowerMode(1, nRF24_PWR_DOWN);
		SetTask((TaskMng)RX_MODE,receiveBuf.pipeNumber,(BaseParam_t)&receiveBuf.pipe);
		registerCallBack((TaskMng)FinishInitMultiReceiver,0,0,(u32*)RX_MODE+receiveBuf.pipeNumber);
		registerCallBack((TaskMng)sendTo,size,(BaseParam_t)data,FinishInitMultiReceiver);
		return;
	case 5:
	default:
		count = 0;
		execCallBack(sendTo);
		return;
	}
}

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFrom(u16 size, byte_ptr result) {
	static const u08 ATTEMPT = 30; // 30 раз пытаемся прочитать с интервалом TIME_DELAY_IF_BUSY
	static u08 tryReceiveAttempt = ATTEMPT;
	if(receiveBuf.isBusy && receiveBuf.buff != NULL) { // Если есть данные
		tryReceiveAttempt = ATTEMPT;
		memCpy(result,receiveBuf.buff,size); // Читаем ровно столько сколько попросили
		receiveBuf.buff = NULL; // Обнуляем буфер для получения следующих данных
		receiveBuf.isBusy = FALSE;
		writeLogStr("RECEIVE:");
		execCallBack(receiveFrom);
		return;
	}
	writeSymb('.');
	if((tryReceiveAttempt--) > 0) SetTimerTask((TaskMng)receiveFrom,size,(BaseParam_t)result,2);
	else {
		tryReceiveAttempt = ATTEMPT;
		execCallBack(receiveFrom);
	}
	return;
}
