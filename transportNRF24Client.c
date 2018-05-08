/*
 * transportNRF24Client.c
 *
 *  Created on: 7 трав. 2018 р.
 *      Author: Admin
 */

#include "transportClient.h"
#include "initTransmitLL.h"
#include "logging.h"
#include "nrf24.h"
#include "nrf24AppLayer.h"

/*
 * Модуль всегда находится в режиме приема
 * Когда нужно что-то передать переключаемся на передатчик
 * и в конце обязательно возвращаемся на прием.
 * */

typedef struct {
		bool_t isReady;
		u08 pipeNumber;
		channel_t pipe;
		byte_ptr buff;
} channelBuff_t;

static channelBuff_t receiveBuf;

static void socetReceivePacet(BaseSize_t pipeNumber, BaseParam_t buff) {
	if(receiveBuf.pipeNumber == pipeNumber) {
		receiveBuf.buff = buff;
	}
}

void initTransportLayer(u08 channel, byte_ptr addrHeader) {
    nRF24_Init();
	nRF24_SetPowerMode(nRF24_PWR_DOWN);
	nRF24_CE_L();
	receiveBuf.isReady = FALSE;
	receiveBuf.pipe.address[0] = 1;  // Server address 1_5
	receiveBuf.pipe.address[1] = addrHeader[3]; // Server address 1_1
	receiveBuf.pipe.address[2] = addrHeader[2]; // Server address 1_2
	receiveBuf.pipe.address[3] = addrHeader[1]; // Server address 1_3
	receiveBuf.pipe.address[4] = addrHeader[0]; // Server address 1_4
	receiveBuf.pipe.channel = channel;
	receiveBuf.pipe.dataLength = 32;
	receiveBuf.pipeNumber = nRF24_PIPE1; // Нулевой занят для приема передатчика с подтверждением
	connectTaskToSignal(socetReceivePacet,(void*)signalNrf24ReceiveMessages);
	SetTask(configureNRF24,nRF24_DR_250kbps,NULL);
	changeCallBackLabel(initTransportLayer,configureNRF24);
}

void enableTranseiver(BaseSize_t arg_n, BaseParam_t arg_p) {
	if(receiveBuf.isReady) { // Если мы уже включены
		execCallBack(enableTranseiver);
		return;
	}
	receiveBuf.isReady = TRUE;
	SetTask((TaskMng)RXModeRetry,receiveBuf.pipeNumber,(BaseParam_t)(&receiveBuf.pipe));
	changeCallBackLabel(enableTranseiver,RXModeRetry);
}

void disableTranseiver(BaseSize_t arg_n, BaseParam_t arg_p) {
	writeLogStr("Disable tr\n");
	receiveBuf.isReady = FALSE;
	nRF24_SetPowerMode(nRF24_PWR_DOWN);
	nRF24_CE_L();
	execCallBack(disableTranseiver);
}

// Функция непосредственной отправки данных
void sendTo(u16 size, byte_ptr data) {
	static u08 count = 0;
	switch(count) {
	case 0:
		nRF24_SetPowerMode(nRF24_PWR_DOWN);
		count++;
		registerCallBack((TaskMng)sendTo,size,(BaseParam_t)data,TXModeRetry);
		SetTask((TaskMng)TXModeRetry,0,(BaseParam_t)&receiveBuf.pipe);
		return;
	case 1: case 2: // Задержка для перехода в режим передатчика
		count++;
		break;
	case 3:
		count++;
		writeLogStr(data);
		registerCallBack((TaskMng)sendTo,size,(BaseParam_t)data,TransmitPacket);
		SetTask(TransmitPacket,receiveBuf.pipe.dataLength,data); // Необходимо заполнить весь буфер (можно мусором)
		return;
	case 4: // Возвращаемся в режим приема
		count++;
		nRF24_SetPowerMode(nRF24_PWR_DOWN);
		registerCallBack((TaskMng)sendTo,size,(BaseParam_t)data,RXModeRetry);
		SetTask((TaskMng)RXModeRetry,receiveBuf.pipeNumber,(BaseParam_t)&receiveBuf.pipe);
		return;
	case 5:
	default:
		count = 0;
		execCallBack(sendTo);
		return;
	}
	SetTimerTask((TaskMng)sendTo,size,(BaseParam_t)data,2);
}

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFrom(u16 size, byte_ptr result) {
	static const u08 ATTEMPT = 100;
	static u08 tryReceiveAttempt = ATTEMPT;
	if(receiveBuf.buff != NULL) { // Если есть данные
		tryReceiveAttempt = ATTEMPT;
		memCpy(result,receiveBuf.buff,size); // Читаем ровно столько сколько попросили
		receiveBuf.buff = NULL; // Обнуляем буфер для получения следующих данных
		execCallBack(receiveFrom);
		return;
	}
	writeLogStr(".");
	if((tryReceiveAttempt--) > 0) SetTimerTask((TaskMng)receiveFrom,size,(BaseParam_t)result,TIME_DELAY_IF_BUSY);
	else {
		tryReceiveAttempt = ATTEMPT;
		execCallBack(receiveFrom);
	}
	return;
}

// Функция сохрания параметры в память
void saveParameters(u16 id, byte_ptr key, u08 size) {
	writeLogU32(id);
	writeLogByteArray(size, key);
	execCallBack(saveParameters);
}

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getParameters(u16* id, byte_ptr key, u08 size) {
	*id = 0x10;
	memSet(key,size,0x31);
	execCallBack(getParameters);
}
