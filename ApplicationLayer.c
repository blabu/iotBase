/*
 * ApplicationLayer.c
 *
 *  Created on: Mar 22, 2018
 *      Author: okh
 */


#include "IotProtocolClient.h"
#include "ApplicationLayer.h"
#include "transportClient.h"
#include "MyString.h"
#include "config.h"
#include "logging.h"
#include "led.h"

/* .
 * .
 * .
 * */
#ifndef SERVER
/* Регистрация устройства по его типу в системе. Выполняется без шифрования
 * Заполнит поле CryptKey ключом шифрования используется AES128
 */
void Register(BaseSize_t type, BaseParam_t buffer){
	static u08 count = 0;
	byte_ptr buff = (byte_ptr)buffer;
	u16 id = 0;
	switch(count) {
	case 0: // Запрос на регистрацию
		if(type == 0) {
			execCallBack(Register);
			return;
		}
		LED_ON();
		writeLogStr("TRY REG\r\n");
		GetLastStatus();
		if(buff != NULL) freeMem(buff);
		buff = allocMem(2+KEY_SIZE+1); // Идентификатор (два байта) + Ключ + запасной байт
		if(buff == NULL) {
			execCallBack(Register);
			return;
		}
		memSet(buff,getAllocateMemmorySize(buff),0);
		setId(type);
		setSecurity(FALSE);
		count++;
		registerCallBack(Register,type,(BaseParam_t)buff,ReadClient);
		SetTask((TaskMng)ReadClient,getAllocateMemmorySize(buff), (BaseParam_t)buff);
		return;
	case 1: // Анализ ответа
		id = *((u16*)buff); // Первые два байта это идентификатор
		if((id>>8) != type) {
			count = 0xFF;
			writeLogStr("ERROR: Reg\r\n");
			SetTask(Register,type,(BaseParam_t)buff);
			return;
		}
		count++;
		registerCallBack(Register,type,(BaseParam_t)buff,saveParameters);
		saveParameters(id, buff+2, KEY_SIZE, FALSE);
		return;
	case 2:
	default:
		count = 0;
		LED_OFF();
		freeMem(buff);
		execCallBack(Register);
		return;
	}
}

#endif
